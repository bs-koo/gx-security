"""Rule-specific behavior and initial priority must remain distinct from verification."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml

from gxsec import adapters, config, policy, source

ROOT = Path(__file__).resolve().parents[1]
CORS_RULE = 'sqisoft-spring-cors-wildcard-credentials'


def catalog():
    return {rule['id']: rule for path in sorted(ROOT.glob('skills/detecting-*/rules/*.yml'))
            for rule in yaml.safe_load(path.read_text(encoding='utf-8-sig'))['rules']}


@pytest.mark.parametrize('review_hint', [None, False, 'false'])
def test_catalog_priorities_are_consumed_without_promoting_candidates(tmp_path, monkeypatch, review_hint):
    root = tmp_path / 'project'
    root.mkdir()
    (root / 'Sample.java').write_text('class Sample { String value; }', encoding='utf-8')
    rules = catalog()

    def probe(name, options, target, check, **kwargs):
        check['engine']['version'] = '1.172.0'
        return 'semgrep-captured-output'

    def output(command, **kwargs):
        target = str(root / 'Sample.java')
        results = [{'check_id': rid, 'path': target, 'start': {'line': 1, 'col': 1},
                    'end': {'line': 1, 'col': 31}, 'extra': {'severity': 'INFO',
                    'metadata': {'severity': 'Info'}, 'message': 'untrusted engine metadata'}}
                   for rid in rules]
        return subprocess.CompletedProcess(command, 0, json.dumps({
            'results': results, 'errors': [], 'paths': {'scanned': [target]}}), '')

    monkeypatch.setattr(adapters, '_probe', probe)
    monkeypatch.setattr(adapters, '_run', output)
    original_guidance = adapters._rule_guidance

    def guidance(*args):
        title, description, remediation, metadata, category = original_guidance(*args)
        metadata = dict(metadata)
        if review_hint is not None:
            metadata['review_required'] = review_hint
        return title, description, remediation, metadata, category

    monkeypatch.setattr(adapters, '_rule_guidance', guidance)
    checked, findings = adapters._sast(root, config.default_config(root), source.collect_source(root), 'static-release')
    assert checked['status'] == 'complete'
    assert len(findings) == len(rules)
    assert all(item['severity'] in {'High', 'Medium', 'Low', 'Info'} for item in findings)
    assert all(item['validation'] == 'candidate' for item in findings)
    assert all(item['review_required'] is True for item in findings)
    assert next(item for item in findings if item['rule_id'] == 'sqisoft-spring-jdbctemplate-string-concat')['severity'] == 'High'
    medium = next(item for item in findings if item['severity'] == 'Medium')
    assert policy.evaluate([checked], [medium])['status'] == 'INCOMPLETE'


def evaluator():
    path = ROOT / 'scripts/evaluate-rule-quality.py'
    assert path.exists(), 'The rule-level evaluator is not implemented'
    spec = importlib.util.spec_from_file_location('gxsec_rule_quality_eval', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_evaluator_counts_misses_false_alarms_and_uncovered_rules_without_inflating_accuracy(tmp_path):
    module = evaluator()
    cases = [{'id': name, 'rule_id': 'sample', 'expected_match': expected,
              'filename': 'Sample.java', 'source': 'class Sample {}'}
             for name, expected in [('hit', True), ('miss', True), ('false_alarm', False), ('safe', False)]]
    files = {case['id']: tmp_path / case['id'] / case['filename'] for case in cases}
    payload = {'version': '1.172.0', 'errors': [], 'paths': {'scanned': [str(p) for p in files.values()]},
               'results': [{'check_id': 'sample', 'path': str(files[name])} for name in ('hit', 'false_alarm')]}
    result = module.score_results({'sample': {}, 'not-exercised': {}}, cases, files, payload)
    assert result['metrics'] == {'true_positive': 1, 'false_positive': 1, 'false_negative': 1,
        'true_negative': 1, 'unscanned': 0, 'precision': 0.5, 'recall': 0.5}
    assert result['rules_with_positive_and_negative'] == ['sample']
    assert result['uncovered_rules'] == ['not-exercised']
    assert result['rule_coverage']['sample'] == {'positive_cases': 2, 'negative_cases': 2, 'scanned_cases': 4,
        'true_positive': 1, 'false_positive': 1, 'false_negative': 1, 'true_negative': 1, 'unscanned': 0}
    assert result['rule_coverage']['not-exercised']['scanned_cases'] == 0
    assert set(result['regressions']) == {'miss', 'false_alarm'}


def test_evaluator_missing_file_is_unmeasured_not_true_negative(tmp_path):
    module = evaluator()
    cases = [{'id': 'safe', 'rule_id': 'sample', 'expected_match': False,
              'filename': 'Sample.java', 'source': 'class Sample {}'}]
    files = {'safe': tmp_path / 'safe' / 'Sample.java'}
    result = module.score_results({'sample': {}}, cases, files,
        {'version': '1.172.0', 'results': [], 'errors': [], 'paths': {'scanned': []}})
    assert result['execution_complete'] is False
    assert result['metrics']['true_negative'] == 0
    assert result['metrics']['unscanned'] == 1
    assert result['metrics']['precision'] is None and result['metrics']['recall'] is None


@pytest.mark.parametrize('expected,observed,counter,status', [
    (True, False, 'false_negative', 'miss'), (False, True, 'false_positive', 'false-alarm')])
def test_evaluator_known_limitation_still_counts_errors(tmp_path, expected, observed, counter, status):
    module = evaluator()
    cases = [{'id': 'helper', 'rule_id': 'sample', 'expected_match': expected,
              'filename': 'Sample.java', 'source': 'class Sample {}',
              'known_limitation': 'The rule cannot distinguish this data-flow case.'}]
    files = {'helper': tmp_path / 'helper' / 'Sample.java'}
    result = module.score_results({'sample': {}}, cases, files,
        {'version': '1.172.0', 'results': [{'check_id': 'sample', 'path': str(files['helper'])}] if observed else [],
         'errors': [], 'paths': {'scanned': [str(files['helper'])]}})
    assert result['metrics'][counter] == 1
    assert result['metrics']['recall' if expected else 'precision'] == 0.0
    assert result['regressions'] == []
    assert result['cases'][0]['status'] == status


@pytest.mark.parametrize('fault', ['engine-error', 'missing-coverage', 'wrong-version', 'malformed-coverage', 'malformed-root'])
def test_evaluator_never_reports_success_for_failed_or_unknown_execution(tmp_path, fault):
    module = evaluator()
    cases = [{'id': 'safe', 'rule_id': 'sample', 'expected_match': False,
              'filename': 'Sample.java', 'source': 'class Sample {}'}]
    files = {'safe': tmp_path / 'safe' / 'Sample.java'}
    payload = {'version': '1.172.0', 'errors': [], 'results': [], 'paths': {'scanned': [str(files['safe'])]}}
    if fault == 'engine-error':
        payload['errors'] = [{'type': 'ParseError'}]
    elif fault == 'missing-coverage':
        payload.pop('paths')
    elif fault == 'malformed-coverage':
        payload['paths'] = ['not-an-object']
    elif fault == 'malformed-root':
        payload = []
    else:
        payload['version'] = 'different'
    result = module.score_results({'sample': {}}, cases, files, payload)
    assert result['execution_complete'] is False


def test_committed_corpus_only_uses_known_rules_and_existing_source_inputs():
    module = evaluator()
    _, rules = module.load_catalog()
    cases = module.load_cases(module.DEFAULT_CORPUS, rules)
    assert len({case['rule_id'] for case in cases}) < len(rules)
    assert any(case.get('known_limitation') and case['expected_match'] for case in cases)


@pytest.mark.skipif(bool(os.environ.get('GXSEC_NO_SEMGREP')) or not shutil.which('semgrep'),
                    reason='Actual rule checks require an enabled Semgrep engine')
def test_cors_same_receiver_both_orders_and_negative_controls(tmp_path):
    cases = {
        'normal': ('first.allowedOrigins("*"); first.allowCredentials(true);', True),
        'reverse': ('first.allowCredentials(true); first.allowedOrigins("*");', True),
        'different_receivers': ('first.allowedOrigins("*"); second.allowCredentials(true);', False),
        'trusted_origin': ('first.allowedOrigins("https://example.invalid"); first.allowCredentials(true);', False),
        'no_credentials': ('first.allowedOrigins("*"); first.allowCredentials(false);', False),
    }
    for name, (body, _) in cases.items():
        (tmp_path / (name + '.java')).write_text('class Config { void configure(CorsRegistration first, CorsRegistration second) { '
                                                  + body + ' } }', encoding='utf-8')
    command = [shutil.which('semgrep'), 'scan', '--json', '--quiet', '--metrics=off', '--disable-version-check',
               '--no-git-ignore', '--no-rewrite-rule-ids', '--strict', '--config',
               str(ROOT / 'skills/detecting-broken-access-control/rules/access-control.yml'), '--', str(tmp_path)]
    result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', timeout=120,
        env={**os.environ, 'PYTHONUTF8': '1', 'SEMGREP_SEND_METRICS': 'off', 'SEMGREP_ENABLE_VERSION_CHECK': '0'})
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    # Exercise the same behavior in the pinned and experimental compatibility jobs.
    # The separate evaluation command enforces the production version pin.
    assert isinstance(payload.get('version'), str) and payload['version']
    assert payload['errors'] == []
    assert len(payload['paths']['scanned']) == len(cases)
    flagged = {Path(item['path']).stem for item in payload['results'] if item['check_id'] == CORS_RULE}
    assert flagged == {'normal', 'reverse'}
