"""Rule-specific behavior and initial priority must remain distinct from verification."""
import importlib.util
import hashlib
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
    hashes = {case['id']: hashlib.sha256(module._case_source(case).encode('utf-8')).hexdigest() for case in cases}
    contract = module._corpus_contract(module.DEFAULT_CORPUS, cases, hashes)
    assert contract['status'] == 'satisfied'
    assert contract['required_case_count'] == 28 and contract['required_rule_count'] == 12


def evaluate_authored_cases(module, tmp_path, monkeypatch, capsys, cases, *, custom=False):
    corpus = tmp_path / ('custom-cases.json' if custom else 'cases.json')
    corpus.write_text(json.dumps({'schema_version': 1, 'cases': cases}), encoding='utf-8')
    if not custom:
        monkeypatch.setattr(module, 'DEFAULT_CORPUS', corpus)
    monkeypatch.setattr(module.shutil, 'which', lambda command: 'synthetic-semgrep')
    calls = []

    def execute(command, **kwargs):
        calls.append(command)
        root = Path(command[-1])
        payload = {'version': module.PINNED_VERSION, 'errors': [], 'paths': {'scanned': []}, 'results': []}
        for case in cases:
            path = str(root / case['id'] / case['filename'])
            payload['paths']['scanned'].append(path)
            # Preserve the existing known FP/FN while accepting genuine future
            # improvements; no aggregate metric is a fixed golden value.
            observed = case['expected_match'] != bool(case.get('known_limitation'))
            if observed:
                payload['results'].append({'check_id': case['rule_id'], 'path': path})
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), '')

    monkeypatch.setattr(module.subprocess, 'run', execute)
    exit_code = module.main(['--corpus', str(corpus)])
    return exit_code, json.loads(capsys.readouterr().out), calls


@pytest.mark.parametrize('reduction', ['known-miss-only', 'positive-only', 'rename-existing-case'])
def test_default_corpus_cannot_hide_reduced_coverage(tmp_path, monkeypatch, capsys, reduction):
    module = evaluator()
    cases = json.loads(module.DEFAULT_CORPUS.read_text(encoding='utf-8'))['cases']
    if reduction == 'known-miss-only':
        cases = [case for case in cases if case['id'] == 'jdbc-helper-risk-retained']
    elif reduction == 'positive-only':
        cases = [case for case in cases if case['expected_match']]
    else:
        cases[0]['id'] += '-renamed'
    code, result, calls = evaluate_authored_cases(module, tmp_path, monkeypatch, capsys, cases)
    assert code == 2 and result['execution_complete'] is False
    assert result['evaluation_scope'] == 'default-corpus'
    assert result['corpus_contract']['status'] == 'violated'
    assert any(item['type'] == 'corpus_contract_case_missing' for item in result['errors'])
    assert calls == []


@pytest.mark.parametrize('change,diagnostic', [
    ('label', 'corpus_contract_case_changed'),
    ('source', 'corpus_contract_source_changed'),
    ('waiver', 'corpus_contract_limitation_unapproved'),
])
def test_default_corpus_cannot_replace_approved_expectations(tmp_path, monkeypatch, capsys, change, diagnostic):
    module = evaluator()
    cases = json.loads(module.DEFAULT_CORPUS.read_text(encoding='utf-8'))['cases']
    if change == 'label':
        cases[1]['expected_match'] = True
    elif change == 'source':
        cases[1].pop('source_path')
        cases[1]['source'] = 'class NoAuth {}'
    else:
        cases[0]['known_limitation'] = 'Newly hidden regression'
    code, result, calls = evaluate_authored_cases(module, tmp_path, monkeypatch, capsys, cases)
    assert code == 2 and result['execution_complete'] is False
    assert result['corpus_contract']['status'] == 'violated'
    assert any(item['type'] == diagnostic for item in result['errors'])
    assert calls == []


def test_duplicate_corpus_case_has_explicit_diagnostic(tmp_path, monkeypatch, capsys):
    module = evaluator()
    cases = json.loads(module.DEFAULT_CORPUS.read_text(encoding='utf-8'))['cases']
    cases.append(dict(cases[0]))
    code, result, calls = evaluate_authored_cases(module, tmp_path, monkeypatch, capsys, cases)
    assert code == 2 and result['execution_complete'] is False
    assert any(item['type'] == 'corpus_case_duplicate' for item in result['errors'])
    assert calls == []


def test_default_corpus_allows_additional_labeled_cases(tmp_path, monkeypatch, capsys):
    module = evaluator()
    cases = json.loads(module.DEFAULT_CORPUS.read_text(encoding='utf-8'))['cases']
    cases += [{'id': 'additional-' + str(expected), 'rule_id': CORS_RULE, 'expected_match': expected,
               'filename': 'Extra.java', 'source': 'class Extra {}'} for expected in (False, True)]
    code, result, calls = evaluate_authored_cases(module, tmp_path, monkeypatch, capsys, cases)
    assert code == 0 and result['execution_complete'] is True and len(calls) == 1
    assert result['corpus_contract']['status'] == 'satisfied'
    assert result['corpus_contract']['required_case_count'] == 28
    assert result['corpus_contract']['required_rule_count'] == 12
    assert len(result['cases']) == 30
    assert len(result['case_source_sha256']) == 30


def test_custom_corpus_is_explicitly_outside_default_coverage_contract(tmp_path, monkeypatch, capsys):
    module = evaluator()
    cases = [{'id': 'custom-safe', 'rule_id': CORS_RULE, 'expected_match': False,
              'filename': 'Custom.java', 'source': 'class Custom {}'}]
    code, result, calls = evaluate_authored_cases(module, tmp_path, monkeypatch, capsys, cases, custom=True)
    assert code == 0 and result['execution_complete'] is True and len(calls) == 1
    assert result['evaluation_scope'] == 'custom-corpus'
    assert result['corpus_contract']['status'] == 'not-applied'
    assert result['corpus_contract']['comparable_to_default'] is False
    assert result['rules_with_cases'] == [CORS_RULE]


@pytest.mark.parametrize('fault', ['invalid-json', 'engine-unavailable'])
def test_failed_custom_corpus_cannot_be_mistaken_for_default_evaluation(tmp_path, monkeypatch, capsys, fault):
    module = evaluator()
    corpus = tmp_path / 'custom.json'
    content = '{' if fault == 'invalid-json' else json.dumps({'schema_version': 1, 'cases': [
        {'id': 'safe', 'rule_id': CORS_RULE, 'expected_match': False, 'filename': 'Custom.java', 'source': 'class Custom {}'}]})
    corpus.write_text(content, encoding='utf-8')
    monkeypatch.setattr(module.shutil, 'which', lambda command: None)
    assert module.main(['--corpus', str(corpus)]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result['evaluation_scope'] == 'custom-corpus'
    assert result['corpus_contract']['comparable_to_default'] is False


@pytest.mark.parametrize('fault', ['missing', 'shortened', 'duplicate', 'one-sided'])
def test_default_contract_itself_must_preserve_minimum_paired_inputs(tmp_path, monkeypatch, capsys, fault):
    module = evaluator()
    cases = json.loads(module.DEFAULT_CORPUS.read_text(encoding='utf-8'))['cases']
    contract = json.loads(module.DEFAULT_CONTRACT.read_text(encoding='utf-8'))
    if fault == 'shortened':
        contract['required_cases'].pop()
    elif fault == 'duplicate':
        contract['required_cases'].append(dict(contract['required_cases'][0]))
    elif fault == 'one-sided':
        contract['required_cases'][1]['expected_match'] = True
    path = tmp_path / 'baseline-contract.json'
    if fault != 'missing':
        path.write_text(json.dumps(contract), encoding='utf-8')
    monkeypatch.setattr(module, 'DEFAULT_CONTRACT', path)
    code, result, calls = evaluate_authored_cases(module, tmp_path, monkeypatch, capsys, cases)
    assert code == 2 and result['execution_complete'] is False
    assert result['errors'] == [{'type': 'corpus_contract_invalid'}]
    assert calls == []


def test_known_errors_may_be_fixed_without_preserving_old_metric_counts(tmp_path, monkeypatch, capsys):
    module = evaluator()
    cases = json.loads(module.DEFAULT_CORPUS.read_text(encoding='utf-8'))['cases']
    for case in cases:
        case.pop('known_limitation', None)
    code, result, _ = evaluate_authored_cases(module, tmp_path, monkeypatch, capsys, cases)
    assert code == 0 and result['execution_complete'] is True
    assert result['corpus_contract']['status'] == 'satisfied'
    assert result['metrics']['false_positive'] == result['metrics']['false_negative'] == 0


def test_incidental_rule_matches_do_not_expand_labeled_rule_coverage(tmp_path):
    module = evaluator()
    cases = [{'id': str(expected), 'rule_id': 'labeled', 'expected_match': expected} for expected in (False, True)]
    files = {case['id']: tmp_path / (case['id'] + '.java') for case in cases}
    payload = {'version': module.PINNED_VERSION, 'errors': [],
               'paths': {'scanned': [str(path) for path in files.values()]},
               'results': [{'check_id': 'incidental', 'path': str(path)} for path in files.values()]}
    result = module.score_results({'labeled': {}, 'incidental': {}}, cases, files, payload)
    assert result['rules_with_cases'] == result['rules_with_positive_and_negative'] == ['labeled']
    assert result['uncovered_rules'] == ['incidental']
    assert result['rule_coverage']['incidental']['scanned_cases'] == 0
    assert result['metrics']['true_positive'] == 0 and result['metrics']['false_negative'] == 1


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
