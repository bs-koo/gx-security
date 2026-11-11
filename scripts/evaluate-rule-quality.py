#!/usr/bin/env python3
"""Measure named synthetic cases, including misses and rules without any cases.

This developer evaluation is not a release gate or a real-project accuracy claim.
Only labeled rule/case pairs enter the metrics; unrelated matches do not establish
evaluation coverage for another rule.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
PINNED_VERSION = '1.172.0'
DEFAULT_CORPUS = ROOT / 'tests/fixtures/rule-quality/cases.json'
DEFAULT_CONTRACT = ROOT / 'tests/fixtures/rule-quality/baseline-contract.json'


class CorpusValidationError(ValueError):
    def __init__(self, diagnostics, *, contract=None):
        super().__init__('Corpus validation failed')
        self.diagnostics = diagnostics if isinstance(diagnostics, list) else [diagnostics]
        self.contract = contract


def _evaluation_scope(path):
    return 'default-corpus' if Path(path).resolve() == DEFAULT_CORPUS.resolve() else 'custom-corpus'


def load_catalog():
    files = sorted(ROOT.glob('skills/detecting-*/rules/*.yml'))
    rules = {}
    for path in files:
        for rule in yaml.safe_load(path.read_text(encoding='utf-8-sig'))['rules']:
            if rule['id'] in rules:
                raise ValueError('Duplicate rule identity')
            rules[rule['id']] = rule
    if not rules:
        raise ValueError('No rules found')
    return files, rules


def load_cases(path, rules):
    document = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(document, dict) or document.get('schema_version') != 1 or not isinstance(document.get('cases'), list):
        raise CorpusValidationError({'type': 'corpus_invalid'})
    cases, seen = document['cases'], set()
    for case in cases:
        if not isinstance(case, dict):
            raise CorpusValidationError({'type': 'corpus_case_invalid'})
        identifier = case.get('id', '')
        filename = case.get('filename', '')
        if isinstance(identifier, str) and identifier in seen:
            raise CorpusValidationError({'type': 'corpus_case_duplicate', 'id': identifier})
        if (not isinstance(identifier, str) or not re.fullmatch('[A-Za-z0-9_-]{1,100}', identifier)
                or not isinstance(case.get('rule_id'), str) or case['rule_id'] not in rules
                or type(case.get('expected_match')) is not bool
                or not isinstance(filename, str) or not re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9]+', filename)):
            raise CorpusValidationError({'type': 'corpus_case_invalid'})
        seen.add(identifier)
        if ('source' in case) == ('source_path' in case):
            raise ValueError('Each case needs exactly one source input')
        if 'source' in case:
            if not isinstance(case['source'], str) or not case['source'].strip():
                raise ValueError('Empty source case')
        else:
            source = (ROOT / case['source_path']).resolve(strict=True)
            source.relative_to(ROOT.resolve())
            if not source.is_file() or source.stat().st_size > 1024 * 1024:
                raise ValueError('Invalid corpus source file')
        if 'known_limitation' in case and (not isinstance(case['known_limitation'], str) or not case['known_limitation'].strip()):
            raise ValueError('Known limitation needs a reason')
    if not cases:
        raise ValueError('Empty corpus')
    return cases


def _case_source(case):
    return case['source'] if 'source' in case else (ROOT / case['source_path']).read_text(encoding='utf-8-sig')


def _corpus_contract(corpus, cases, source_hashes):
    """Preserve reviewed inputs, not a fixed precision/recall or known-error count."""
    if _evaluation_scope(corpus) == 'custom-corpus':
        return {'status': 'not-applied', 'baseline_preserved': None, 'comparable_to_default': False,
                'notice': 'Custom corpus metrics do not establish preservation of the default evaluation coverage.'}
    try:
        raw = DEFAULT_CONTRACT.read_bytes()
        document = json.loads(raw)
        required = document['required_cases']
        minimum_cases, minimum_rules = document['minimum_case_count'], document['minimum_rule_count']
        if (document.get('schema_version') != 1 or not isinstance(document.get('contract_id'), str)
                or not document['contract_id'] or not isinstance(required, list)
                or type(minimum_cases) is not int or minimum_cases < 1
                or type(minimum_rules) is not int or minimum_rules < 1 or len(required) < minimum_cases):
            raise ValueError('Invalid contract schema')
        expected, labels = {}, {}
        for row in required:
            if (not isinstance(row, dict) or not isinstance(row.get('id'), str)
                    or not re.fullmatch('[A-Za-z0-9_-]{1,100}', row['id']) or row['id'] in expected
                    or not isinstance(row.get('rule_id'), str) or not row['rule_id']
                    or type(row.get('expected_match')) is not bool
                    or not isinstance(row.get('filename'), str)
                    or not re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9]+', row['filename'])
                    or not re.fullmatch('[a-f0-9]{64}', str(row.get('source_sha256', '')))
                    or type(row.get('allow_known_limitation')) is not bool):
                raise ValueError('Invalid required case')
            expected[row['id']] = row
            labels.setdefault(row['rule_id'], set()).add(row['expected_match'])
        if len(labels) < minimum_rules or any(values != {True, False} for values in labels.values()):
            raise ValueError('Contract needs both labels for every required rule')
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise CorpusValidationError({'type': 'corpus_contract_invalid'}) from exc
    metadata = {'contract_id': document['contract_id'], 'sha256': hashlib.sha256(raw).hexdigest(),
                'required_case_count': len(expected), 'required_rule_count': len(labels),
                'additional_case_count': len(set(case['id'] for case in cases) - set(expected)),
                'baseline_preserved': True, 'comparable_to_default': len(cases) == len(expected), 'status': 'satisfied'}
    actual = {case['id']: case for case in cases}
    diagnostics = []
    for identifier, baseline in expected.items():
        case = actual.get(identifier)
        if case is None:
            diagnostics.append({'type': 'corpus_contract_case_missing', 'id': identifier})
            continue
        if any(case[key] != baseline[key] for key in ('rule_id', 'expected_match', 'filename')):
            diagnostics.append({'type': 'corpus_contract_case_changed', 'id': identifier})
        if source_hashes[identifier] != baseline['source_sha256']:
            diagnostics.append({'type': 'corpus_contract_source_changed', 'id': identifier})
        if case.get('known_limitation') and not baseline['allow_known_limitation']:
            diagnostics.append({'type': 'corpus_contract_limitation_unapproved', 'id': identifier})
    if diagnostics:
        metadata.update(status='violated', baseline_preserved=False, comparable_to_default=False)
        raise CorpusValidationError(diagnostics, contract=metadata)
    return metadata


def _key(path):
    return os.path.normcase(str(Path(path).resolve()))


def score_results(rules, cases, files, payload, *, expected_version=PINNED_VERSION):
    """Score supported execution only; missing files never become safe negatives."""
    payload = payload if isinstance(payload, dict) else {}
    errors = payload.get('errors')
    matches = payload.get('results')
    paths = payload.get('paths')
    scanned = paths.get('scanned') if isinstance(paths, dict) else None
    shape_valid = (isinstance(errors, list) and isinstance(matches, list) and isinstance(scanned, list)
                   and all(isinstance(path, str) and bool(path.strip()) for path in scanned))
    scanned_paths = {_key(path) for path in scanned} if shape_valid else set()
    observed = set()
    invalid_match = False
    for item in matches if isinstance(matches, list) else []:
        if not isinstance(item, dict) or not isinstance(item.get('path'), str) or not isinstance(item.get('check_id'), str):
            invalid_match = True
            continue
        observed.add((item['check_id'], _key(item['path'])))
    counts = {'true_positive': 0, 'false_positive': 0, 'false_negative': 0, 'true_negative': 0, 'unscanned': 0}
    coverage = {rid: {'positive_cases': 0, 'negative_cases': 0, 'scanned_cases': 0, **counts}
                for rid in sorted(rules)}
    rows, regressions, labels = [], [], {}
    for case in cases:
        rid, expected = case['rule_id'], case['expected_match']
        labels.setdefault(rid, set()).add(expected)
        path = _key(files[case['id']])
        actual = (rid, path) in observed if path in scanned_paths else None
        if actual is None:
            status, counter = 'unscanned', 'unscanned'
        elif expected and actual:
            status, counter = 'match', 'true_positive'
        elif expected:
            status, counter = 'miss', 'false_negative'
        elif actual:
            status, counter = 'false-alarm', 'false_positive'
        else:
            status, counter = 'safe-no-match', 'true_negative'
        counts[counter] += 1
        coverage[rid]['positive_cases' if expected else 'negative_cases'] += 1
        coverage[rid][counter] += 1
        if actual is not None:
            coverage[rid]['scanned_cases'] += 1
        row = {'id': case['id'], 'rule_id': rid, 'expected_match': expected,
               'observed_match': actual, 'status': status}
        if case.get('known_limitation'):
            row['known_limitation'] = case['known_limitation']
        if status == 'unscanned' or (status in {'miss', 'false-alarm'} and not case.get('known_limitation')):
            regressions.append(case['id'])
        rows.append(row)
    tp, fp, fn = counts['true_positive'], counts['false_positive'], counts['false_negative']
    counts.update(precision=tp / (tp + fp) if tp + fp else None,
                  recall=tp / (tp + fn) if tp + fn else None)
    return {'schema_version': 1, 'evaluation_kind': 'synthetic-rule-regression',
        'notice': 'Metrics cover only labeled synthetic rule/case pairs. Uncovered rules and real-project accuracy remain unmeasured.',
        'engine_version': payload.get('version'), 'expected_engine_version': expected_version,
        'execution_complete': shape_valid and not errors and not invalid_match
            and payload.get('version') == expected_version and counts['unscanned'] == 0,
        'rules_total': len(rules), 'rules_with_cases': sorted(labels),
        'rule_coverage': coverage,
        'rules_with_positive_and_negative': sorted(rid for rid, kinds in labels.items() if kinds == {True, False}),
        'uncovered_rules': sorted(set(rules) - set(labels)),
        'metrics': counts, 'regressions': regressions, 'cases': rows,
        'errors': errors if isinstance(errors, list) else ['Missing engine errors metadata']}


def evaluate(corpus=DEFAULT_CORPUS, *, engine='semgrep', expected_version=PINNED_VERSION):
    paths, rules = load_catalog()
    cases = load_cases(corpus, rules)
    sources = {case['id']: _case_source(case) for case in cases}
    source_hashes = {identifier: hashlib.sha256(text.encode('utf-8')).hexdigest() for identifier, text in sources.items()}
    contract = _corpus_contract(corpus, cases, source_hashes)
    executable = shutil.which(engine)
    if not executable:
        raise ValueError('Semgrep is unavailable; use the pinned runtime or an explicit verified engine path')
    with tempfile.TemporaryDirectory(prefix='gxsec-rule-evaluation-') as temporary:
        root = Path(temporary).resolve()
        files = {}
        for case in cases:
            destination = root / case['id'] / case['filename']
            destination.parent.mkdir()
            destination.write_text(sources[case['id']], encoding='utf-8', newline='\n')
            files[case['id']] = destination
        command = [executable, 'scan', '--json', '--quiet', '--metrics=off', '--disable-version-check',
                   '--disable-nosem', '--no-git-ignore', '--no-rewrite-rule-ids', '--strict']
        for path in paths:
            command += ['--config', str(path)]
        command += ['--', str(root)]
        process = subprocess.run(command, capture_output=True, text=True, encoding='utf-8',
            errors='replace', timeout=300, cwd=ROOT,
            env={**os.environ, 'PYTHONUTF8': '1', 'SEMGREP_SEND_METRICS': 'off', 'SEMGREP_ENABLE_VERSION_CHECK': '0'})
        payload = json.loads(process.stdout)
        result = score_results(rules, cases, files, payload, expected_version=expected_version)
        result['engine_exit_code'] = process.returncode
        result['execution_complete'] = result['execution_complete'] and process.returncode == 0
        result['corpus_sha256'] = hashlib.sha256(Path(corpus).read_bytes()).hexdigest()
        result['case_source_sha256'] = source_hashes
        result['evaluation_scope'] = _evaluation_scope(corpus)
        result['corpus_contract'] = contract
        result['rule_files'] = {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                                for path in paths}
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, default=DEFAULT_CORPUS,
                        help='Default corpus enforces its reviewed baseline; another path is reported as a custom evaluation.')
    parser.add_argument('--engine', default='semgrep')
    parser.add_argument('--expected-version', default=PINNED_VERSION)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    scope = _evaluation_scope(args.corpus)
    failed_contract = {'status': 'not-evaluated' if scope == 'default-corpus' else 'not-applied',
                       'baseline_preserved': None, 'comparable_to_default': False}
    try:
        result = evaluate(args.corpus, engine=args.engine, expected_version=args.expected_version)
    except CorpusValidationError as exc:
        result = {'schema_version': 1, 'execution_complete': False, 'error': 'corpus_validation_failed',
                  'evaluation_scope': scope, 'errors': exc.diagnostics,
                  'corpus_contract': exc.contract or {**failed_contract,
                      **({'status': 'invalid', 'baseline_preserved': False} if scope == 'default-corpus' else {})}}
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        result = {'schema_version': 1, 'execution_complete': False,
                  'evaluation_scope': scope, 'corpus_contract': failed_contract,
                  'error': type(exc).__name__, 'message': 'Rule evaluation could not complete; inspect the local engine/corpus.'}
    serialized = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding='utf-8')
    print(serialized)
    return 2 if not result['execution_complete'] else 1 if result['regressions'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
