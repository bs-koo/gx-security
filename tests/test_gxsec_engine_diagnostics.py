"""Failure output is evidence, never a successful scan or raw report text."""
import json
import subprocess
import io
import sys
from pathlib import Path
from types import SimpleNamespace
from contextlib import contextmanager

import pytest

from gxsec import adapters, config, policy, source


def test_snapshot_copy_budget_has_structured_budget_diagnostic(tmp_path, monkeypatch):
    from gxsec.execution import BudgetExceeded

    @contextmanager
    def exhausted(*args):
        raise BudgetExceeded('duration', 'snapshot-copy')
        yield

    monkeypatch.setattr(adapters, 'verified_snapshot', exhausted)
    checks, findings = adapters.run_static_checks(tmp_path, {'_inventory': {'hash': 'source-hash'}}, 'check')
    assert findings == []
    assert len(checks) == 4
    for check in checks:
        assert check['status'] == 'incomplete'
        assert check['errors'] == [{'type': 'execution_budget_exceeded', 'reason': 'duration', 'stage': 'snapshot-copy'}]


@pytest.fixture
def sast(tmp_path, monkeypatch):
    (tmp_path / 'A.java').write_text('class A {}', encoding='utf-8')
    monkeypatch.setattr(source, '_git', lambda *args, **kwargs: None)
    inventory = source.collect_source(tmp_path)
    cfg = config.default_config(tmp_path)
    cfg['_state_dir'] = tmp_path.parent / (tmp_path.name + '-state')
    def probe(name, options, path, check, **kwargs):
        check['engine'] = {'name': name, 'version': '1.172.0', 'available': True}
        return 'approved-semgrep'
    monkeypatch.setattr(adapters, '_probe', probe)
    def run(result):
        def execute(*args, **kwargs):
            if isinstance(result, Exception):
                raise result
            return result
        monkeypatch.setattr(adapters, '_run', execute)
        return adapters._sast(tmp_path, cfg, inventory, 'check')
    return run


def payload(errors=None):
    return {'results': [{'check_id': 'synthetic-rule', 'path': 'A.java',
            'start': {'line': 1}, 'end': {'line': 1}, 'extra': {'severity': 'ERROR'}}],
            'errors': errors or [], 'paths': {'scanned': ['A.java']}}


def test_exit_two_keeps_safe_diagnostics_and_partial_candidates(sast):
    native = payload([{'type': 'PartialParsing', 'code': 3, 'path': 'A.java',
                       'message': 'fixture-private-value', 'details': {'source': 'fixture-private-value'}}])
    check, findings = sast(subprocess.CompletedProcess([], 2, json.dumps(native), 'fixture-private-value'))
    assert check['status'] == 'incomplete'
    assert len(findings) == 1 and findings[0]['validation'] == 'candidate'
    assert check['coverage']['scanned'] == 1 and check['coverage']['partial'] is True
    assert any(item.get('error_type') == 'PartialParsing' and item.get('path') == 'A.java'
               and item.get('code') == 3 for item in check['errors'])
    assert policy.evaluate([check], findings)['status'] == 'INCOMPLETE'
    assert 'fixture-private-value' not in json.dumps([check, findings])


@pytest.mark.parametrize('returncode,stderr,category', [
    (-9, '', 'terminated_by_signal'),
    (137, '', 'nonzero_exit'),
    (2, 'fatal: out of memory fixture-private-value', 'memory_exhaustion_reported'),
    (2, 'pthread_create: Resource temporarily unavailable fixture-private-value', 'resource_exhaustion_reported'),
    (2, 'No space left on device fixture-private-value', 'storage_exhaustion_reported'),
    (2, 'unexpected fixture-private-value', 'nonzero_exit'),
])
def test_non_json_failure_has_safe_category_without_guessing_oom(sast, returncode, stderr, category):
    check, findings = sast(subprocess.CompletedProcess([], returncode, 'not JSON fixture-private-value', stderr))
    assert check['status'] == 'incomplete' and findings == []
    failure = next(item for item in check['errors'] if item['type'] == 'engine_failed')
    assert failure['category'] == category and failure['returncode'] == returncode
    assert 'fixture-private-value' not in json.dumps(check)
    if returncode in (-9, 137):
        assert 'memory' not in json.dumps(check).lower()


def test_timeout_never_exports_command_or_captured_output(sast):
    failure = subprocess.TimeoutExpired(['approved-tool', 'fixture-private-value'], 3,
                                        output='fixture-private-value', stderr='fixture-private-value')
    check, findings = sast(failure)
    assert check['status'] == 'incomplete' and findings == []
    assert any(item.get('category') == 'timeout' for item in check['errors'])
    assert 'fixture-private-value' not in json.dumps(check)


def test_native_diagnostics_require_known_type_bounded_code_and_inventory_path(sast):
    errors = [
        {'type': 'fixture-private-value', 'code': 10 ** 100, 'path': '../outside-fixture-private-value'},
        {'type': 'OutOfMemory', 'code': True, 'path': '/outside-fixture-private-value'},
        {'type': 'ParseError', 'code': 3, 'spans': [{'file': 'A.java', 'start': {'line': 1},
                                                 'source': 'fixture-private-value'}]},
    ]
    check, _ = sast(subprocess.CompletedProcess([], 2, json.dumps(payload(errors)), ''))
    rows = [item for item in check['errors'] if item['type'] == 'semgrep_diagnostic']
    assert rows[0]['error_type'] == 'unclassified' and 'code' not in rows[0] and 'path' not in rows[0]
    assert rows[1]['category'] == 'memory_exhaustion_reported' and 'code' not in rows[1] and 'path' not in rows[1]
    assert rows[2]['path'] == 'A.java' and rows[2]['line'] == 1
    assert 'fixture-private-value' not in json.dumps(check)


def test_diagnostic_count_is_bounded_and_truncation_remains_visible(sast):
    check, _ = sast(subprocess.CompletedProcess([], 2,
        json.dumps(payload([{'type': 'ParseError'} for _ in range(1000)])), ''))
    assert check['status'] == 'incomplete'
    assert len(check['errors']) <= 102
    assert any(item['type'] == 'diagnostics_truncated' and item['omitted'] == 900 for item in check['errors'])


@pytest.mark.parametrize('omitted', ['paths', 'results'])
def test_failure_diagnostics_survive_missing_coverage_or_result_metadata(sast, omitted):
    native = payload([{'type': 'SemgrepCoreError', 'code': 2, 'message': 'fixture-private-value'}])
    native.pop(omitted)
    check, findings = sast(subprocess.CompletedProcess([], 2, json.dumps(native), ''))
    assert check['status'] == 'incomplete'
    assert any(item.get('error_type') == 'SemgrepCoreError' for item in check['errors'])
    assert len(findings) == (1 if omitted == 'paths' else 0)
    assert check['coverage']['scanned'] == 0
    assert 'fixture-private-value' not in json.dumps([check, findings])


def test_valid_success_output_does_not_gain_failure_status(sast):
    check, findings = sast(subprocess.CompletedProcess([], 0, json.dumps(payload()), ''))
    assert check['status'] == 'complete' and len(findings) == 1
    assert check['errors'] == [] and not check['coverage'].get('partial')


def test_failed_osv_preserves_only_candidates_not_source_verified_matches(tmp_path, monkeypatch):
    from tests.test_gxsec_adapters import osv_matching_fixture
    monkeypatch.setattr(source, '_git', lambda *args, **kwargs: None)
    cfg, inventory, _ = osv_matching_fixture(tmp_path)
    monkeypatch.setattr(adapters, '_probe', lambda *args, **kwargs: 'approved-osv')
    native = {'results': [{'source': {'path': str(tmp_path / 'package-lock.json'), 'type': 'lockfile'},
               'packages': [{'package': {'name': 'a', 'version': '1.0.0', 'ecosystem': 'npm',
                                         'purl': 'pkg:npm/a@1.0.0?source=PUBLIC_REGISTRY'},
                             'vulnerabilities': [{'id': 'GHSA-synthetic', 'summary': 'Synthetic advisory'}]}]}]}
    monkeypatch.setattr(adapters, '_run', lambda *args, **kwargs:
                        subprocess.CompletedProcess([], 2, json.dumps(native), 'fixture-private-value'))
    check, findings = adapters._sca(tmp_path, cfg, inventory, 'check')
    assert check['status'] == 'incomplete' and check['coverage']['partial'] is True
    assert len(findings) == 1 and findings[0]['validation'] == 'candidate'
    assert 'fixture-private-value' not in json.dumps([check, findings])


def test_failed_gitleaks_preserves_redacted_report_without_completed_mode(tmp_path, monkeypatch):
    monkeypatch.setattr(source, '_git', lambda *args, **kwargs: None)
    (tmp_path / 'A.java').write_text('class A {}', encoding='utf-8')
    cfg = config.default_config(tmp_path)
    cfg['_state_dir'] = tmp_path.parent / (tmp_path.name + '-state')
    monkeypatch.setattr(adapters, '_probe', lambda *args, **kwargs: 'approved-gitleaks')
    def execute(cmd, **kwargs):
        Path(cmd[cmd.index('--report-path') + 1]).write_text(json.dumps([{
            'File': 'A.java', 'StartLine': 1, 'RuleID': 'synthetic-secret',
            'Secret': 'fixture-private-value', 'Match': 'fixture-private-value'}]), encoding='utf-8')
        return subprocess.CompletedProcess(cmd, 2, '', 'fixture-private-value')
    monkeypatch.setattr(adapters, '_run', execute)
    check, findings = adapters._secrets(tmp_path, cfg, source.collect_source(tmp_path), 'check')
    assert check['status'] == 'incomplete' and check['coverage']['partial'] is True
    assert check['coverage']['scanned'] == 0
    assert len(findings) == 1 and findings[0]['validation'] == 'candidate'
    assert 'fixture-private-value' not in json.dumps([check, findings])


def test_static_process_capture_stops_at_shared_output_limit(tmp_path):
    with pytest.raises(ValueError, match='output limit'):
        adapters._run([sys.executable, '-c',
            'import sys; sys.stdout.buffer.write(b"x" * (17 * 1024 * 1024))'], cwd=tmp_path, timeout=10)


def test_static_process_timeout_uses_remaining_global_budget(tmp_path):
    from gxsec.execution import session
    with session(0.2, max_input_bytes=1024, stream=io.StringIO()):
        with pytest.raises(subprocess.TimeoutExpired):
            adapters._run([sys.executable, '-c', 'import time; time.sleep(2)'], cwd=tmp_path, timeout=10)


def test_static_process_retains_nonzero_code_and_bounded_output(tmp_path):
    result = adapters._run([sys.executable, '-c',
        'import sys; print("safe stdout"); print("safe stderr", file=sys.stderr); sys.exit(2)'], cwd=tmp_path)
    assert result.returncode == 2
    assert result.stdout.strip() == 'safe stdout' and result.stderr.strip() == 'safe stderr'


def test_exhausted_budget_skips_later_engines_and_keeps_earlier_candidates(tmp_path, monkeypatch):
    from gxsec import framework, optional
    from gxsec.execution import session
    from gxsec.models import make_check, make_finding
    monkeypatch.setattr(source, '_git', lambda *args, **kwargs: None)
    (tmp_path / 'A.java').write_text('class A {}', encoding='utf-8')
    inventory = source.collect_source(tmp_path)
    cfg = {'_snapshot_object': SimpleNamespace(verify=lambda: True), 'tools': {}}
    now, calls = [0.0], []
    def first(*args):
        calls.append('sast')
        now[0] = 2.0
        return make_check('sast', status='complete'), [make_finding(
            category='sast', rule='synthetic', path='A.java', check_id='sast')]
    def forbidden(*args):
        calls.append('later-engine')
        return make_check('unexpected'), []
    monkeypatch.setattr(adapters, '_sast', first)
    monkeypatch.setattr(adapters, '_sca', forbidden)
    monkeypatch.setattr(adapters, '_secrets', forbidden)
    monkeypatch.setattr(framework, 'run_framework_check', forbidden)
    monkeypatch.setattr(optional, 'run_optional_checks', lambda *args: (calls.append('optional') or [], []))
    monkeypatch.setattr(adapters, 'contextualize_findings', lambda *args: calls.append('contextual') or [])
    with session(1, max_input_bytes=1024, stream=io.StringIO(), clock=lambda: now[0]) as budget:
        checks, findings = adapters._run_snapshot_checks(tmp_path, cfg, inventory, 'check')
    assert calls == ['sast']
    assert len(findings) == 1 and findings[0]['validation'] == 'candidate'
    assert all(check['status'] == 'incomplete' for check in checks if check['id'] != 'sast')
    assert any(error['type'] == 'execution_budget_exceeded' for check in checks for error in check['errors'])
    assert 'engine-sast' in budget.summary()['phases']


def test_final_snapshot_budget_failure_is_incomplete_without_erasing_candidates(tmp_path, monkeypatch):
    from gxsec.execution import BudgetExceeded
    from gxsec.models import make_check, make_finding
    monkeypatch.setattr(source, '_git', lambda *args, **kwargs: None)
    (tmp_path / 'A.java').write_text('class A {}', encoding='utf-8')
    def exhausted():
        raise BudgetExceeded('duration', 'snapshot-verify')
    @contextmanager
    def snapshot(*args):
        yield SimpleNamespace(path=tmp_path, verify=exhausted,
            provenance={'copy_verified': True, 'stable_after_scan': True})
    monkeypatch.setattr(adapters, 'verified_snapshot', snapshot)
    monkeypatch.setattr(adapters, '_run_snapshot_checks', lambda *args:
        ([make_check('sast', status='complete')],
         [make_finding(category='sast', rule='synthetic', path='A.java', check_id='sast')]))
    checks, findings = adapters.run_static_checks(tmp_path, {}, 'check')
    assert len(findings) == 1 and findings[0]['validation'] == 'candidate'
    assert checks[0]['status'] == 'incomplete'
    assert checks[0]['snapshot']['stable_after_scan'] is False
    assert any(item['type'] == 'execution_budget_exceeded' for item in checks[0]['errors'])


def test_optional_process_uses_remaining_global_budget(tmp_path):
    from gxsec.execution import session
    from gxsec.optional import _bounded_process
    with session(0.2, max_input_bytes=1024, stream=io.StringIO()):
        with pytest.raises(ValueError, match='deadline'):
            _bounded_process([sys.executable, '-c', 'import time; time.sleep(2)'],
                cwd=str(tmp_path), environment=adapters._env(), timeout=10, maximum=1024)
