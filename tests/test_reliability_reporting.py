"""Specialist observations must not become stronger claims in legacy reports."""
import importlib.util
from pathlib import Path
import sys
import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'reliability_audit', ROOT / 'skills/auditing-web-application-security/scripts/audit.py')
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


def rendered(finding):
    return '\n'.join(audit.render_pathupload({
        'confidence': 'dynamic', 'targets': {'traversal': True, 'upload': True},
        'result': {'findings': [finding]},
    }))


def test_unconfirmed_successful_path_response_is_not_defense():
    text = rendered({'kind': 'path-traversal', 'status': 200,
                     'vulnerable': False, 'undetermined': True, 'findings': []})
    assert '미확정' in text
    assert '방어' not in text
    assert '동적 확정 발사' not in text


def test_retrieved_inert_marker_does_not_become_a_high_vulnerability():
    text = rendered({'kind': 'file-upload', 'status': 200, 'accepted': True,
                     'retrievable': True, 'vulnerable': False, 'undetermined': True,
                     'execution_confirmed': False, 'leftover': 'gxmarker_fixture.jsp',
                     'cleanup': {'status': 'manual-required', 'attempted': False,
                                 'marker': 'gxmarker_fixture.jsp', 'leftover_status': 'confirmed'}})
    assert '미확정' in text and '마커 회수' in text
    assert 'High' not in text and '🔴' not in text
    assert '정리 필요' in text


def test_upload_timeout_preserves_possible_cleanup_without_accepted_flag():
    text = rendered({'kind': 'file-upload', 'status': None, 'accepted': False,
                     'vulnerable': False, 'undetermined': True,
                     'error': 'Upload response unavailable', 'leftover': 'gxmarker_fixture.jsp',
                     'cleanup': {'status': 'manual-required', 'attempted': False,
                                 'marker': 'gxmarker_fixture.jsp', 'leftover_status': 'possible'}})
    assert '오류' in text
    assert '정리 필요' in text and 'gxmarker_fixture.jsp' in text


def test_redirect_undetermined_survives_summary():
    text = audit._ssrf_finding_line({'kind': 'open-redirect', 'status': 200,
                                     'vulnerable': False, 'undetermined': True})
    assert '미확정' in text and '방어' not in text


def test_safe_specialist_diagnostic_survives_summary():
    finding = {'kind': 'file-upload', 'error': '[REDACTED]',
               'error_type': 'connection_error', 'vulnerable': False}
    assert 'connection_error' in rendered(finding)
    finding['kind'] = 'open-redirect'
    assert 'connection_error' in audit._ssrf_finding_line(finding)


def test_unrecognized_diagnostic_is_not_shared_verbatim():
    finding = {'kind': 'file-upload', 'error': '[REDACTED]',
               'error_type': 'person@example.invalid', 'vulnerable': False}
    text = rendered(finding)
    assert 'request_failed' in text
    assert 'person@example.invalid' not in text


def summary_output(monkeypatch, tmp_path, capsys):
    """Render the real CLI summary while keeping all probes synthetic."""
    monkeypatch.setattr(sys, 'argv', ['audit.py', str(tmp_path), '--target', 'http://127.0.0.1'])
    results = {
        'run_static': ({'by_skill': []}, None),
        'run_dynamic': [],
        'run_access_dynamic': {'confidence': 'static-only', 'candidate_count': 1},
        'run_auth_dynamic': {'skipped': 'synthetic'},
        'run_ssrf_dynamic': {'confidence': 'dynamic', 'result': {'findings': [
            {'kind': 'open-redirect', 'status': 302, 'vulnerable': False, 'undetermined': True}
        ]}},
        'run_pathupload_dynamic': {'skipped': 'synthetic'},
        '_apply_burp_proxy': {'enabled': False},
    }
    for name, result in results.items():
        monkeypatch.setattr(audit, name, lambda *args, _result=result, **kwargs: _result)
    audit.main()
    return capsys.readouterr().out


def test_ssrf_summary_heading_does_not_confirm_an_undetermined_probe(monkeypatch, tmp_path, capsys):
    text = summary_output(monkeypatch, tmp_path, capsys)
    assert '[SSRF/오픈리다이렉트] 동적 검사 수행' in text
    verdict = next(line for line in text.splitlines() if '[open-redirect]' in line)
    assert '미확정' in verdict and '방어' not in verdict
    assert '동적 확정 발사' not in text


def test_summary_does_not_promise_confirmation_after_retry(monkeypatch, tmp_path, capsys):
    text = summary_output(monkeypatch, tmp_path, capsys)
    assert '동적으로 확정됩니다' not in text
    assert '테스트 계정 제공 시 동적 확정' not in text
    assert '근거가 부족하면 미확정으로 남습니다' in text


@pytest.mark.parametrize('kind', ['access', 'ssrf', 'pathupload'])
def test_missing_prerequisites_note_does_not_promise_confirmation(kind, monkeypatch):
    def unexpected_probe(*args, **kwargs):
        raise AssertionError('missing prerequisites must not start a probe')
    monkeypatch.setattr(audit.subprocess, 'run', unexpected_probe)
    target = 'http://127.0.0.1'
    if kind == 'access':
        static = {'by_skill': [{'skill': 'detecting-broken-access-control',
                                'candidates': [{'rule_id': 'synthetic'}]}]}
        result = audit.run_access_dynamic(target, static, {}, False)
    elif kind == 'ssrf':
        result = audit.run_ssrf_dynamic(target, {}, None, None, False)
    else:
        result = audit.run_pathupload_dynamic(target, {}, None, None, 'file', None, False, False)
    assert result['confidence'] == 'static-only'
    assert '동적 확정' not in result['note']
    assert '근거가 부족하면 미확정' in result['note']
