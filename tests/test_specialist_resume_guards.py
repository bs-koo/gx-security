"""Review follow-ups must fail before dispatch and retain safe limit diagnostics."""
import importlib.util
from pathlib import Path
import ssl
from unittest.mock import Mock

import pytest
import requests

from tools import specialist_transport as transport


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'resume_boundary_audit', ROOT / 'skills/auditing-web-application-security/scripts/audit.py')
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


@pytest.mark.parametrize('disable_certificate', [False, True])
def test_mutated_tls_verification_is_rejected_before_any_socket(monkeypatch, disable_certificate):
    operation = transport.OperationContext(['https://localhost'])
    operation._tls_context.check_hostname = False
    if disable_certificate:
        operation._tls_context.verify_mode = ssl.CERT_NONE
    socket = Mock(side_effect=AssertionError('Weakened TLS must not reach the socket'))
    monkeypatch.setattr(transport.socket, 'socket', socket)
    request = requests.Request('GET', 'https://localhost/').prepare()
    with pytest.raises(transport.PolicyError):
        transport.BoundedAdapter(operation).send(request)
    socket.assert_not_called()


def test_unsupported_https_proxy_is_rejected_before_audit_preflight(monkeypatch):
    monkeypatch.setenv('SECURITY_PLUGIN_BURP_PROXY', 'http://127.0.0.1:8989')
    probe = Mock(return_value=True)
    result = audit._apply_burp_proxy('https://127.0.0.1:8443', probe=probe)
    probe.assert_not_called()
    assert result['error'] == 'invalid_burp_proxy' and result['strict_abort']


@pytest.mark.parametrize('code', ['response_limit', 'budget_exhausted'])
def test_limit_reason_survives_human_summary_without_a_safe_verdict(code):
    finding = {'kind': 'file-upload', 'error': True, 'error_type': code,
               'vulnerable': False, 'undetermined': True, 'validation': 'undetermined'}
    text = '\n'.join(audit.render_pathupload({'confidence': 'dynamic',
                    'result': {'findings': [finding]}}))
    assert code in text
    assert '방어' not in text


@pytest.mark.parametrize('failure', [transport.DeadlineError, transport.BudgetError])
@pytest.mark.parametrize('cleanup_target', ['response', 'socket'])
def test_cleanup_failure_preserves_original_limit_and_closes_socket(monkeypatch, failure, cleanup_target):
    operation = transport.OperationContext(['http://127.0.0.1:1'])
    sock, response = Mock(), Mock()
    sock.send.side_effect = len
    response.begin.side_effect = failure()
    closer = response.close if cleanup_target == 'response' else sock.close
    closer.side_effect = RuntimeError('private cleanup detail')
    monkeypatch.setattr(transport.socket, 'socket', Mock(return_value=sock))
    monkeypatch.setattr(transport, '_StrictResponse', Mock(return_value=response))
    prepared = requests.Request('GET', 'http://127.0.0.1:1/').prepare()
    with pytest.raises(failure) as caught:
        transport.BoundedAdapter(operation).send(prepared)
    assert str(caught.value) in {'timeout', 'budget_exhausted'}
    response.close.assert_called_once()
    sock.close.assert_called_once()
