"""A disallowed proxy must be rejected before even the TCP preflight."""
import importlib.util
import json
import os
from pathlib import Path
import sys
from unittest.mock import Mock

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'isolated_proxy_audit', ROOT / 'skills/auditing-web-application-security/scripts/audit.py')
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


@pytest.mark.parametrize('proxy', [
    'http://203.0.113.1:8080', 'http://localhost:8080',
    'http://name:secret@127.0.0.1:8080', 'http://127.0.0.1:8080?secret=value',
    'socks5://127.0.0.1:8080', 'http://127.0.0.1:not-a-port',
])
def test_invalid_proxy_never_reaches_preflight_or_changes_environment(monkeypatch, proxy):
    original = 'http://127.0.0.1:8989'
    monkeypatch.setenv('SECURITY_PLUGIN_BURP_PROXY', original)
    probe = Mock(return_value=True)
    result = audit._apply_burp_proxy(proxy, probe=probe)
    probe.assert_not_called()
    assert result['error'] == 'invalid_burp_proxy' and result['strict_abort']
    assert result['enabled'] is False
    assert os.environ['SECURITY_PLUGIN_BURP_PROXY'] == original


@pytest.mark.parametrize('scheme,port', [('http', 80)])
def test_preflight_uses_the_same_default_port_as_the_http_client(monkeypatch, scheme, port):
    key = 'SECURITY_PLUGIN_BURP_PROXY'
    present, previous = key in os.environ, os.environ.get(key)
    with monkeypatch.context() as environment:
        # Record the absent state too: the real helper writes this variable.
        environment.setenv(key, '')
        probe = Mock(return_value=True)
        result = audit._apply_burp_proxy(scheme + '://127.0.0.1', probe=probe)
        probe.assert_called_once_with('127.0.0.1', port)
        assert result['enabled']
    assert (key in os.environ) is present
    assert os.environ.get(key) == previous


def test_unavailable_explicit_proxy_does_not_leave_an_old_proxy_active(monkeypatch):
    monkeypatch.setenv('SECURITY_PLUGIN_BURP_PROXY', 'http://127.0.0.1:8989')
    result = audit._apply_burp_proxy('http://127.0.0.1:8080', probe=lambda *_: False)
    assert not result['enabled']
    assert 'SECURITY_PLUGIN_BURP_PROXY' not in os.environ


def test_invalid_proxy_cli_stops_before_any_dynamic_probe(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(sys, 'argv', ['audit.py', str(tmp_path), '--target', 'http://127.0.0.1',
                                     '--burp-proxy', 'http://203.0.113.1:8080', '--json'])
    monkeypatch.setattr(audit, 'run_static', lambda *_: ({'by_skill': []}, None))
    monkeypatch.setattr(audit.burp_preflight, 'probe_port', Mock(return_value=False))
    dynamic = Mock(side_effect=AssertionError('invalid proxy must not run a dynamic probe'))
    monkeypatch.setattr(audit, 'run_dynamic', dynamic)
    with pytest.raises(SystemExit) as stopped:
        audit.main()
    assert stopped.value.code == 2
    assert json.loads(capsys.readouterr().out)['error'] == 'invalid_burp_proxy'
    dynamic.assert_not_called()
    audit.burp_preflight.probe_port.assert_not_called()
