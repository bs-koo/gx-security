"""Fixed transport causes survive payload probes, login wrappers and CLI output."""
import importlib.util
import json
from pathlib import Path
import sys
from unittest.mock import Mock

import pytest

from tools import dyn_session
from tools.specialist_transport import BudgetError, DeadlineError

ROOT = Path(__file__).resolve().parents[1]


def load(skill, name):
    spec = importlib.util.spec_from_file_location('limit_' + name,
            ROOT / 'skills' / skill / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SQLI = load('exploiting-sql-injection', 'attack_sqli')
XSS = load('exploiting-xss-vulnerabilities', 'attack_xss')
AUTH = load('exploiting-auth-session', 'attack_auth')
ACCESS = load('exploiting-broken-access-control', 'attack_access')


@pytest.fixture(params=['response_limit', 'budget_exhausted', 'timeout'])
def failure(request):
    return DeadlineError() if request.param == 'timeout' else BudgetError(request.param)


@pytest.mark.parametrize('content_type', ['form', 'json'])
def test_sqli_limit_after_successful_probe_is_not_lost(monkeypatch, capsys, failure, content_type):
    response = {'status': 200, 'body': 'normal', 'elapsed': 0.01, 'headers': {}}
    monkeypatch.setattr(dyn_session, 'request', Mock(side_effect=[response, failure]))
    monkeypatch.setattr(dyn_session, '_client', Mock(side_effect=failure))
    monkeypatch.setattr(SQLI, '_run_sqlmap', Mock(return_value=None))
    args = SQLI._build_parser().parse_args(['http://localhost/search', '--param', 'q',
                                           '--content-type', content_type, '--json'])
    with pytest.raises(SystemExit) as stopped:
        SQLI.run_attack(args)
    output = json.loads(capsys.readouterr().out)
    assert stopped.value.code == 2 and output['error_type'] == failure.code
    assert not output.get('exploited')


@pytest.mark.parametrize('content_type', ['form', 'json'])
def test_xss_limit_after_successful_probe_is_not_lost(monkeypatch, capsys, failure, content_type):
    monkeypatch.setattr(dyn_session, 'request', Mock(side_effect=[
        {'status': 200, 'body': 'normal', 'elapsed': 0.01}, failure]))
    monkeypatch.setattr(dyn_session, '_client', Mock(side_effect=[
        Mock(status_code=200, content=b'normal'), failure]))
    monkeypatch.setattr(XSS, 'build_payloads', Mock(return_value=[
        {'name': 'one', 'context': 'html_body', 'payload': 'marker'},
        {'name': 'two', 'context': 'html_body', 'payload': 'marker'}]))
    monkeypatch.setattr(sys, 'argv', ['attack_xss.py', 'http://localhost/search', '--param', 'q',
                                    '--content-type', content_type, '--json'])
    with pytest.raises(SystemExit) as stopped:
        XSS.main()
    output = json.loads(capsys.readouterr().out)
    assert stopped.value.code == 2 and output['error_type'] == failure.code
    assert output['verdict'] == 'unreached' and not output['exploited']


def test_auth_limit_after_successful_control_is_not_lost(monkeypatch, capsys, failure):
    monkeypatch.setattr(dyn_session, 'request', Mock(side_effect=[
        {'status': 200, 'body': 'normal', 'elapsed': 0.01}, failure, failure]))
    args = AUTH._build_parser().parse_args(['http://localhost', '--token-a', 'synthetic-token',
                                           '--probe', '/me', '--json'])
    AUTH.run(args)
    findings = [f for f in json.loads(capsys.readouterr().out)['findings'] if f.get('error')]
    assert findings and all(f['error_type'] == failure.code for f in findings)
    assert all(f['undetermined'] and not f.get('vulnerable') for f in findings)


def test_auth_probe_selection_limit_is_not_lost(monkeypatch, capsys, failure):
    monkeypatch.setattr(AUTH, '_probe_candidates_from_scan', Mock(return_value=['/missing', '/me']))
    monkeypatch.setattr(dyn_session, 'request', Mock(side_effect=[
        {'status': 404, 'body': '', 'elapsed': 0.01}, failure]))
    args = AUTH._build_parser().parse_args(['http://localhost', '--token-a', 'synthetic-token',
                                           '--scan', 'synthetic.json', '--json'])
    AUTH.run(args)
    findings = json.loads(capsys.readouterr().out)['findings']
    finding = next(f for f in findings if f.get('kind') == 'probe-select')
    assert finding['error_type'] == failure.code and finding['undetermined']


def test_access_limit_after_successful_control_is_not_lost(monkeypatch, capsys, tmp_path, failure):
    scan = tmp_path / 'scan.json'
    scan.write_text('{}', encoding='utf-8')
    monkeypatch.setattr(ACCESS, 'build_targets', Mock(return_value=[{'kind': 'bfla', 'path': '/admin'}]))
    monkeypatch.setattr(dyn_session, 'request', Mock(side_effect=[
        {'status': 401, 'body': '', 'elapsed': 0.01}, failure]))
    args = ACCESS._build_parser().parse_args(['http://localhost', '--token-a', 'synthetic-token',
                                             '--scan', str(scan), '--json'])
    ACCESS.run(args)
    finding = json.loads(capsys.readouterr().out)['findings'][0]
    assert finding['error_type'] == failure.code and finding['undetermined']
    assert not finding.get('vulnerable')


@pytest.mark.parametrize('lane', ['login', 'login_response', 'form_login'])
def test_login_wrapper_preserves_fixed_limit_code(monkeypatch, failure, lane):
    monkeypatch.setattr(dyn_session, '_client', Mock(side_effect=failure))
    options = {'success_path': '/home'} if lane == 'form_login' else {}
    with pytest.raises(RuntimeError) as stopped:
        getattr(dyn_session, lane)('http://localhost', '/login', {'id': 'fixture', 'pw': 'fixture'}, **options)
    assert dyn_session.request_error_type(stopped.value) == failure.code
