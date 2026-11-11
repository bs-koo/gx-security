"""CLI/context wiring and real client integration for specialist transport."""
import importlib.util
import json
from pathlib import Path
import sys
from unittest.mock import Mock

import pytest
import requests

from tools import dyn_session
from tools.scope_guard import ScopeError
from tests.test_specialist_http_isolation import probe_server

ROOT = Path(__file__).resolve().parents[1]


def scope(urls, **kwargs):
    factory = getattr(dyn_session, "diagnostic_scope", None)
    assert callable(factory), "one diagnostic context must bind CLI authorization and budgets"
    return factory(urls, **kwargs)


def limits(**kwargs):
    from tools.specialist_transport import Limits
    return Limits(**kwargs)


@pytest.fixture(autouse=True)
def clean_transport_env(monkeypatch):
    for key in ("SECURITY_PLUGIN_BURP_PROXY", "SECURITY_PLUGIN_BURP_CA", "SECURITY_PLUGIN_TARGET_IPS",
                "SECURITY_PLUGIN_AUTHORIZED", "SECURITY_PLUGIN_ALLOW_HOSTS", "SECURITY_PLUGIN_ALLOW_PRIVATE"):
        monkeypatch.delenv(key, raising=False)


def test_login_anonymous_probe_and_fresh_sessions_share_one_request_budget():
    from tools.specialist_transport import BudgetError
    with probe_server("target") as target, scope([target.url], limits=limits(max_requests=2)):
        assert dyn_session.login(target.url, "/login", {"id": "fixture", "pw": "fixture"}) == "fixture-token"
        dyn_session.request("GET", target.url + "/observe")
        with pytest.raises(BudgetError):
            dyn_session.request("GET", target.url + "/observe")
        assert len(target.observed) == 2


def test_nested_context_exception_restores_outer_budget_and_exit_resets_scope():
    from tools.specialist_transport import BudgetError
    with probe_server("target") as target:
        with scope([target.url], limits=limits(max_requests=2)):
            dyn_session.request("GET", target.url)
            with pytest.raises(RuntimeError, match="fixture interruption"):
                with scope([target.url], limits=limits(max_requests=1)):
                    dyn_session.request("GET", target.url)
                    raise RuntimeError("fixture interruption")
            dyn_session.request("GET", target.url)
            with pytest.raises(BudgetError):
                dyn_session.request("GET", target.url)
        dyn_session.request("GET", target.url)  # a standalone literal target has a fresh local scope
        assert len(target.observed) == 4


def test_existing_cookie_auth_session_cannot_send_to_a_different_port():
    with probe_server("target") as first, probe_server("second-target") as second:
        session = requests.Session()
        session.auth = ("fixture-user", "fixture-password")
        session.cookies.set("fixture_cookie", "fixture-cookie", domain="127.0.0.1", path="/")
        try:
            dyn_session.request("GET", first.url, session=session)
            with pytest.raises(ScopeError):
                dyn_session.request("GET", second.url, session=session)
            assert second.observed == []
        finally:
            session.close()


def test_same_bearer_cannot_cross_origins_by_using_fresh_sessions():
    with probe_server("target") as first, probe_server("second-target") as second, scope([first.url, second.url]):
        dyn_session.request("GET", first.url, token="synthetic-origin-bound-token")
        with pytest.raises(ScopeError):
            dyn_session.request("GET", second.url, token="synthetic-origin-bound-token")
        assert second.observed == []


class InterceptAdapter(requests.adapters.BaseAdapter):
    def __init__(self):
        self.observed = []

    def send(self, request, **kwargs):
        self.observed.append(request)
        response = requests.Response()
        response.status_code = 200
        response._content = b'{"source":"custom-adapter"}'
        response.request = request
        return response

    def close(self):
        pass


def test_longer_prefix_session_adapter_cannot_bypass_the_shared_boundary():
    with probe_server("target") as target:
        session = requests.Session()
        custom = InterceptAdapter()
        session.mount(target.url + "/", custom)
        try:
            result = dyn_session.request("GET", target.url + "/observe", session=session)
            assert custom.observed == []
            assert json.loads(result["body"])["source"] == "target"
        finally:
            session.close()


def test_stream_override_is_rejected_before_any_request():
    with probe_server("target") as target:
        with pytest.raises((ValueError, ScopeError)):
            dyn_session._client("GET", target.url, stream=True, allow_redirects=False)
        assert target.observed == []


def load_script(skill, filename):
    spec = importlib.util.spec_from_file_location("integrated_" + filename, ROOT / "skills" / skill / "scripts" / (filename + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("skill, filename", [
    ("exploiting-auth-session", "attack_auth"),
    ("exploiting-broken-access-control", "attack_access"),
    ("exploiting-path-traversal-upload", "attack_pathupload"),
    ("exploiting-ssrf-and-open-redirect", "attack_ssrf"),
    ("exploiting-sql-injection", "attack_sqli"),
    ("exploiting-xss-vulnerabilities", "attack_xss"),
])
def test_each_cli_prepares_complete_scope_before_any_login(skill, filename, monkeypatch, capsys):
    module = load_script(skill, filename)
    login = Mock(return_value="fixture-token")
    login_response = Mock(return_value={"token": "fixture-token", "set_cookie": ""})
    form_login = Mock()
    monkeypatch.setattr(dyn_session, "login", login)
    monkeypatch.setattr(dyn_session, "login_response", login_response)
    monkeypatch.setattr(dyn_session, "form_login", form_login)
    monkeypatch.setattr(dyn_session, "request", Mock(return_value={"status": 200, "body": "{}", "headers": {}, "elapsed": 0.01}))
    argv = ["http://unpinned-app.test:8080", "--user-a-id", "fixture", "--user-a-pw", "fixture", "--json"]
    if filename in {"attack_sqli", "attack_xss"}:
        argv += ["--param", "id"]
    with pytest.raises(SystemExit) as caught:
        if filename == "attack_xss":
            monkeypatch.setattr(sys, "argv", [filename + ".py", *argv])
            module.main()
        else:
            args = module._build_parser().parse_args(argv)
            (module.run_attack if filename == "attack_sqli" else module.run)(args)
    assert caught.value.code == 1
    login.assert_not_called()
    login_response.assert_not_called()
    form_login.assert_not_called()
    output = capsys.readouterr()
    assert "scope_blocked" in output.out
    assert "Traceback" not in output.err


def test_cross_origin_retrieval_is_unsupported_before_login_or_upload(monkeypatch, capsys):
    module = load_script("exploiting-path-traversal-upload", "attack_pathupload")
    login = Mock(return_value={"token": "fixture-token"})
    upload = Mock(return_value={"kind": "file-upload", "vulnerable": False, "accepted": True,
                                "retrievable": False, "undetermined": True})
    monkeypatch.setattr(dyn_session, "login_response", login)
    monkeypatch.setattr(module, "run_upload", upload)
    args = module._build_parser().parse_args([
        "http://127.0.0.1:8123", "--retrieve-base", "http://127.0.0.1:8124/files", "--upload-target", "/upload",
        "--allow-destructive", "--user-a-id", "fixture", "--user-a-pw", "fixture", "--json"])
    with pytest.raises(SystemExit) as caught:
        module.run(args)
    assert caught.value.code == 1
    login.assert_not_called()
    upload.assert_not_called()
