"""The legacy specialist client must not inherit ambient proxy/auth/CA policy."""
import contextlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import threading
from urllib.parse import urlsplit
from urllib.parse import parse_qs
from unittest.mock import Mock

import pytest
import requests

from tools import dyn_session

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "isolated_sqli", ROOT / "skills/exploiting-sql-injection/scripts/attack_sqli.py")
SQLI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SQLI)


class ProbeHandler(http.server.BaseHTTPRequestHandler):
    def respond(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.observed.append({"path": self.path, "authorization": self.headers.get("Authorization"),
                                     "cookie": self.headers.get("Cookie"), "body": body,
                                     "user_agent": self.headers.get("User-Agent"),
                                     "content_type": self.headers.get("Content-Type")})
        if self.server.label == "html":
            path = urlsplit(self.path).path.rsplit("/", 1)[-1]
            status = int(path) if path.isdigit() else 200
            fields = parse_qs(body.decode()) if self.command == "POST" else parse_qs(urlsplit(self.path).query)
            payload = fields.get("q", [""])[0]
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=iso-8859-1")
            if status == 302:
                self.send_header("Location", "/followed")
            self.end_headers()
            self.wfile.write("한글: ".encode() + payload.encode() + b"\xff")
            return
        if urlsplit(self.path).path == "/form":
            self.send_response(302)
            self.send_header("Location", "/home")
            self.send_header("Set-Cookie", "fixture_session=explicit-cookie; Path=/")
        else:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"source": self.server.label, "data": {"accessToken": "fixture-token"}}).encode())

    do_GET = respond
    do_POST = respond

    def log_message(self, *_args):
        pass


@contextlib.contextmanager
def probe_server(label):
    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), ProbeHandler) as server:
        server.observed = []
        server.label = label
        server.url = f"http://127.0.0.1:{server.server_port}"
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join(2)


@pytest.fixture
def pair(monkeypatch):
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy",
                "NO_PROXY", "no_proxy", "SECURITY_PLUGIN_BURP_PROXY", "SECURITY_PLUGIN_BURP_CA",
                "NETRC", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        monkeypatch.delenv(key, raising=False)
    with probe_server("target") as target, probe_server("ambient-proxy") as proxy:
        yield target, proxy


def invoke(lane, base):
    if lane.startswith("xss_"):
        spec = importlib.util.spec_from_file_location(
            "isolated_xss", ROOT / "skills/exploiting-xss-vulnerabilities/scripts/attack_xss.py")
        xss = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(xss)  # the old opener captured proxy settings at import time
        return xss.check_reflection(base + "/observe", "q", lane.removeprefix("xss_"),
                                    {"keep": "preserved"}, "synthetic-payload", "marker")
    if lane == "request":
        return dyn_session.request("GET", base + "/observe")
    if lane == "login":
        return dyn_session.login(base, "/login", {"id": "fixture-user", "pw": "fixture-password"})
    if lane == "login_response":
        return dyn_session.login_response(base, "/login", {"id": "fixture-user", "pw": "fixture-password"})
    if lane == "form_login":
        result = dyn_session.form_login(base, "/form", {"id": "fixture-user", "pw": "fixture-password"}, success_path="/home")
        result["session"].close()
        return result
    return SQLI._send(base + "/observe", "id", "synthetic-payload", lane.removeprefix("sql_"), {"keep": "preserved"})


def test_new_session_disables_environment_policy():
    session = dyn_session.new_session()
    try:
        assert session.trust_env is False
        assert session.verify is True
    finally:
        session.close()


@pytest.mark.parametrize("lane", ["request", "login", "login_response", "form_login", "sql_get", "sql_post", "xss_get", "xss_post"])
def test_real_target_receives_requests_while_ambient_proxy_receives_nothing(pair, monkeypatch, tmp_path, lane):
    target, proxy = pair
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(key, proxy.url)
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setenv("no_proxy", "")
    netrc = tmp_path / "ambient.netrc"
    netrc.write_text("machine 127.0.0.1 login ambient-user password synthetic-ambient-password\n", encoding="utf-8")
    monkeypatch.setenv("NETRC", str(netrc))
    assert invoke(lane, target.url) is not None
    assert len(proxy.observed) == 0
    assert len(target.observed) == 1
    assert target.observed[0]["authorization"] is None
    if lane == "sql_get":
        assert parse_qs(urlsplit(target.observed[0]["path"]).query)["id"] == ["synthetic-payload"]
    elif lane == "sql_post":
        assert parse_qs(target.observed[0]["body"].decode()) == {"keep": ["preserved"], "id": ["synthetic-payload"]}


@pytest.mark.parametrize("lane", ["request", "login", "sql_get", "xss_get"])
def test_real_netrc_file_is_not_used_for_target_authentication(pair, monkeypatch, tmp_path, lane):
    target, proxy = pair
    netrc = tmp_path / "ambient.netrc"
    netrc.write_text("machine 127.0.0.1 login ambient-user password synthetic-ambient-password\n", encoding="utf-8")
    monkeypatch.setenv("NETRC", str(netrc))
    assert invoke(lane, target.url) is not None
    assert proxy.observed == []
    assert len(target.observed) == 1
    assert target.observed[0]["authorization"] is None


@pytest.mark.parametrize("lane", ["request", "xss_get", "xss_post"])
def test_explicit_loopback_proxy_still_receives_the_intended_request(pair, monkeypatch, tmp_path, lane):
    target, proxy = pair
    netrc = tmp_path / "ambient.netrc"
    netrc.write_text("machine 127.0.0.1 login ambient-user password synthetic-ambient-password\n", encoding="utf-8")
    monkeypatch.setenv("NETRC", str(netrc))
    monkeypatch.setenv("SECURITY_PLUGIN_BURP_PROXY", proxy.url)
    result = dyn_session.request("GET", target.url + "/observe", token="intentional-bearer") if lane == "request" else invoke(lane, target.url)
    assert json.loads(result["body"] if lane == "request" else result[2])["source"] == "ambient-proxy"
    assert target.observed == []
    assert len(proxy.observed) == 1
    assert proxy.observed[0]["path"].startswith(target.url + "/observe")
    assert proxy.observed[0]["authorization"] == ("Bearer intentional-bearer" if lane == "request" else None)


def test_passed_session_preserves_explicit_auth_and_cookie_but_not_its_unvalidated_proxy(pair):
    target, proxy = pair
    session = requests.Session()
    session.proxies = {"http": proxy.url, "https": proxy.url}
    session.auth = ("explicit-user", "explicit-password")
    session.cookies.set("fixture_cookie", "intended-cookie", domain="127.0.0.1", path="/")
    session.verify = False
    try:
        result = dyn_session.request("GET", target.url + "/observe", session=session)
        assert json.loads(result["body"])["source"] == "target"
        assert proxy.observed == []
        assert target.observed[0]["authorization"].startswith("Basic ")
        assert target.observed[0]["cookie"] == "fixture_cookie=intended-cookie"
        assert session.auth == ("explicit-user", "explicit-password")
        assert session.trust_env is False
        assert session.verify is True
        assert session.proxies == {}
    finally:
        session.close()


def test_form_session_reuses_cookie_without_environment_auth_or_proxy(pair, monkeypatch):
    target, proxy = pair
    monkeypatch.setenv("HTTP_PROXY", proxy.url)
    monkeypatch.setenv("NO_PROXY", "")
    result = dyn_session.form_login(target.url, "/form", {"id": "fixture-user", "pw": "fixture-password"}, success_path="/home")
    session = result["session"]
    try:
        dyn_session.request("GET", target.url + "/observe", session=session)
        assert len(target.observed) == 2
        assert proxy.observed == []
        assert target.observed[1]["cookie"] == "fixture_session=explicit-cookie"
        assert target.observed[1]["authorization"] is None
    finally:
        session.close()


@pytest.mark.parametrize("override", [{"proxies": {"http": "http://remote.invalid:8080"}}, {"verify": False}])
def test_private_dispatch_cannot_override_checked_proxy_or_verified_tls(override, monkeypatch):
    monkeypatch.delenv("SECURITY_PLUGIN_BURP_PROXY", raising=False)
    send = Mock(return_value=requests.Response())
    monkeypatch.setattr(requests.Session, "request", send)
    with pytest.raises(ValueError, match="override"):
        dyn_session._client("GET", "http://127.0.0.1/", **override)
    send.assert_not_called()


@pytest.mark.parametrize("failed", [False, True])
def test_owned_dispatch_session_is_closed_on_success_and_failure(failed, monkeypatch):
    monkeypatch.delenv("SECURITY_PLUGIN_BURP_PROXY", raising=False)
    session = Mock()
    session.request.side_effect = TimeoutError("fixture") if failed else None
    monkeypatch.setattr(dyn_session, "new_session", lambda: session)
    if failed:
        with pytest.raises(TimeoutError):
            dyn_session._client("GET", "http://127.0.0.1/")
    else:
        assert dyn_session._client("GET", "http://127.0.0.1/") is session.request.return_value
    session.close.assert_called_once()


def test_explicit_proxy_ca_is_the_only_ca_override(monkeypatch, tmp_path):
    monkeypatch.setenv("SECURITY_PLUGIN_BURP_PROXY", "https://127.0.0.1:8443")
    ca = tmp_path / "explicit-burp.pem"
    ca.write_text("fixture public CA\n", encoding="utf-8")
    monkeypatch.setenv("SECURITY_PLUGIN_BURP_CA", str(ca))
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(tmp_path / "ambient.pem"))
    captured = {}
    def send(session, request, **kwargs):
        captured.update(kwargs, trust_env=session.trust_env)
        result = requests.Response()
        result.status_code = 200
        result._content = b"ok"
        result.request = request
        return result
    monkeypatch.setattr(requests.Session, "send", send)
    dyn_session.request("GET", "https://127.0.0.1/")
    assert captured["trust_env"] is False
    assert captured["verify"] == str(ca)
    assert captured["proxies"] == {"http": "https://127.0.0.1:8443", "https": "https://127.0.0.1:8443"}


@pytest.mark.parametrize("lane", ["request", "xss_get"])
def test_ambient_ca_bundles_do_not_override_verified_tls(monkeypatch, tmp_path, lane):
    for key in ("SECURITY_PLUGIN_BURP_PROXY", "SECURITY_PLUGIN_BURP_CA", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(tmp_path / "untrusted-requests.pem"))
    monkeypatch.setenv("CURL_CA_BUNDLE", str(tmp_path / "untrusted-curl.pem"))
    captured = {}
    def send(session, request, **kwargs):
        captured.update(kwargs, trust_env=session.trust_env)
        result = requests.Response()
        result.status_code = 200
        result._content = b"ok"
        result.request = request
        return result
    monkeypatch.setattr(requests.Session, "send", send)
    if lane == "request":
        dyn_session.request("GET", "https://127.0.0.1/observe")
    else:
        invoke(lane, "https://127.0.0.1")
    assert captured.get("verify") is True
    assert captured["trust_env"] is False
    assert captured["proxies"] == {}


@pytest.mark.parametrize("proxy", [
    "http://remote.invalid:8080", "http://localhost:8080", "http://127.1:8080",
    "http://2130706433:8080", "http://127.0.0.1.evil.test:8080", "socks5://127.0.0.1:8080",
    "file://127.0.0.1:8080", "http://user:password@127.0.0.1:8080", "http://@127.0.0.1:8080",
    "http://127.0.0.1:8080/", "http://127.0.0.1:8080/path", "http://127.0.0.1:8080?token=x",
    "http://127.0.0.1:8080?", "http://127.0.0.1:8080#fragment", "http://127.0.0.1:8080#",
    "http://127.0.0.1:invalid", "http://127.0.0.1:0", "http://127.0.0.1:65536",
    "http://[::1%loopback]:8080", "http://[::ffff:127.0.0.1]:8080", " http://127.0.0.1:8080",
    "http://127.0.0.1:8080\r\nX: injected",
])
def test_ambiguous_or_remote_proxy_values_are_rejected(proxy, monkeypatch):
    monkeypatch.setenv("SECURITY_PLUGIN_BURP_PROXY", proxy)
    with pytest.raises(dyn_session.ScopeError, match="loopback"):
        dyn_session._burp_proxies()


@pytest.mark.parametrize("proxy", ["http://127.0.0.1:8080", "https://127.23.45.67:8443", "http://[::1]:8080"])
def test_unambiguous_loopback_http_proxy_values_remain_supported(proxy, monkeypatch):
    monkeypatch.setenv("SECURITY_PLUGIN_BURP_PROXY", proxy)
    assert dyn_session._burp_proxies() == {"http": proxy, "https": proxy}


@pytest.mark.parametrize("value", ["", " ", None, 123, {}, b"http://127.0.0.1:8080"])
def test_pure_proxy_validator_rejects_empty_and_non_text_values(value):
    validator = getattr(dyn_session, "validate_burp_proxy_url", None)
    assert callable(validator)
    with pytest.raises(dyn_session.ScopeError, match="loopback"):
        validator(value)


@pytest.mark.parametrize("value, expected", [("HTTP://127.0.0.1:08080", "http://127.0.0.1:8080"),
                                            ("http://127.0.0.1", "http://127.0.0.1:80"),
                                            ("https://[::1]", "https://[::1]:443")])
def test_pure_proxy_validator_normalizes_without_changing_environment(value, expected, monkeypatch):
    monkeypatch.setenv("SECURITY_PLUGIN_BURP_PROXY", "preserve-this-value")
    validator = getattr(dyn_session, "validate_burp_proxy_url", None)
    assert callable(validator)
    assert validator(value) == expected
    assert os.environ["SECURITY_PLUGIN_BURP_PROXY"] == "preserve-this-value"


def test_proxy_scope_exception_keeps_the_safe_scope_code():
    assert dyn_session.request_error_type(dyn_session.ScopeError("fixture")) == "scope_blocked"


@pytest.mark.parametrize("method", ["login", "login_response"])
@pytest.mark.parametrize("proxy", ["http://remote.invalid:8080", "http://user:synthetic-proxy-password@127.0.0.1:8080"])
def test_login_bad_proxy_keeps_runtime_error_contract_without_dispatch(method, proxy, monkeypatch):
    monkeypatch.setenv("SECURITY_PLUGIN_BURP_PROXY", proxy)
    send = Mock()
    monkeypatch.setattr(requests.Session, "request", send)
    with pytest.raises(RuntimeError, match="로그인 요청 실패") as caught:
        getattr(dyn_session, method)("http://127.0.0.1", "/login?password=synthetic-target-password",
                                    {"id": "fixture-user", "pw": "fixture-password"})
    send.assert_not_called()
    assert "scope_blocked" in str(caught.value)
    assert "synthetic-proxy-password" not in str(caught.value)
    assert "synthetic-target-password" not in str(caught.value)


@pytest.mark.parametrize("owned", [True, False])
@pytest.mark.parametrize("status, location", [(None, None), (200, None), (302, "/wrong"),
                                            (302, None), (401, None), (500, None), (302, "/home")])
def test_form_login_closes_only_owned_failed_sessions(owned, status, location, monkeypatch):
    monkeypatch.delenv("SECURITY_PLUGIN_BURP_PROXY", raising=False)
    session = Mock()
    session.request.return_value = SimpleNamespace(status_code=status, headers={"Location": location} if location else {})
    if status is None:
        session.request.side_effect = TimeoutError("synthetic failure")
    factory = Mock(return_value=session)
    monkeypatch.setattr(dyn_session, "new_session", factory)
    kwargs = {} if owned else {"session": session}
    if status == 302 and location == "/home":
        result = dyn_session.form_login("http://127.0.0.1", "/form", {"id": "fixture", "pw": "fixture"}, success_path="/home", **kwargs)
        assert result["session"] is session
        session.close.assert_not_called()
    else:
        with pytest.raises(RuntimeError):
            dyn_session.form_login("http://127.0.0.1", "/form", {"id": "fixture", "pw": "fixture"}, success_path="/home", **kwargs)
        if owned:
            session.close.assert_called_once()
        else:
            session.close.assert_not_called()


@pytest.mark.parametrize("method", ["get", "post"])
@pytest.mark.parametrize("status", [200, 302, 403, 500])
def test_real_xss_preserves_original_status_utf8_replacement_and_reflection(method, status, monkeypatch):
    monkeypatch.delenv("SECURITY_PLUGIN_BURP_PROXY", raising=False)
    marker = "sqixssfixture"
    payload = "<script>window.__xss_fired='" + marker + "'</script>"
    with probe_server("html") as target:
        spec = importlib.util.spec_from_file_location(
            "xss_status_contract", ROOT / "skills/exploiting-xss-vulnerabilities/scripts/attack_xss.py")
        xss = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(xss)
        context, observed_status, body = xss.check_reflection(
            target.url + "/status/" + str(status), "q", method, {"keep": "preserved"}, payload, marker)
        assert observed_status == status
        assert body == "한글: " + payload + "\ufffd"
        assert context == "js_block"
        assert len(target.observed) == 1
        assert target.observed[0]["user_agent"] == "SQI-SecurityPlugin-XSS-Scanner/0.1"
        if method == "post":
            assert target.observed[0]["content_type"] == "application/x-www-form-urlencoded"
            assert parse_qs(target.observed[0]["body"].decode()) == {"keep": ["preserved"], "q": [payload]}
