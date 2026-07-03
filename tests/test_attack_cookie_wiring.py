"""attack 4종 cookie 모드 배선 wiring 테스트 (U4 리뷰 이월 3건).

엔진(dyn_session.form_login/request)은 test_dyn_session_form 22건으로 이미 커버됨.
여기서는 각 attack의 main/run 인라인 cookie 분기가
  1) form_login 을 호출해 세션을 확보하고
  2) 그 세션을 dyn_session.request(session=...) 로 스레딩하며
  3) cookie 모드에서 Bearer 토큰(token=None)을 싣지 않고
  4) access BFLA anon 레그는 항상 fresh(session=None, token=None) 이며
  5) cookie 모드에서 --token-* 를 주면 무시 경고를 내는지
를 검증한다(배선 회귀 방지).
"""
import argparse
import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))

# 세션 스레딩 추적용 센티넬 — 코드가 이 객체를 request(session=...)로 그대로 넘겨야 한다
_SENTINEL_SESSION = object()
_CANNED_RESP = {"status": 200, "body": "", "headers": {}, "elapsed": 0.01}


def _load(rel, name):
    mod_path = os.path.join(_ROOT, *rel.split("/"))
    spec = importlib.util.spec_from_file_location(name, mod_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


attack_ssrf = _load("skills/exploiting-ssrf-and-open-redirect/scripts/attack_ssrf.py", "cwire_ssrf")
attack_pathupload = _load("skills/exploiting-path-traversal-upload/scripts/attack_pathupload.py", "cwire_pathupload")
attack_access = _load("skills/exploiting-broken-access-control/scripts/attack_access.py", "cwire_access")
attack_auth = _load("skills/exploiting-auth-session/scripts/attack_auth.py", "cwire_auth")


def _fresh_form_login():
    return MagicMock(return_value={
        "session": _SENTINEL_SESSION,
        "set_cookie": "JSESSIONID=abc; HttpOnly; Secure",
        "status": 302, "location": "/home",
    })


@contextlib.contextmanager
def _patched(mod, form_login=None):
    """attack 모듈이 참조하는 dyn_session 의 scope/form_login/request/emit 을 격리한다."""
    req = MagicMock(return_value=dict(_CANNED_RESP))
    fl = form_login or _fresh_form_login()
    with patch.object(mod.dyn_session, "assert_in_scope", return_value="ok"), \
         patch.object(mod.dyn_session, "form_login", fl), \
         patch.object(mod.dyn_session, "request", req), \
         patch.object(mod.dyn_session, "emit", MagicMock()):
        yield fl, req


class TestSsrfCookieWiring(unittest.TestCase):
    def test_cookie_threads_session_no_bearer(self):
        args = attack_ssrf._build_parser().parse_args([
            "http://localhost:7171", "--auth-mode", "cookie",
            "--user-a-id", "u", "--user-a-pw", "p", "--success-path", "/home",
            "--redirect-target", "/go?u=", "--json"])
        with _patched(attack_ssrf) as (fl, req):
            attack_ssrf.run(args)
        self.assertTrue(fl.called, "cookie 모드는 form_login 을 호출해야 함")
        self.assertGreaterEqual(req.call_count, 1)
        for c in req.call_args_list:
            self.assertIsNone(c.kwargs.get("token"), "cookie 모드는 Bearer 토큰을 싣지 않음")
        self.assertTrue(any(c.kwargs.get("session") is _SENTINEL_SESSION
                            for c in req.call_args_list),
                        "form_login 세션이 request 로 스레딩되어야 함")


class TestPathuploadCookieWiring(unittest.TestCase):
    def test_cookie_threads_session_no_bearer(self):
        args = attack_pathupload._build_parser().parse_args([
            "http://localhost:7171", "--auth-mode", "cookie",
            "--user-a-id", "u", "--user-a-pw", "p", "--success-path", "/home",
            "--traversal-target", "/download?filePath=", "--json"])
        with _patched(attack_pathupload) as (fl, req):
            attack_pathupload.run(args)
        self.assertTrue(fl.called)
        self.assertGreaterEqual(req.call_count, 1)
        for c in req.call_args_list:
            self.assertIsNone(c.kwargs.get("token"))
        self.assertTrue(any(c.kwargs.get("session") is _SENTINEL_SESSION
                            for c in req.call_args_list))


class TestAccessCookieWiring(unittest.TestCase):
    def _scan_file(self):
        scan = {"candidates": [
            {"rule_id": "spring-admin-no-preauthorize",
             "file": "AdminController.java", "line": 10,
             "snippet": '@RequestMapping("/adm/v1/users")'}]}
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(scan, fh)
        return path

    def test_cookie_threads_session_and_anon_leg_is_fresh(self):
        scan_path = self._scan_file()
        self.addCleanup(os.remove, scan_path)
        args = attack_access._build_parser().parse_args([
            "http://localhost:7171", "--auth-mode", "cookie",
            "--user-a-id", "u", "--user-a-pw", "p", "--success-path", "/home",
            "--scan", scan_path, "--json"])
        with _patched(attack_access) as (fl, req):
            attack_access.run(args)
        self.assertTrue(fl.called)
        self.assertEqual(req.call_count, 2, "BFLA 는 anon + 일반 두 번 발사")
        # 모든 발사에 Bearer 토큰 없음
        for c in req.call_args_list:
            self.assertIsNone(c.kwargs.get("token"))
        sessions = [c.kwargs.get("session") for c in req.call_args_list]
        self.assertIn(None, sessions, "anon 레그는 session=None (fresh) 이어야 함")
        self.assertIn(_SENTINEL_SESSION, sessions, "일반 레그는 form_login 세션을 스레딩")

    def test_resolve_auth_cookie_returns_session(self):
        args = attack_access._build_parser().parse_args([
            "http://localhost:7171", "--auth-mode", "cookie",
            "--user-a-id", "u", "--user-a-pw", "p", "--success-path", "/home"])
        with _patched(attack_access) as (fl, _req):
            token, session = attack_access._resolve_auth(
                args.token_a, args.user_a_id, args.user_a_pw,
                "http://localhost:7171", args, "cookie")
        self.assertIsNone(token)
        self.assertIs(session, _SENTINEL_SESSION)
        self.assertTrue(fl.called)


class TestAuthCookieWiring(unittest.TestCase):
    def test_cookie_calls_form_login_and_skips_bearer_jwt(self):
        # cookie + probe: JWT 변조/재사용은 N/A → 인증 request 없음. form_login 확보가 배선 핵심.
        args = attack_auth._build_parser().parse_args([
            "http://localhost:7171", "--auth-mode", "cookie",
            "--user-a-id", "u", "--user-a-pw", "p", "--success-path", "/home",
            "--probe", "/api/v1/users/me", "--json"])
        with _patched(attack_auth) as (fl, req):
            attack_auth.run(args)
        self.assertTrue(fl.called, "cookie 모드는 form_login 을 호출해야 함")
        # form_login 이 로그인 경로·필드·성공경로로 호출됐는지 확인
        _pos, kw = fl.call_args.args, fl.call_args.kwargs
        self.assertEqual(kw.get("success_path"), "/home")
        self.assertEqual(req.call_count, 0, "cookie 모드는 Bearer JWT 검사(request)를 발사하지 않음")


class TestCookieTokenIgnoredWarning(unittest.TestCase):
    """cookie 모드에서 --token-* 를 주면 stderr 경고(무시)를 낸다."""

    def _run_capture_stderr(self, mod, argv):
        buf = io.StringIO()
        with _patched(mod), contextlib.redirect_stderr(buf):
            mod.run(mod._build_parser().parse_args(argv))
        return buf.getvalue()

    def test_ssrf_warns(self):
        err = self._run_capture_stderr(attack_ssrf, [
            "http://localhost:7171", "--auth-mode", "cookie", "--token-a", "TOK",
            "--user-a-id", "u", "--user-a-pw", "p", "--success-path", "/home",
            "--redirect-target", "/go?u=", "--json"])
        self.assertIn("무시", err)

    def test_pathupload_warns(self):
        err = self._run_capture_stderr(attack_pathupload, [
            "http://localhost:7171", "--auth-mode", "cookie", "--token-a", "TOK",
            "--user-a-id", "u", "--user-a-pw", "p", "--success-path", "/home",
            "--traversal-target", "/download?filePath=", "--json"])
        self.assertIn("무시", err)

    def test_access_warns(self):
        scan = {"candidates": []}
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(scan, fh)
        self.addCleanup(os.remove, path)
        err = self._run_capture_stderr(attack_access, [
            "http://localhost:7171", "--auth-mode", "cookie", "--token-a", "TOK",
            "--user-a-id", "u", "--user-a-pw", "p", "--success-path", "/home",
            "--scan", path, "--json"])
        self.assertIn("무시", err)

    def test_auth_warns(self):
        err = self._run_capture_stderr(attack_auth, [
            "http://localhost:7171", "--auth-mode", "cookie", "--token-a", "TOK",
            "--user-a-id", "u", "--user-a-pw", "p", "--success-path", "/home",
            "--probe", "/api/v1/users/me", "--json"])
        self.assertIn("무시", err)


if __name__ == "__main__":
    unittest.main()
