"""attack_sqli JSON 바디 주입(D4)·인증(D3) 배선 단위 검증.

인증/JSON 경로는 dyn_session.request를 사용한다. 무인증 form 경로도 환경을
상속하지 않는 공통 _client로 발사하며 원응답 인터페이스와 GET/POST 주입은 보존한다.
"""
import importlib.util
import os
import unittest
from unittest.mock import MagicMock, patch

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_MOD = os.path.join(_ROOT, "skills", "exploiting-sql-injection",
                    "scripts", "attack_sqli.py")
_spec = importlib.util.spec_from_file_location("attack_sqli", _MOD)
attack_sqli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(attack_sqli)


class TestSendJsonMode(unittest.TestCase):
    """content_type='json'이면 dyn_session.request가 json_body로 발사된다(D4)."""

    @patch("tools.dyn_session.request")
    def test_json_body_defaults_inject_path_to_param(self, mock_req):
        mock_req.return_value = {"status": 200, "body": "{}", "headers": {}, "elapsed": 0.01}
        attack_sqli._send("http://localhost/api/search", "q", "1' OR '1'='1",
                          "post", None, content_type="json")
        _, kwargs = mock_req.call_args
        self.assertEqual(kwargs["json_body"], {"q": "1' OR '1'='1"})

    @patch("tools.dyn_session.request")
    def test_json_body_uses_explicit_inject_path(self, mock_req):
        mock_req.return_value = {"status": 200, "body": "{}", "headers": {}, "elapsed": 0.01}
        attack_sqli._send("http://localhost/api/search", "q", "X",
                          "post", None, content_type="json", inject_path="data.query")
        _, kwargs = mock_req.call_args
        self.assertEqual(kwargs["json_body"], {"data": {"query": "X"}})

    @patch("tools.dyn_session.request")
    def test_json_mode_dispatches_to_dyn_session_request(self, mock_req):
        mock_req.return_value = {"status": 200, "body": "{}", "headers": {}, "elapsed": 0.01}
        result = attack_sqli._send("http://localhost/api/search", "q", "X",
                                   "post", None, content_type="json")
        mock_req.assert_called_once()
        self.assertIsNotNone(result)


class TestSendAuthMode(unittest.TestCase):
    """token/session이 주어지면 dyn_session.request로 발사되고 인증이 전달된다(D3)."""

    @patch("tools.dyn_session.request")
    def test_token_forwarded_to_dyn_session(self, mock_req):
        mock_req.return_value = {"status": 200, "body": "", "headers": {}, "elapsed": 0.01}
        attack_sqli._send("http://localhost/board", "id", "1' OR '1'='1",
                          "get", None, token="T")
        _, kwargs = mock_req.call_args
        self.assertEqual(kwargs["token"], "T")

    @patch("tools.dyn_session.request")
    def test_session_forwarded_to_dyn_session(self, mock_req):
        mock_req.return_value = {"status": 200, "body": "", "headers": {}, "elapsed": 0.01}
        fake_session = object()
        attack_sqli._send("http://localhost/board", "id", "1",
                          "get", None, session=fake_session)
        _, kwargs = mock_req.call_args
        self.assertIs(kwargs["session"], fake_session)

    @patch("tools.dyn_session.request")
    def test_auth_mode_get_still_injects_query_string(self, mock_req):
        # 인증만 붙고 form(기본)이면 기존처럼 쿼리스트링에 파라미터를 주입해야 한다.
        mock_req.return_value = {"status": 200, "body": "", "headers": {}, "elapsed": 0.01}
        attack_sqli._send("http://localhost/board?id=1", "id", "1' OR '1'='1",
                          "get", None, token="T")
        args, _ = mock_req.call_args
        method, url = args[0], args[1]
        self.assertEqual(method, "get")
        self.assertIn("id=1%27+OR+%271%27%3D%271", url)


class TestSendIsolatedRawResponse(unittest.TestCase):
    """Raw-response compatibility must pass through the isolated session, not global requests."""

    @patch("tools.dyn_session.request")
    @patch("requests.Session.request")
    def test_default_form_get_uses_isolated_raw_client(self, mock_get, mock_dyn):
        mock_get.return_value = MagicMock(status_code=200, text="", content=b"")
        attack_sqli._send("http://localhost/board?id=1", "id", "1' OR '1'='1", "get", {})
        mock_dyn.assert_not_called()
        mock_get.assert_called_once()

    @patch("tools.dyn_session.request")
    @patch("requests.Session.request")
    def test_default_form_post_uses_isolated_raw_client(self, mock_post, mock_dyn):
        mock_post.return_value = MagicMock(status_code=200, text="", content=b"")
        attack_sqli._send("http://localhost/login", "username", "admin'--",
                          "post", {"password": "x"})
        mock_dyn.assert_not_called()
        mock_post.assert_called_once()


class TestBuildParserNewArgs(unittest.TestCase):
    """신규 CLI 인자가 파서에 등록되고 기본값이 하위호환을 지킨다."""

    def test_defaults(self):
        p = attack_sqli._build_parser()
        args = p.parse_args(["http://x", "--param", "id"])
        self.assertEqual(args.content_type, "form")
        self.assertIsNone(args.inject_path)
        self.assertIsNone(args.token_a)
        self.assertIsNone(args.auth_mode)

    def test_json_and_auth_args_parsed(self):
        p = attack_sqli._build_parser()
        args = p.parse_args(["http://x", "--param", "q", "--content-type", "json",
                             "--inject-path", "data.query", "--token-a", "T",
                             "--auth-mode", "bearer"])
        self.assertEqual(args.content_type, "json")
        self.assertEqual(args.inject_path, "data.query")
        self.assertEqual(args.token_a, "T")
        self.assertEqual(args.auth_mode, "bearer")

    def test_content_type_rejects_invalid_choice(self):
        p = attack_sqli._build_parser()
        with self.assertRaises(SystemExit):
            p.parse_args(["http://x", "--param", "id", "--content-type", "xml"])


class TestResolveAuth(unittest.TestCase):
    """_resolve_auth — attack_access 패턴 이식(단일 계정 버전)."""

    def test_no_auth_args_returns_none_none(self):
        p = attack_sqli._build_parser()
        args = p.parse_args(["http://x", "--param", "id"])
        attack_sqli._apply_creds_and_profile(args, None)
        token, session = attack_sqli._resolve_auth(args, "http://x")
        self.assertIsNone(token)
        self.assertIsNone(session)

    def test_token_a_bearer_mode_returns_token(self):
        p = attack_sqli._build_parser()
        args = p.parse_args(["http://x", "--param", "id", "--token-a", "T"])
        attack_sqli._apply_creds_and_profile(args, None)
        token, session = attack_sqli._resolve_auth(args, "http://x")
        self.assertEqual(token, "T")
        self.assertIsNone(session)

    @patch("tools.dyn_session.form_login")
    def test_cookie_mode_uses_form_login(self, mock_form_login):
        mock_form_login.return_value = {"session": "SESSOBJ", "set_cookie": "",
                                        "status": 302, "location": "/home"}
        p = attack_sqli._build_parser()
        args = p.parse_args(["http://x", "--param", "id", "--auth-mode", "cookie",
                             "--user-a-id", "u", "--user-a-pw", "p",
                             "--success-path", "/home"])
        attack_sqli._apply_creds_and_profile(args, None)
        token, session = attack_sqli._resolve_auth(args, "http://x")
        self.assertIsNone(token)
        self.assertEqual(session, "SESSOBJ")

    def test_id_without_pw_raises(self):
        p = attack_sqli._build_parser()
        args = p.parse_args(["http://x", "--param", "id", "--user-a-id", "u"])
        attack_sqli._apply_creds_and_profile(args, None)
        with self.assertRaises(RuntimeError):
            attack_sqli._resolve_auth(args, "http://x")


if __name__ == "__main__":
    unittest.main()
