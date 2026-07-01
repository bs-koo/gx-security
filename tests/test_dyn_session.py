# tests/test_dyn_session.py
import inspect
import unittest
from tools import dyn_session
from unittest.mock import patch, MagicMock


class TestHelpers(unittest.TestCase):
    def test_mask_token_short(self):
        self.assertEqual(dyn_session.mask_token("abc"), "****")

    def test_mask_token_long(self):
        self.assertEqual(dyn_session.mask_token("abcdefghijkl"), "abcd…ijkl")

    def test_mask_token_none(self):
        self.assertEqual(dyn_session.mask_token(None), "<none>")

    def test_mask_token_nonstring(self):
        # JSON int 토큰이 와도 크래시하지 않는다 (M2 회귀)
        self.assertEqual(dyn_session.mask_token(12345678901234), "1234…1234")

    def test_extract_by_path_nested(self):
        obj = {"data": {"accessToken": "TKN"}}
        self.assertEqual(dyn_session.extract_by_path(obj, "data.accessToken"), "TKN")

    def test_extract_by_path_missing(self):
        self.assertIsNone(dyn_session.extract_by_path({"data": {}}, "data.accessToken"))

    def test_reexports_scope(self):
        self.assertTrue(hasattr(dyn_session, "assert_in_scope"))
        self.assertTrue(hasattr(dyn_session, "ScopeError"))


class TestLogin(unittest.TestCase):
    @patch("requests.post")
    def test_login_extracts_token_preset(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=200, json=lambda: {"data": {"accessToken": "TKN123"}})
        tok = dyn_session.login(
            "http://localhost:7171", "/api/v1/auth/login", {"id": "a", "pw": "b"})
        self.assertEqual(tok, "TKN123")
        # 프리셋 바디 확인
        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["json"], {"lgnId": "a", "password": "b"})

    @patch("requests.post")
    def test_login_rejects_4xx(self, mock_post):
        mock_post.return_value = MagicMock(status_code=401, json=lambda: {})
        with self.assertRaises(RuntimeError):
            dyn_session.login("http://localhost:7171", "/login", {"id": "a", "pw": "b"})

    @patch("requests.post")
    def test_login_rejects_3xx(self, mock_post):
        # 3xx 리다이렉트(세션 로그인 페이지 등)는 2xx 아님 → 조기 거부(리뷰 반영)
        mock_post.return_value = MagicMock(status_code=302, json=lambda: {})
        with self.assertRaises(RuntimeError):
            dyn_session.login("http://localhost:7171", "/login", {"id": "a", "pw": "b"})

    @patch("requests.post")
    def test_login_token_path_miss_raises(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200, json=lambda: {"data": {}})
        with self.assertRaises(RuntimeError):
            dyn_session.login("http://localhost:7171", "/login", {"id": "a", "pw": "b"})

    @patch("requests.post")
    def test_login_body_template_no_keyerror(self, mock_post):
        # JSON 중괄호가 있는 body-template이 KeyError 없이 동작 (H1 회귀)
        mock_post.return_value = MagicMock(status_code=200, json=lambda: {"tok": "X"})
        tok = dyn_session.login(
            "http://h", "/login", {"id": "a", "pw": "b"},
            body_template='{"u":"{id}","p":"{pw}"}', token_json_path="tok")
        self.assertEqual(tok, "X")
        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["json"], {"u": "a", "p": "b"})


class TestLoginResponseContract(unittest.TestCase):
    """blocker 재발 방지 — attack_auth.py:200이 의존하는 login_response 계약을 CI에서 즉시 노출.

    부재/시그니처 어긋남 시 계정 발사 경로에서 AttributeError/TypeError로 터지므로
    존재와 파라미터명을 유닛으로 고정한다(design-critic blocker 어서션).
    """

    def test_login_response_exists(self):
        self.assertTrue(hasattr(dyn_session, "login_response"))

    def test_login_response_signature(self):
        params = inspect.signature(dyn_session.login_response).parameters
        for name in ("base_url", "login_path", "cred", "body_template",
                     "token_json_path", "timeout"):
            self.assertIn(name, params)


class TestRequest(unittest.TestCase):
    @patch("requests.request")
    def test_request_adds_bearer(self, mock_req):
        mock_req.return_value = MagicMock(status_code=200, text="ok")
        out = dyn_session.request("GET", "http://localhost:7171/adm/v1/users", token="TKN")
        self.assertEqual(out["status"], 200)
        self.assertEqual(out["body"], "ok")
        _, kwargs = mock_req.call_args
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer TKN")
        self.assertFalse(kwargs["allow_redirects"])

    @patch("requests.request")
    def test_request_no_token_no_header(self, mock_req):
        mock_req.return_value = MagicMock(status_code=403, text="")
        out = dyn_session.request("GET", "http://localhost:7171/x")
        self.assertEqual(out["status"], 403)
        _, kwargs = mock_req.call_args
        self.assertNotIn("Authorization", kwargs["headers"])


if __name__ == "__main__":
    unittest.main()
