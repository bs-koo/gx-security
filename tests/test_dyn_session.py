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

    @patch("requests.post")
    def test_login_stringifies_int_token(self, mock_post):
        # 서버가 정수 토큰(JSON number)을 주면 str로 통일 — "Bearer "+token 결합 크래시 방어 (PR 리뷰)
        mock_post.return_value = MagicMock(
            status_code=200, json=lambda: {"data": {"accessToken": 12345}})
        tok = dyn_session.login(
            "http://localhost:7171", "/api/v1/auth/login", {"id": "a", "pw": "b"})
        self.assertEqual(tok, "12345")


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

    @patch("requests.post")
    def test_login_response_stringifies_int_token(self, mock_post):
        # 서버가 정수 토큰을 줘도 token은 str로 통일(다운스트림 split/결합 크래시 방어, PR 리뷰)
        mock_post.return_value = MagicMock(
            status_code=200, headers={},
            json=lambda: {"data": {"accessToken": 12345}})
        out = dyn_session.login_response(
            "http://localhost:7171", "/api/v1/auth/login", {"id": "a", "pw": "b"})
        self.assertEqual(out["token"], "12345")


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

    @patch("requests.request")
    def test_request_passes_files_and_data(self, mock_req):
        # FR-0/AC-1: files=/data=가 실제 HTTP 요청 호출에 그대로 전달돼야 한다(업로드 검사
        # 크래시 방지). 미전달이면 requests가 바디에 싣지 못해 파일업로드 발사가 100% 죽는다.
        mock_req.return_value = MagicMock(status_code=200, text="ok", headers={})
        files = {"file": ("gxmarker.jsp", "GXMARKER-x")}
        out = dyn_session.request("POST", "http://localhost:7171/api/upload",
                                  files=files, data={"k": "v"})
        self.assertEqual(out["status"], 200)
        _, kwargs = mock_req.call_args
        self.assertEqual(kwargs["files"], files)
        self.assertEqual(kwargs["data"], {"k": "v"})

    @patch("requests.request")
    def test_request_defaults_files_data_none(self, mock_req):
        # 하위호환(AC-2): 미전달 시 files/data는 None으로 전달돼 기존 5종 호출 바이트 불변.
        mock_req.return_value = MagicMock(status_code=200, text="ok", headers={})
        dyn_session.request("GET", "http://localhost:7171/x", token="TKN")
        _, kwargs = mock_req.call_args
        self.assertIsNone(kwargs["files"])
        self.assertIsNone(kwargs["data"])

    @patch("requests.request")
    def test_request_returns_response_headers(self, mock_req):
        # CRITICAL 재발 방지(P3): request()는 응답 헤더를 "headers" 키로 반환해야 한다.
        # attack_ssrf.run_open_redirect가 r["headers"]로 Location을 참조하므로, headers
        # 키가 없으면 매 변형 KeyError → 오픈리다이렉트 판정 100% 비작동(Location 외부 미실행).
        mock_req.return_value = MagicMock(
            status_code=302, text="", headers={"Location": "http://x"})
        out = dyn_session.request("GET", "http://localhost:7171/go?u=evil")
        self.assertIn("headers", out)
        self.assertEqual(out["headers"], {"Location": "http://x"})


if __name__ == "__main__":
    unittest.main()
