# tests/test_dyn_session_form.py
import unittest
from tools import dyn_session
from unittest.mock import patch, MagicMock


def _resp(status, headers=None):
    """form_login 판정용 mock 응답(status_code + headers)."""
    m = MagicMock()
    m.status_code = status
    m.headers = headers or {}
    return m


class TestLocationMatches(unittest.TestCase):
    def test_absolute_url(self):
        self.assertTrue(dyn_session._location_matches("http://h/home", "/home"))

    def test_relative_path(self):
        self.assertTrue(dyn_session._location_matches("/home", "/home"))

    def test_scheme_relative(self):
        # //host/home 의 path 는 /home
        self.assertTrue(dyn_session._location_matches("//host/home", "/home"))

    def test_trailing_slash_normalized(self):
        self.assertTrue(dyn_session._location_matches("/home/", "/home"))
        self.assertTrue(dyn_session._location_matches("/home", "/home/"))

    def test_root_path(self):
        self.assertTrue(dyn_session._location_matches("/", "/"))

    def test_success_path_full_url(self):
        # success_path 가 전체 URL 이어도 path 비교
        self.assertTrue(dyn_session._location_matches("/home", "http://h/home/"))

    def test_mismatch(self):
        self.assertFalse(dyn_session._location_matches("/login", "/home"))

    def test_falsy_location(self):
        self.assertFalse(dyn_session._location_matches("", "/home"))

    def test_falsy_success_path(self):
        self.assertFalse(dyn_session._location_matches("/home", ""))


class TestFormLoginTransport(unittest.TestCase):
    def test_form_urlencoded_default_fields(self):
        mock = MagicMock()
        mock.post.return_value = _resp(302, {"Location": "/home"})
        dyn_session.form_login(
            "http://h", "/login", {"id": "u", "pw": "p"},
            success_path="/home", session=mock)
        kwargs = mock.post.call_args.kwargs
        self.assertEqual(kwargs["data"], {"username": "u", "password": "p"})
        self.assertIs(kwargs["allow_redirects"], False)

    def test_form_custom_fields(self):
        mock = MagicMock()
        mock.post.return_value = _resp(302, {"Location": "/home"})
        dyn_session.form_login(
            "http://h", "/login", {"id": "u", "pw": "p"},
            id_field="j_username", pw_field="j_password",
            success_path="/home", session=mock)
        kwargs = mock.post.call_args.kwargs
        self.assertEqual(kwargs["data"], {"j_username": "u", "j_password": "p"})

    def test_url_built_from_base_and_path(self):
        mock = MagicMock()
        mock.post.return_value = _resp(302, {"Location": "/home"})
        dyn_session.form_login(
            "http://h/", "/login", {"id": "u", "pw": "p"},
            success_path="/home", session=mock)
        args, _ = mock.post.call_args
        self.assertEqual(args[0], "http://h/login")


class TestFormLoginVerdict(unittest.TestCase):
    def _login(self, resp, **kw):
        mock = MagicMock()
        mock.post.return_value = resp
        return dyn_session.form_login(
            "http://h", "/login", {"id": "u", "pw": "p"},
            session=mock, **kw)

    def test_success_302_match_returns_session(self):
        mock = MagicMock()
        mock.post.return_value = _resp(
            302, {"Location": "/home", "Set-Cookie": "SID=abc; HttpOnly"})
        out = dyn_session.form_login(
            "http://h", "/login", {"id": "u", "pw": "p"},
            success_path="/home", session=mock)
        self.assertIs(out["session"], mock)
        self.assertEqual(out["set_cookie"], "SID=abc; HttpOnly")
        self.assertEqual(out["status"], 302)
        self.assertEqual(out["location"], "/home")

    def test_missing_success_path_raises(self):
        with self.assertRaises(RuntimeError) as ctx:
            self._login(_resp(302, {"Location": "/home"}))
        self.assertIn("success-path", str(ctx.exception))

    def test_302_mismatch_raises_credential(self):
        with self.assertRaises(RuntimeError) as ctx:
            self._login(_resp(302, {"Location": "/login?error"}),
                        success_path="/home")
        self.assertIn("자격 추정", str(ctx.exception))

    def test_3xx_no_location_raises_format(self):
        with self.assertRaises(RuntimeError) as ctx:
            self._login(_resp(302, {}), success_path="/home")
        self.assertIn("Location 없음", str(ctx.exception))

    def test_2xx_raises_format_field(self):
        with self.assertRaises(RuntimeError) as ctx:
            self._login(_resp(200, {}), success_path="/home")
        self.assertIn("형식/필드", str(ctx.exception))

    def test_4xx_raises_rejected(self):
        with self.assertRaises(RuntimeError) as ctx:
            self._login(_resp(401, {}), success_path="/home")
        self.assertIn("요청 거부", str(ctx.exception))

    def test_5xx_raises_rejected(self):
        with self.assertRaises(RuntimeError) as ctx:
            self._login(_resp(500, {}), success_path="/home")
        self.assertIn("요청 거부", str(ctx.exception))

    def test_request_exception_raises(self):
        mock = MagicMock()
        mock.post.side_effect = ValueError("boom")
        with self.assertRaises(RuntimeError) as ctx:
            dyn_session.form_login(
                "http://h", "/login", {"id": "u", "pw": "p"},
                success_path="/home", session=mock)
        self.assertIn("로그인 요청 실패", str(ctx.exception))


class TestRequestSession(unittest.TestCase):
    def test_request_uses_session_when_provided(self):
        # 세션 주입 시 session.request 로 발사(쿠키 jar 재사용) + token 미전달이라 Authorization 없음
        mock_session = MagicMock()
        mock_session.request.return_value = MagicMock(
            status_code=200, text="ok", headers={})
        out = dyn_session.request("GET", "http://h/x", session=mock_session)
        self.assertEqual(out["status"], 200)
        mock_session.request.assert_called_once()
        _, kwargs = mock_session.request.call_args
        self.assertNotIn("Authorization", kwargs["headers"])
        self.assertFalse(kwargs["allow_redirects"])

    @patch("requests.request")
    def test_request_no_session_hits_requests_with_bearer(self, mock_req):
        # 하위호환: session 미전달 → requests.request 적중 + token 있으면 Bearer 부착
        mock_req.return_value = MagicMock(status_code=200, text="ok", headers={})
        out = dyn_session.request("GET", "http://h/x", token="TKN")
        self.assertEqual(out["status"], 200)
        mock_req.assert_called_once()
        _, kwargs = mock_req.call_args
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer TKN")


if __name__ == "__main__":
    unittest.main()
