# tests/test_dyn_session.py
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
    def test_login_token_path_miss_raises(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200, json=lambda: {"data": {}})
        with self.assertRaises(RuntimeError):
            dyn_session.login("http://localhost:7171", "/login", {"id": "a", "pw": "b"})


if __name__ == "__main__":
    unittest.main()
