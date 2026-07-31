import os
import unittest
from unittest.mock import patch, MagicMock
from tools import dyn_session


class TestBurpProxyResolution(unittest.TestCase):
    def test_no_env_returns_none(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SECURITY_PLUGIN_BURP_PROXY", None)
            self.assertIsNone(dyn_session._burp_proxies())

    def test_env_returns_proxies_dict(self):
        with patch.dict(os.environ, {"SECURITY_PLUGIN_BURP_PROXY": "http://127.0.0.1:8080"}):
            self.assertEqual(
                dyn_session._burp_proxies(),
                {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"})

    def test_blank_env_returns_none(self):
        with patch.dict(os.environ, {"SECURITY_PLUGIN_BURP_PROXY": "   "}):
            self.assertIsNone(dyn_session._burp_proxies())


class TestRequestProxyWiring(unittest.TestCase):
    @patch("requests.request")
    def test_request_no_env_no_proxies_kwarg(self, mock_req):
        # 하위호환: env 없으면 proxies/verify 키를 아예 넘기지 않는다(바이트 불변).
        mock_req.return_value = MagicMock(status_code=200, text="ok", headers={})
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SECURITY_PLUGIN_BURP_PROXY", None)
            dyn_session.request("GET", "http://localhost:7171/x", token="TKN")
        _, kwargs = mock_req.call_args
        self.assertNotIn("proxies", kwargs)
        self.assertNotIn("verify", kwargs)

    @patch("requests.request")
    def test_request_env_sets_proxies_and_verify_false(self, mock_req):
        mock_req.return_value = MagicMock(status_code=200, text="ok", headers={})
        with patch.dict(os.environ, {"SECURITY_PLUGIN_BURP_PROXY": "http://127.0.0.1:8080"}):
            dyn_session.request("GET", "http://localhost:7171/x", token="TKN")
        _, kwargs = mock_req.call_args
        self.assertEqual(kwargs["proxies"], {"http": "http://127.0.0.1:8080",
                                             "https": "http://127.0.0.1:8080"})
        self.assertFalse(kwargs["verify"])


class TestLoginProxyWiring(unittest.TestCase):
    @patch("requests.post")
    def test_login_env_sets_proxies(self, mock_post):
        mock_post.return_value = MagicMock(
            status_code=200, headers={}, json=lambda: {"data": {"accessToken": "T"}})
        with patch.dict(os.environ, {"SECURITY_PLUGIN_BURP_PROXY": "http://127.0.0.1:8080"}):
            dyn_session.login("http://localhost:7171", "/login", {"id": "a", "pw": "b"})
        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["proxies"]["http"], "http://127.0.0.1:8080")
        self.assertFalse(kwargs["verify"])

    @patch("requests.post", side_effect=OSError("proxy refused"))
    def test_login_proxy_error_hint(self, _mock):
        # 엣지 F: 프록시 활성 중 요청 예외를 '자격 실패'로 오진단하지 않도록 Burp 힌트를 남긴다
        with patch.dict(os.environ, {"SECURITY_PLUGIN_BURP_PROXY": "http://127.0.0.1:8080"}):
            with self.assertRaises(RuntimeError) as cm:
                dyn_session.login("http://localhost:7171", "/login", {"id": "a", "pw": "b"})
        self.assertIn("Burp", str(cm.exception))


class TestProxyWarningSuppress(unittest.TestCase):
    @patch("requests.request")
    def test_verify_false_warning_suppressed_once(self, mock_req):
        # 엣지 B: 프록시 활성 시 InsecureRequestWarning 억제가 1회만 호출되는지(로그 오염 방지)
        mock_req.return_value = MagicMock(status_code=200, text="ok", headers={})
        dyn_session._burp_warned = False
        with patch("urllib3.disable_warnings") as mock_dis:
            with patch.dict(os.environ, {"SECURITY_PLUGIN_BURP_PROXY": "http://127.0.0.1:8080"}):
                dyn_session.request("GET", "http://localhost:7171/x")
                dyn_session.request("GET", "http://localhost:7171/y")
        self.assertEqual(mock_dis.call_count, 1)


if __name__ == "__main__":
    unittest.main()
