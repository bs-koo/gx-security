import unittest
from unittest.mock import patch, MagicMock
from tools import burp_preflight


class TestSplitHostport(unittest.TestCase):
    def test_split_full_url(self):
        self.assertEqual(burp_preflight.split_hostport("http://127.0.0.1:8080"), ("127.0.0.1", 8080))

    def test_split_bare_hostport(self):
        self.assertEqual(burp_preflight.split_hostport("127.0.0.1:8080"), ("127.0.0.1", 8080))

    def test_split_default_port_when_missing(self):
        # 포트 없으면 프록시 기본 8080으로 폴백
        self.assertEqual(burp_preflight.split_hostport("http://127.0.0.1"), ("127.0.0.1", 8080))


class TestProbePort(unittest.TestCase):
    @patch("socket.create_connection")
    def test_probe_open(self, mock_conn):
        mock_conn.return_value = MagicMock()
        self.assertTrue(burp_preflight.probe_port("127.0.0.1", 8080))

    @patch("socket.create_connection", side_effect=OSError("refused"))
    def test_probe_closed(self, _mock):
        self.assertFalse(burp_preflight.probe_port("127.0.0.1", 8080))


class TestCheckAndOnboarding(unittest.TestCase):
    @patch("tools.burp_preflight.probe_port")
    def test_check_reports_both(self, mock_probe):
        mock_probe.side_effect = [True, False]  # proxy up, mcp down
        st = burp_preflight.check()
        self.assertTrue(st["proxy_up"])
        self.assertFalse(st["mcp_up"])

    def test_onboarding_mentions_setup_steps(self):
        txt = burp_preflight.onboarding_text()
        self.assertIn("claude mcp add", txt)
        self.assertIn("Extensions", txt)
        self.assertIn("Intercept", txt)  # 엣지 A: Intercept OFF 경고 포함


if __name__ == "__main__":
    unittest.main()
