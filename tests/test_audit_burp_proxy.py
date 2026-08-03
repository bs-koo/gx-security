import os
import sys
import importlib
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..",
                                "skills", "auditing-web-application-security", "scripts"))
audit = importlib.import_module("audit")


class TestApplyBurpProxy(unittest.TestCase):
    def setUp(self):
        os.environ.pop("SECURITY_PLUGIN_BURP_PROXY", None)

    def tearDown(self):
        os.environ.pop("SECURITY_PLUGIN_BURP_PROXY", None)

    def test_none_disabled_no_env(self):
        out = audit._apply_burp_proxy(None)
        self.assertFalse(out["enabled"])
        self.assertNotIn("SECURITY_PLUGIN_BURP_PROXY", os.environ)

    def test_proxy_up_sets_env(self):
        out = audit._apply_burp_proxy("http://127.0.0.1:8080", probe=lambda h, p: True)
        self.assertTrue(out["enabled"])
        self.assertEqual(os.environ["SECURITY_PLUGIN_BURP_PROXY"], "http://127.0.0.1:8080")

    def test_proxy_down_no_env_fallback(self):
        out = audit._apply_burp_proxy("http://127.0.0.1:8080", probe=lambda h, p: False)
        self.assertFalse(out["enabled"])
        self.assertNotIn("SECURITY_PLUGIN_BURP_PROXY", os.environ)

    def test_strict_down_aborts(self):
        # 엣지 C: strict + 미가동 → strict_abort True, env 미설정(발사 중단 신호)
        out = audit._apply_burp_proxy("http://127.0.0.1:8080", strict=True, probe=lambda h, p: False)
        self.assertTrue(out["strict_abort"])
        self.assertNotIn("SECURITY_PLUGIN_BURP_PROXY", os.environ)

    def test_strict_up_no_abort(self):
        out = audit._apply_burp_proxy("http://127.0.0.1:8080", strict=True, probe=lambda h, p: True)
        self.assertFalse(out["strict_abort"])
        self.assertTrue(out["enabled"])


if __name__ == "__main__":
    unittest.main()
