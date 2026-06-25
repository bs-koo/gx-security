import importlib.util
import os
import unittest
import urllib.request

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_MOD = os.path.join(_ROOT, "skills", "exploiting-ssrf-and-open-redirect",
                    "scripts", "oob_canary.py")
_spec = importlib.util.spec_from_file_location("oob_canary", _MOD)
oob_canary = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(oob_canary)


class TestCanaryListener(unittest.TestCase):
    def test_roundtrip_callback_detected(self):
        lis = oob_canary.CanaryListener()
        lis.start()
        try:
            self.assertGreater(lis.port, 0)
            url = lis.url_for("nonceABC")
            self.assertIn("/c/nonceABC", url)
            urllib.request.urlopen(url, timeout=2).read()
            self.assertTrue(lis.received("nonceABC", timeout=2))
            self.assertFalse(lis.received("never", timeout=0.1))
        finally:
            lis.stop()


if __name__ == "__main__":
    unittest.main()
