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

    def test_ignores_non_c_paths(self):
        # /c/ 외 경로(favicon 등)는 nonce로 기록하지 않는다(위조 hit 방지, 리뷰 반영)
        lis = oob_canary.CanaryListener()
        lis.start()
        try:
            base = f"http://127.0.0.1:{lis.port}"
            urllib.request.urlopen(base + "/favicon.ico", timeout=2).read()
            urllib.request.urlopen(base + "/random/path", timeout=2).read()
            self.assertFalse(lis.received("favicon.ico", timeout=0.1))
            self.assertFalse(lis.received("path", timeout=0.1))
        finally:
            lis.stop()

    def test_port_raises_before_start(self):
        # start() 전 url_for/port는 :0 같은 잘못된 값 대신 에러(리뷰 반영)
        with self.assertRaises(RuntimeError):
            oob_canary.CanaryListener().url_for("x")


if __name__ == "__main__":
    unittest.main()
