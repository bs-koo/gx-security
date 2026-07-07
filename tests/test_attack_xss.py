import importlib.util
import io
import os
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_MOD = os.path.join(_ROOT, "skills", "exploiting-xss-vulnerabilities",
                    "scripts", "attack_xss.py")
_spec = importlib.util.spec_from_file_location("attack_xss", _MOD)
attack_xss = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(attack_xss)


class TestNoRedirectOpener(unittest.TestCase):
    """FR-4 — _OPENER는 3xx를 추종하지 않고 원응답(code/body)을 포착한다(PRG 미탐 방지)."""

    def test_redirect_request_returns_none(self):
        h = attack_xss._NoRedirect()
        self.assertIsNone(
            h.redirect_request(MagicMock(), MagicMock(), 302, "Found", {}, "http://x/"))

    def test_opener_has_noredirect_handler(self):
        self.assertTrue(any(isinstance(h, attack_xss._NoRedirect)
                            for h in attack_xss._OPENER.handlers))

    @patch.object(attack_xss._OPENER, "open")
    def test_302_not_followed_original_captured(self, mock_open):
        # 302 응답 → 추종 안 함 → urllib이 HTTPError를 올리고 except가 원응답 code/body 포착.
        marker = "sqixssaaaaaaaa"
        body = f"<html>original 302 body {marker}</html>"
        mock_open.side_effect = urllib.error.HTTPError(
            "http://app.local/search", 302, "Found", {}, io.BytesIO(body.encode()))
        _ctx, status, resp_body = attack_xss.check_reflection(
            "http://app.local/search", "q", "get", {},
            "<script>x</script>", marker)
        self.assertEqual(status, 302)          # 리다이렉트 원응답 코드 포착(추종 안 함)
        self.assertIn(marker, resp_body)       # 리다이렉트 목적지가 아닌 원응답 본문

    @patch.object(attack_xss._OPENER, "open")
    def test_uses_opener_not_direct_urlopen(self, mock_open):
        # check_reflection이 전역 _OPENER.open을 호출 경로로 쓰는지 확인(정의만 하고 미사용 방지).
        mock_open.return_value.__enter__.return_value = MagicMock(
            status=200, read=lambda: b"<html>sqixssbbbbbbbb</html>")
        attack_xss.check_reflection(
            "http://app.local/search", "q", "get", {}, "<b>x</b>", "sqixssbbbbbbbb")
        self.assertTrue(mock_open.called)


if __name__ == "__main__":
    unittest.main()
