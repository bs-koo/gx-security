import importlib.util
import os
import unittest
from unittest.mock import MagicMock, patch

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_MOD = os.path.join(_ROOT, "skills", "exploiting-sql-injection",
                    "scripts", "attack_sqli.py")
_spec = importlib.util.spec_from_file_location("attack_sqli", _MOD)
attack_sqli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(attack_sqli)


class TestSqlmapVerdict(unittest.TestCase):
    """sqlmap 출력 판정 — [CRITICAL] 로그레벨 오탐 제거(Task 1.1)."""

    def test_critical_not_injectable_is_safe(self):
        # [CRITICAL]은 '미주입'에도 찍히는 로그레벨 → 취약으로 오판하면 안 된다.
        out = "[CRITICAL] all tested parameters do not appear to be injectable"
        self.assertFalse(attack_sqli._classify_sqlmap(out))

    def test_unable_to_connect_is_safe(self):
        out = "unable to connect to the target url"
        self.assertFalse(attack_sqli._classify_sqlmap(out))

    def test_identified_injection_point_is_vulnerable(self):
        out = "sqlmap identified the following injection point"
        self.assertTrue(attack_sqli._classify_sqlmap(out))

    def test_backend_dbms_is_vulnerable(self):
        # 대소문자 무관 판정(입력은 대문자 DBMS)
        out = "the back-end DBMS is PostgreSQL"
        self.assertTrue(attack_sqli._classify_sqlmap(out))


class TestSendNoRedirect(unittest.TestCase):
    """FR-4 — _send는 리다이렉트를 추종하지 않고 원응답으로 판정한다(추종 시 미탐 방지)."""

    @patch("requests.get")
    def test_get_no_follow_redirect(self, mock_get):
        mock_get.return_value = MagicMock(status_code=200, text="", content=b"")
        attack_sqli._send("http://app.local/board?id=1", "id", "1' OR '1'='1", "get", {})
        _, kwargs = mock_get.call_args
        self.assertFalse(kwargs["allow_redirects"])

    @patch("requests.post")
    def test_post_no_follow_redirect(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200, text="", content=b"")
        attack_sqli._send("http://app.local/login", "username", "admin'--",
                          "post", {"password": "x"})
        _, kwargs = mock_post.call_args
        self.assertFalse(kwargs["allow_redirects"])


if __name__ == "__main__":
    unittest.main()
