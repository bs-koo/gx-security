import importlib.util
import os
import unittest

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


if __name__ == "__main__":
    unittest.main()
