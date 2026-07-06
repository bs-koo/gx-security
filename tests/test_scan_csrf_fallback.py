"""scan_csrf 폴백 회귀 (F3 FR-6).

메서드참조형 CSRF 비활성 http.csrf(AbstractHttpConfigurer::disable) 를 기존
spring-csrf-disabled 룰로 후보화함을 고정한다. 신규 rule_id 는 없다(동일 취약 클래스).
http.csrf(withDefaults()) 는 CSRF를 활성화하므로 미매칭이어야 한다(방향성 오탐 차단).
"""
import importlib.util
import os
import tempfile
import unittest

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_MOD = os.path.join(_ROOT, "skills", "detecting-csrf-vulnerabilities",
                    "scripts", "scan_csrf.py")
_spec = importlib.util.spec_from_file_location("scan_csrf", _MOD)
scan_csrf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scan_csrf)


class TestCsrfMethodRefDisable(unittest.TestCase):
    def _rule_ids(self, filename, body):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, filename), "w", encoding="utf-8") as fh:
                fh.write(body)
            findings = scan_csrf.run_fallback(d)
        return {c["rule_id"] for c in findings}

    def test_method_ref_disable_flagged(self):
        # http.csrf(AbstractHttpConfigurer::disable) — 메서드참조 비활성
        rules = self._rule_ids(
            "Sec.java",
            "class Sec { void c(Object http) { http.csrf(AbstractHttpConfigurer::disable); } }\n")
        self.assertIn("spring-csrf-disabled", rules)

    def test_with_defaults_safe(self):
        # http.csrf(withDefaults()) — CSRF 활성화(안전) → 미매칭
        rules = self._rule_ids(
            "Sec.java",
            "class Sec { void c(Object http) { http.csrf(withDefaults()); } }\n")
        self.assertNotIn("spring-csrf-disabled", rules)


if __name__ == "__main__":
    unittest.main()
