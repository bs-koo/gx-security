"""scan_ssrf 폴백 회귀 (F3 FR-7).

기존 변수명 고정형(restTemplate.) ssrf-resttemplate 룰을 임의 변수명 일반화 룰로
대체했음을 고정한다:
  · 변수명이 restTemplate 이 아니어도(httpClient 등) RestTemplate 컨텍스트가 있으면 후보화
  · RestTemplate 선언이 없는 파일은 미검출(광범위 오탐 억제, 컨텍스트 게이트)
  · execute 는 정규식에서 제외 → RestTemplate 있는 파일의 jdbcTemplate.execute 도 미검출
"""
import importlib.util
import os
import tempfile
import unittest

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_MOD = os.path.join(_ROOT, "skills", "detecting-ssrf-and-open-redirect",
                    "scripts", "scan_ssrf.py")
_spec = importlib.util.spec_from_file_location("scan_ssrf", _MOD)
scan_ssrf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scan_ssrf)


class TestSsrfRestTemplateVarCall(unittest.TestCase):
    def _rule_ids(self, filename, body):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, filename), "w", encoding="utf-8") as fh:
                fh.write(body)
            findings = scan_ssrf.run_fallback(d)
        return {c["rule_id"] for c in findings}

    def test_arbitrary_var_name_flagged(self):
        # 변수명이 restTemplate 이 아니어도 RestTemplate 컨텍스트가 있으면 잡힘
        rules = self._rule_ids(
            "Client.java",
            "class Client {\n"
            "  private RestTemplate httpClient;\n"
            "  void a(String url) {\n"
            "    httpClient.getForObject(url, String.class);\n"
            "  }\n"
            "}\n")
        self.assertIn("ssrf-resttemplate", rules)

    def test_no_resttemplate_context_safe(self):
        # RestTemplate 선언·HTTP 없음 → 컨텍스트 게이트로 미검출(==0)
        rules = self._rule_ids(
            "Calc.java",
            "class Calc { public void calc() { int a = 1 + 2; } }\n")
        self.assertNotIn("ssrf-resttemplate", rules)

    def test_execute_excluded_even_with_resttemplate_context(self):
        # RestTemplate 필드가 있는 파일이라도 execute 는 정규식 제외 → 미검출(jdbc 충돌 차단)
        rules = self._rule_ids(
            "Mixed.java",
            "class Mixed {\n"
            "  private RestTemplate rt;\n"
            "  void a() {\n"
            '    jdbcTemplate.execute("UPDATE t SET x=1");\n'
            "  }\n"
            "}\n")
        self.assertNotIn("ssrf-resttemplate", rules)


if __name__ == "__main__":
    unittest.main()
