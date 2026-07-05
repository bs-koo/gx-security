"""scan_auth 폴백 회귀 (코드리뷰 M1).

parseClaimsJws(서명키 설정 시 서명을 검증하는 안전 호출)를 no-verify 취약으로
뒤집어 판정하던 방향성 오탐을 제거했음을 고정한다. 미검증은 parseClaimsJwt/parse( 만.
"""
import importlib.util
import os
import tempfile
import unittest

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_spec = importlib.util.spec_from_file_location(
    "scan_auth", os.path.join(_ROOT, "skills", "detecting-auth-session-weaknesses",
                              "scripts", "scan_auth.py"))
scan_auth = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scan_auth)


class TestJwtParseNoVerify(unittest.TestCase):
    def _rule_ids(self, filename, body):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, filename), "w", encoding="utf-8") as fh:
                fh.write(body)
            findings = scan_auth.run_fallback(d)
        return {c["rule_id"] for c in findings}

    def test_parse_claims_jws_not_flagged(self):
        # 서명키 설정 후 parseClaimsJws = 서명 검증(안전) → no-verify 아님
        rules = self._rule_ids(
            "Safe.java",
            "class Safe { void a(){ Jwts.parser().setSigningKey(k).parseClaimsJws(tok); } }\n")
        self.assertNotIn("spring-jwt-parse-no-verify", rules)

    def test_parse_claims_jwt_is_flagged(self):
        # parseClaimsJwt(서명 없는 파싱) = 취약 후보 유지
        rules = self._rule_ids(
            "Unsafe.java",
            "class Unsafe { void a(){ Jwts.parser().parseClaimsJwt(tok); } }\n")
        self.assertIn("spring-jwt-parse-no-verify", rules)


if __name__ == "__main__":
    unittest.main()
