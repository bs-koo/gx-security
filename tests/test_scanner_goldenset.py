"""스캐너 골든셋 — recall/precision 회귀 가드.

취약 픽스처는 후보로 잡고, 안전 픽스처는 안 잡는지 candidate_count로 검증한다.
이 픽스처는 grep-fallback·semgrep 두 엔진 모두 동일 판정(vuln>=1, safe==0)이라
엔진 설치 여부와 무관하게 결정론적이다. SQLi부터 시작하며, 이후 CSRF·XSS 등 6종으로 확장한다.
"""
import json
import os
import subprocess
import sys
import unittest

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def _scan(scanner_rel, target_rel):
    scanner = os.path.join(_ROOT, scanner_rel)
    target = os.path.join(_ROOT, target_rel)
    proc = subprocess.run(
        [sys.executable, scanner, target, "--json"],
        capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=120,
    )
    return json.loads(proc.stdout)


class TestSqliGoldenset(unittest.TestCase):
    SCANNER = "skills/detecting-sql-injection/scripts/scan_sqli.py"

    def test_vuln_dollar_is_flagged(self):
        r = _scan(self.SCANNER, "tests/fixtures/vuln")
        self.assertGreaterEqual(r["candidate_count"], 1,
                                "취약형 MyBatis ${} 가 후보로 잡혀야 한다")

    def test_safe_hash_not_flagged(self):
        r = _scan(self.SCANNER, "tests/fixtures/safe")
        self.assertEqual(r["candidate_count"], 0,
                         "안전형 MyBatis #{} 는 후보로 잡히면 안 된다")


if __name__ == "__main__":
    unittest.main()
