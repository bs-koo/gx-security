"""스캐너 골든셋 — recall/precision 회귀 가드.

취약 픽스처는 후보로 잡고, 안전 픽스처는 안 잡는지 candidate_count로 검증한다.
이 픽스처는 grep-fallback·semgrep 두 엔진 모두 동일 판정(vuln>=1, safe==0)이라
엔진 설치 여부와 무관하게 결정론적이다. SQLi부터 시작하며, 이후 CSRF·XSS 등 6종으로 확장한다.

[U1-Important] 픽스처 명명 규약(6종 확장 시 준수):
  MyBatis XML 픽스처는 파일명에 'Mapper' 포함(또는 mybatis/sqlmap 경로 하위)이어야
  scan_sqli의 _is_mybatis_xml() 폴백 필터를 통과한다. 일반 이름(Board.xml·queries.xml 등)은
  스캔에서 skip되어, recall 테스트가 가짜로 실패(취약인데 미검출)하거나 safe 테스트가 가짜로
  통과(파일이 안 읽혔는데 0)할 수 있다. safe는 아래 혼합 디렉토리 테스트로 위양성 통과를 배제한다.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_SCANNER = "skills/detecting-sql-injection/scripts/scan_sqli.py"
_VULN = "<mapper><select id=\"x\">SELECT * FROM t WHERE a = '${p}'</select></mapper>"
_SAFE = "<mapper><select id=\"y\">SELECT * FROM t WHERE b = #{q}</select></mapper>"


def _scan(scanner_rel, target_rel):
    return _scan_abs(os.path.join(_ROOT, target_rel), scanner_rel)


def _scan_abs(target, scanner_rel=_SCANNER):
    scanner = os.path.join(_ROOT, scanner_rel)
    proc = subprocess.run(
        [sys.executable, scanner, target, "--json"],
        capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=120,
    )
    return json.loads(proc.stdout)


class TestSqliGoldenset(unittest.TestCase):
    SCANNER = _SCANNER

    def test_vuln_dollar_is_flagged(self):
        r = _scan(self.SCANNER, "tests/fixtures/vuln")
        self.assertGreaterEqual(r["candidate_count"], 1,
                                "취약형 MyBatis ${} 가 후보로 잡혀야 한다")

    def test_safe_hash_not_flagged(self):
        r = _scan(self.SCANNER, "tests/fixtures/safe")
        self.assertEqual(r["candidate_count"], 0,
                         "안전형 MyBatis #{} 는 후보로 잡히면 안 된다")

    def test_safe_not_flagged_when_scanned_with_vuln(self):
        """[U1-Important] 혼합 디렉토리(${}+#{})를 스캔해 파일이 실제로 읽혔음을 증명하며 #{}가
        미검출임을 확인한다. safe 픽스처가 skip돼도 0이라 '잘못된 이유로 통과'하는 위양성을 배제."""
        tmp = tempfile.mkdtemp(prefix="gxsec_gold_")
        try:
            with open(os.path.join(tmp, "VulnMapper.xml"), "w", encoding="utf-8") as f:
                f.write(_VULN)
            with open(os.path.join(tmp, "SafeMapper.xml"), "w", encoding="utf-8") as f:
                f.write(_SAFE)
            r = _scan_abs(tmp)
            self.assertGreaterEqual(r["candidate_count"], 1,
                                    "디렉토리가 실제 스캔됨(${} 검출)")
            flagged = " ".join(c.get("file", "") for c in r.get("candidates", []))
            self.assertNotIn("SafeMapper", flagged,
                             "#{} 안전형은 (파일이 읽혔음에도) 검출되면 안 된다")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
