"""M7 (FR-5): pom.xml 을 spring-modern 스택 신호로 인식하는지 회귀 가드 (AC-6).

9스캐너 모두 detect_stacks 의 Gradle 신호 튜플에 pom.xml 을 추가했다(BR-4: 내용 미분석 정책 유지).
pom.xml 만 있는 임시 디렉토리를 각 스캐너로 --json 스캔 → detected_stacks 에 spring-modern 포함.
엔진(semgrep/폴백)과 무관하게 detect_stacks 는 파일명 기반이라 결정론적이다.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))

SCANNERS = {
    "sqli": "skills/detecting-sql-injection/scripts/scan_sqli.py",
    "access": "skills/detecting-broken-access-control/scripts/scan_access.py",
    "csrf": "skills/detecting-csrf-vulnerabilities/scripts/scan_csrf.py",
    "xss": "skills/detecting-xss-vulnerabilities/scripts/scan_xss.py",
    "ssrf": "skills/detecting-ssrf-and-open-redirect/scripts/scan_ssrf.py",
    "upload": "skills/detecting-file-upload-vulnerabilities/scripts/scan_upload.py",
    "pathtraversal": "skills/detecting-path-traversal/scripts/scan_pathtraversal.py",
    "auth": "skills/detecting-auth-session-weaknesses/scripts/scan_auth.py",
    "secrets": "skills/detecting-sensitive-data-exposure/scripts/scan_secrets.py",
}

# 내용은 파싱하지 않으므로(BR-4) 최소 pom 이면 충분하다.
_POM = "<project><modelVersion>4.0.0</modelVersion></project>\n"


def _scan_abs(target, scanner_rel):
    scanner = os.path.join(_ROOT, scanner_rel)
    proc = subprocess.run(
        [sys.executable, scanner, target, "--json"],
        capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=120,
    )
    return json.loads(proc.stdout)


class TestPomStackDetection(unittest.TestCase):
    def test_pom_detected_as_spring_modern(self):
        for key, rel in SCANNERS.items():
            with self.subTest(scanner=key):
                with tempfile.TemporaryDirectory(prefix="gxsec_pom_") as d:
                    with open(os.path.join(d, "pom.xml"), "w", encoding="utf-8") as f:
                        f.write(_POM)
                    r = _scan_abs(d, rel)
                    self.assertIn(
                        "spring-modern", r["detected_stacks"],
                        f"{key}: pom.xml 은 spring-modern 스택 신호로 인식되어야 한다")


if __name__ == "__main__":
    unittest.main()
