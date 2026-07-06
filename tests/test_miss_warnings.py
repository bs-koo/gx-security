"""M9-A (FR-6, D4): 미탐 경고(build_warnings) 회귀 가드 (AC-7/8).

각 스캐너에 인라인 복붙된 build_warnings 가 두 경고를 올바르게 방출하는지 9스캐너 subTest 로 검증한다.
  - AC-7 스택 경고: detected_stacks == ["unknown"] 일 때. 엔진과 무관(폴백/semgrep 양쪽).
  - AC-8 폴백 경고: candidate_count == 0 이며 engine == grep-fallback 일 때. semgrep job 에선
    engine==semgrep 이라 폴백 경고가 나오지 않는 게 정상 → semgrep 설치 시 skip.
JSON 결과의 warnings 키(비어있지 않을 때만 존재)와 문구를 검증한다.
"""
import json
import os
import shutil
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

_STACK_WARNING = "프로젝트 구조를 인식하지 못했습니다"
_FALLBACK_WARNING = "정규식 폴백 엔진은 재현율이 낮습니다"

# 내용은 파싱하지 않으므로 최소 pom 이면 spring-modern 스택 신호가 된다.
_POM = "<project><modelVersion>4.0.0</modelVersion></project>\n"


def _scan_abs(target, scanner_rel):
    scanner = os.path.join(_ROOT, scanner_rel)
    proc = subprocess.run(
        [sys.executable, scanner, target, "--json"],
        capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=120,
    )
    return json.loads(proc.stdout)


class TestUnknownStackWarning(unittest.TestCase):
    """AC-7: 스택 신호가 없는 트리는 unknown → 스택 경고(엔진 무관)."""

    def test_unknown_stack_warns(self):
        for key, rel in SCANNERS.items():
            with self.subTest(scanner=key):
                with tempfile.TemporaryDirectory(prefix="gxsec_warn_") as d:
                    # 스택 신호가 아니고 후보도 만들지 않는 무해 파일
                    with open(os.path.join(d, "notes.txt"), "w", encoding="utf-8") as f:
                        f.write("hello world\n")
                    r = _scan_abs(d, rel)
                    self.assertEqual(r["detected_stacks"], ["unknown"],
                                     f"{key}: 스택 신호가 없으면 unknown")
                    warnings = r.get("warnings", [])
                    self.assertTrue(
                        any(_STACK_WARNING in w for w in warnings),
                        f"{key}: unknown 스택이면 스택 미탐 경고가 있어야 한다 (warnings={warnings})")


@unittest.skipIf(shutil.which("semgrep"),
                 "semgrep 설치 시 engine==semgrep 이라 폴백 경고 미발생(정상) → 스킵")
class TestFallbackWarning(unittest.TestCase):
    """AC-8: 폴백 엔진 + 0건 → 폴백 경고. pom.xml 로 스택은 known(spring-modern)이라
    스택 경고 없이 폴백 경고만 나오는 것을 확인한다."""

    def test_fallback_zero_warns(self):
        for key, rel in SCANNERS.items():
            with self.subTest(scanner=key):
                with tempfile.TemporaryDirectory(prefix="gxsec_warn_") as d:
                    with open(os.path.join(d, "pom.xml"), "w", encoding="utf-8") as f:
                        f.write(_POM)
                    r = _scan_abs(d, rel)
                    self.assertEqual(r["engine"], "grep-fallback",
                                     f"{key}: semgrep 미설치 시 grep-fallback")
                    self.assertEqual(r["candidate_count"], 0,
                                     f"{key}: 최소 pom 만 있으면 후보 0")
                    warnings = r.get("warnings", [])
                    self.assertTrue(
                        any(_FALLBACK_WARNING in w for w in warnings),
                        f"{key}: 폴백+0건이면 폴백 미탐 경고가 있어야 한다 (warnings={warnings})")
                    self.assertFalse(
                        any(_STACK_WARNING in w for w in warnings),
                        f"{key}: 스택 known(spring-modern)이면 스택 경고는 없어야 한다")


if __name__ == "__main__":
    unittest.main()
