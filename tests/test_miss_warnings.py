"""M9-A (FR-6, D4): 미탐 경고(build_warnings) 회귀 가드 (AC-7/8).

각 스캐너에 인라인 복붙된 build_warnings 가 두 경고를 올바르게 방출하는지 9스캐너 subTest 로 검증한다.
  - AC-7 스택 경고: detected_stacks == ["unknown"] 일 때. 엔진과 무관(폴백/semgrep 양쪽).
  - AC-8 폴백 경고: candidate_count == 0 이며 engine == grep-fallback 일 때. semgrep job 에선
    engine==semgrep 이라 폴백 경고가 나오지 않는 게 정상 → semgrep 설치 시 skip.
JSON 결과의 warnings 키(비어있지 않을 때만 존재)와 문구를 검증한다.
"""
import importlib.util
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


def _load_build_warnings():
    """대표 스캐너(scan_sqli) 를 importlib 로 로드해 build_warnings 를 직접 얻는다.
    9스캐너의 build_warnings 는 완전 동일 복붙이므로 하나로 대표 검증한다."""
    scanner = os.path.join(_ROOT, SCANNERS["sqli"])
    spec = importlib.util.spec_from_file_location("_scan_sqli_for_warntest", scanner)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.build_warnings


class TestBuildWarningsUnit(unittest.TestCase):
    """build_warnings 직접 단위 테스트. 두 경고 모두 candidate_count==0 게이트 안에
    묶였는지 검증한다 (Gemini 리뷰: 후보 1건 이상이면 "0건이..." 문구 미발화)."""

    @classmethod
    def setUpClass(cls):
        cls.build_warnings = staticmethod(_load_build_warnings())

    def test_unknown_fallback_zero_two_warnings(self):
        # unknown 스택 + 폴백 + 0건 → 스택 경고 + 폴백 경고 2건.
        w = self.build_warnings(["unknown"], "grep-fallback", 0)
        self.assertEqual(len(w), 2, f"2건이어야 한다: {w}")
        self.assertTrue(any(_STACK_WARNING in x for x in w))
        self.assertTrue(any(_FALLBACK_WARNING in x for x in w))

    def test_unknown_fallback_nonzero_no_warnings(self):
        # Gemini 시나리오 회귀: 후보 3건이면 unknown 이어도 "0건이..." 문구 없음.
        w = self.build_warnings(["unknown"], "grep-fallback", 3)
        self.assertEqual(w, [], f"후보 1건 이상이면 경고 없음: {w}")

    def test_known_fallback_zero_fallback_only(self):
        # known 스택 + 폴백 + 0건 → 폴백 경고만.
        w = self.build_warnings(["spring-modern"], "grep-fallback", 0)
        self.assertEqual(len(w), 1, f"폴백 경고만 1건: {w}")
        self.assertTrue(any(_FALLBACK_WARNING in x for x in w))
        self.assertFalse(any(_STACK_WARNING in x for x in w))

    def test_unknown_semgrep_zero_stack_only(self):
        # unknown 스택 + semgrep + 0건 → 스택 경고만 (semgrep 이라 폴백 경고 없음).
        w = self.build_warnings(["unknown"], "semgrep", 0)
        self.assertEqual(len(w), 1, f"스택 경고만 1건: {w}")
        self.assertTrue(any(_STACK_WARNING in x for x in w))
        self.assertFalse(any(_FALLBACK_WARNING in x for x in w))


if __name__ == "__main__":
    unittest.main()
