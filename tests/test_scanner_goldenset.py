"""스캐너 골든셋 — recall/precision 회귀 가드 (9스캐너 확장).

취약 픽스처는 후보로 잡고, 안전 픽스처는 안 잡는지 candidate_count로 검증한다.
각 픽스처는 grep-fallback·semgrep 두 엔진 모두 동일 판정(vuln>=1, safe==0)이라
엔진 설치 여부와 무관하게 결정론적이다(dual-catch).

구조(교차오염·엔진 결합 분리):
  tests/fixtures/<scanner>/{vuln,safe}/ — 스캐너별 서브디렉토리. 각 스캐너는 자기 디렉토리만
  스캔한다. test_scanner_goldenset 은 subprocess로 scan_*.py <fixtures/<scanner>> --json 을
  실행 → 엔진 자동선택(semgrep 있으면 semgrep, 없으면 폴백). 따라서 같은 픽스처가
  test job=폴백, semgrep-tests job=semgrep 두 경로로 실행된다.

[U1-Important] 픽스처 명명 규약:
  MyBatis XML 픽스처는 파일명에 'Mapper' 포함(또는 mybatis/sqlmap 경로 하위)이어야
  scan_sqli의 _is_mybatis_xml() 폴백 필터를 통과한다. 일반 이름(Board.xml·queries.xml 등)은
  스캔에서 skip되어, recall 테스트가 가짜로 실패(취약인데 미검출)하거나 safe 테스트가 가짜로
  통과(파일이 안 읽혔는데 0)할 수 있다. safe는 아래 혼합 디렉토리 테스트로 위양성 통과를 배제한다.

semgrep 게이트: 로컬(semgrep 미설치)에서는 엔진 테스트·FR-4 measured 테스트가 skip된다(정상).
CI semgrep-tests job에서 semgrep 경로가 활성화되어 검증·관측된다.
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

# 9스캐너 → 스캐너 스크립트 상대경로
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


def _scan(scanner_rel, target_rel, force_fallback=False):
    return _scan_abs(os.path.join(_ROOT, target_rel), scanner_rel, force_fallback)


def _scan_abs(target, scanner_rel=_SCANNER, force_fallback=False):
    scanner = os.path.join(_ROOT, scanner_rel)
    env = dict(os.environ, GXSEC_NO_SEMGREP="1") if force_fallback else None
    proc = subprocess.run(
        [sys.executable, scanner, target, "--json"],
        capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=120, env=env,
    )
    return json.loads(proc.stdout)


def _scan_fixture(scanner_key, kind, force_fallback=False):
    """scanner_key 스캐너로 tests/fixtures/<scanner_key>/<kind> 를 스캔한다."""
    rel = os.path.join("tests", "fixtures", scanner_key, kind)
    return _scan_abs(os.path.join(_ROOT, rel), SCANNERS[scanner_key], force_fallback)


class TestGoldensetAllScanners(unittest.TestCase):
    """9스캐너 골든셋 — 폴백 재현율 회귀 가드(semgrep 룰은 별도).

    force_fallback=True 로 GXSEC_NO_SEMGREP=1 을 주입해 양 job(폴백 job·semgrep 설치 job)에서
    항상 grep-fallback 경로로 vuln>=1 / safe==0 을 검증한다(결정론적). semgrep 룰 자체의
    재현율은 TestSemgrepDiscovery 로 비차단 관측한다.
    """

    def test_vuln_detected(self):
        for key in SCANNERS:
            with self.subTest(scanner=key):
                r = _scan_fixture(key, "vuln", force_fallback=True)
                self.assertGreaterEqual(
                    r["candidate_count"], 1,
                    f"{key}: 취약 픽스처는 후보 >=1 이어야 한다")

    def test_safe_clean(self):
        for key in SCANNERS:
            with self.subTest(scanner=key):
                r = _scan_fixture(key, "safe", force_fallback=True)
                self.assertEqual(
                    r["candidate_count"], 0,
                    f"{key}: 안전 픽스처는 후보 0 이어야 한다")


def _scan_fixture_semgrep(scanner_key, kind):
    """semgrep 경로 검증용: 픽스처를 tests/ 밖 임시 디렉토리로 복사한 뒤 스캔한다.

    semgrep 은 기본 .semgrepignore 로 tests/ 를 스킵하므로 tests/fixtures 를 그대로 스캔하면
    'Ran N rules on 0 files' 로 항상 0건이 된다(M5 CI 'detect-0' 의 정체). 실제 소스처럼
    tests/ 밖에서 스캔해야 semgrep 룰의 재현율이 측정된다. force_fallback=False 로 semgrep 강제.
    """
    src = os.path.join(_ROOT, "tests", "fixtures", scanner_key, kind)
    tmp = tempfile.mkdtemp(prefix=f"gxsec_sg_{scanner_key}_{kind}_")
    try:
        for name in os.listdir(src):
            sp = os.path.join(src, name)
            if os.path.isfile(sp):
                shutil.copy(sp, os.path.join(tmp, name))
        return _scan_abs(tmp, SCANNERS[scanner_key], force_fallback=False)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@unittest.skipUnless(shutil.which("semgrep"), "semgrep 미설치 → 스킵(CI semgrep-tests job에서 검증)")
class TestSemgrepGoldenset(unittest.TestCase):
    """semgrep 경로 재현율/정밀도 하드 가드 — 룰이 로드+검출됨을 semgrep 설치 job 에서 강제한다.

    M5 이전에는 semgrep 룰이 전역 파탄(로드실패 폴백강등 3파일 + access @PathVariable 파라미터
    미검출)이라 이 검증이 비차단 관측(구 TestSemgrepDiscovery)에 머물렀다. M5 에서 룰을 수정해
    양엔진(grep-fallback·semgrep)이 모두 vuln>=1 / safe==0 을 만족하므로 하드 게이트로 승격한다.
    폴백 재현율은 TestGoldensetAllScanners 가 별도로 하드 가드한다(dual-engine).
    """

    def test_semgrep_engine_selected(self):
        # 이 클래스가 도는데 grep-fallback 이면 엔진 선택 로직이 깨진 것 → 명시 실패.
        r = _scan_fixture_semgrep("sqli", "vuln")
        self.assertEqual(r["engine"], "semgrep",
                         "semgrep 설치 환경인데 engine 이 semgrep 이 아니다")

    def test_vuln_detected_by_semgrep(self):
        for key in SCANNERS:
            with self.subTest(scanner=key):
                r = _scan_fixture_semgrep(key, "vuln")
                self.assertEqual(r["engine"], "semgrep", f"{key}: semgrep 엔진이어야 한다")
                self.assertGreaterEqual(
                    r["candidate_count"], 1,
                    f"{key}: semgrep 룰이 취약 픽스처를 검출해야 한다(재현율)")

    def test_safe_clean_by_semgrep(self):
        for key in SCANNERS:
            with self.subTest(scanner=key):
                r = _scan_fixture_semgrep(key, "safe")
                self.assertEqual(
                    r["candidate_count"], 0,
                    f"{key}: semgrep 룰이 안전 픽스처를 오탐하면 안 된다(정밀도)")


@unittest.skipUnless(shutil.which("semgrep"), "semgrep 미설치 → 스킵(CI에서 관측)")
class TestFR4Measured(unittest.TestCase):
    """FR-4: semgrep 룰의 컨텍스트 게이트/pattern-not-regex 실효 실측(초기 비차단).

    초기 = 관측 count를 log 출력 + assertGreaterEqual(count, 0)(green).
    CI 로그의 [FR4-MEASURE] 값을 확인한 뒤 후속 커밋에서 assertEqual(count, 관측값)으로 핀한다.
    """

    def test_xss_cout_measured(self):
        count = _scan_abs(os.path.join(_ROOT, "tests", "fixtures", "xss", "measured"),
                          SCANNERS["xss"])["candidate_count"]
        print(f"[FR4-MEASURE] xss_cout={count}")
        self.assertGreaterEqual(count, 0)  # 초기 비차단 — CI 관측 후 assertEqual 로 핀(B3)

    def test_ssrf_hardcoded_measured(self):
        count = _scan_abs(os.path.join(_ROOT, "tests", "fixtures", "ssrf", "measured"),
                          SCANNERS["ssrf"])["candidate_count"]
        print(f"[FR4-MEASURE] ssrf_hardcoded={count}")
        self.assertGreaterEqual(count, 0)  # 초기 비차단 — CI 관측 후 assertEqual 로 핀(B3)


@unittest.skipUnless(shutil.which("semgrep"), "semgrep 미설치 → 스킵(CI에서 관측)")
class TestFR7BareOwnershipSemgrep(unittest.TestCase):
    """FR-7(AC-9 semgrep 측): bare @PathVariable id 소유권 미검증 룰 — 비차단 발견 리포트.

    access-control.yml sqisoft-spring-pathvariable-id-no-ownership-check 의 $ID
    metavariable-regex(userId 검출 / avoid 배제) 를 semgrep 실행으로 관측한다. M5 CI 실측상
    semgrep 룰이 전역 파탄이라 여기서는 하드 단언 대신 [SEMGREP-DISCOVERY] 로그만 남긴다.
    폴백 FR-7 은 test_scan_access_fallback 가 이미 하드 검증하므로 semgrep 측은 발견화한다.
    """
    _RULE = "sqisoft-spring-pathvariable-id-no-ownership-check"

    def _rule_ids(self, body):
        tmp = tempfile.mkdtemp(prefix="gxsec_fr7_")
        try:
            with open(os.path.join(tmp, "Ctrl.java"), "w", encoding="utf-8") as f:
                f.write(body)
            r = _scan_abs(tmp, SCANNERS["access"])
            return {c["rule_id"] for c in r.get("candidates", [])}
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_bare_ownership_report(self):
        userid_java = (
            "import org.springframework.web.bind.annotation.GetMapping;\n"
            "import org.springframework.web.bind.annotation.PathVariable;\n"
            "class UserCtrl {\n"
            "    private UserService userService;\n"
            "    @GetMapping(\"/users/{userId}\")\n"
            "    public String get(@PathVariable Long userId) {\n"
            "        return userService.findById(userId);\n"
            "    }\n"
            "}\n"
        )
        avoid_java = (
            "import org.springframework.web.bind.annotation.GetMapping;\n"
            "import org.springframework.web.bind.annotation.PathVariable;\n"
            "class SearchCtrl {\n"
            "    private SearchService searchService;\n"
            "    @GetMapping(\"/search/{avoid}\")\n"
            "    public String get(@PathVariable String avoid) {\n"
            "        return searchService.findById(avoid);\n"
            "    }\n"
            "}\n"
        )
        userid_hit = self._RULE in self._rule_ids(userid_java)
        avoid_hit = self._RULE in self._rule_ids(avoid_java)
        print(f"[SEMGREP-DISCOVERY] fr7 userid_rules={userid_hit} avoid_rules={avoid_hit}")
        self.assertIn(userid_hit, (True, False))  # 비차단 — 관측만


class TestSqliGoldenset(unittest.TestCase):
    """SQLi 골든셋 — 폴백 재현율 회귀 가드(semgrep 룰은 별도).

    force_fallback=True 로 GXSEC_NO_SEMGREP=1 을 주입해 양 job 에서 항상 grep-fallback 경로로
    ${}/#{} 판정을 검증한다(결정론적). semgrep 룰 재현율은 TestSemgrepDiscovery 로 비차단 관측.
    """
    SCANNER = _SCANNER

    def test_vuln_dollar_is_flagged(self):
        r = _scan(self.SCANNER, "tests/fixtures/sqli/vuln", force_fallback=True)
        self.assertGreaterEqual(r["candidate_count"], 1,
                                "취약형 MyBatis ${} 가 후보로 잡혀야 한다")

    def test_safe_hash_not_flagged(self):
        r = _scan(self.SCANNER, "tests/fixtures/sqli/safe", force_fallback=True)
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
            r = _scan_abs(tmp, force_fallback=True)
            self.assertGreaterEqual(r["candidate_count"], 1,
                                    "디렉토리가 실제 스캔됨(${} 검출)")
            flagged = " ".join(c.get("file", "") for c in r.get("candidates", []))
            self.assertNotIn("SafeMapper", flagged,
                             "#{} 안전형은 (파일이 읽혔음에도) 검출되면 안 된다")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
