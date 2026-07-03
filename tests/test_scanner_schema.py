"""후보 객체 스키마 균일화 계약 테스트 (계획 Task 5.1).

9종 scan_*.py 가
  · 모든 후보(candidate)가 필수 6키(file/line/rule_id/stack/confidence/snippet)를 갖는지
  · 상위 JSON 이 균일 필드(rule_summary 포함)를 방출하는지
  · 선택 필드 severity 는 있으면 str 인지
를 검증한다. 각 스캐너가 ≥1 후보를 내도록 픽스처를 맞춰 "0건이면 무조건 통과"
(vacuous pass)로 계약이 무력화되는 것을 막는다.

엔진 독립성: `run_fallback()` 을 직접 호출하는 결정적 경로(semgrep 유무 무관)로
per-candidate 계약을 검증한다. subprocess(main) 경로는 상위 스키마(rule_summary 등)를
검증하되, ≥1 단언은 grep-fallback 엔진일 때만 강제한다(semgrep 설치 개발환경 거짓실패 방지).
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))

# 스캐너 키 → 스크립트 상대경로
SCANNERS = {
    "sqli": "skills/detecting-sql-injection/scripts/scan_sqli.py",
    "xss": "skills/detecting-xss-vulnerabilities/scripts/scan_xss.py",
    "csrf": "skills/detecting-csrf-vulnerabilities/scripts/scan_csrf.py",
    "ssrf": "skills/detecting-ssrf-and-open-redirect/scripts/scan_ssrf.py",
    "upload": "skills/detecting-file-upload-vulnerabilities/scripts/scan_upload.py",
    "pathtraversal": "skills/detecting-path-traversal/scripts/scan_pathtraversal.py",
    "access": "skills/detecting-broken-access-control/scripts/scan_access.py",
    "auth": "skills/detecting-auth-session-weaknesses/scripts/scan_auth.py",
    "secrets": "skills/detecting-sensitive-data-exposure/scripts/scan_secrets.py",
}


def _load(key, rel):
    spec = importlib.util.spec_from_file_location(
        f"schema_{key}", os.path.join(_ROOT, *rel.split("/")))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_MODS = {key: _load(key, rel) for key, rel in SCANNERS.items()}

# 각 스캐너의 run_fallback 정규식이 grep-fallback 에서 ≥1 후보를 잡도록 만드는 최소 트리거.
_FIXTURES = {
    # sqli: JDBC Statement 문자열 연결
    "Sql.java": (
        "public class Sql {\n"
        "  void a(java.sql.Statement stmt) throws Exception {\n"
        '    stmt.executeQuery("SELECT * FROM t WHERE id=" + id);\n'
        "  }\n"
        "}\n"
    ),
    # xss: innerHTML 할당
    "app.js": "function r(x){ document.getElementById('a').innerHTML = x; }\n",
    # csrf: POST 폼 (jsp-form-post)
    "form.jsp": '<form method="post" action="/x"><input name="a"></form>\n',
    # ssrf: RestTemplate
    "Ssrf.java": (
        "public class Ssrf {\n"
        "  void a(org.springframework.web.client.RestTemplate restTemplate){\n"
        "    restTemplate.getForObject(url, String.class);\n"
        "  }\n"
        "}\n"
    ),
    # upload: MultipartFile.transferTo
    "Upload.java": (
        "public class Upload {\n"
        "  void a(org.springframework.web.multipart.MultipartFile mf) throws Exception {\n"
        "    mf.transferTo(dest);\n"
        "  }\n"
        "}\n"
    ),
    # pathtraversal: new File(filePath, ...) — 경로 관련 변수명
    "Traversal.java": (
        "public class Traversal {\n"
        "  void a(String filePath, String name){\n"
        "    Object f = new File(filePath, name);\n"
        "  }\n"
        "}\n"
    ),
    # access: /adm 매핑 (spring-admin-no-preauthorize)
    "AdmCtrl.java": (
        '@RequestMapping("/adm/v1/users")\n'
        "public class AdmCtrl {\n"
        "  public String get(@PathVariable Long userId){ return \"x\"; }\n"
        "}\n"
    ),
    # auth: JWT 시크릿 리터럴 (secrets 도 hardcoded-credential-java-string 로 잡음)
    "Jwt.java": (
        "public class Jwt {\n"
        '  private String secretKey = "hardcodedsecretvalue123";\n'
        "}\n"
    ),
    # secrets: properties 평문 시크릿
    "app.properties": "password=SuperSecretValue123\n",
}

REQUIRED_CANDIDATE_KEYS = {"file", "line", "rule_id", "stack", "confidence", "snippet"}
REQUIRED_TOP_KEYS = {
    "target", "detected_stacks", "engine",
    "candidate_count", "rule_summary", "candidates", "note",
}


def _assert_candidate_uniform(tc, key, candidates):
    for c in candidates:
        missing = REQUIRED_CANDIDATE_KEYS - set(c)
        tc.assertFalse(
            missing, f"{key}: 후보 필드 누락 {missing} (rule_id={c.get('rule_id')})")
        tc.assertIsInstance(c["confidence"], str, f"{key}: confidence 는 str 여야 함")
        tc.assertTrue(c["confidence"].strip(), f"{key}: confidence 가 빈 문자열")
        if "severity" in c:
            tc.assertIsInstance(c["severity"], str, f"{key}: severity 는 str 여야 함")


class TestScannerSchemaUniformity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        target = cls._tmp.name
        for name, content in _FIXTURES.items():
            with open(os.path.join(target, name), "w", encoding="utf-8") as fh:
                fh.write(content)
        cls.target = target
        # main() 산출 상위 스키마 검증용 — 각 스캐너 --json 을 한 번씩 캐시
        cls.results = {}
        for key, rel in SCANNERS.items():
            proc = subprocess.run(
                [sys.executable, os.path.join(_ROOT, rel), target, "--json"],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
            )
            assert proc.returncode == 0, (
                f"{rel} 비정상 종료(rc={proc.returncode}): {proc.stderr[:300]}")
            cls.results[key] = json.loads(proc.stdout)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_fallback_candidates_uniform(self):
        """엔진 독립: run_fallback() 을 직접 호출해 ≥1 후보 + 필수 6키를 결정적으로 검증."""
        for key, mod in _MODS.items():
            with self.subTest(scanner=key):
                findings = mod.run_fallback(self.target)
                self.assertGreaterEqual(
                    len(findings), 1,
                    f"{key}: run_fallback 픽스처가 후보를 트리거하지 못함 — 계약 검증 무효화")
                _assert_candidate_uniform(self, key, findings)

    def test_top_level_schema_uniform(self):
        """9종 상위 JSON(main 산출)이 rule_summary 포함 균일 필드를 방출한다."""
        for key in SCANNERS:
            with self.subTest(scanner=key):
                r = self.results[key]
                missing = REQUIRED_TOP_KEYS - set(r)
                self.assertFalse(missing, f"{key}: 상위 필드 누락 {missing}")
                self.assertIsInstance(r["rule_summary"], dict,
                                      f"{key}: rule_summary 는 dict 여야 함")
                self.assertIsInstance(r["candidates"], list)

    def test_main_candidates_uniform(self):
        """main 산출 후보(추가 분석 포함)도 균일. ≥1 단언은 grep-fallback 엔진일 때만 강제
        (semgrep 설치 개발환경에서 폴백용 픽스처 미매치로 인한 거짓실패 방지)."""
        for key in SCANNERS:
            with self.subTest(scanner=key):
                r = self.results[key]
                if r.get("engine") == "grep-fallback":
                    self.assertGreaterEqual(
                        r["candidate_count"], 1,
                        f"{key}: 픽스처가 후보를 트리거하지 못함 — 계약 검증 무효화")
                _assert_candidate_uniform(self, key, r["candidates"])


if __name__ == "__main__":
    unittest.main()
