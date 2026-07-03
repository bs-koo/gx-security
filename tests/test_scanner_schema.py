"""후보 객체 스키마 균일화 계약 테스트 (계획 Task 5.1).

9종 scan_*.py 를 grep-fallback 경로에서 트리거 픽스처에 돌려,
  · 상위 JSON 이 균일 필드(rule_summary 포함)를 방출하는지
  · 모든 후보(candidate)가 필수 6키(file/line/rule_id/stack/confidence/snippet)를 갖는지
  · 선택 필드 severity 는 있으면 str 인지
를 검증한다. 각 스캐너가 ≥1 후보를 내도록 픽스처를 맞춰 "0건이면 무조건 통과"
(vacuous pass)로 계약이 무력화되는 것을 막는다.
"""
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

# 각 스캐너가 grep-fallback 에서 ≥1 후보를 반환하도록 만드는 최소 트리거 픽스처.
# (semgrep 미설치 환경 = CI 기준. 폴백 정규식은 스택 감지와 무관하게 확장자로 적용됨)
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
        '@RequestMapping("/adm/users")\n'
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


class TestScannerSchemaUniformity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        target = cls._tmp.name
        for name, content in _FIXTURES.items():
            with open(os.path.join(target, name), "w", encoding="utf-8") as fh:
                fh.write(content)
        # 각 스캐너를 한 번씩만 실행해 결과를 캐시(subprocess 중복 방지)
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

    def test_top_level_schema_uniform(self):
        """9종 상위 JSON 이 rule_summary 포함 균일 필드를 방출한다."""
        for key in SCANNERS:
            with self.subTest(scanner=key):
                r = self.results[key]
                missing = REQUIRED_TOP_KEYS - set(r)
                self.assertFalse(missing, f"{key}: 상위 필드 누락 {missing}")
                self.assertIsInstance(r["rule_summary"], dict,
                                      f"{key}: rule_summary 는 dict 여야 함")
                self.assertIsInstance(r["candidates"], list)

    def test_every_candidate_has_required_keys(self):
        """모든 후보가 필수 6키(confidence 포함)를 갖고, confidence 는 비지 않은 str."""
        for key in SCANNERS:
            with self.subTest(scanner=key):
                r = self.results[key]
                self.assertGreaterEqual(
                    r["candidate_count"], 1,
                    f"{key}: 픽스처가 후보를 트리거하지 못함 — 계약 검증이 무효화됨")
                for c in r["candidates"]:
                    missing = REQUIRED_CANDIDATE_KEYS - set(c)
                    self.assertFalse(
                        missing, f"{key}: 후보 필드 누락 {missing} (rule_id={c.get('rule_id')})")
                    self.assertIsInstance(c["confidence"], str,
                                          f"{key}: confidence 는 str 여야 함")
                    self.assertTrue(c["confidence"].strip(),
                                    f"{key}: confidence 가 빈 문자열")

    def test_optional_severity_is_str_when_present(self):
        """선택 필드 severity 는 있으면 str (있으면-쓰고-없으면-무시 계약)."""
        for key in SCANNERS:
            with self.subTest(scanner=key):
                for c in self.results[key]["candidates"]:
                    if "severity" in c:
                        self.assertIsInstance(c["severity"], str,
                                              f"{key}: severity 는 str 여야 함")


if __name__ == "__main__":
    unittest.main()
