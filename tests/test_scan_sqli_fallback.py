import importlib.util
import os
import tempfile
import unittest

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_MOD = os.path.join(_ROOT, "skills", "detecting-sql-injection",
                    "scripts", "scan_sqli.py")
_spec = importlib.util.spec_from_file_location("scan_sqli", _MOD)
scan_sqli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scan_sqli)


class TestFallbackRegexConcat(unittest.TestCase):
    """FR3-4/AC-14 — 폴백 정규식 3종의 문자열리터럴 concat 탐지 + 변수연결 하위호환 회귀.

    각 정규식이 노리는 대상 메서드명이 다르므로 케이스를 정규식별로 맞춘다:
      _STMT_CONCAT        → executeQuery / executeUpdate / execute
      _JDBC_TMPL_CONCAT   → .query / .queryForObject / .queryForList / .update
      _JPA_CREATE_CONCAT  → .createQuery / .createNativeQuery
    """

    # ── _STMT_CONCAT ────────────────────────────────────────────
    def test_stmt_concat_literal_with_spaces(self):
        # 문자열 리터럴 내부 공백 포함 concat 신규 탐지(AC-14)
        line = 'stmt.executeQuery("SELECT * FROM t WHERE id=" + id);'
        self.assertIsNotNone(scan_sqli._STMT_CONCAT.search(line))

    def test_stmt_concat_variable_backward_compat(self):
        # 기존 변수연결 형태 유지(미탐 회귀 방지)
        line = 'stmt.executeQuery(sql + x);'
        self.assertIsNotNone(scan_sqli._STMT_CONCAT.search(line))

    # ── _JDBC_TMPL_CONCAT ───────────────────────────────────────
    def test_jdbc_tmpl_concat_literal_with_spaces(self):
        line = 'jdbcTemplate.queryForObject("SELECT * FROM t WHERE id=" + id, Long.class);'
        self.assertIsNotNone(scan_sqli._JDBC_TMPL_CONCAT.search(line))

    def test_jdbc_tmpl_concat_variable_backward_compat(self):
        line = 'jdbcTemplate.query(sql + x);'
        self.assertIsNotNone(scan_sqli._JDBC_TMPL_CONCAT.search(line))

    # ── _JPA_CREATE_CONCAT ──────────────────────────────────────
    def test_jpa_create_concat_literal_with_spaces(self):
        line = 'em.createQuery("SELECT u FROM User u WHERE u.id=" + id);'
        self.assertIsNotNone(scan_sqli._JPA_CREATE_CONCAT.search(line))

    def test_jpa_create_concat_variable_backward_compat(self):
        line = 'em.createQuery(jpql + x);'
        self.assertIsNotNone(scan_sqli._JPA_CREATE_CONCAT.search(line))


class TestFallbackFixtureIntegration(unittest.TestCase):
    """AC-15 — tempfile fixture에 concat 라인 포함 Vuln.java 작성 후
    run_fallback 호출 → 반환 후보에 SQLi concat rule이 존재함을 assert."""

    _JAVA = (
        "public class Vuln {\n"
        "    void a(java.sql.Statement stmt) throws Exception {\n"
        '        stmt.executeQuery("SELECT * FROM t WHERE id=" + id);\n'
        "    }\n"
        "    void b(org.springframework.jdbc.core.JdbcTemplate jdbcTemplate) {\n"
        '        jdbcTemplate.queryForObject("SELECT * FROM t WHERE id=" + id, Long.class);\n'
        "    }\n"
        "    void c(javax.persistence.EntityManager em) {\n"
        '        em.createQuery("SELECT u FROM User u WHERE u.id=" + id);\n'
        "    }\n"
        "}\n"
    )

    def test_run_fallback_detects_concat_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "Vuln.java"), "w", encoding="utf-8") as fh:
                fh.write(self._JAVA)
            findings = scan_sqli.run_fallback(tmp)
        rule_ids = {c["rule_id"] for c in findings}
        # 정규식 3종이 각각 다른 메서드 라인에 매치되어 세 rule_id가 모두 나와야 한다
        self.assertIn("jdbc-statement-string-concat", rule_ids)
        self.assertIn("spring-jdbctemplate-string-concat", rule_ids)
        self.assertIn("spring-jpa-createquery-string-concat", rule_ids)


if __name__ == "__main__":
    unittest.main()
