"""scan_access 폴백 회귀 (F3 FR-5).

@PathVariable("id")/@PathVariable(name="userId") 처럼 어노테이션 값으로 id/seq/no
계열 경로 변수를 받는 형태를 spring-pathvariable-annotated-id 로 후보화함을 고정한다.
value= 및 name= 별칭 모두 처리한다.
"""
import importlib.util
import os
import tempfile
import unittest

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_MOD = os.path.join(_ROOT, "skills", "detecting-broken-access-control",
                    "scripts", "scan_access.py")
_spec = importlib.util.spec_from_file_location("scan_access", _MOD)
scan_access = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scan_access)


class TestPathVariableAnnotatedId(unittest.TestCase):
    def _rule_ids(self, filename, body):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, filename), "w", encoding="utf-8") as fh:
                fh.write(body)
            findings = scan_access.run_fallback(d)
        return {c["rule_id"] for c in findings}

    def test_pathvariable_value_id_flagged(self):
        # @PathVariable("id") — 값 지정형(id 부분매칭)
        rules = self._rule_ids(
            "Ctrl.java",
            'class Ctrl { public String get(@PathVariable("id") Long id) { return "x"; } }\n')
        self.assertIn("spring-pathvariable-annotated-id", rules)

    def test_pathvariable_name_alias_flagged(self):
        # @PathVariable(name="userId") — name= 별칭(userId 부분매칭)
        rules = self._rule_ids(
            "Ctrl.java",
            'class Ctrl { public String get(@PathVariable(name="userId") Long uid) { return "x"; } }\n')
        self.assertIn("spring-pathvariable-annotated-id", rules)

    def test_no_pathvariable_safe(self):
        # @PathVariable 없는 코드 → 후보 아님(==0)
        rules = self._rule_ids(
            "Safe.java",
            'class Safe { public String list() { return "ok"; } }\n')
        self.assertNotIn("spring-pathvariable-annotated-id", rules)

    # ── FR-5 워드바운더리 과탐 축소 회귀 ────────────────────────────
    def test_pathvariable_userid_still_flagged(self):
        # @PathVariable("userId") — id가 값 끝 경계 → 유지(≥1)
        rules = self._rule_ids(
            "Ctrl.java",
            'class Ctrl { public String get(@PathVariable("userId") Long uid) { return "x"; } }\n')
        self.assertIn("spring-pathvariable-annotated-id", rules)

    def test_pathvariable_boardseq_still_flagged(self):
        # @PathVariable("boardSeq") — seq가 값 끝 경계 → 유지(≥1)
        rules = self._rule_ids(
            "Ctrl.java",
            'class Ctrl { public String get(@PathVariable("boardSeq") Long sq) { return "x"; } }\n')
        self.assertIn("spring-pathvariable-annotated-id", rules)

    def test_pathvariable_annotation_not_flagged(self):
        # @PathVariable("annotation") — "no"+tation, 경계 없음 → 배제(==0)
        rules = self._rule_ids(
            "Ctrl.java",
            'class Ctrl { public String get(@PathVariable("annotation") String a) { return "x"; } }\n')
        self.assertNotIn("spring-pathvariable-annotated-id", rules)

    def test_pathvariable_consequence_not_flagged(self):
        # @PathVariable("consequence") — "seq"+uence, 경계 없음 → 배제(==0)
        rules = self._rule_ids(
            "Ctrl.java",
            'class Ctrl { public String get(@PathVariable("consequence") String c) { return "x"; } }\n')
        self.assertNotIn("spring-pathvariable-annotated-id", rules)


if __name__ == "__main__":
    unittest.main()
