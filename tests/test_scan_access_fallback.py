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

    def test_pathvariable_avoid_not_flagged(self):
        # @PathVariable("avoid") — "id" 부분포함이나 값 전체가 id/seq/no도 camelCase 접미도 아님 → 배제(==0)
        rules = self._rule_ids(
            "Ctrl.java",
            'class Ctrl { public String get(@PathVariable("avoid") String a) { return "x"; } }\n')
        self.assertNotIn("spring-pathvariable-annotated-id", rules)

    def test_pathvariable_boardid_not_flagged(self):
        # @PathVariable("boardid") — all-lowercase 접미 → camelCase 접미도 whole-word도 아님 → 배제(==0)(D1)
        rules = self._rule_ids(
            "Ctrl.java",
            'class Ctrl { public String get(@PathVariable("boardid") Long b) { return "x"; } }\n')
        self.assertNotIn("spring-pathvariable-annotated-id", rules)


class TestPathVariableBareId(unittest.TestCase):
    """FR-7 (D1, AC-9): bare @PathVariable id/seq/no 계열 변수명 워드바운더리 회귀.

    spring-pathvariable-id 폴백 룰(어노테이션 값이 아닌 '변수명' 기준):
      alt1 = 대소문자 구분 camelCase 접미(userId/boardSeq/certiNo/seqNo) 유지,
      alt2 = whole-word 정확한 id/seq/no 유지, avoid/String avoid 는 둘 다 실패 → 배제.
    all-lowercase 접미(boardid 등)는 미탐 손실 허용·문서화(D1).
    """

    def _rule_ids(self, filename, body):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, filename), "w", encoding="utf-8") as fh:
                fh.write(body)
            findings = scan_access.run_fallback(d)
        return {c["rule_id"] for c in findings}

    def test_bare_userid_flagged(self):
        # @PathVariable Long userId — camelCase 접미 Id → 검출
        rules = self._rule_ids(
            "Ctrl.java",
            'class Ctrl { public String get(@PathVariable Long userId) { return "x"; } }\n')
        self.assertIn("spring-pathvariable-id", rules)

    def test_bare_boardseq_flagged(self):
        # @PathVariable Long boardSeq — camelCase 접미 Seq → 검출
        rules = self._rule_ids(
            "Ctrl.java",
            'class Ctrl { public String get(@PathVariable Long boardSeq) { return "x"; } }\n')
        self.assertIn("spring-pathvariable-id", rules)

    def test_bare_certino_flagged(self):
        # @PathVariable Long certiNo — camelCase 접미 No → 검출
        rules = self._rule_ids(
            "Ctrl.java",
            'class Ctrl { public String get(@PathVariable Long certiNo) { return "x"; } }\n')
        self.assertIn("spring-pathvariable-id", rules)

    def test_bare_seqno_flagged(self):
        # @PathVariable Long seqNo — camelCase 접미 No → 검출
        rules = self._rule_ids(
            "Ctrl.java",
            'class Ctrl { public String get(@PathVariable Long seqNo) { return "x"; } }\n')
        self.assertIn("spring-pathvariable-id", rules)

    def test_bare_id_flagged(self):
        # @PathVariable Long id — whole-word id → 검출
        rules = self._rule_ids(
            "Ctrl.java",
            'class Ctrl { public String get(@PathVariable Long id) { return "x"; } }\n')
        self.assertIn("spring-pathvariable-id", rules)

    def test_bare_avoid_not_flagged(self):
        # @PathVariable String avoid — "avoid" 는 camelCase 접미도 whole-word 도 아님 → 배제
        rules = self._rule_ids(
            "Ctrl.java",
            'class Ctrl { public String get(@PathVariable String avoid) { return "x"; } }\n')
        self.assertNotIn("spring-pathvariable-id", rules)


class TestOwnershipSuppression(unittest.TestCase):
    """P4 Task 2 (결정 2): 접근통제 전용 소유권/권한 집행 신호로 오탐 억제.

    같은 메서드 창에 강한 집행 신호(@Pre/PostAuthorize 소유권 표현·소유자 스코핑 조회)가
    있으면 id 계열 후보를 제외하되, 신호가 '다른 메서드'에 있으면 억제하지 않는다(FN 회피).
    """

    def _findings(self, filename, body):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, filename), "w", encoding="utf-8") as fh:
                fh.write(body)
            return scan_access.run_fallback(d)

    def _rule_ids(self, filename, body):
        return {c["rule_id"] for c in self._findings(filename, body)}

    def test_preauthorize_owns_suppresses_pathvariable(self):
        body = (
            "public class Foo {\n"
            '    @PreAuthorize("@auth.owns(#id)")\n'
            '    @GetMapping("/{id}")\n'
            "    public Post get(@PathVariable Long id) {\n"
            "        return service.find(id);\n"
            "    }\n"
            "}\n"
        )
        self.assertNotIn("spring-pathvariable-id", self._rule_ids("Foo.java", body))

    def test_owner_scoped_query_suppresses_getparameter(self):
        body = (
            "public class Bar {\n"
            "    public String view(HttpServletRequest req) {\n"
            '        String id = req.getParameter("id");\n'
            "        return repo.findByIdAndOwner(id, currentUser());\n"
            "    }\n"
            "}\n"
        )
        self.assertNotIn("jsp-getparameter-id", self._rule_ids("Bar.java", body))

    def test_unprotected_method_still_flagged(self):
        # 보호 메서드(other) + 비보호 메서드(get)가 한 파일에. get 은 소유권 스코핑이 없으므로
        # 다른 메서드의 @PreAuthorize 에 억제되지 않고 여전히 후보로 남아야 한다(FN 가드).
        body = (
            "public class Baz {\n"
            '    @PreAuthorize("@auth.owns(#other)")\n'
            "    public Post other(@PathVariable Long other) {\n"
            "        return svc.get(other);\n"
            "    }\n"
            "\n"
            "    public Post get(@PathVariable Long id) {\n"
            "        return repo.findById(id);\n"
            "    }\n"
            "}\n"
        )
        self.assertIn("spring-pathvariable-id", self._rule_ids("Baz.java", body))

    def test_context_block_attached_to_flagged(self):
        body = (
            "public class Q {\n"
            "    public Post get(@PathVariable Long id) {\n"
            "        return postService.findById(id);\n"
            "    }\n"
            "}\n"
        )
        cands = [c for c in self._findings("Q.java", body)
                 if c["rule_id"] == "spring-pathvariable-id"]
        self.assertEqual(len(cands), 1)
        ctx = cands[0].get("context")
        self.assertIsInstance(ctx, dict)
        self.assertIn("delegates_to", ctx)
        self.assertIn("postService.findById", ctx["delegates_to"])


if __name__ == "__main__":
    unittest.main()
