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

    같은 메서드 창에 집행 신호(@Pre/PostAuthorize 소유권 표현·결합형 소유자 스코핑 조회)가
    있으면 id 계열 후보를 '삭제'하지 않고 confidence='enforcement-detected-verify'로 태그해
    AI 2단계로 넘긴다(silent FN 방지 — 코드리뷰). 주석/문자열/도달불가/공격자 파라미터는 태그하지 않거나
    태그돼도 후보로 남아야 한다 — 어느 경우든 '삭제'는 절대 없다.
    """

    def _cands(self, filename, body, rule_id):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, filename), "w", encoding="utf-8") as fh:
                fh.write(body)
            return [c for c in scan_access.run_fallback(d) if c["rule_id"] == rule_id]

    # ── 집행 신호 → 삭제하지 않고 태그(가시성 유지) ─────────────────────────────
    def test_preauthorize_owns_tags_not_deletes(self):
        body = (
            "public class Foo {\n"
            '    @PreAuthorize("@auth.owns(#id)")\n'
            '    @GetMapping("/{id}")\n'
            "    public Post get(@PathVariable Long id) {\n"
            "        return service.find(id);\n"
            "    }\n"
            "}\n"
        )
        cands = self._cands("Foo.java", body, "spring-pathvariable-id")
        self.assertEqual(len(cands), 1, "삭제되면 안 됨 — 태그만")
        self.assertEqual(cands[0]["confidence"], "enforcement-detected-verify")

    def test_owner_scoped_query_tags_not_deletes(self):
        body = (
            "public class Bar {\n"
            "    public String view(HttpServletRequest req) {\n"
            '        String id = req.getParameter("id");\n'
            "        return repo.findByIdAndOwner(id, currentUser());\n"
            "    }\n"
            "}\n"
        )
        cands = self._cands("Bar.java", body, "jsp-getparameter-id")
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]["confidence"], "enforcement-detected-verify")

    # ── silent FN 방지: 아래 케이스는 모두 후보가 '반드시' 남아야 한다(삭제 금지) ──
    def test_unprotected_present_and_not_tagged(self):
        body = (
            "public class Baz {\n"
            '    @PreAuthorize("@auth.owns(#other)")\n'
            "    public Post other(@PathVariable Long other) { return svc.get(other); }\n"
            "\n"
            "    public Post get(@PathVariable Long id) {\n"
            "        return repo.findById(id);\n"
            "    }\n"
            "}\n"
        )
        # 'other'는 변수명이 id/seq/no 형태가 아니라 규칙 미매치 → 후보는 get()의 id 1건.
        # 그 1건이 옆 메서드 other()의 @PreAuthorize에 태그되지 않고 needs-context로 남아야 한다.
        cands = self._cands("Baz.java", body, "spring-pathvariable-id")
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]["confidence"], "needs-context")

    def test_multiline_block_comment_not_tagged(self):
        body = (
            "public class C {\n"
            '    @GetMapping("/r/{id}")\n'
            "    public Object get(@PathVariable Long id) {\n"
            "        /*\n"
            "         * Historical: checkOwnership(id) was verified upstream.\n"
            "         */\n"
            "        return repo.findById(id);\n"
            "    }\n"
            "}\n"
        )
        cands = self._cands("C.java", body, "spring-pathvariable-id")
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]["confidence"], "needs-context")

    def test_string_literal_not_tagged(self):
        body = (
            "public class C {\n"
            "    public Object get(@PathVariable Long id) {\n"
            '        logger.warn("Missing checkOwnership(id) call");\n'
            "        return repo.findById(id);\n"
            "    }\n"
            "}\n"
        )
        cands = self._cands("C.java", body, "spring-pathvariable-id")
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]["confidence"], "needs-context")

    def test_unrelated_feature_flag_bean_not_tagged(self):
        body = (
            "public class C {\n"
            "    @PreAuthorize(\"@featureFlags.isEnabled('newApi')\")\n"
            '    @GetMapping("/r/{id}")\n'
            "    public Object get(@PathVariable Long id) {\n"
            "        return repo.findById(id);\n"
            "    }\n"
            "}\n"
        )
        cands = self._cands("C.java", body, "spring-pathvariable-id")
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]["confidence"], "needs-context")

    def test_kotlin_fun_no_brace_bleed(self):
        body = (
            "class BoardController(private val boardService: BoardService) {\n"
            '    @GetMapping("/api/boards/{id}")\n'
            "    fun getBoard(@PathVariable id: Long): BoardDto {\n"
            "        return boardService.findById(id)\n"
            "    }\n"
            '    @PreAuthorize("#id == authentication.principal.id")\n'
            '    @PutMapping("/api/boards/{id}")\n'
            "    fun updateBoard(@PathVariable id: Long): BoardDto {\n"
            "        return boardService.save(id)\n"
            "    }\n"
            "}\n"
        )
        cands = self._cands("BoardController.kt", body, "spring-pathvariable-id")
        # getBoard 후보가 updateBoard의 @PreAuthorize를 흡수해 태그되면 안 됨(brace-bleed 차단).
        self.assertTrue([c for c in cands if c["confidence"] == "needs-context"],
                        "getBoard()가 needs-context로 남아야 함(옆 메서드 신호 미흡수)")

    def test_dead_code_and_attacker_param_still_present(self):
        # 도달 불가 익명 클래스 안 checkOwnership, 공격자 통제 결합 파라미터 — 정적으로 완벽히
        # 가려낼 수 없지만 '삭제되지 않고' 후보로 남아 AI가 봐야 한다(핵심 안전 불변식).
        dead = (
            "public class C {\n"
            "    public Object get(@PathVariable Long id) {\n"
            "        Runnable r = new Runnable() { public void run() { checkOwnership(id); } };\n"
            "        return repo.findById(id);\n"
            "    }\n"
            "}\n"
        )
        self.assertEqual(len(self._cands("C.java", dead, "spring-pathvariable-id")), 1)
        attacker = (
            "public class C {\n"
            "    public Object get(@PathVariable Long id, @RequestParam Long userId) {\n"
            "        return repo.findByIdAndUserId(id, userId);\n"
            "    }\n"
            "}\n"
        )
        self.assertEqual(len(self._cands("C.java", attacker, "spring-pathvariable-id")), 1)

    def test_bare_findbyuserid_not_tagged(self):
        body = (
            "public class C {\n"
            "    public Post get(@PathVariable Long id) {\n"
            "        return orderRepo.findByUserId(id);\n"
            "    }\n"
            "}\n"
        )
        cands = self._cands("C.java", body, "spring-pathvariable-id")
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]["confidence"], "needs-context")

    def test_context_block_attached(self):
        body = (
            "public class Q {\n"
            "    public Post get(@PathVariable Long id) {\n"
            "        return postService.findById(id);\n"
            "    }\n"
            "}\n"
        )
        cands = self._cands("Q.java", body, "spring-pathvariable-id")
        self.assertEqual(len(cands), 1)
        ctx = cands[0].get("context")
        self.assertIsInstance(ctx, dict)
        self.assertIn("postService.findById", ctx["delegates_to"])


if __name__ == "__main__":
    unittest.main()
