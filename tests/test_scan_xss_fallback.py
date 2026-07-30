import importlib.util
import os
import tempfile
import unittest

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_MOD = os.path.join(_ROOT, "skills", "detecting-xss-vulnerabilities",
                    "scripts", "scan_xss.py")
_spec = importlib.util.spec_from_file_location("scan_xss", _MOD)
scan_xss = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scan_xss)


def _scan(filename, content):
    """tempfile에 파일을 쓰고 run_fallback 후보의 rule_id 집합을 반환."""
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, filename), "w", encoding="utf-8") as fh:
            fh.write(content)
        return {c["rule_id"] for c in scan_xss.run_fallback(tmp)}


class TestServletReflectedXss(unittest.TestCase):
    """FR-3/AC-3 — 서블릿 반사형 XSS 폴백. getWriter().print/write 직후 바로
    request.getParameter는 후보, 이스케이프 래핑은 미검출(QE-1)."""

    def test_vuln_inline_getparameter(self):
        java = (
            "public class Servlet {\n"
            "    void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {\n"
            '        response.getWriter().print(request.getParameter("q"));\n'
            "    }\n"
            "}\n"
        )
        self.assertIn("servlet-getwriter-reflected-xss", _scan("Servlet.java", java))

    def test_safe_escaped_wrapping(self):
        # print(Encode.forHtml(request.getParameter(...))) → 사이에 함수호출이 끼어 미검출
        java = (
            "public class Servlet {\n"
            "    void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {\n"
            '        response.getWriter().print(Encode.forHtml(request.getParameter("q")));\n'
            "    }\n"
            "}\n"
        )
        self.assertNotIn("servlet-getwriter-reflected-xss", _scan("Servlet.java", java))


class TestJspElUnescapedModel(unittest.TestCase):
    """FR-4/AC-4 — 저장형 모델 EL 미이스케이프. ${board.title}는 후보,
    <c:out>/fn:escapeXml 래핑은 후처리로 제외(QE-1)."""

    def test_vuln_model_attr_el(self):
        jsp = "<td>${board.title}</td>\n"
        self.assertIn("jsp-el-unescaped-model", _scan("board.jsp", jsp))

    def test_safe_c_out_wrapping(self):
        jsp = '<td><c:out value="${board.title}"/></td>\n'
        self.assertNotIn("jsp-el-unescaped-model", _scan("board.jsp", jsp))

    def test_safe_escapexml_wrapping(self):
        jsp = "<td>${fn:escapeXml(board.title)}</td>\n"
        self.assertNotIn("jsp-el-unescaped-model", _scan("board.jsp", jsp))

    def test_safe_implicit_object_excluded(self):
        # 내장 암묵객체 param.x는 model 룰의 lookahead로 제외(jsp-el-unescaped-param이 담당)
        jsp = "<td>${param.keyword}</td>\n"
        self.assertNotIn("jsp-el-unescaped-model", _scan("board.jsp", jsp))


class TestFrontendXss(unittest.TestCase):
    """P4 Task 4 — 프론트엔드(Vue/Nuxt) XSS frontend 모드.

    v-html 미새니타이즈(핵심 저장형 XSS 싱크)·insertAdjacentHTML/outerHTML·eval을 잡되,
    sanitize/DOMPurify 래핑은 제외. node_modules 오염 배제. frontend 스택 감지.
    """

    _FX = os.path.join(_ROOT, "tests", "fixtures", "xss", "frontend")

    def _scan_dir(self, d):
        return scan_xss.run_fallback(d)

    def test_fixture_vuln_detected(self):
        cands = self._scan_dir(os.path.join(self._FX, "vuln"))
        rule_ids = {c["rule_id"] for c in cands}
        self.assertIn("vue-v-html-unsanitized", rule_ids)
        self.assertGreaterEqual(len(cands), 1)
        # frontend 스택으로 태깅됐는지
        self.assertTrue(any(c["stack"] == "frontend" for c in cands))

    def test_fixture_safe_clean(self):
        # DOMPurify.sanitize 래핑 v-html + 텍스트 보간 → 후보 0
        cands = self._scan_dir(os.path.join(self._FX, "safe"))
        self.assertEqual(cands, [], f"안전 픽스처 오탐: {[c['rule_id'] for c in cands]}")

    def test_v_html_unsanitized_flagged(self):
        self.assertIn("vue-v-html-unsanitized",
                      _scan("C.vue", '<div v-html="post.content"></div>\n'))

    def test_v_html_sanitized_not_flagged(self):
        self.assertNotIn("vue-v-html-unsanitized",
                         _scan("C.vue", '<div v-html="DOMPurify.sanitize(post.content)"></div>\n'))

    def test_insertadjacenthtml_flagged(self):
        self.assertIn("dom-insertadjacenthtml-outerhtml",
                      _scan("c.ts", 'el.insertAdjacentHTML("beforeend", userInput)\n'))

    def test_eval_flagged(self):
        self.assertIn("js-eval-dynamic-code",
                      _scan("c.js", 'const r = eval(userInput)\n'))

    def test_detect_stacks_frontend(self):
        self.assertIn("frontend", scan_xss.detect_stacks(os.path.join(self._FX, "vuln")))

    def test_node_modules_not_scanned(self):
        # node_modules 하위 .vue 는 절대 후보에 들어가지 않는다(766개 노이즈 배제)
        with tempfile.TemporaryDirectory() as tmp:
            nm = os.path.join(tmp, "node_modules", "pkg")
            os.makedirs(nm)
            with open(os.path.join(nm, "Bad.vue"), "w", encoding="utf-8") as fh:
                fh.write('<div v-html="x"></div>\n')
            self.assertEqual(scan_xss.run_fallback(tmp), [])


class TestVHtmlAttributeScope(unittest.TestCase):
    """코드리뷰 finding — v-html sanitize 판정을 '속성값' 스코프로. 같은 줄의 다른 속성/주석의
    sanitize에 오도돼 미새니타이즈 v-html을 놓치면 안 된다."""

    def test_mixed_sanitized_and_raw_same_line_flagged(self):
        line = '<span v-html="sanitize(title)"></span><span v-html="rawBody"></span>\n'
        self.assertIn("vue-v-html-unsanitized", _scan("C.vue", line))

    def test_sibling_attr_sanitize_still_flagged(self):
        line = '<div v-html="rawUserContent" :title="sanitize(tooltip)"></div>\n'
        self.assertIn("vue-v-html-unsanitized", _scan("C.vue", line))

    def test_comment_purify_still_flagged(self):
        line = '<div v-html="rawComment"></div><!-- TODO purify later -->\n'
        self.assertIn("vue-v-html-unsanitized", _scan("C.vue", line))

    def test_all_sanitized_not_flagged(self):
        line = '<span v-html="sanitize(a)"></span><span v-html="DOMPurify.sanitize(b)"></span>\n'
        self.assertNotIn("vue-v-html-unsanitized", _scan("C.vue", line))


if __name__ == "__main__":
    unittest.main()
