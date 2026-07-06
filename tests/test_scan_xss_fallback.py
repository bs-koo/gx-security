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


if __name__ == "__main__":
    unittest.main()
