// 골든셋 안전 픽스처 (xss): 출력 전 HTML 인코딩 → 폴백/semgrep 모두 반사형 XSS 룰 미검출(0).
public class Servlet {
    public void handle(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
        response.getWriter().print(Encode.forHtml(request.getParameter("q")));
    }
}
