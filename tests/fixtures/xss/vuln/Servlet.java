// 골든셋 취약 픽스처 (xss): 사용자 입력을 이스케이프 없이 응답 스트림에 직접 출력(반사형 XSS).
// dual-catch: fallback servlet-getwriter-reflected-xss + semgrep sqisoft-spring-servlet-reflected-xss-writer.
public class Servlet {
    public void handle(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
        response.getWriter().print(request.getParameter("q"));
    }
}
