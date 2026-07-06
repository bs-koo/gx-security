// 골든셋 취약 픽스처 (pathtraversal): 요청 파라미터를 정규화 없이 new File 에 연결(CWE-22).
// dual-catch: fallback jsp-getparam-to-file/spring-new-file-with-param
//             + semgrep sqisoft-spring-requestparam-to-path(new File($BASE + $PARAM)).
import java.io.File;

public class Dl {
    public File load(String base, HttpServletRequest request) {
        return new File(base + request.getParameter("f"));
    }
}
