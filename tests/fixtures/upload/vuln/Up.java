// 골든셋 취약 픽스처 (upload): 검증 없이 원본 파일명으로 transferTo(CWE-434).
// dual-catch: fallback spring-transferto/spring-originalfilename-direct
//             + semgrep sqisoft-spring-transferto-without-validation/originalfilename-direct-use.
import java.io.File;

public class Up {
    public void save(MultipartFile mf, File dir) throws Exception {
        mf.transferTo(new File(dir, mf.getOriginalFilename()));
    }
}
