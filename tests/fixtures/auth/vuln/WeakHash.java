// 골든셋 취약 픽스처 (auth): 비밀번호를 MD5(약한 해시)로 저장(CWE-916).
// D2 설계표는 cookie 멀티라인 폼을 제시했으나, semgrep 멀티라인 구조 룰은 로컬 검증이
// 불가하고 CI-green 리스크가 커, 폴백+semgrep 모두 단일 라인으로 확실히 잡는 MD5 폼으로 교체.
// dual-catch: fallback spring-weak-password-hash + semgrep sqisoft-spring-bcrypt-not-used.
import java.security.MessageDigest;

public class WeakHash {
    public byte[] hash(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password.getBytes());
    }
}
