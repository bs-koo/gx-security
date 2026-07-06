// 골든셋 취약 픽스처 (csrf): Spring Security CSRF 보호 비활성화.
// dual-catch: fallback spring-csrf-disabled + semgrep sqisoft-spring-csrf-disabled.
public class Sec {
    public void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
    }
}
