// 골든셋 안전 픽스처 (csrf): CSRF 활성(withDefaults) + CORS wildcard 없음 → 양엔진 0.
public class Sec {
    public void configure(HttpSecurity http) throws Exception {
        http.csrf(Customizer.withDefaults());
    }
}
