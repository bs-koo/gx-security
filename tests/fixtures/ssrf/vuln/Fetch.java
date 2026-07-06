// 골든셋 취약 픽스처 (ssrf): RestTemplate 로 사용자 유래 URL을 서버측 요청(SSRF).
// dual-catch: fallback ssrf-resttemplate(RestTemplate 컨텍스트 존재) + semgrep sqisoft-ssrf-resttemplate-var-call.
public class Fetch {
    public String fetch(String userUrl) {
        RestTemplate rt = new RestTemplate();
        return rt.getForObject(userUrl, String.class);
    }
}
