// FR-4 measured (ssrf): 하드코딩 상수 URL RestTemplate 호출. 사용자 입력 없음.
// semgrep sqisoft-ssrf-resttemplate-var-call 는 컨텍스트 게이트가 없어 상수 URL도 후보화(과탐)
// → 그 실효(과탐 규모)를 CI 로그로 실측하기 위한 격리 픽스처. 골든셋 safe 아님.
public class Hardcoded {
    public String fetch() {
        RestTemplate rt = new RestTemplate();
        return rt.getForObject("https://fixed.internal/api", String.class);
    }
}
