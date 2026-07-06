// 골든셋 취약 픽스처 (access): @PathVariable 어노테이션 값으로 id 계열 경로 변수 수신.
// dual-catch: fallback spring-pathvariable-annotated-id + semgrep sqisoft-spring-pathvariable-annotated-id.
public class Ctrl {
    public String get(@PathVariable("userId") Long uid) {
        return "x";
    }
}
