// 골든셋 안전 픽스처 (ssrf): HTTP 호출/리다이렉트/returnUrl 파라미터 없음 → 양엔진 0.
public class NoEgress {
    public int sum(int a, int b) {
        return a + b;
    }
}
