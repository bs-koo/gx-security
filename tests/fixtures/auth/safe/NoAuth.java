// 골든셋 안전 픽스처 (auth): 시크릿/쿠키/약한해시/세션정책 없음 → 양엔진 0.
public class NoAuth {
    public int add(int a, int b) {
        return a + b;
    }
}
