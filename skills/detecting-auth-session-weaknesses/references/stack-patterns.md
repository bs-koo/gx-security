# 인증·세션·JWT — 스택별 실제 코드 패턴

스캐너 룰과 AI 검증이 참조하는 SQIsoft 두 스택의 구체 패턴.
실제 사업부 코드(sef-2026 / Gseed_Web_Renew)에서 관찰된 형태 기준.

---

## spring-modern (Spring Boot + JWT SPA — sef-2026)

### 아키텍처 요약

- 인증: JWT Bearer 토큰 (STATELESS — `SessionCreationPolicy.STATELESS`)
- 세션: 서버 HttpSession 미사용 → 세션 고정 위험 없음
- 비밀번호: `BCryptPasswordEncoder` (WebSecurityConfig 등록)
- JWT 구현: `JwtTokenProvider.java` (jjwt 0.12.6)
- Refresh Token: 쿠키 저장 가능 (`security.cookie.secure` 환경변수)

---

### 취약 패턴 1 — JWT 시크릿 하드코딩

```java
// ⚠️ 코드에 직접 시크릿 리터럴 — 소스 유출 시 즉시 위험
@Value("${security.jwt.secret-key}")
private String secretKey = "my-hardcoded-secret-key-1234567890abcdef";
```

**sef-2026 실제 현황(안전):**

```java
// JwtTokenProvider.java — 환경변수 주입, 최소 길이 검증
@Value("${security.jwt.secret-key}")
private String secretKey;   // application.yml: ${JWT_SECRET_KEY}

@PostConstruct
public void init() {
    var keyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
    if (keyBytes.length < MINIMUM_KEY_LENGTH) {   // 64바이트 최소
        if (isDevelopmentEnvironment()) {
            keyBytes = generateSecureRandomKey();  // 개발 환경: 자동 생성
        } else {
            throw new IllegalStateException("JWT 시크릿 키 설정 오류");
        }
    }
    this.key = Keys.hmacShaKeyFor(keyBytes);
}
```

---

### 취약 패턴 2 — JWT 서명 검증 누락 / alg=none 허용

```java
// ⚠️ 서명 없이 파싱 (jjwt 구버전 패턴)
Jwts.parser().parseClaimsJwt(token);   // 서명 미검증

// ⚠️ 알고리즘 none 허용 (직접 허용 설정)
parser.setAllowedClockSkewSeconds(...)
      .parse(token);  // alg=none 토큰 허용 가능
```

**sef-2026 실제 현황(안전):**

```java
// JwtTokenProvider.validateToken() — verifyWith(key)로 서명 강제 검증
Jwts.parser()
    .verifyWith(key)          // HMAC 서명 검증 필수
    .build()
    .parseSignedClaims(token); // Signed 타입만 허용 (unsigned 거부)
// jjwt 0.12.x: parseSignedClaims는 alg=none 자동 거부
```

---

### 취약 패턴 3 — Refresh Token 쿠키 보안속성 미설정

```java
// ⚠️ Secure/HttpOnly/SameSite 없이 쿠키 발행
Cookie cookie = new Cookie("refreshToken", token);
cookie.setPath("/");
response.addCookie(cookie);
```

**안전 패턴:**

```java
ResponseCookie cookie = ResponseCookie.from("refreshToken", token)
    .httpOnly(true)              // JavaScript 접근 차단
    .secure(cookieSecure)        // HTTPS 전용 (운영: true)
    .sameSite("Strict")          // 크로스사이트 전송 차단
    .path("/api/v1/auth/refresh")
    .maxAge(refreshTokenValidity / 1000)
    .build();
response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
```

**sef-2026 점검 포인트:**

```yaml
# application.yml
security:
  cookie:
    secure: ${COOKIE_SECURE:false}   # ⚠️ 기본값 false — 운영 미설정 시 위험
```

---

### 취약 패턴 4 — BCryptPasswordEncoder 미사용

```java
// ⚠️ 약한 해시 또는 평문 저장
String encoded = DigestUtils.md5Hex(password);
String encoded = DigestUtils.sha256Hex(password);  // salt 없음
```

**sef-2026 실제 현황(안전):**

```java
// WebSecurityConfig.java
@Bean
public BCryptPasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();  // 솔트 내장, 의도적 느린 해시
}
```

---

### 판별 질문 (spring-modern)

- 시크릿 키가 `@Value` + 환경변수로 주입되는가? 코드 내 리터럴이 있는가?
- `parseSignedClaims()` 를 사용하는가? (`parseClaimsJwt()` 는 서명 미검증)
- Refresh Token 쿠키에 `HttpOnly=true`, `Secure=true`, `SameSite=Strict` 모두 있는가?
- `COOKIE_SECURE` 환경변수가 운영 서버에 실제로 설정됐는가?
- `BCryptPasswordEncoder`가 비밀번호 저장·검증에 실제 사용되는가?

---

## jsp-legacy (Spring MVC + eGovFrame 세션 — Gseed_Web_Renew)

### 아키텍처 요약

- 인증: HttpSession 기반, `LoginVo` 세션 저장
- 비밀번호: `context-security.xml` — `hash="plaintext"`, `hashBase64="true"`
  → **Base64만 적용, 실질적 평문 저장**
- 암호화 유틸: `EgovFileScrty.encryptPassword()` — SHA-256 + ID salt
- 세션 타임아웃: `web.xml` 30분
- 동시 세션: `concurrentMaxSessons="10"`

---

### 취약 패턴 1 — 평문(Base64) 비밀번호 저장

```xml
<!-- context-security.xml:42 — 실제 설정 -->
<egov-security:config
    hash="plaintext"          <!-- ⚠️ 해시 없음 -->
    hashBase64="true"         <!-- ⚠️ Base64는 인코딩, 암호화 아님 -->
    ...
/>
```

```
DB password 컬럼 값: "dXNlcjEyMzQ="
Base64 디코딩 → "user1234"  (즉시 복원)
```

---

### 취약 패턴 2 — SHA-256 단순 해시 (salt 약함)

```java
// EgovFileScrty.java — 실제 구현
// @Deprecated: salt 없는 버전
public static String encryptPassword(String data) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    hashValue = md.digest(plainText);  // ⚠️ 고정 salt 없음, 레인보우 테이블 취약
    return new String(Base64.encodeBase64(hashValue));
}

// 현재 사용 버전: ID를 salt로 사용 (개선됐으나 여전히 취약)
public static String encryptPassword(String password, String id) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.reset();
    md.update(id.getBytes());          // ⚠️ salt = 사용자 ID (예측 가능, 변경 불가)
    hashValue = md.digest(password.getBytes());
    // SHA-256은 빠름 → GPU 브루트포스에 취약
}
```

**안전 패턴:**

```java
// BCrypt 사용 (Spring Security)
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
String encoded = encoder.encode(rawPassword);
boolean match = encoder.matches(rawPassword, encoded);  // 검증
```

---

### 취약 패턴 3 — 세션 고정 (Session Fixation)

```java
// MemberController.memberLoginAction() — 실제 패턴
// 로그인 성공 후 세션 재생성 없이 setAttribute만 호출
req.getSession().setAttribute("LoginVo", loginVo);  // ⚠️ 세션 ID 유지

// springSecurity.doFilter() 호출로 Spring Security가 처리하나,
// session-fixation-protection 명시 없으면 기본값 확인 필요
```

**안전 패턴:**

```java
// 로그인 성공 후 반드시 세션 재생성
HttpSession oldSession = req.getSession(false);
if (oldSession != null) {
    oldSession.invalidate();              // 기존 세션 파기
}
HttpSession newSession = req.getSession(true);  // 새 세션 ID 발급
newSession.setAttribute("LoginVo", loginVo);
```

---

### 취약 패턴 4 — JSESSIONID 쿠키 보안속성 미설정

```xml
<!-- web.xml — 실제 설정 -->
<session-config>
    <session-timeout>30</session-timeout>
    <tracking-mode>COOKIE</tracking-mode>
    <!-- ⚠️ cookie-config 없음 — HttpOnly/Secure 미설정 -->
</session-config>
```

**안전 패턴:**

```xml
<session-config>
    <session-timeout>30</session-timeout>
    <tracking-mode>COOKIE</tracking-mode>
    <cookie-config>
        <http-only>true</http-only>   <!-- XSS 쿠키 탈취 방지 -->
        <secure>true</secure>         <!-- HTTPS 전용 (운영) -->
    </cookie-config>
</session-config>
```

SameSite는 Servlet 4.x 이하에서 직접 설정 불가 → Tomcat `context.xml`에서 설정:

```xml
<!-- Tomcat context.xml -->
<Context>
    <CookieProcessor sameSiteCookies="strict" />
</Context>
```

---

### 취약 패턴 5 — 동시 세션 과다 허용

```xml
<!-- context-security.xml -->
concurrentMaxSessons="10"   <!-- ⚠️ 10개 동시 접속 허용 — 계정 공유 가능 -->
```

업무 시스템에서는 1로 제한해 계정 공유·탈취 세션 감지 권장:

```xml
concurrentMaxSessons="1"
concurrentExpiredUrl="/accessExpired.do"
```

---

### 안전 패턴 (오탐 주의)

```java
// EgovMultiLoginPreventor — 중복 로그인 방지 (기존 세션 강제 만료)
// → 동시 세션 제한 기능 일부 구현됨. concurrentMaxSessons 설정과 중복 확인.

// context-security.xml hash=sha-256 (현재는 plaintext)
// → sha-256으로 변경됐다면 @Deprecated 버전인지 salt 버전인지 확인 필요.
```

---

## 공통 오탐(False Positive) 가이드

1. **SessionCreationPolicy.STATELESS** — Spring Boot JWT 앱: 서버 세션 없음 → 세션 고정 해당 없음
2. **BCryptPasswordEncoder 사용 확인** — Bean 등록만으로는 부족. 실제 인코딩 호출 여부 확인
3. **jjwt 0.12.x `parseSignedClaims()`** — alg=none 자동 거부. `parseClaimsJwt()` 와 혼동 금지
4. **`hash="sha-256"` 설정** — plaintext보다 나으나 BCrypt보다 취약. Medium으로 보고
5. **개발 환경 전용 설정** — `dev`/`local` 프로필 한정 설정은 운영 적용 여부 별도 확인

---
> 심각도 판정은 공통 루브릭을 따른다: [`docs/severity-rubric.md`](../../../docs/severity-rubric.md)
