# CSRF — 스택별 실제 코드 패턴

스캐너 룰과 AI 검증이 참조하는 SQIsoft 두 스택의 구체 패턴. 실제 사업부 코드에서 관찰되는 형태 기준.

---

## spring-modern (Spring Boot + JS SPA)

### 취약 패턴

```java
// SecurityConfig.java — 전역 비활성 (쿠키 세션이면 High)
@Bean
SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.csrf(csrf -> csrf.disable());   // ⚠️ 또는 .csrf().disable()
    return http.build();
}
```

```java
// 상태변경인데 보호 범위 밖 (permitAll로 통째 열림)
http.authorizeHttpRequests(a -> a.requestMatchers("/api/**").permitAll());
```

### 안전 패턴 (이건 취약 아님 — 오탐 주의)

```java
// SPA용 쿠키 토큰 저장소 — 정상 보호
http.csrf(csrf -> csrf.csrfTokenRepository(
        CookieCsrfTokenRepository.withHttpOnlyFalse()));
```

```java
// 진짜 stateless JWT (헤더 인증, 쿠키 미사용) — disable이 의도된 예외일 수 있음
http.csrf(csrf -> csrf.disable())
    .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
    .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
// → 단, 쿠키로 JWT를 보관하면 다시 CSRF 위험. SameSite 확인 필수.
```

### 판별 질문
- 인증 토큰이 **쿠키**에 있나(JSESSIONID / 쿠키 JWT)? → CSRF 위험 有, disable은 취약
- 인증이 **Authorization 헤더 only**인가? → 위험 낮음, disable은 의도된 예외 가능
- SPA 프론트는 토큰을 어디서 받아 어디로 보내나(`XSRF-TOKEN` 쿠키 → `X-XSRF-TOKEN` 헤더)?

---

## jsp-legacy (JSP/Servlet + Maven WAR)

### 취약 패턴

```jsp
<%-- 토큰 없는 상태변경 form (High) --%>
<form action="/board/delete.do" method="post">
  <input type="hidden" name="seq" value="${seq}">
  <button>삭제</button>
</form>
```

```jsp
<%-- GET으로 상태변경 — 설계 결함 (토큰과 무관하게 보고) --%>
<a href="/member/withdraw.do?id=${id}">탈퇴</a>
```

```java
// Servlet doPost — 토큰 검증 없음
protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
    String seq = req.getParameter("seq");
    boardDao.delete(seq);   // ⚠️ CSRF 토큰 확인 없이 바로 처리
}
```

### 안전 패턴

```jsp
<%-- 토큰 hidden 필드 (CSRFGuard / 자체 토큰) --%>
<form action="/board/write.do" method="post">
  <input type="hidden" name="_csrf" value="${csrfToken}">
  ...
</form>
```

```xml
<!-- web.xml — 전역 CSRF 필터 존재 (좋음) -->
<filter>
  <filter-name>CSRFGuard</filter-name>
  <filter-class>org.owasp.csrfguard.CsrfGuardFilter</filter-class>
</filter>
```

### 판별 질문
- 전역 CSRF 필터(`web.xml`의 CSRFGuard 등)가 있나? → 있으면 form별 누락만 확인. 없으면 **모든 상태변경 form 전수 점검**
- 토큰을 발급(JSP 출력)만 하고 서버에서 **검증**은 안 하나? → 검증 부재면 취약
- 상태변경을 GET으로 하는 링크가 있나? → 설계 결함

---

## 공통 보조 방어 (스캐너가 못 잡음 → AI가 보강)

| 점검 | 위치 | 판정 |
|---|---|---|
| SameSite 쿠키 | `Set-Cookie` 헤더 / 서버 세션 설정 / `application.yml server.servlet.session.cookie.same-site` | 미설정 시 Low(보조 방어 부재) |
| CORS 과허용 | `@CrossOrigin(origins="*")`, CorsConfiguration | `*` + credentials면 위험 가중 |
| 멀티파트 업로드 폼 | 파일 첨부 게시판 | 토큰 처리 동일하게 확인 |

---

## 오탐(False Positive) 가이드

스캐너가 `csrf().disable()` 또는 "토큰 없는 form"을 잡아도 아래는 취약이 아니다.

1. **순수 stateless REST**(헤더 JWT, 쿠키 인증 전무) + SameSite/CORS 적절 → 의도된 예외
2. **읽기 전용 form**(검색 `method=post`이지만 상태변경 없음) → 오탐
3. **내부 서버간 통신 엔드포인트**(브라우저 비경유, mTLS 등) → 위험 모델 다름

오탐으로 판정하면 리포트의 "오탐 제외"에 사유 한 줄로 남긴다.
