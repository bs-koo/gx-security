---
name: detecting-auth-session-weaknesses
description: >-
  SQIsoft 웹 애플리케이션에서 인증(Authentication)·세션(Session)·JWT 관련 취약점을 검사한다.
  프로젝트 스택(Spring Boot 모던 / JSP·Servlet 레거시)을 자동 감지하여 스택별 Semgrep 룰로
  1차 탐지하고, AI가 세션 고정·약한 해시·JWT 설정 오류·쿠키 보안속성 누락을 컨텍스트로 검증한다.
  탐지 대상: 세션 재발급 누락(세션 고정), SHA-256 단순 해시 비밀번호(솔트 약함/BCrypt 미사용),
  JWT 시크릿 하드코딩·서명검증 우회 가능성, 쿠키 Secure/HttpOnly/SameSite 미설정,
  Refresh Token 쿠키 보안속성 누락, 세션 타임아웃 미설정.
domain: cybersecurity
subdomain: web-application-security
tags:
  - authentication
  - session-management
  - jwt
  - session-fixation
  - weak-password-hash
  - cookie-security
  - cwe-287
  - cwe-384
  - cwe-916
  - cwe-614
  - owasp-a07
  - spring-security
  - jsp
  - servlet
  - sqisoft
cwe:
  - CWE-287
  - CWE-384
  - CWE-916
  - CWE-614
  - CWE-798
owasp:
  - A07:2021-Identification-and-Authentication-Failures
stacks:
  - spring-modern
  - jsp-legacy
version: "0.1"
author: sqisoft-security
license: Proprietary
---

# 인증·세션·JWT 취약점 검사

## When to Use

다음 중 하나라도 해당하면 이 스킬을 실행한다.

- 로그인 성공 후 세션 ID가 재발급되는지 확인할 때 (세션 고정 공격 방어 여부)
- 비밀번호 저장 방식이 BCrypt인지, SHA-256 단순 해시인지 확인할 때
- JWT 시크릿 키가 코드·설정 파일에 하드코딩됐는지, 서명 검증이 적절한지 확인할 때
- Refresh Token 쿠키에 `HttpOnly`, `Secure`, `SameSite=Strict` 속성이 있는지 확인할 때
- 세션 타임아웃·동시 세션 제한이 설정됐는지 확인할 때

**이 스킬을 쓰지 않을 때:** 접근통제·IDOR(→ `detecting-broken-access-control`),
CSRF 위조(→ `detecting-csrf-vulnerabilities`), SQL 인젝션·XSS 등 다른 취약점 클래스.

## Prerequisites

- 대상 프로젝트 소스에 대한 읽기 접근
- (선택, 권장) `semgrep` 설치 — 없으면 `scripts/scan_auth.py`가 grep 폴백으로 동작
- 스택 판별 참고: `references/stack-patterns.md`

## Workflow

### 0단계 — 스택 자동 감지

| 스택 | 감지 신호 | 적용 룰 |
|---|---|---|
| `spring-modern` | `build.gradle.kts` / `settings.gradle*`, `src/main/java/**` | `rules/auth-session.yml`의 spring 룰 |
| `jsp-legacy` | `**/WEB-INF/web.xml`, `*.jsp`, `src/main/webapp/**` | `rules/auth-session.yml`의 jsp 룰 + AI 패턴 검사 |

### 1단계 — 스캐너 1차 탐지 (재현 가능)

```bash
python skills/detecting-auth-session-weaknesses/scripts/scan_auth.py "$TARGET" --json
```

스크립트는 스택을 감지해 Semgrep 룰을 실행하고, 없으면 grep 폴백으로 후보를 수집한다.
출력: `{file, line, rule_id, stack, snippet}` 목록.

### 2단계 — AI 컨텍스트 검증 (핵심)

스캐너 후보는 출발점일 뿐이다. 각 후보를 아래 기준으로 직접 검증한다.

**spring-modern 검증 포인트**

1. **JWT 시크릿 키 관리** — `JwtTokenProvider.java` 실사례 확인:
   - `@Value("${security.jwt.secret-key}")` + `${JWT_SECRET_KEY}` 환경변수 주입 → 안전
   - 코드에 문자열 리터럴로 하드코딩(`private String secretKey = "my-secret"`) → 위험
   - 키 길이 검증 로직(`MINIMUM_KEY_LENGTH = 64`) 존재 → 양호
   - 개발 환경에서 짧은 키 시 자동 랜덤 키 생성 + 로그 출력 → 운영 환경 실수 방지 확인

2. **JWT 서명 검증** — `validateToken()` 메서드:
   - `Jwts.parser().verifyWith(key).build().parseSignedClaims(token)` 패턴 → 정상
   - `alg=none` 허용 여부: jjwt 0.12.x 기본은 none 거부. `Jwts.parser()`에 별도 허용 없으면 안전
   - `ExpiredJwtException` 처리: 만료 토큰 재사용 방지 확인

3. **Refresh Token 쿠키 보안속성** — `application.yml` / `AuthController`:
   - `security.cookie.secure: ${COOKIE_SECURE:false}` — 운영 환경에서 `false` 기본값 위험
   - `Refresh Token`이 쿠키에 담기는지, 담긴다면 `HttpOnly=true`, `Secure=true`, `SameSite=Strict` 설정 확인
   - `SessionCreationPolicy.STATELESS` 확인 → 서버 세션 미생성 (세션 고정 위험 없음)

4. **비밀번호 인코더** — `WebSecurityConfig.java`:
   - `BCryptPasswordEncoder` Bean 등록 → 양호
   - 실제로 회원가입·비밀번호 변경 로직에서 `passwordEncoder.encode()` 사용 확인

**jsp-legacy 검증 포인트**

1. **비밀번호 해시 방식** — `context-security.xml` / `EgovFileScrty.java`:
   - `hash="plaintext"`, `hashBase64="true"` → **평문 저장** (실제 운영 DB에 Base64만 적용, 해시 없음)
   - `EgovFileScrty.encryptPassword(password, id)` — SHA-256 + 사용자 ID를 salt로 사용
   - SHA-256은 BCrypt보다 훨씬 빠르므로 대규모 브루트포스에 취약. BCrypt/Argon2 전환 권장
   - `@Deprecated` 된 `encryptPassword(String data)` — salt 없는 SHA-256 단순 해시, 더 위험

2. **세션 고정(Session Fixation)** — `MemberController.memberLoginAction()`:
   - 로그인 성공 후 `req.getSession().setAttribute("LoginVo", loginVo)` 직전에
     `req.getSession().invalidate()` 또는 `changeSessionId()` 호출 여부 확인
   - `springSecurity.doFilter(...)` 호출 시 Spring Security가 세션을 재생성하는지 확인
   - `context-security.xml`에 `session-fixation-protection` 명시 없으면 기본값(`migrateSession`) 확인

3. **세션 타임아웃** — `web.xml`:
   - `<session-timeout>30</session-timeout>` → 30분 설정. 업무 특성상 적절한지 확인
   - 동시 접속 제한: `concurrentMaxSessons="10"` → 10개. 1개로 제한해야 계정 공유 방지

4. **자동로그인 쿠키** — `MemberController` / 세션 쿠키 설정:
   - `<tracking-mode>COOKIE</tracking-mode>` 확인
   - JSESSIONID 쿠키에 `HttpOnly`, `Secure` 속성 여부 → `web.xml cookie-config` 확인
   - SameSite는 Servlet 3.x에서 직접 설정 불가 — 서버(Tomcat) 레벨 설정 필요

**공통 — 누락 보강(스캐너가 못 잡는 것)**
- OTP/이메일 인증 우회 가능성 (토큰 만료 미검증)
- 계정 잠금 임계값·잠금 해제 정책 적절성
- 비밀번호 복잡도 정책 서버 검증 유무

### 3단계 — 사업부 표준 리포트

확정 항목만 아래 양식으로 출력. 스캐너 후보 중 검증 탈락은 "오탐 제외"에 남긴다.

## Output Format

```markdown
# 인증·세션·JWT 취약점 점검 리포트
- 대상: <프로젝트/경로>   | 감지 스택: <spring-modern | jsp-legacy | mixed>
- 스캐너: <semgrep vX.Y | grep-fallback>   | 점검일: <YYYY-MM-DD>

## 요약
- 확정 취약: N건 (High n / Medium n / Low n)
- 의도된 예외: M건   | 오탐 제외: K건

## 확정 취약점

### [High] 평문 비밀번호 저장 — context-security.xml:42
- 스택 / 위치: jsp-legacy / context-security.xml:42
- **① 취약한 점(What)**: `hash="plaintext"` + `hashBase64="true"` 설정으로 비밀번호가
  Base64 인코딩만 적용된 상태로 DB에 저장된다. Base64는 암호화가 아니며 즉시 복원 가능하다.
- **② 취약한 이유(Why)**: DB가 유출되면 모든 사용자 비밀번호가 노출된다.
  해시 없이 Base64만 적용하면 디코딩으로 원문 복원이 가능하다.
- **③ 뚫리는 방법(How · 개념 PoC)**:
  DB 덤프에서 `password` 컬럼 값을 Base64 디코딩하면 원문 비밀번호 획득.
  `echo "dXNlcjEyMzQ=" | base64 -d` → `user1234`
- **④ 해결방법(Fix)**:
  ```xml
  <!-- context-security.xml: hash를 bcrypt로 전환 -->
  hash="bcrypt"
  ```
  ```java
  // 가입/변경 시 BCryptPasswordEncoder 사용
  String encoded = new BCryptPasswordEncoder().encode(rawPassword);
  ```
  기존 사용자는 다음 로그인 시 재해시 로직(마이그레이션) 적용 필요.
- 참조: CWE-916, OWASP A07:2021

### [Medium] 세션 고정 취약점 — MemberController.java:331
- 스택 / 위치: jsp-legacy / MemberController.java:331
- **① 취약한 점(What)**: 로그인 성공 직전/직후에 세션 ID 재발급(`invalidate()` /
  `changeSessionId()`) 코드가 없다. Spring Security `doFilter` 호출로 처리되는지 불명확.
- **② 취약한 이유(Why)**: 공격자가 피해자에게 미리 알려진 세션 ID를 심어두고
  피해자가 로그인하면 공격자가 해당 세션 ID로 인증된 세션을 탈취한다.
- **③ 뚫리는 방법(How · 개념 PoC)**:
  공격자가 JSESSIONID 쿠키를 피해자 브라우저에 심은 후, 피해자가 로그인하면
  동일 JSESSIONID로 인증 완료 → 공격자가 해당 쿠키로 접근.
- **④ 해결방법(Fix)**:
  ```java
  // MemberController.memberLoginAction — 로그인 성공 후 세션 재생성
  HttpSession oldSession = req.getSession(false);
  if (oldSession != null) {
      oldSession.invalidate();
  }
  HttpSession newSession = req.getSession(true);
  newSession.setAttribute("LoginVo", loginVo);
  ```
- 참조: CWE-384, OWASP A07:2021

### [Low] Refresh Token 쿠키 Secure 속성 기본값 false — application.yml:121
- 스택 / 위치: spring-modern / application.yml:121
- **① 취약한 점(What)**: `security.cookie.secure: ${COOKIE_SECURE:false}` — 환경변수
  미설정 시 운영 환경에서도 `Secure` 속성 없이 쿠키 발행.
- **② 취약한 이유(Why)**: HTTP 평문 채널에서 쿠키가 전송되면 네트워크 도청으로 탈취 가능.
- **③ 뚫리는 방법(How · 개념 PoC)**:
  내부망 중간자(ARP 스푸핑 등) 환경에서 HTTP 요청 패킷 캡처 시 Refresh Token 쿠키 노출.
- **④ 해결방법(Fix)**:
  ```yaml
  security:
    cookie:
      secure: ${COOKIE_SECURE:true}   # 기본값을 true로 전환
  ```
  운영 환경 HTTPS 강제 적용 확인 후 변경.
- 참조: CWE-614, OWASP A07:2021

## 의도된 예외 (확인 필요)
- [Info] JwtTokenProvider — 시크릿 키 환경변수(`${JWT_SECRET_KEY}`) 주입, 64바이트 최소 길이 검증 → 안전

## 오탐 제외
- JwtTokenProvider.validateToken() — `verifyWith(key)`로 서명 검증, 만료/폐기 검증 정상.
  alg=none 허용 코드 없음.
```

## Verification (검사 자체의 신뢰성 확인)

- [ ] 스택 감지 결과가 실제 프로젝트와 일치하는가
- [ ] `context-security.xml`의 `hash=` 값을 코드로 직접 확인했는가
- [ ] 로그인 핸들러에서 세션 재생성 코드를 확인했는가(추측 금지)
- [ ] JWT `validateToken()` 메서드가 서명·만료·폐기를 모두 검증하는가
- [ ] Refresh Token 쿠키에 `HttpOnly`, `Secure`, `SameSite` 속성이 모두 있는가
- [ ] 시크릿 키가 환경변수·외부 볼트로 주입되는가(코드 내 리터럴 금지)
- [ ] 각 확정 취약점에 재현 근거(파일:라인)가 붙어 있는가

## Key Concepts

| 용어 | 설명 |
|---|---|
| 세션 고정(Session Fixation) | 로그인 전후 세션 ID가 동일 → 미리 심어둔 세션으로 탈취 가능 |
| SHA-256 단순 해시 | 빠른 연산 = 대규모 브루트포스에 취약. BCrypt/Argon2로 전환 필요 |
| BCrypt | 의도적으로 느린 해시 함수 — 솔트 내장, 워크팩터 조정 가능 |
| JWT alg=none | 서명 없는 토큰 허용 취약점. jjwt 0.12.x는 기본 거부. 명시적 허용 코드 확인 |
| Secure 쿠키 | HTTPS 채널에서만 전송 — HTTP 도청 방지 |
| HttpOnly 쿠키 | JavaScript 접근 차단 — XSS를 통한 쿠키 탈취 방지 |
| SameSite=Strict/Lax | 크로스사이트 요청에서 쿠키 전송 제한 — CSRF 보조 방어 |
| COOKIE_SECURE:false | 기본값 false → 운영 환경 실수 위험. 기본값 true 권장 |

## Tools & Systems

- Semgrep (룰: `rules/auth-session.yml`) · grep 폴백
- Spring Security (`BCryptPasswordEncoder`, `SessionCreationPolicy`), eGovFrame Security
- 참고: `references/stack-patterns.md`
- sef-2026 실사례: `JwtTokenProvider.java`(서명 검증), `WebSecurityConfig.java`(BCrypt), `application.yml`(cookie.secure)
- Gseed 실사례: `context-security.xml`(hash=plaintext), `MemberController.java`(세션 재생성), `EgovFileScrty.java`(SHA-256)
