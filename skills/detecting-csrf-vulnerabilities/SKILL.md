---
name: detecting-csrf-vulnerabilities
description: >-
  SQIsoft 웹 애플리케이션에서 CSRF(Cross-Site Request Forgery) 취약점을 검사한다.
  프로젝트 스택(Spring Boot 모던 / JSP·Servlet 레거시)을 자동 감지하여 스택에 맞는
  Semgrep 룰로 1차 탐지하고, AI가 상태변경 엔드포인트의 토큰 보호 유무를 컨텍스트로
  검증한다. Spring Security csrf().disable(), 토큰 없는 JSP form POST, 검증 없는 doPost,
  SameSite 미설정 쿠키 등을 찾는다.
domain: cybersecurity
subdomain: web-application-security
tags: [csrf, cwe-352, owasp-a01, spring-security, jsp, servlet, sqisoft]
cwe: [CWE-352]
owasp: [A01:2021-Broken-Access-Control]
stacks: [spring-modern, jsp-legacy]
version: "0.1"
author: sqisoft-security
license: Proprietary
---

# CSRF 취약점 검사 (Cross-Site Request Forgery)

## When to Use

다음 중 하나라도 해당하면 이 스킬을 실행한다.

- SQIsoft 프로젝트(예: `sqisoft-sef-2026`, `Gseed_Web_Renew`)의 **상태를 변경하는 요청**(로그인, 회원정보 수정, 게시글/댓글 작성·삭제, 관리자 설정 변경)을 점검할 때
- 보안 코드 리뷰 / 출시 전 점검에서 CSRF 보호 적용 여부를 확인할 때
- Spring Security 설정에서 `csrf().disable()`이 의심될 때, 또는 JSP `<form>`에 CSRF 토큰이 있는지 확인할 때

**이 스킬을 쓰지 않을 때:** 순수 읽기 전용 API, 인증이 전혀 없는 공개 정적 페이지, 또는 XSS/SQLi 등 다른 취약점 클래스(→ 해당 스킬 사용).

## Prerequisites

- 대상 프로젝트 소스에 대한 읽기 접근
- (선택, 권장) `semgrep` 설치 — 없으면 `scripts/scan_csrf.py`가 `grep` 폴백으로 동작
- 스택 판별 참고: `references/stack-patterns.md`

## Workflow

### 0단계 — 스택 자동 감지

대상 경로의 루트 신호를 확인해 스택을 판별한다. 한 리포에 둘이 섞이면 디렉토리별로 나눠 판별한다.

| 스택 | 감지 신호 | 적용 룰 |
|---|---|---|
| `spring-modern` | `build.gradle.kts`/`settings.gradle*`, `src/main/java/**`, `@Controller`/`@RestController` | `rules/csrf.yml`의 spring 룰 |
| `jsp-legacy` | `**/WEB-INF/web.xml`, `*.jsp`, `pom.xml`, `src/main/webapp/**` | `rules/csrf.yml`의 jsp 룰 + AI 패턴 검사 |

```bash
# 스택 신호 빠른 확인
ls "$TARGET"/build.gradle.kts "$TARGET"/settings.gradle.kts 2>/dev/null   # → spring-modern
find "$TARGET" -name web.xml -path '*WEB-INF*' -o -name '*.jsp' | head     # → jsp-legacy
```

### 1단계 — 스캐너 1차 탐지 (재현 가능)

```bash
python skills/detecting-csrf-vulnerabilities/scripts/scan_csrf.py "$TARGET" --json
```

스크립트는 스택을 감지해 알맞은 Semgrep 룰을 돌리고, Semgrep이 없으면 grep 폴백으로 후보를 잡는다. 출력은 `{file, line, rule_id, stack, snippet}` 목록.

### 2단계 — AI 컨텍스트 검증 (핵심)

스캐너 후보는 **출발점일 뿐**이다. 각 후보를 다음 기준으로 직접 검증한다.

**spring-modern 검증 포인트**
1. `http.csrf(csrf -> csrf.disable())` / `csrf().disable()`가 보이면 → **무조건 보호 비활성**인지, 아니면 stateless JWT API라서 의도적으로 끈 것인지 구분.
   - SPA가 **쿠키 기반 세션**이면 disable은 진짜 취약점.
   - **순수 stateless JWT(Authorization 헤더)**이고 쿠키 인증을 안 쓰면 CSRF 위험은 낮음 → "의도된 예외"로 표기하되 SameSite·CORS 설정 동반 확인.
2. `csrf().disable()`이 없으면 Spring Security가 기본 보호. 단 `@PostMapping`/`@PutMapping`/`@DeleteMapping`이 **SecurityFilterChain 적용 범위 밖**(permitAll 경로, 별도 필터 무시)인지 확인.
3. CSRF 토큰을 SPA에 어떻게 전달하는지(`CookieCsrfTokenRepository` + `XSRF-TOKEN`) 확인.

**jsp-legacy 검증 포인트**
1. 상태변경 `<form method="post">`에 **CSRF 토큰 hidden 필드**(예: `_csrf`, `OWASP CSRFGuard` 토큰)가 있는지.
2. 토큰이 있어도 **서버(Servlet `doPost`/Controller)에서 실제로 검증**하는지 — 발급만 하고 검증 안 하면 취약.
3. 전역 필터(`web.xml`의 CSRFGuard `FilterChainProxy`, 또는 자체 필터)가 있는지. 없으면 form별로 전수 확인 필요.
4. GET으로 상태를 변경하는 링크(`<a href="...delete?id=">`)는 토큰 유무와 무관하게 **설계 결함**으로 보고.

**공통 — 누락 보강(스캐너가 못 잡는 것)**
- SameSite 쿠키 속성(`Set-Cookie: ...; SameSite=Lax/Strict`) 미설정 → 보조 방어 부재로 기록.
- 멀티파트(파일 첨부) 업로드 폼의 토큰 처리.

### 3단계 — 사업부 표준 리포트

확정된 항목만 아래 양식으로 출력한다. 스캐너 후보 중 검증에서 탈락한 것은 "오탐 제외"에 간단히 남긴다.

## Output Format

```markdown
# CSRF 취약점 점검 리포트
- 대상: <프로젝트/경로>   | 감지 스택: <spring-modern | jsp-legacy | mixed>
- 스캐너: <semgrep vX.Y | grep-fallback>   | 점검일: <YYYY-MM-DD>

## 요약
- 확정 취약: N건 (High n / Medium n / Low n)
- 의도된 예외: M건   | 오탐 제외: K건

## 확정 취약점
### [High] CSRF 보호 전역 비활성 — SecurityConfig.java:42
- 스택 / 위치: spring-modern / SecurityConfig.java:42
- **① 취약한 점(What)**: `http.csrf(csrf -> csrf.disable())`로 모든 상태변경 엔드포인트(POST /api/member/update 등)에 CSRF 토큰 검증이 전혀 없음
- **② 취약한 이유(Why)**: 인증이 쿠키 세션(JSESSIONID)에 의존 → 브라우저는 크로스사이트 요청에도 쿠키를 자동 첨부하므로, 공격자는 피해자의 인증 상태를 그대로 빌려 요청을 위조할 수 있음
- **③ 뚫리는 방법(How · 개념 PoC)**: 로그인된 피해자가 공격자 페이지를 열면 자동 제출 폼이 피해자 세션으로 실행됨
  ```html
  <form action="https://victim/api/member/update" method="POST">
    <input name="email" value="attacker@evil.com">
  </form>
  <script>document.forms[0].submit()</script>
  ```
- **④ 해결방법(Fix)**: stateless가 아니면 disable 제거 후 토큰 보호 활성화
  ```java
  http.csrf(c -> c.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));
  // 프론트: XSRF-TOKEN 쿠키를 읽어 X-XSRF-TOKEN 헤더로 전송
  ```
- 참조: CWE-352, OWASP A01:2021

## 의도된 예외 (확인 필요)
- [Info] /api/auth/token 은 stateless JWT(헤더 인증)이라 CSRF 제외 — SameSite=Strict 동반 권장

## 오탐 제외
- SecurityConfig.java:55 actuator 헬스체크 permitAll — 상태변경 아님
```

## Verification (검사 자체의 신뢰성 확인)

- [ ] 스택 감지 결과가 실제 프로젝트와 일치하는가(섞인 경우 디렉토리별로 처리했는가)
- [ ] 모든 `@PostMapping`/`@PutMapping`/`@DeleteMapping` 또는 `<form method=post>`/`doPost`를 빠짐없이 훑었는가
- [ ] `csrf().disable()` 발견 시 stateless 여부를 코드로 확인했는가(추측 금지)
- [ ] 각 확정 취약점에 재현 근거(파일:라인 + 인증 방식)가 붙어 있는가
- [ ] SameSite·CORS 등 보조 방어 상태를 함께 기록했는가

## Key Concepts

| 용어 | 설명 |
|---|---|
| CSRF | 인증된 사용자의 브라우저를 이용해 의도하지 않은 상태변경 요청을 위조 |
| Synchronizer Token | 서버가 발급한 1회성 토큰을 form/헤더로 검증하는 표준 방어 |
| `csrf().disable()` | Spring Security CSRF 보호 해제 — stateless API가 아니면 위험 |
| SameSite 쿠키 | `Lax`/`Strict`로 크로스사이트 쿠키 전송 차단 — 보조 방어 |
| CSRFGuard | JSP/Servlet 레거시에서 흔히 쓰는 OWASP CSRF 필터 |

## Tools & Systems

- Semgrep (룰: `rules/csrf.yml`) · grep 폴백
- Spring Security, OWASP CSRFGuard(레거시)
- 참고: `references/stack-patterns.md`
