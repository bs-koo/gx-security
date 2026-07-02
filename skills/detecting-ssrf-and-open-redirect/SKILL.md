---
name: detecting-ssrf-and-open-redirect
description: >-
  SQIsoft 웹 애플리케이션에서 SSRF(Server-Side Request Forgery)와 오픈 리다이렉트(Open Redirect)
  취약점을 검사한다. 사용자 입력 URL을 서버측 HTTP 요청에 검증 없이 사용하는 패턴
  (RestTemplate, WebClient, HttpURLConnection, URL.openStream)과, 사용자 입력을
  그대로 리다이렉트 목적지로 사용하는 패턴(sendRedirect, "redirect:"+param, returnUrl/next 파라미터)을
  탐지한다. 내부망·클라우드 메타데이터(169.254.169.254) 접근 및 피싱 경유지 악용을 방지한다.
  CWE-918(SSRF), CWE-601(오픈 리다이렉트), OWASP A10:2021(SSRF), A01:2021(접근제어 실패)에 대응.
domain: cybersecurity
subdomain: web-application-security
tags:
  - ssrf
  - open-redirect
  - server-side-request-forgery
  - url-redirect
  - cwe-918
  - cwe-601
  - owasp-a10
  - owasp-a01
  - resttemplate
  - webclient
  - spring
  - jsp
  - sqisoft
cwe: [CWE-918, CWE-601]
owasp: [A10:2021-Server-Side-Request-Forgery, A01:2021-Broken-Access-Control]
stacks: [spring-modern, jsp-legacy]
version: "0.3.0"
author: sqisoft-security
license: Proprietary
---

# SSRF / 오픈 리다이렉트 취약점 검사

## When to Use

다음 중 하나라도 해당하면 이 스킬을 실행한다.

- SQIsoft 프로젝트에서 **사용자가 입력한 URL을 서버가 직접 HTTP 요청**(`RestTemplate`, `WebClient`, `HttpURLConnection`, `URL.openStream`)에 사용하는 코드를 점검할 때
- **로그인 후 리다이렉트 파라미터**(`returnUrl`, `next`, `redirectUrl`)를 검증 없이 사용하는지 확인할 때
- **`response.sendRedirect(request.getParameter(...))`** 또는 Spring **`"redirect:" + param`** 패턴이 있는지 확인할 때
- 외부 API 호출(주소검색, 공공데이터 API 등)에서 URL 구성에 사용자 입력이 섞이는지 확인할 때

**이 스킬을 쓰지 않을 때:** 하드코딩된 내부 URL만 사용하는 HTTP 클라이언트, 완전히 화이트리스트 검증된 리다이렉트, CSRF·XSS 등 다른 취약점 클래스(→ 해당 스킬 사용).

## Prerequisites

- 대상 프로젝트 소스에 대한 읽기 접근
- (선택, 권장) `semgrep` 설치 — 없으면 `scripts/scan_ssrf.py`가 정규식 폴백으로 동작
- 스택 판별 참고: `references/stack-patterns.md`

## Workflow

### 0단계 — 스택 자동 감지

| 스택 | 감지 신호 | 중점 검사 위치 |
|---|---|---|
| `spring-modern` | `build.gradle.kts`, `@RestController`, `application.yml` | RestTemplate/WebClient 빈, Controller redirect 반환값 |
| `jsp-legacy` | `WEB-INF/web.xml`, `*.jsp`, `pom.xml` | Servlet `response.sendRedirect`, Controller `"redirect:"`, URL.openStream |

### 1단계 — 스캐너 1차 탐지 (재현 가능)

```bash
python skills/detecting-ssrf-and-open-redirect/scripts/scan_ssrf.py <TARGET> --json
```

스크립트는 스택을 감지해 Semgrep 룰 또는 정규식 폴백으로 후보를 잡는다.
출력은 `{file, line, rule_id, stack, snippet}` 목록.

### 2단계 — AI 컨텍스트 검증 (핵심)

스캐너 후보는 **출발점일 뿐**이다. 각 후보를 다음 기준으로 직접 검증한다.

**SSRF 검증 포인트**

1. HTTP 클라이언트(`RestTemplate`, `URL.openStream` 등) 호출 코드를 찾으면 → **URL이 어디서 왔는지** 역추적.
   - `request.getParameter("url")` 등 **사용자 입력이 URL에 직접 또는 간접 포함**되면 → 취약.
   - **설정 파일(`@Value`, `application.yml`)에서 읽어온 고정 URL** → 오탐.
   - **내부 로직이 URL을 완전히 생성**하고 사용자 입력은 keyword 같은 파라미터만 포함 → 일부 위험(인젝션 가능성 확인).
2. Gseed `CertiController.java:1444` — `apiUrl`에 `keyword="+URLEncoder.encode(keyword,"UTF-8")` 포함: URL 도메인(juso.go.kr)은 고정이지만 keyword 파라미터가 사용자 입력 → **파라미터 인젝션 위험은 낮음, SSRF 위험은 낮음** (도메인 고정). 단 URL 객체 자체를 외부 입력으로 바꿀 수 있으면 즉시 SSRF.
3. 내부망 IP 범위(`10.x`, `172.16-31.x`, `192.168.x`, `169.254.169.254`) 또는 `localhost`/`file://` 스킴 접근 차단 여부 확인.

**오픈 리다이렉트 검증 포인트**

1. `response.sendRedirect(...)` 또는 `"redirect:" + 변수`를 찾으면 → **변수 값이 사용자 입력인지** 확인.
   - `response.sendRedirect(request.getContextPath() + "/memberLoginForm.do")` → 경로가 **하드코딩** → 오탐.
   - `"redirect:/memberLoginForm.do"` → 하드코딩 상수 → 오탐.
   - `response.sendRedirect(request.getParameter("returnUrl"))` → 즉시 취약.
   - `"redirect:" + request.getParameter("next")` → 즉시 취약.
2. 로그인 성공 후 `returnUrl`/`next` 파라미터로 이동하는 코드가 있으면 → 도메인 화이트리스트·상대경로 검증 여부 확인.
3. Spring MVC 컨트롤러에서 `RedirectAttributes` 또는 `HttpServletResponse.sendRedirect` 사용 패턴 전수 확인.

**공통 — 스캐너가 못 잡는 것(AI 보강)**

- URL 조각을 여러 변수에 나눠 조합한 후 마지막에 HTTP 요청 → 데이터 흐름 추적 필요
- `@RequestParam String url`이 있는데 해당 메서드 내 HTTP 클라이언트 호출 없이 다른 서비스로 전달 → 간접 SSRF
- 리다이렉트 목적지가 DB에서 읽히는 경우 → DB 오염을 통한 2차 오픈 리다이렉트

### 3단계 — 사업부 표준 리포트

확정된 항목만 아래 양식으로 출력한다.

## Output Format

```markdown
# SSRF / 오픈 리다이렉트 점검 리포트
- 대상: <프로젝트/경로>   | 감지 스택: <spring-modern | jsp-legacy | mixed>
- 스캐너: <semgrep vX.Y | grep-fallback>   | 점검일: <YYYY-MM-DD>

## 요약
- 확정 취약: N건 (High n / Medium n / Low n)
- 의도된 예외: M건   | 오탐 제외: K건

## 확정 취약점

### [High] SSRF — 사용자 입력 URL로 서버측 HTTP 요청
- 스택 / 위치: jsp-legacy / SomeController.java:55
- **① 취약한 점(What)**: `request.getParameter("url")`로 받은 값을 URL 객체로 변환해 `url.openStream()` 직접 호출. 도메인·스킴 검증 없음
- **② 취약한 이유(Why)**: 서버가 공격자가 지정한 임의의 내부·외부 주소로 HTTP 요청을 보냄. 클라우드 환경에서는 인스턴스 메타데이터(169.254.169.254)에 접근해 IAM 자격증명 탈취 가능
- **③ 뚫리는 방법(How · 개념 PoC)**:
  ```
  GET /api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
  GET /api/fetch?url=http://10.0.0.1:8080/admin/
  GET /api/fetch?url=file:///etc/passwd
  ```
- **④ 해결방법(Fix)**: URL 화이트리스트 검증 후 요청
  ```java
  private static final Set<String> ALLOWED_HOSTS = Set.of("juso.go.kr", "api.example.com");
  URI uri = URI.create(userInput);
  if (!ALLOWED_HOSTS.contains(uri.getHost())) {
      throw new SecurityException("허용되지 않은 호스트: " + uri.getHost());
  }
  // 그 다음 HTTP 요청
  ```
- 참조: CWE-918, OWASP A10:2021

### [High] 오픈 리다이렉트 — 미검증 파라미터로 sendRedirect
- 스택 / 위치: jsp-legacy / LoginController.java:88
- **① 취약한 점(What)**: 로그인 성공 후 `response.sendRedirect(request.getParameter("returnUrl"))` — returnUrl 값을 검증 없이 사용
- **② 취약한 이유(Why)**: 공격자가 피해자에게 `/login?returnUrl=https://evil.com` 링크를 전송 → 정상 로그인 후 피싱 사이트로 리다이렉트
- **③ 뚫리는 방법(How · 개념 PoC)**:
  ```
  https://gseed.or.kr/memberLoginForm.do?returnUrl=https://evil.com
  ```
  피해자는 정상 도메인에 로그인 후 공격자 사이트로 이동
- **④ 해결방법(Fix)**: 상대경로만 허용하거나 화이트리스트 검증
  ```java
  String returnUrl = request.getParameter("returnUrl");
  // 상대경로만 허용
  if (returnUrl == null || returnUrl.startsWith("http") || returnUrl.startsWith("//")) {
      returnUrl = "/siteMain.do";
  }
  response.sendRedirect(request.getContextPath() + returnUrl);
  ```
- 참조: CWE-601, OWASP A01:2021

## 의도된 예외 (확인 필요)
- [Info] CertiController.java:1444 juso.go.kr API 호출 — URL 도메인 고정, keyword만 사용자 입력. SSRF 위험 낮음. 단 keyword에 URL 인젝션 불가 여부 확인 권장

## 오탐 제외
- AuthInterceptor.java:165 `response.sendRedirect(request.getContextPath() + "/memberLoginForm.do")` — 하드코딩 경로, 사용자 입력 없음
- CertiController.java:174 `return "redirect:/memberLoginForm.do"` — 하드코딩 상수
```

## Verification (검사 자체의 신뢰성 확인)

- [ ] `RestTemplate`, `WebClient`, `HttpURLConnection`, `URL.openStream` 호출 전체를 찾았는가
- [ ] 각 HTTP 클라이언트 호출의 URL이 사용자 입력에서 유래하는지 데이터 흐름을 추적했는가
- [ ] `sendRedirect`와 `"redirect:"` 패턴 전체에서 사용자 입력 여부를 확인했는가
- [ ] 하드코딩 경로/상수 리다이렉트를 오탐으로 올바르게 제외했는가
- [ ] URL 화이트리스트·도메인 검증·상대경로 제한 등 방어 코드가 있는지 확인했는가
- [ ] 클라우드 환경(AWS)인 경우 169.254.169.254 메타데이터 엔드포인트 차단 여부를 확인했는가

## Key Concepts

| 용어 | 설명 |
|---|---|
| SSRF | 서버가 공격자 지정 내부·외부 URL로 요청을 보내 내부망 정찰·메타데이터 탈취에 악용 |
| CWE-918 | Server-Side Request Forgery — 외부 입력으로 서버측 요청 대상 제어 |
| 오픈 리다이렉트 | 검증 없는 리다이렉트 목적지로 피싱 경유지·자격증명 탈취에 악용 |
| CWE-601 | URL Redirection to Untrusted Site — 미검증 리다이렉트 |
| 클라우드 메타데이터 | AWS `169.254.169.254` — SSRF로 접근 시 IAM 자격증명 탈취 가능 |
| URL 화이트리스트 | 허용된 호스트 목록으로만 서버측 요청 제한 — SSRF 방어 |
| 상대경로 제한 | `http://` 절대 URL 리다이렉트 차단, 자사 경로만 허용 — 오픈 리다이렉트 방어 |
| `URL.openStream` | Java 기본 HTTP 클라이언트 — 사용자 입력 URL 사용 시 SSRF 위험 |

## Tools & Systems

- Semgrep (룰: `rules/ssrf-redirect.yml`) · 정규식 폴백
- 참고: `references/stack-patterns.md`
- 관련 도구: OWASP ZAP (능동 스캔으로 SSRF/오픈리다이렉트 검증)
