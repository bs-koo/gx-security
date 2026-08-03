---
name: detecting-broken-access-control
description: >-
  SQIsoft 웹 애플리케이션에서 IDOR(Insecure Direct Object Reference)·BFLA(Broken Function-Level
  Authorization)·강제 브라우징(Forced Browsing) 등 접근통제 취약점을 검사한다.
  프로젝트 스택(Spring Boot 모던 / JSP·Servlet 레거시)을 자동 감지하여 스택별 Semgrep 룰로
  1차 탐지하고, AI가 소유권 검증 유무·권한 체크 누락을 컨텍스트로 검증한다.
  탐지 대상: PathVariable/파라미터 ID 소유권 미검증, 관리자 컨트롤러 @PreAuthorize 누락,
  SecurityConfig adminPaths 미보호, JSP 관리자 URL 강제 브라우징, 메뉴 숨김에만 의존한 접근통제.
domain: cybersecurity
subdomain: web-application-security
tags:
  - broken-access-control
  - idor
  - bfla
  - forced-browsing
  - cwe-639
  - cwe-284
  - cwe-285
  - owasp-a01
  - spring-security
  - jsp
  - servlet
  - sqisoft
cwe:
  - CWE-639
  - CWE-284
  - CWE-285
owasp:
  - A01:2021-Broken-Access-Control
stacks:
  - spring-modern
  - jsp-legacy
version: "0.8.0"
author: sqisoft-security
license: Proprietary
---

# 접근통제 취약점 검사 (Broken Access Control / IDOR / BFLA)

## When to Use

다음 중 하나라도 해당하면 이 스킬을 실행한다.

- SQIsoft 프로젝트(`sqisoft-sef-2026`, `Gseed_Web_Renew`)에서 URL 파라미터(예: `?seq=`, `?userId=`, `{id}`)로
  객체를 조회·수정·삭제하는 엔드포인트가 있을 때 (IDOR 점검)
- 관리자 전용 API(`/adm/**`, `adminCerti/*.do` 등)에 역할 체크(`@PreAuthorize`, `AuthUtil.isAdmin`)가
  있는지 확인할 때 (BFLA 점검)
- 로그인 없이 JSP 관리자 페이지 URL을 직접 입력해 접근 가능한지 확인할 때 (강제 브라우징)
- `SecurityConfig`의 `anyRequest().permitAll()` 범위 안에 관리자 경로가 누락됐는지 확인할 때

**이 스킬을 쓰지 않을 때:** 읽기 전용 공개 조회(공지사항·자료실 목록), 인증 자체 결함(→ `detecting-auth-session-weaknesses`),
CSRF 위조(→ `detecting-csrf-vulnerabilities`).

## Prerequisites

- 대상 프로젝트 소스에 대한 읽기 접근
- (선택, 권장) `semgrep` 설치 — 없으면 `scripts/scan_access.py`가 grep 폴백으로 동작
- 스택 판별 참고: `references/stack-patterns.md`

## Workflow

### 0단계 — 스택 자동 감지

| 스택 | 감지 신호 | 적용 룰 |
|---|---|---|
| `spring-modern` | `build.gradle.kts` / `settings.gradle*`, `src/main/java/**` | `rules/access-control.yml`의 spring 룰 |
| `jsp-legacy` | `**/WEB-INF/web.xml`, `*.jsp`, `src/main/webapp/**` | `rules/access-control.yml`의 jsp 룰 + AI 패턴 검사 |

### 1단계 — 스캐너 1차 탐지 (재현 가능)

```bash
python skills/detecting-broken-access-control/scripts/scan_access.py "$TARGET" --json
```

스크립트는 스택을 감지해 Semgrep 룰을 실행하고, 없으면 grep 폴백으로 후보를 수집한다.
출력: `{file, line, rule_id, stack, snippet}` 목록.

### 2단계 — AI 컨텍스트 검증 (핵심)

스캐너 후보는 출발점일 뿐이다. 각 후보를 아래 기준으로 직접 검증한다.

#### 소유권/권한 판정 사다리 (모든 접근통제 후보에 필수 적용)

각 후보 엔드포인트를 아래 절차로 판정하고, **결과를 `secure` / `vulnerable` / `needs-runtime` 세 값 중 하나 + 근거 `파일:라인`으로 기록**한다. 스캐너가 후보에 붙인 `context` 블록(`method` · `annotations` · `delegates_to`)을 출발점으로 삼되, 반드시 소스를 직접 열어 확인한다. (스캐너는 강한 소유권 집행 신호가 있으면 이미 후보에서 제외하므로, 남은 후보는 "집행이 안 보이는" 것들이다 — 그래서 사다리가 필요하다.)

1. **자원 식별자 추출** — 후보가 다루는 ID를 특정한다: `@PathVariable` / `@RequestParam` / `getParameter("…")` / 요청 DTO 필드. 식별자가 없으면(예: 목록 조회) IDOR 후보에서 제외.
2. **집행 지점까지 추적** — `context.delegates_to`가 가리키는 서비스 → 도메인/매퍼를 **직접 열어**, 그 ID가 **인증 주체로 스코핑**되는지 확인한다: `WHERE user_id = #{principal}` · `findByIdAndOwner(id, me)` · 도메인 `validateOwner(userId)` · `@PreAuthorize("@auth.owns(#id)")`.
3. **3-값 판정 + 근거 인용**:
   - **secure** — 소유권/역할이 실제로 강제됨(위 스코핑 · `@Pre/PostAuthorize` 소유권 표현 · 도메인 `validateOwner` 확인). → **오탐 제외**에 근거 라인과 함께 남긴다.
   - **vulnerable** —
     - *IDOR*: 인증은 요구되나 자원이 principal로 스코핑되지 않음(id로 바로 조회/수정). 심각도는 **데이터 민감도**로 산정(개인정보·심사결과 = High).
     - *BFLA*: 관리자 경로가 URL 레벨 `.authenticated()`뿐이고(`context.annotations`에 `@PreAuthorize`/`@Secured` 없음) 핸들러·서비스에도 역할 필터가 없음.
   - **needs-runtime** — 집행이 정적으로 안 보이는 층(동적 SpEL · 외부 정책 엔진 · DB 룰 테이블 `TB_EG_SECU_ROLE_INFO`)에만 존재. **High로 단정하지 말고** `exploiting-broken-access-control`(사용자 2명 PoC) 또는 사람 확인으로 이관한다.
4. **불변식**: 서비스 계층에서 검증이 안 보인다는 이유만으로 `vulnerable`로 확정하지 않는다 — 도메인 계층까지 (2)를 끝냈거나 `needs-runtime`으로 넘긴 뒤에만 판정한다(sef-2026 rich domain `BoardComment.validateOwner` 실사례).

아래 스택별 포인트는 이 사다리의 (2) 집행 추적을 스택 문법에 맞게 구체화한 것이다.

**spring-modern 검증 포인트**

1. `@GetMapping("/{id}")` / `@PathVariable` 사용 엔드포인트에서 **세션 사용자 == 리소스 소유자** 확인 여부.
   - `@AuthenticationPrincipal SecurityUser user`로 받은 `user.getUserId()`를 서비스단에서
     조회 결과의 소유자 ID와 비교하는지 확인.
   - `sef-2026` 기준: `UserController`는 `user.getUserId()`를 서비스에 전달하나, 다른 도메인 컨트롤러에서
     동일 패턴을 사용하는지 각각 확인 필요.
   - **추적 깊이(필수)**: 검증은 Controller → Service → **Domain** 순으로 따라간다. 서비스가
     `entity.update(userId)` / `entity.delete(userId)`를 호출하면 그 도메인 메서드 내부(`validateOwner` 등)를
     **반드시 열어** 확인한다. 서비스 계층에서 검증이 안 보인다고 IDOR로 확정하지 않는다.
     (sef-2026은 rich domain — `BoardComment.validateOwner` 실사례)
   - **반례 우선**: Swagger 명세에 "본인만"이라는데 서비스에 검증이 없으면, "명세-구현 불일치"가 아니라
     **검증이 다른 계층(도메인)에 있다는 신호**로 먼저 의심한다.
   - **동적 미확정**: IDOR/BFLA는 사용자 2명 PoC로 동적 확정해야 한다(→ `exploiting-broken-access-control`).
     동적 발사를 못 했으면 High 확정이 아니라 **"정적 추정(미확정)"** 으로 표기한다.
2. `/adm/v1/**` 경로 컨트롤러에 `@PreAuthorize("hasMenuAuthority(...)")` 또는 클래스 레벨 어노테이션이 있는지.
   - `WebSecurityConfig`에서 `adminPaths(/adm/v1/**)` 는 `.authenticated()`만 요구 — **역할 구분 없음**.
   - 관리자 컨트롤러(`BoardAdminController`, `UserAdminController` 등)에 메서드 레벨 `@PreAuthorize` 없이
     `.authenticated()` 만으로 운영하면 일반 인증 사용자가 관리자 API 호출 가능 → BFLA.
3. `WebSecurityConfig`의 `anyRequest().permitAll()` 범위에 보호받지 않는 경로가 없는지.
   - `JWT_AUTH_WHITELIST` + `adminPaths` + `apiPaths` 외 경로는 `permitAll()` — 의도된 것인지 확인.

**jsp-legacy 검증 포인트**

1. `AuthInterceptor`의 `mode` 값(`off` / `audit` / `enforce`)을 확인.
   - `off` 또는 `audit`이면 인터셉터가 비인증 접근을 허용 → 강제 브라우징 가능.
   - `enforce`라도 `WHITELIST`에 관리자 URL이 포함된 경우 → 강제 브라우징 취약.
2. `CertiController`처럼 `loginVo = (LoginVo) req.getSession().getAttribute("LoginVo")` 후
   `loginVo.getId()`를 서비스에 넘기는 패턴 — 소유권 파라미터를 **세션에서** 가져오는지,
   아니면 `req.getParameter(...)`로 클라이언트에서 받는지 구분.
3. `AuthUtil.isAdmin(loginVo)` 체크가 있어도 `loginVo == null` 시 NullPointerException·bypass 가능성 확인.
4. `context-security.xml` DB 기반 URL 접근제어(`TB_EG_SECU_ROLE_INFO`)가 **실제로 데이터가 있는지** 확인.
   - 테이블이 비어있으면 Spring Security URL 룰이 무력화 → 인터셉터만 남은 상태.

**공통 — 누락 보강(스캐너가 못 잡는 것)**
- 응답에 불필요한 사용자 ID·내부 식별자가 포함되는 과다 노출(IDOR 가중 요인)
- 페이지네이션 API에서 본인 데이터만 반환하는지(`LIMIT`·WHERE 절 없는 전건 조회)

### 3단계 — 사업부 표준 리포트

확정 항목만 아래 양식으로 출력. 스캐너 후보 중 검증 탈락은 "오탐 제외"에 남긴다.

## Output Format

```markdown
# 접근통제 취약점 점검 리포트
- 대상: <프로젝트/경로>   | 감지 스택: <spring-modern | jsp-legacy | mixed>
- 스캐너: <semgrep vX.Y | grep-fallback>   | 점검일: <YYYY-MM-DD>

## 요약
- 확정 취약: N건 (High n / Medium n / Low n)
- 의도된 예외: M건   | 오탐 제외: K건
- **신뢰도**: 동적 확정 n건 / 정적 추정(미확정) m건
  - `동적 확정(dynamic)` = `exploiting-broken-access-control`로 실제 발사해 악용 입증
  - `정적 추정(static-only)` = 정적 분석만 — IDOR/BFLA는 동적 확정 전까지 High로 단정하지 않는다

## 접근통제 판정 매트릭스 (전 후보)

스캐너 후보 **전체**를 소유권/권한 사다리로 판정한 표. `secure`는 근거와 함께 오탐 제외로,
`needs-runtime`은 동적/사람 확인으로 이관한다. "N건 발견"이 아니라 "판정 완료"가 산출물이다.

| 엔드포인트(메서드) | 자원 ID | 소유권/역할 근거 (파일:라인) | 판정 | 심각도 |
|---|---|---|---|---|
| `DELETE /adm/v1/…/boards/{id}` (BoardAdminController.deleteBoard) | boardId | @PreAuthorize 없음 · 서비스 역할필터 없음 (BoardAdminController.java:57) | 🔴 vulnerable(BFLA) | High |
| `GET /api/v1/users/{id}` (UserController.get) | id | user.getUserId() 스코핑 (UserService.java:88) | ✅ secure | — |
| `GET /certiDetailPage.do?seq=` (CertiController) | seq | 세션 룰 DB 테이블 의존 · 정적 미확인 | 🟡 needs-runtime | (동적 확정) |

## 확정 취약점

### [High] BFLA — 관리자 API 역할 미검증 — BoardAdminController.java:57
- 스택 / 위치: spring-modern / BoardAdminController.java:57
- **① 취약한 점(What)**: `/adm/v1/menus/{menuId}/boards` 관리자 엔드포인트 전체에
  `@PreAuthorize` 없음. `WebSecurityConfig`는 `/adm/v1/**`을 `.authenticated()`만 요구.
- **② 취약한 이유(Why)**: 인증(로그인 여부)과 인가(역할·권한)는 별개다.
  일반 사용자도 유효한 JWT를 가지면 관리자 API를 호출할 수 있고,
  서비스 레이어에 별도 역할 검증이 없으면 데이터 조작이 가능하다.
- **③ 뚫리는 방법(How · 개념 PoC)**:
  일반 사용자로 로그인 후 발급받은 JWT로 `DELETE /adm/v1/menus/notice/boards/1` 호출.
  서버는 인증된 요청이므로 처리한다(역할 미검증).
- **④ 해결방법(Fix)**:
  ```java
  // 클래스 레벨 또는 각 메서드에 @PreAuthorize 추가
  @PreAuthorize("hasMenuAuthority('ADM_BOARD', 'D')")
  @DeleteMapping("/{boardId}")
  public ResponseEntity<?> deleteBoard(...) { ... }
  ```
  또는 `WebSecurityConfig`에서 `/adm/v1/**`을 `hasAuthority("ROLE_ADMIN")`으로 격상.
- 참조: CWE-285, OWASP A01:2021

### [Medium] IDOR — 인증서 상세 조회 소유권 미검증 — CertiController.java:172
- 스택 / 위치: jsp-legacy / CertiController.java:172
- **① 취약한 점(What)**: 인증신청 상세(`/certiDetailPage.do`)에서 `req.getParameter()`로 받은
  `seq`(신청번호)로 DB 조회 시 세션 사용자와의 소유권 비교 없음.
- **② 취약한 이유(Why)**: 타인의 신청번호를 파라미터로 넣으면 인증 여부와 무관하게
  다른 신청인의 개인정보·심사 결과를 조회할 수 있다.
- **③ 뚫리는 방법(How · 개념 PoC)**:
  로그인 후 `/certiDetailPage.do?seq=<타인_신청번호>` 접근.
- **④ 해결방법(Fix)**:
  ```java
  // 서비스 레이어에서 소유권 검증 추가
  CertiVo certi = certiDao.selectCerti(seq);
  if (certi == null || !certi.getUserId().equals(loginVo.getId())) {
      return "redirect:/accessDenied.do";
  }
  ```
- 참조: CWE-639, OWASP A01:2021

## 의도된 예외 (확인 필요)
- [Info] BoardController의 공개 게시판 조회(`hasMenuAuthority(#menuId, 'R')`)는
  공개 메뉴에 한해 인증 없이 허용 — 설계 의도.

## 오탐 제외
- UserController.java:64 — `@AuthenticationPrincipal`로 본인 userId 추출 후 서비스 전달, 소유권 검증 정상.
```

## Verification (검사 자체의 신뢰성 확인)

- [ ] 스택 감지 결과가 실제 프로젝트와 일치하는가
- [ ] 모든 `@PathVariable` / `req.getParameter()` ID 파라미터를 훑었는가
- [ ] 관리자 컨트롤러 전수에 `@PreAuthorize` 또는 클래스 레벨 권한 체크가 있는가
- [ ] JSP 관리자 경로가 `AuthInterceptor WHITELIST`에 잘못 포함되지 않았는가
- [ ] `context-security.xml` DB 룰 테이블이 비어있는지 확인했는가
- [ ] 각 확정 취약점에 재현 근거(파일:라인 + 인증 방식)가 붙어 있는가
- [ ] 모든 접근통제 후보를 3-값(secure / vulnerable / needs-runtime)으로 판정하고 근거 파일:라인을 인용했는가
- [ ] `needs-runtime` 후보를 `exploiting-broken-access-control` 또는 사람 확인으로 이관했는가(정적만으로 High 단정 금지)

## Key Concepts

| 용어 | 설명 |
|---|---|
| IDOR | 사용자가 직접 제어하는 파라미터(seq, id)로 타인 리소스에 접근 — 소유권 검증 부재가 원인 |
| BFLA | 인증은 됐으나 해당 기능을 사용할 **역할·권한**이 없는 사용자가 함수(API)를 호출 |
| 강제 브라우징 | URL을 직접 입력해 비인가 페이지에 접근 — 메뉴 숨김만으로는 방어 불충분 |
| @PreAuthorize | Spring Security 메서드 보안 어노테이션 — 역할/권한 표현식으로 접근 통제 |
| hasMenuAuthority | sef-2026 커스텀 SpEL 표현식 — 메뉴별 CRUD 권한(R/C/U/D) 확인 |
| AuthUtil.isAdmin | Gseed 레거시 관리자 판별 유틸 — `loginVo` null 체크 동반 필수 |
| anyRequest().permitAll() | Spring Security 미매칭 경로 전체 허용 — 누락 경로 오픈 위험 |

## Tools & Systems

- Semgrep (룰: `rules/access-control.yml`) · grep 폴백
- Spring Security (`@PreAuthorize`, `WebSecurityConfig`), eGovFrame `AuthInterceptor`
- 참고: `references/stack-patterns.md`
- sef-2026 실사례: `WebSecurityConfig.java`(adminPaths), `BoardAdminController.java`(@PreAuthorize 현황)
- Gseed 실사례: `AuthInterceptor.java`(mode/WHITELIST), `CertiController.java`(소유권 패턴)
