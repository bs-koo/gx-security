# 접근통제 — 스택별 실제 코드 패턴

스캐너 룰과 AI 검증이 참조하는 SQIsoft 두 스택의 구체 패턴.
실제 사업부 코드(sef-2026 / Gseed_Web_Renew)에서 관찰된 형태 기준.

---

## spring-modern (Spring Boot + JWT SPA — sef-2026)

### 아키텍처 요약

- 인증: JWT Bearer 토큰 (STATELESS), 쿠키 세션 없음
- 인가 구조:
  - URL 레벨: `WebSecurityConfig` — `/adm/v1/**` → `.authenticated()`, `/api/v1/**` → `.authenticated()`
  - 메서드 레벨: `@PreAuthorize("hasMenuAuthority(#menuId, 'R')")` (MethodSecurityConfig 활성)
  - 커스텀 표현식: `MenuSecurityExpressionRoot.hasMenuAuthority(menuId, permission)`
- 소유권 추출: `@AuthenticationPrincipal SecurityUser user` → `user.getUserId()`

---

### 취약 패턴 1 — BFLA: 관리자 컨트롤러 @PreAuthorize 누락

```java
// BoardAdminController.java — 클래스/메서드 레벨 @PreAuthorize 없음
@RestController
@RequestMapping("/adm/v1/menus/{menuId}/boards")
public class BoardAdminController {

    @GetMapping                          // ⚠️ authenticated()만 통과하면 누구나 접근
    public ResponseEntity<?> list(...) { ... }

    @DeleteMapping("/{boardId}")         // ⚠️ 일반 사용자도 삭제 가능
    public ResponseEntity<?> delete(...) { ... }
}
```

**왜 취약한가:** `WebSecurityConfig`에서 `/adm/v1/**`을 `.authenticated()`로만 보호.
유효한 JWT를 가진 일반 사용자는 관리자 API에 접근 가능 → BFLA.

**안전 패턴:**

```java
// 클래스 레벨 — 모든 메서드에 적용
@PreAuthorize("hasMenuAuthority('ADM_BOARD', 'R')")
@RestController
@RequestMapping("/adm/v1/menus/{menuId}/boards")
public class BoardAdminController {

    @PreAuthorize("hasMenuAuthority('ADM_BOARD', 'D')")
    @DeleteMapping("/{boardId}")
    public ResponseEntity<?> delete(...) { ... }
}
```

---

### 취약 패턴 2 — IDOR: PathVariable 소유권 미검증

```java
// ⚠️ id가 PathVariable인데 본인/권한 검증 없이 서비스 호출
@GetMapping("/members/{id}")
public ResponseEntity<?> getMember(@PathVariable String id) {
    return ResponseEntity.ok(memberService.findById(id));   // 타인 id 조회 가능
}
```

**안전 패턴 (sef-2026 UserController 실사례):**

```java
@GetMapping("/me")
public ResponseEntity<?> getMyProfile(
        @AuthenticationPrincipal SecurityUser user) {
    // PathVariable 없이 세션 사용자 ID로만 조회 → IDOR 불가
    return ResponseEntity.ok(userService.findByUserId(user.getUserId()));
}
```

**안전 패턴 2 — rich domain 캡슐화 (sef-2026 BoardComment 실사례):**

```java
// 서비스: if 검증이 없지만 도메인 메서드에 위임 — 정상
comment.update(request.getCmntCn(), userId);   // BoardCommentServiceImpl
// 도메인(BoardComment): 검증이 여기 캡슐화됨
public void update(String content, String userId) {
    validateOwner(userId);   // rgtrId != userId 이면 FORBIDDEN
}
// → 서비스에 if가 없는 게 오히려 정상이다. 호출 체인을 도메인까지
//    추적해야 IDOR 오탐(서비스만 보고 '검증 없음'으로 단정)을 피한다.
```

---

### 취약 패턴 3 — anyRequest().permitAll() 사각지대

```java
// WebSecurityConfig.java — 실제 코드
.authorizeHttpRequests(authorize -> authorize
    .requestMatchers(JWT_AUTH_WHITELIST).permitAll()
    .requestMatchers(getIgnoredPaths()).permitAll()
    .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
    .requestMatchers(adminPaths.split(",")).authenticated()   // /adm/v1/**
    .requestMatchers(apiPaths.split(",")).authenticated()     // /api/v1/**
    .anyRequest().permitAll()    // ⚠️ 나머지 모든 경로 오픈
)
```

`/adm/v1/**`, `/api/v1/**` 에 포함되지 않는 내부 경로(예: 테스트용 경로, 마이그레이션 엔드포인트)가
있으면 인증 없이 접근 가능.

---

### 판별 질문 (spring-modern)

- 어드민 컨트롤러에 클래스/메서드 레벨 `@PreAuthorize`가 있는가?
  → 없으면 BFLA 후보
- `@PathVariable`이나 `@RequestParam`으로 받은 ID를 **세션 사용자와 교차 검증**하는가?
  → 없으면 IDOR 후보
- `anyRequest().permitAll()` 이전에 모든 보호 경로가 커버되는가?
  → 누락 경로 있으면 강제 브라우징 후보

---

## jsp-legacy (Spring MVC + eGovFrame 세션 — Gseed_Web_Renew)

### 아키텍처 요약

- 인증: HttpSession 기반, `LoginVo` 세션 저장
- 인가 구조:
  - Spring Security URL 룰: `context-security.xml` DB 테이블(`TB_EG_SECU_ROLE_INFO`) 기반
    → **실제 테이블이 비어있어 무력화됨** (AuthInterceptor 주석 참조)
  - 인터셉터: `AuthInterceptor` (mode: off/audit/enforce) — `globals.properties`로 제어
  - 컨트롤러 내 개별 가드: `AuthUtil.isAdmin(loginVo)`, `AuthUtil.isEnt(loginVo)`
- 소유권 추출: `(LoginVo) req.getSession().getAttribute("LoginVo")` → `loginVo.getId()`

---

### 취약 패턴 1 — 강제 브라우징: AuthInterceptor mode=off/audit

```java
// AuthInterceptor.java
private String mode = MODE_OFF;   // ⚠️ 기본값 off — 인터셉터 비활성

@Override
public boolean preHandle(...) {
    if (MODE_OFF.equals(mode)) {
        return true;   // 비활성: 모든 요청 통과
    }
    // audit: 차단 없이 로그만 수집
    if (MODE_AUDIT.equals(mode)) {
        log.warn("[AUTH-GATE][AUDIT] would-block path={}...", path);
        return true;   // ⚠️ 통과
    }
    ...
}
```

`enforce` 이외에는 비인증 사용자가 보호 URL에 접근 가능.

---

### 취약 패턴 2 — IDOR: 파라미터 기반 객체 조회 소유권 미검증

```java
// CertiController.java — 세션 userId를 서비스에 전달하는 안전 패턴(참고)
LoginVo loginVo = (LoginVo) req.getSession().getAttribute("LoginVo");
vo.setUserId(loginVo.getId());   // ← 세션에서 가져오므로 IDOR 불가

// ⚠️ 취약 패턴 — 클라이언트 파라미터를 소유권 필터 없이 직접 조회
String seq = req.getParameter("seq");
CertiVo result = certiDao.selectDetail(seq);   // 소유권 검증 없으면 타인 데이터 조회
```

상세 조회 메서드가 `WHERE seq = ?` 만 사용하고 `AND user_id = ?` 조건이 없으면 IDOR.

---

### 취약 패턴 3 — BFLA: 관리자 가드 null 안전성 문제

```java
// 일부 메서드: loginVo null 체크 누락 상태에서 isAdmin 호출
LoginVo loginVo = AuthUtil.getLoginVo(req);
if (!(AuthUtil.isAdmin(loginVo) || AuthUtil.isEnt(loginVo))) {
    return "redirect:/accessDenied.do";
}
// ↑ AuthUtil.isAdmin 내부에서 loginVo null 처리 방식 확인 필요.
// null을 받으면 NullPointerException → 500 오류 또는 예외 처리에 따라 통과 가능성.
```

---

### 취약 패턴 4 — DB URL 접근제어 무력화

```xml
<!-- context-security.xml -->
<!-- DB 기반 URL 룰: TB_EG_SECU_ROLE_INFO / TB_EG_SECU_AUTH_ROLE -->
<!-- ⚠️ AuthInterceptor 주석: "실제 DB 테이블이 비어있어 URL 단위 접근제어가 무력화됨" -->
<!-- → Spring Security URL 필터는 동작하나 룰이 없으면 차단 대상이 없음 -->
```

---

### 안전 패턴 (오탐 주의)

```java
// 세션에서 userId를 직접 추출해 서비스에 넘기는 패턴 — IDOR 아님
LoginVo loginVo = (LoginVo) req.getSession().getAttribute("LoginVo");
vo.setUserId(loginVo.getId());      // 세션 값 → 서버측 소유자 고정
vo.setOrgnztId(loginVo.getOrgnztId());  // 기관 ID도 세션 기반
// → 사용자가 직접 userId를 조작할 수 없으므로 IDOR 방어됨

// 관리자 체크 정상 패턴
LoginVo loginVo = AuthUtil.getLoginVo(req);
if (loginVo == null || !(AuthUtil.isAdmin(loginVo) || AuthUtil.isEnt(loginVo))) {
    return "redirect:/accessDenied.do";
}
// → null 체크 포함 시 안전
```

---

### 판별 질문 (jsp-legacy)

- `AuthInterceptor`의 실제 mode가 `enforce`인가? → `globals.properties` 확인 필수
- 상세 조회 SQL에 `WHERE seq = ? AND user_id = ?` 처럼 소유자 조건이 있는가?
- `AuthUtil.isAdmin` 호출 전 `loginVo == null` 체크가 있는가?
- `context-security.xml` DB 테이블에 실제 URL 룰이 등록되어 있는가?

---

## 공통 오탐(False Positive) 가이드

스캐너가 "관리자 경로" 또는 "ID 파라미터 접근"을 잡아도 아래는 취약이 아니다.

1. **세션에서 userId를 추출해 서비스에 전달** — 클라이언트가 조작 불가
2. **공개 리소스 조회** — 게시판 목록, 공지사항, 자료실 파일 등 로그인 없이 공개된 데이터
3. **@AuthenticationPrincipal 기반 본인 조회** — `/me` 패턴으로 PathVariable 없이 조회
4. **서비스 또는 도메인 계층에서 소유권 검증** — 컨트롤러·서비스에 `if` 검증이 안 보여도,
   서비스가 `entity.update(content, userId)` / `entity.delete(userId)` 같은 **도메인 메서드**를
   호출하면 검증(`validateOwner` 등)이 그 안에 캡슐화돼 있을 수 있다.
   **호출 체인을 도메인까지 따라가기 전에는 IDOR로 확정하지 않는다.**
   (sef-2026 `BoardComment.update()` → `validateOwner()` 실사례)
5. **화이트리스트 기반 공개 경로** — `JWT_AUTH_WHITELIST` / `AuthInterceptor.WHITELIST` 의도적 공개

오탐으로 판정하면 리포트의 "오탐 제외"에 사유 한 줄로 남긴다.
