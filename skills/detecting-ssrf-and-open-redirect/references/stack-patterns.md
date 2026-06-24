# SSRF / 오픈 리다이렉트 — 스택별 실제 코드 패턴

스캐너 룰과 AI 검증이 참조하는 SQIsoft 두 스택의 구체 패턴. 실제 사업부 코드에서 관찰되는 형태 기준.

---

## spring-modern (Spring Boot + JS SPA)

### SSRF 취약 패턴

```java
// ⚠️ RestTemplate — 사용자 입력 URL 직접 사용
@GetMapping("/proxy")
public ResponseEntity<String> proxy(@RequestParam String url) {
    return restTemplate.getForEntity(url, String.class);  // ⚠️ SSRF
}

// ⚠️ WebClient — 사용자 입력 URL
return webClient.get()
    .uri(request.getParameter("targetUrl"))  // ⚠️
    .retrieve()
    .bodyToMono(String.class);

// ⚠️ URL 조각 + 사용자 입력 파라미터 → URL 전체를 조립
String apiUrl = "http://" + request.getParameter("host") + "/api/data";
restTemplate.getForObject(apiUrl, String.class);  // ⚠️ host 파라미터 제어 가능
```

### 오픈 리다이렉트 취약 패턴

```java
// ⚠️ "redirect:" + 파라미터 — 사용자 입력이 외부 URL이면 취약
@GetMapping("/login-success")
public String loginSuccess(@RequestParam String returnUrl) {
    return "redirect:" + returnUrl;  // ⚠️ returnUrl=https://evil.com
}

// ⚠️ HttpServletResponse.sendRedirect + 파라미터
@PostMapping("/login")
public void login(HttpServletResponse response, @RequestParam String next)
        throws IOException {
    // 인증 처리...
    response.sendRedirect(next);  // ⚠️
}
```

### 안전 패턴 (오탐 주의)

```java
// 도메인 화이트리스트 검증 (안전)
private static final Set<String> ALLOWED = Set.of("api.example.com", "juso.go.kr");
URI uri = URI.create(userInput);
if (!ALLOWED.contains(uri.getHost())) throw new SecurityException("불허 호스트");
restTemplate.getForObject(uri, String.class);

// 하드코딩 URL만 사용 (안전 — 오탐)
restTemplate.getForObject("https://internal.api/data", String.class);

// 상대경로 강제 (안전)
if (returnUrl == null || returnUrl.matches("^https?://.*")) {
    returnUrl = "/dashboard";
}
return "redirect:" + returnUrl;

// 하드코딩 리다이렉트 (안전 — 오탐)
return "redirect:/memberLoginForm.do";
// AuthInterceptor.java:165 response.sendRedirect(request.getContextPath() + "/memberLoginForm.do") → 오탐
```

### 판별 질문
- `RestTemplate`/`WebClient`에 넘기는 URL 변수가 `request.getParameter()`에서 왔는가?
- `"redirect:"` 뒤의 문자열이 상수인가, 사용자 입력인가?
- URL에 도메인·스킴이 고정돼 있고 사용자 입력은 query param 값만 영향 주는가(SSRF 위험 낮음)?

---

## jsp-legacy (JSP/Servlet + Maven WAR — Gseed_Web_Renew 기준)

### SSRF 취약 패턴

```java
// ⚠️ URL.openStream — 외부 입력 URL (CertiController.java:1447 패턴 참고)
String userUrl = request.getParameter("apiUrl");
URL url = new URL(userUrl);                      // ⚠️ 사용자 제어 URL
BufferedReader br = new BufferedReader(new InputStreamReader(url.openStream()));
```

**실제 발견 패턴 (낮은 위험, 확인 권장):**

```java
// CertiController.java:1441~1451 — URL 도메인은 하드코딩, keyword만 사용자 입력
String confmKey = "QVBJX0tFWV9QTEFDRUhPTERFUg==";
String keyword = req.getParameter("keyword");
String apiUrl = "http://juso.go.kr/addrlink/addrLinkApi.do?currentPage="+currentPage
    +"&countPerPage="+countPerPage+"&keyword="+URLEncoder.encode(keyword,"UTF-8")
    +"&confmKey="+confmKey+"&resultType="+resultType;
URL url = new URL(apiUrl);
br = new BufferedReader(new InputStreamReader(url.openStream(),"UTF-8"));
// → 도메인(juso.go.kr) 고정 → SSRF 위험 낮음
// → 단, keyword에 %00 등 URL 구조 변경 불가 여부 확인 권장
// → confmKey 하드코딩은 별도 민감정보 노출 취약점 (detecting-sensitive-data-exposure 스킬 참조)
```

### 오픈 리다이렉트 취약 패턴

```java
// ⚠️ sendRedirect + getParameter 직접 연결
String returnUrl = request.getParameter("returnUrl");
response.sendRedirect(returnUrl);  // ⚠️

// ⚠️ Spring MVC "redirect:" + 파라미터 변수
@RequestMapping("/afterLogin")
public String afterLogin(String next) {
    return "redirect:" + next;  // ⚠️
}
```

### 안전 패턴 (오탐 주의)

```java
// 하드코딩 경로 sendRedirect (안전 — 오탐)
response.sendRedirect(request.getContextPath() + "/memberLoginForm.do");
// → AuthInterceptor.java:165 에서 실제 확인. getContextPath()는 서버 제어값. 오탐.

// 하드코딩 리다이렉트 반환 (안전 — 오탐)
return "redirect:/memberLoginForm.do";
return "redirect:/accessDenied.do";
// → CertiController, BoardController 등 다수에서 발견. 모두 오탐.
```

---

## 공통 보조 점검 (스캐너가 못 잡음 → AI가 보강)

| 점검 항목 | 위치 | 판정 기준 |
|---|---|---|
| URL 화이트리스트 | HTTP 클라이언트 호출 전 검증 로직 | 없으면 SSRF 위험 |
| 클라우드 메타데이터 차단 | 네트워크 정책 / IMDSv2 설정 | AWS 환경이면 반드시 확인 |
| 상대경로 강제 | 리다이렉트 파라미터 처리 | `http://` 시작 차단 없으면 오픈 리다이렉트 |
| DNS Rebinding | 화이트리스트 검증 후 지연 요청 | 고급 SSRF 우회 기법, 운영 환경 필요 |
| 간접 SSRF | 사용자 URL → DB 저장 → 나중에 서버가 요청 | 데이터 흐름 전체 추적 필요 |

---

## 오탐(False Positive) 가이드

스캐너가 `sendRedirect` 또는 `URL.openStream`을 잡아도 아래는 취약이 아니다.

1. **하드코딩 경로 리다이렉트** — `"redirect:/memberLoginForm.do"`, `sendRedirect(contextPath + "/fixed")` → 오탐
2. **서버 설정에서만 읽히는 URL** — `@Value("${api.url}")` 고정 URL → 오탐 (단, 설정값 외부 조작 불가 전제)
3. **URL 도메인이 고정**이고 사용자 입력은 query param value만 → 낮은 위험, "의도된 예외(확인 권장)"으로 기록
4. **내부 서비스간 통신** — 브라우저 경유 없이 MSA 내부 호출만 하는 경우 → 위험 모델 다름, 별도 기록
