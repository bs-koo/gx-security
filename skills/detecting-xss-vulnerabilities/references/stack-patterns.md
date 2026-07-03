# XSS — 스택별 실제 코드 패턴

스캐너 룰과 AI 검증이 참조하는 SQIsoft 두 스택의 구체 패턴. 실제 사업부 코드에서 관찰되는 형태 기준.

---

## jsp-legacy (JSP/Servlet + eGovFramework + Maven WAR)

### 취약 패턴

#### 1. Scriptlet 직접 출력 — 반사형 XSS (High)

```jsp
<%-- request.getParameter 값을 이스케이프 없이 출력 --%>
<input type="text" value="<%= request.getParameter("keyword") %>">
<p><%= request.getAttribute("errMsg") %></p>
```

#### 2. EL 표현식 미이스케이프 출력 — 반사형/저장형 XSS (High)

```jsp
<%-- ${param.x} 는 HTML 자동이스케이프 없음 --%>
<p>${param.keyword}</p>
<div>${board.bbsContent}</div>

<%-- 게시판 상세: DB 저장값 그대로 출력 — 저장형 XSS --%>
<p class="content__text">${board.bbsContent}</p>
```

#### 3. c:out escapeXml="false" — 의도적 비이스케이프 (High)

```jsp
<%-- escapeXml="false" 명시 시 HTML 이스케이프 비활성 --%>
<c:out value="${board.htmlContent}" escapeXml="false"/>
```

#### 4. JS 블록 내 EL 삽입 — DOM/반사형 XSS (High)

```jsp
<%-- JS 문자열에 EL 값 직접 삽입 — HTML 이스케이프는 JS 컨텍스트 무의미 --%>
<script>
    var keyword = "${param.keyword}";        // ⚠️ 반사형
    var title   = "${board.bbsTitle}";       // ⚠️ 저장형
    var loginUser = "${sessionScope.LoginVo.userSe}";  // 실제 Gseed 코드에 존재
</script>
```

실제 `Gseed_Web_Renew/boardDetailPage.jsp` 패턴:
```jsp
<script type="text/javascript">
    var contextPath = "${pageContext.request.contextPath}";
    var loginUser = "${sessionScope.LoginVo.userSe}";
```
`loginUser`는 세션값이라 직접 공격 벡터는 낮으나, 세션 조작이 가능한 다른 취약점과 연계 시 위험.

#### 5. 파일 다운로드 링크 — 반사형 XSS (Medium)

```jsp
<%-- 파일명이 사용자 제어 가능하면 href에 삽입 시 XSS 가능 --%>
<a href="/download.do?filePath=${item.filePath}&fileRealName=${item.fileNm}" download>${item.fileNm}</a>
```

fn:escapeXml 래핑 여부에 따라 안전/취약 결정됨.

---

### 안전 패턴 (이건 취약 아님 — 오탐 주의)

```jsp
<%-- fn:escapeXml() — HTML 특수문자 이스케이프 (안전) --%>
<p>${fn:escapeXml(item.bbsTitle)}</p>
<p>${fn:escapeXml(item.bbsContent)}</p>

<%-- c:out 기본값(escapeXml="true") — 안전 --%>
<c:out value="${board.title}"/>
<c:out value="${param.keyword}"/>

<%-- JS에 숫자·날짜 등 비HTML 데이터만 삽입 — 낮은 위험 --%>
<script>
    var pageNum = ${pageNum};   // 숫자형 — XSS 불가
</script>
```

---

## spring-modern (Spring Boot + MyBatis + JS/React SPA)

### 취약 패턴

#### 1. @ResponseBody HTML 문자열 반환 (High)

```java
// @RestController에서 사용자 입력을 HTML에 포함해 반환
@GetMapping("/preview")
@ResponseBody
public String preview(@RequestParam String content) {
    return "<div class='preview'>" + content + "</div>";  // ⚠️ 반사형 XSS
}
```

#### 2. Thymeleaf th:utext (High)

```html
<!-- th:utext — Unescaped. 사용자 데이터 바인딩 시 위험 -->
<div th:utext="${board.content}"></div>

<!-- th:text — 이스케이프됨 (안전) -->
<div th:text="${board.content}"></div>
```

#### 3. React dangerouslySetInnerHTML (High)

```jsx
// 사용자 입력 / API 응답을 직접 주입
function BoardContent({ content }) {
    return <div dangerouslySetInnerHTML={{ __html: content }} />;  // ⚠️
}
```

#### 4. DOM innerHTML 할당 — DOM XSS (Medium~High)

```js
// API 응답의 사용자 데이터를 innerHTML로 삽입
function renderTitle(data) {
    document.getElementById("title").innerHTML = data.title;   // ⚠️
    element.innerHTML = response.content;                       // ⚠️
}
```

#### 5. MyBatis Mapper — 검색 정렬 컬럼명 ${ } (Low~Medium)

```xml
<!-- ${ }는 SQL 값이 아닌 식별자 삽입 — SQL Injection 겸 결과 반영 XSS 간접 경로 -->
<select id="searchBoards">
    SELECT * FROM board ORDER BY ${sortColumn}   <!-- ⚠️ -->
</select>
```

---

### 안전 패턴 (이건 취약 아님 — 오탐 주의)

```jsx
// textContent — HTML 파서 미사용, 안전
element.textContent = data.title;

// React 기본 렌더링 — JSX {expr}는 자동 이스케이프
function Safe({ title }) {
    return <div>{title}</div>;   // 안전
}

// DOMPurify 정화 후 innerHTML — 조건부 허용
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(rawHtml);  // 허용 (Sanitizer 존재)
```

```java
// Thymeleaf th:text — 이스케이프됨 (안전)
// Spring의 @ResponseBody + JSON — Content-Type: application/json 은 브라우저가 HTML 파싱 안 함
@RestController  // JSON 반환 시 XSS 위험 낮음 (단, JSONP 예외)
```

---

## 공통 보조 방어 (스캐너가 못 잡음 → AI가 보강)

| 점검 | 위치 | 판정 |
|---|---|---|
| Content-Security-Policy 헤더 | HTTP 응답 헤더, Spring Security 설정 | 미설정 시 Low (XSS 발생 시 피해 폭 확대) |
| X-XSS-Protection 헤더 | HTTP 응답 헤더 | 구형 브라우저 보호. 최신 브라우저는 CSP 우선 |
| 서버 측 입력 정화 | 게시판 서비스 레이어 | AntiSamy·jsoup Safelist 미적용 시 저장형 XSS 위험 |
| HttpOnly 쿠키 | 세션 쿠키 설정 | XSS 성공 시 쿠키 탈취 차단 보조 방어 |

---

## 오탐(False Positive) 가이드

스캐너가 EL 표현식이나 innerHTML을 잡아도 아래는 취약이 아니다.

1. **`fn:escapeXml()` 래핑** — `${fn:escapeXml(x)}` 형태는 안전. 오탐.
2. **`<c:out value="..." />` 기본** — `escapeXml="true"`(기본값)이면 안전. 오탐.
3. **Thymeleaf `th:text`** — 이스케이프됨. 오탐.
4. **React JSX `{expr}`** — 자동 이스케이프됨. 오탐.
5. **JS에 정수/날짜만 삽입** — `var count = ${count};` 숫자형은 XSS 불가. 오탐.
6. **DOMPurify 등 Sanitizer 적용 후 innerHTML** — 허용 목록 방식 Sanitizer 사용 시 조건부 허용. 단 Sanitizer 버전·설정 확인 필수.
7. **JSON API 응답** — `Content-Type: application/json`이고 JSONP 없으면 브라우저가 HTML 파싱 안 함 → XSS 위험 낮음(단 `//`로 시작하는 JSON 하이재킹 별도 확인).

오탐으로 판정하면 리포트의 "오탐 제외"에 사유 한 줄로 남긴다.

---
> 심각도 판정은 공통 루브릭을 따른다: [`docs/severity-rubric.md`](../../../docs/severity-rubric.md)
