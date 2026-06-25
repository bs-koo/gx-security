# 경로 탐색(Path Traversal) 취약점 — 스택별 실제 코드 패턴

스캐너 룰과 AI 검증이 참조하는 SQIsoft 두 스택의 구체 패턴. 실제 사업부 코드에서 관찰되는 형태 기준.

---

## spring-modern (Spring Boot + @RequestParam / Path)

### 취약 패턴

```java
// ① @RequestParam 파일명을 경로 검증 없이 바로 사용 (High)
@GetMapping("/files/download")
public ResponseEntity<Resource> download(@RequestParam String fileName) {
    Path path = Paths.get(uploadDir).resolve(fileName);  // ⚠️ ../../../ 가능
    Resource resource = new FileSystemResource(path.toFile());
    return ResponseEntity.ok()
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + fileName)
            .body(resource);
}
```

```java
// ② new File(base + param) — 문자열 연결 (High)
String filePath = uploadDir + "/" + request.getParameter("file"); // ⚠️
File f = new File(filePath);
// → ?file=../../../../etc/passwd
```

```java
// ③ normalize() 만 사용, startsWith 검증 없음 (Medium)
Path resolved = Paths.get(baseDir).resolve(fileName).normalize();
// normalize()는 .. 해석은 하지만 기준 경로 이탈 여부는 검사 안 함
Resource resource = new FileSystemResource(resolved);  // ⚠️
```

```java
// ④ ZipSlip — ZipEntry.getName() 경로 검증 없음 (High)
ZipInputStream zis = new ZipInputStream(file.getInputStream());
ZipEntry entry;
while ((entry = zis.getNextEntry()) != null) {
    File outFile = new File(destDir, entry.getName());  // ⚠️ ../../../ 포함 가능
    // getCanonicalPath() 비교 없음
    Files.copy(zis, outFile.toPath());
}
```

### 안전 패턴 (오탐 주의)

> **추적 원칙**: 호출부에 `getCanonicalPath()`+`startsWith()` 검증이 안 보여도
> `FileValidator`·공용 유틸·도메인 메서드에 캡슐화돼 있을 수 있다. 한 줄 스니펫이 아니라
> 검증 함수 정의까지 열어 확인하기 전에는 취약으로 확정하지 않는다.

```java
// sqisoft-sef-2026 BoardFileServiceImpl.downloadBoardFile() — 안전 (오탐)
// DB에서 strgFilePath를 조회 후 getCanonicalPath()로 기준 경로 검증
File file = new File(boardFileResponse.getStrgFilePath());
String canonicalPath = file.getCanonicalPath();                       // 정규화
String allowedBase   = new File(uploadPath).getCanonicalPath();       // 기준 경로 정규화
if (!canonicalPath.startsWith(allowedBase)) {
    throw new BusinessException(ErrorCode.FORBIDDEN, "error.file.path.forbidden"); // 차단
}
// → 경로 이탈 시 FORBIDDEN, DB 저장 경로를 외부에서 직접 지정 불가
```

```java
// 화이트리스트 ID 매핑 — 가장 안전 (오탐)
// 외부에 파일 경로 대신 불투명한 ID만 노출
@GetMapping("/files/{fileId}")
public ResponseEntity<Resource> download(@PathVariable Long fileId, @AuthenticationPrincipal UserDetails user) {
    BoardFile boardFile = boardFileRepository.findById(fileId)
            .orElseThrow(() -> new BusinessException(ErrorCode.NOT_FOUND, ...));
    // 소유권/접근 권한 검증 후 DB의 실제 경로 사용
    // 사용자 입력이 경로에 직접 개입하지 않음
    File file = new File(boardFile.getStrgFilePath());
    ...
}
```

### 판별 질문

- `@RequestParam`/`@PathVariable`/`request.getParameter()`로 받은 값이 `Paths.get()`, `new File()`, `resolve()`에 직접 들어가는가?
- `getCanonicalPath()` 호출 후 기준 경로와 `startsWith()`로 비교하는가? → 있으면 안전
- DB에서 꺼낸 경로라도 `getCanonicalPath()` 검증을 하는가? → DB 경로 조작(IDOR 체인) 가능성 고려

---

## jsp-legacy (JSP/Servlet + @RequestMapping)

### 취약 패턴

```java
// ① filePath 파라미터 블랙리스트만 사용 (Medium — 인코딩 우회 가능)
// Gseed_Web_Renew FileController.download() 실제 패턴
@RequestMapping(value = "/download.do")
public ModelAndView download(@RequestParam("filePath") String filePath,
                              @RequestParam("fileRealName") String fileRealName) throws Exception {
    String blockchar[] = {"..", "../", "..\\"};   // ⚠️ 블랙리스트 방식
    Boolean checkResult = true;
    for (int i = 0; i < blockchar.length; i++) {
        if (filePath.indexOf(blockchar[i]) != -1) {
            checkResult = false;
            break;
        }
    }
    if (filePath.toLowerCase().startsWith("/home/was/gseed_files".toLowerCase()) && checkResult) {
        // startsWith 검사는 있으나:
        // 1) 블랙리스트는 %2e%2e%2f(URL 인코딩) 우회 가능
        // 2) getCanonicalPath() 없어 심볼릭 링크 우회 가능
        File file = new File(filePath);
        return new ModelAndView("fileDownView", "downloadFile", file)...;
    }
    ...
}
```

```java
// ② request.getParameter("file")을 문자열 연결로 경로 구성 (High)
String baseDir = "/home/was/app/files/";
String fileName = request.getParameter("fileName");            // ⚠️
File f = new File(baseDir + fileName);                         // ⚠️ ../ 가능
// → ?fileName=../../../../etc/passwd
```

```jsp
<%-- ③ JSP에서 직접 파일 경로 파라미터 처리 (High) --%>
<%
  String filePath = request.getParameter("path");             // ⚠️
  File f = new File(filePath);                                // ⚠️ 아무 검증 없음
  // 파일 내용을 response에 직접 출력
%>
```

```java
// ④ DB 조회 경로를 직접 사용 — IDOR와 Path Traversal 체인 (Medium)
String dbFilePath = fileDao.selectFilePath(fileSeq);  // DB에서 경로 조회
File f = new File(dbFilePath);                         // ⚠️ getCanonicalPath() 검증 없음
// fileSeq를 타인 것으로 바꾸면 타인 파일 접근 가능(IDOR)
```

### 안전 패턴 (오탐 주의)

```java
// 블랙리스트 + startsWith 조합 — 부분적 방어(오탐 아님, Medium으로 기록)
// 개선 권고: getCanonicalPath() 기반 검증으로 대체
if (filePath.toLowerCase().startsWith("/home/was/gseed_files") && checkResult) { ... }
// → 의도는 맞으나 블랙리스트 우회 가능 → Medium

// 완전 안전 패턴 (권고안)
File requested = new File(filePath);
String canonical  = requested.getCanonicalPath();
String allowedBase = new File("/home/was/gseed_files").getCanonicalPath();
if (!canonical.startsWith(allowedBase + File.separator)) {
    response.sendError(HttpServletResponse.SC_FORBIDDEN);
    return null;
}
```

### 판별 질문

- `filePath` 파라미터 필터가 블랙리스트(`../` 문자열 포함 여부)에만 의존하는가? → 인코딩 우회 가능, Medium
- `startsWith(allowedBase)` 비교 전에 `getCanonicalPath()`로 정규화를 하는가? → 없으면 심볼릭 링크 우회 가능
- 파일 조회 시 DB에서 꺼낸 경로를 추가 검증 없이 사용하는가? → IDOR 체인 가능

---

## 공통 안전 패턴 비교

| 방어 기법 | 설명 | 신뢰도 |
|---|---|---|
| 블랙리스트(`../` 포함 여부) | URL 인코딩/유니코드 우회 가능 | 낮음 |
| `startsWith(base)` 문자열 비교 | 정규화 없이 비교 → 심볼릭 링크·인코딩 우회 가능 | 낮음 |
| `normalize()` + `startsWith(base)` | `..` 해석하나 심볼릭 링크 미해석 | 보통 |
| `getCanonicalPath()` + `startsWith(canonical_base)` | 심볼릭 링크·`..` 모두 해석 후 비교 | **높음** |
| 화이트리스트 ID 매핑 (DB ID → 경로) | 경로 자체를 외부에 노출 안 함 | **가장 높음** |

---

## 오탐(False Positive) 가이드

스캐너가 `new File(param)` 또는 `Paths.get(base, name)` 을 잡아도 아래는 취약이 아니다.

1. **`getCanonicalPath()` + `startsWith(canonical_base)` 검증 완비** → 안전 (오탐)
   - 예: `sqisoft-sef-2026`의 `BoardFileServiceImpl.downloadBoardFile()` (라인 121~124)
2. **화이트리스트 ID 매핑** — 파일 경로를 외부에 노출하지 않고 DB ID만 사용 → 오탐
3. **경로가 100% 서버 내부 상수** — 사용자 입력이 경로에 개입하지 않음 → 오탐
