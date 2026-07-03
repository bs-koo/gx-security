# 파일 업로드 취약점 — 스택별 실제 코드 패턴

스캐너 룰과 AI 검증이 참조하는 SQIsoft 두 스택의 구체 패턴. 실제 사업부 코드에서 관찰되는 형태 기준.

---

## spring-modern (Spring Boot + MultipartFile)

### 취약 패턴

```java
// ① 확장자·매직바이트 검증 없이 바로 저장 (High)
@PostMapping("/upload")
public ResponseEntity<?> upload(@RequestParam MultipartFile file) {
    String originalName = file.getOriginalFilename();          // ⚠️ 원본명 그대로
    File dest = new File(uploadDir + "/" + originalName);      // ⚠️ 경로 조작 가능
    file.transferTo(dest);                                      // ⚠️ 검증 없음
    return ResponseEntity.ok("업로드 완료");
}
```

```java
// ② Content-Type만 신뢰 (Medium — 클라이언트 위조 가능)
String contentType = file.getContentType();                    // ⚠️ 요청 헤더 기반
if (contentType.startsWith("image/")) {
    file.transferTo(dest);   // jpeg처럼 위장한 .jsp 파일 통과
}
```

```java
// ③ 블랙리스트만 사용 (Medium — 신규 위험 확장자 누락 가능)
String ext = getExt(file.getOriginalFilename()).toLowerCase();
if (ext.equals("exe") || ext.equals("sh")) {   // ⚠️ .jsp, .jspx 등 미포함
    throw new BusinessException("허용되지 않은 파일");
}
file.transferTo(dest);
```

```java
// ④ 마지막 확장자만 검사 → 이중 확장자 우회 (Medium)
// "evil.jsp.jpg" → ext = "jpg" → 통과되지만 일부 WAS는 .jsp로 실행
String ext = originalName.substring(originalName.lastIndexOf(".") + 1);
```

```java
// ⑤ 웹루트 내부 저장 (High — 업로드된 .jsp 파일 URL로 직접 실행 가능)
String uploadDir = servletContext.getRealPath("/uploads/");    // ⚠️ 웹루트 내
File dest = new File(uploadDir, savedName);
file.transferTo(dest);
```

### 안전 패턴 (오탐 주의)

> **추적 원칙**: `transferTo()` 직전에 검증이 안 보여도 `validateFile`·`UploadFileSaveHandler`
> 같은 공용 핸들러에 캡슐화돼 있을 수 있다. 검증 함수 정의를 열어 화이트리스트+시그니처
> 유무를 확인하기 전에는 취약으로 확정하지 않는다.

```java
// sqisoft-sef-2026 FileUtils.validateFile() — 안전 (오탐)
// 1) 확장자 화이트리스트: ALLOWED_EXTENSIONS.contains(ext)
// 2) 이중 확장자: split("\\.", -1) 로 모든 토큰 검사
// 3) 매직바이트: 선두 12바이트 시그니처 교차검증
// 4) 저장: ${file.upload.path}(웹루트 밖) + UUID 파일명
FileUtils.validateFile(file, maxFileSize);   // 위 네 조건 모두 포함 → 안전
String savedName = FileUtils.generateUniqueFileName(originalFileName);
file.transferTo(new File(directoryPath.toFile(), savedName));
```

### 판별 질문

- `file.transferTo()` 직전에 `validateFile()` 또는 동등한 화이트리스트+시그니처 검증이 있나?
- 저장 경로가 `getRealPath()`, `webapp/`, `static/`, `resources/` 하위인가? → 웹루트 내 저장
- `getOriginalFilename()` 결과를 경로/파일명에 그대로 쓰는가? → Path Traversal + 원본명 노출

---

## jsp-legacy (JSP/Servlet + MultipartHttpServletRequest)

### 취약 패턴

```java
// ① FileValidator 호출 없이 직접 저장 (High)
MultipartFile mf = req.getFile("uploadFile");
String oriName = mf.getOriginalFilename();
String ext = oriName.substring(oriName.lastIndexOf(".") + 1);  // ⚠️ 마지막 확장자만
String savedPath = uploadRoot + "/" + UUID.randomUUID() + "." + ext;
mf.transferTo(new File(savedPath));                            // ⚠️ 검증 없음
```

```java
// ② FileValidator 있지만 호출 skip (High)
// UploadFileSaveHandler.init() 대신 직접 루프 — FileValidator.validate() 누락
for (MultipartFile mf : req.getFiles("files")) {
    mf.transferTo(new File(saveRoot + "/" + mf.getOriginalFilename())); // ⚠️
}
```

```java
// ③ saveFileRootPath가 getRealPath() 기반 (High — 웹루트 내 저장)
String saveRoot = req.getSession().getServletContext().getRealPath("/upload/"); // ⚠️
UploadFileSaveHandler.init(req, saveRoot);
```

```jsp
<%-- ④ JSP에서 직접 파일 처리 (레거시 극단적 패턴) --%>
<%@ page import="org.apache.commons.fileupload.*,java.io.*" %>
<%
  DiskFileItemFactory factory = new DiskFileItemFactory();
  // 확장자 검증 없이 바로 저장
  item.write(new File(application.getRealPath("/uploads/") + item.getName())); // ⚠️
%>
```

### 안전 패턴 (오탐 주의)

```java
// Gseed_Web_Renew UploadFileSaveHandler.init() 경로 — 안전 (오탐)
// FileValidator.validate(mf) 호출 → 화이트리스트 + DENY 목록 + 매직바이트 검증
// saveFileRootPath = "/home/was/gseed_files/..." (웹루트 밖)
// 저장명 = UUID + "." + ext (원본명 미사용)
FileValidator.validate(mf);   // 이 호출이 있으면 안전 경로
mf.transferTo(new File(tempVo.getFilePath()));
```

### 판별 질문

- `UploadFileSaveHandler.init()` 또는 `FileValidator.validate()` 없이 `transferTo()` 직접 호출하는 경로가 있나?
- `saveFileRootPath`가 `/home/was/...` 같은 WAS 외부인가, 아니면 `getRealPath("/upload/")` 같은 웹루트 내인가?
- 새로 추가된 기능(신규 컨트롤러)이 기존 `UploadFileSaveHandler`를 우회해 파일 저장하는가?

---

## 공통 위험 패턴 (스캐너가 못 잡음 → AI가 보강)

| 패턴 | 탐지 방법 | 위험도 |
|---|---|---|
| ZipSlip | ZIP 처리 코드에서 `ZipEntry.getName()` + `new File(base, entry)` 경로 검증 없음 | High |
| Null Byte 삽입 | `%00` 또는 `\x00`이 파일명에 포함될 때 일부 언어에서 확장자 잘림 | Medium |
| 파일명 Path Traversal | `../../../etc/passwd` 형태로 `getOriginalFilename()` 사용 | Medium |
| SVG 업로드 | SVG는 이미지처럼 보이나 내부에 `<script>` 포함 가능 → XSS | Medium |

---

## 오탐(False Positive) 가이드

스캐너가 `transferTo()` 또는 `getOriginalFilename()`을 잡아도 아래는 취약이 아니다.

1. **완전한 화이트리스트 + 매직바이트 + 웹루트 밖 저장 + UUID 파일명** 네 조건 모두 충족 → 안전
   - 예: `sqisoft-sef-2026`의 `BoardFileServiceImpl.uploadBoardFile()` — `FileUtils.validateFile()` → UUID 파일명 → `${file.upload.path}` (외부 경로)
   - 예: `Gseed_Web_Renew`의 `UploadFileSaveHandler.init()` — `FileValidator.validate()` → UUID 파일명 → `/home/was/gseed_files/` (외부 경로)
2. **파일 저장이 없는 읽기 처리** (엑셀 파싱 후 DB 저장, 이미지 리사이즈 후 스트림 반환 등) → 오탐
3. **내부 배치/관리자 도구만 사용** (인터넷 노출 없음, 강한 접근 통제) → 위험 모델 다름, 낮음으로 기록

---
> 심각도 판정은 공통 루브릭을 따른다: [`docs/severity-rubric.md`](../../../docs/severity-rubric.md)
