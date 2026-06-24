---
name: detecting-file-upload-vulnerabilities
description: >-
  SQIsoft 웹 애플리케이션에서 악성 파일 업로드(웹쉘 업로드, CWE-434) 취약점을 검사한다.
  파일 업로드 기능이 있는 게시판·첨부파일·인증서 등록 화면에서 확장자 화이트리스트 부재,
  매직바이트 미검증, 웹루트 내부 저장, Content-Type만 신뢰, 원본 파일명 그대로 사용,
  이중 확장자 우회 등의 패턴을 탐지한다. spring-modern(Spring Boot + MultipartFile)과
  jsp-legacy(JSP/Servlet + commons-fileupload) 두 스택을 지원한다.
domain: cybersecurity
subdomain: web-application-security
tags:
  - file-upload
  - webshell
  - cwe-434
  - owasp-a04
  - owasp-a05
  - multipart
  - spring-boot
  - jsp
  - servlet
  - sqisoft
cwe: [CWE-434]
owasp: [A04:2021-Insecure-Design, A05:2021-Security-Misconfiguration]
stacks: [spring-modern, jsp-legacy]
version: "0.1"
author: sqisoft-security
license: Proprietary
---

# 악성 파일 업로드 취약점 검사 (CWE-434 / Unrestricted Upload of File with Dangerous Type)

## When to Use

다음 중 하나라도 해당하면 이 스킬을 실행한다.

- SQIsoft 프로젝트(예: `sqisoft-sef-2026`, `Gseed_Web_Renew`)에 **파일 첨부/업로드 기능**이 있는 경우
  (게시판 첨부파일, 인증서 등록, 엑셀 일괄 업로드, 프로필 이미지 등)
- 보안 코드 리뷰에서 `MultipartFile`, `transferTo()`, `commons-fileupload`, `FileItem` 처리 코드가 보일 때
- 확장자 검증 또는 저장 경로 로직이 의심스러울 때 (`getOriginalFilename()` 결과를 그대로 저장하는 경우)
- 업로드된 파일이 웹 서버에서 직접 실행 가능한 경로(웹루트 내부)에 저장되는지 점검할 때

**이 스킬을 쓰지 않을 때:** 파일 업로드 기능이 전혀 없는 순수 API, 또는 다운로드 경로 검증 이슈(→ `detecting-path-traversal` 스킬 사용).

## Prerequisites

- 대상 프로젝트 소스에 대한 읽기 접근
- (선택, 권장) `semgrep` 설치 — 없으면 `scripts/scan_upload.py`가 grep 폴백으로 동작
- 스택 판별 참고: `references/stack-patterns.md`

## Workflow

### 0단계 — 스택 자동 감지

| 스택 | 감지 신호 | 적용 룰 |
|---|---|---|
| `spring-modern` | `build.gradle.kts`/`settings.gradle*`, `@RestController`/`@Controller`, `MultipartFile` | `rules/file-upload.yml`의 spring 룰 |
| `jsp-legacy` | `**/WEB-INF/web.xml`, `*.jsp`, `FileItem`/`DiskFileItemFactory`, `MultipartHttpServletRequest` | `rules/file-upload.yml`의 jsp 룰 + AI 패턴 검사 |

```bash
python skills/detecting-file-upload-vulnerabilities/scripts/scan_upload.py "$TARGET" --json
```

### 1단계 — 스캐너 1차 탐지

스크립트가 스택을 감지해 Semgrep 룰 또는 grep 폴백으로 후보를 수집한다.
출력: `{file, line, rule_id, stack, snippet}` 목록.

### 2단계 — AI 컨텍스트 검증 (핵심)

스캐너 후보는 출발점이다. 각 후보를 아래 기준으로 코드를 직접 열어 검증한다.

**spring-modern 검증 포인트**

1. `MultipartFile.transferTo()` / `file.getInputStream()` 저장 전에 다음이 **모두** 적용됐는지 확인:
   - **확장자 화이트리스트**: `ALLOWED_EXTENSIONS.contains(ext)` 형태의 양성 집합 비교. 블랙리스트만으로는 불충분.
   - **이중 확장자 방어**: `"evil.jsp.jpg"` 우회를 막기 위해 마지막 확장자만이 아닌 **전체 확장자 체인** 검사 여부.
   - **매직바이트(파일 시그니처) 검증**: `getInputStream()`으로 파일 선두 바이트를 읽어 선언된 확장자와 교차검증 여부.
2. **저장 경로가 웹루트 밖인지**: `${file.upload.path}` 등 설정 값이 `src/main/webapp` 또는 `static/` 하위가 아닌지 확인.
3. **저장 파일명**: `UUID.randomUUID()` 등으로 원본 파일명을 대체했는지, `getOriginalFilename()` 결과를 그대로 사용하지 않는지.
4. **Content-Type 신뢰 여부**: `getContentType()`만으로 판단하면 클라이언트 위조 가능 → 반드시 서버 측 시그니처/확장자 검증과 병행해야 안전.

**jsp-legacy 검증 포인트**

1. `UploadFileSaveHandler.init()` 호출 전에 `FileValidator.validate(mf)` 가 실행되는지.
2. `FileValidator`가 없거나 호출하지 않은 경로(새로 추가된 컨트롤러 등)에서 `transferTo()` 직접 호출 여부.
3. `saveFileRootPath`가 WAS 외부 경로(`/home/was/gseed_files` 등)를 가리키는지, 아니면 `getRealPath("uploads/")` 처럼 웹루트 내부인지.
4. JSP 업로드 폼에서 `enctype="multipart/form-data"` 폼이 있을 때 서버 측 검증 없이 저장하는 경우.
5. `mf.getContentType()` 또는 `Content-Type` 헤더만 신뢰해 확장자를 결정하는 코드.

**공통 — 누락 보강(스캐너가 못 잡는 것)**

- ZIP 파일 업로드 후 서버에서 자동 압축 해제(ZipSlip): `ZipEntry.getName()`을 경로 검증 없이 사용 → 파일이 압축 해제 기준 경로 밖에 쓰일 수 있음.
- 파일명에 `../` 또는 null byte(`%00`) 삽입: `getOriginalFilename()`에 경로 구분자가 포함된 경우.

### 3단계 — 사업부 표준 리포트

확정된 항목만 아래 Output Format으로 출력한다.

## Output Format

```markdown
# 파일 업로드 취약점 점검 리포트
- 대상: <프로젝트/경로>   | 감지 스택: <spring-modern | jsp-legacy | mixed>
- 스캐너: <semgrep vX.Y | grep-fallback>   | 점검일: <YYYY-MM-DD>

## 요약
- 확정 취약: N건 (High n / Medium n / Low n)
- 의도된 예외: M건   | 오탐 제외: K건

## 확정 취약점

### [High] 확장자 검증 없이 파일 저장 — UploadController.java:87
- 스택 / 위치: spring-modern / UploadController.java:87
- **① 취약한 점(What)**: `file.transferTo(dest)` 호출 전 확장자 화이트리스트 검증이 없어 .jsp, .jspx 등 실행 파일 업로드가 허용됨
- **② 취약한 이유(Why)**: 서버가 파일 유형을 클라이언트 제출 값(Content-Type 헤더 또는 파일명)으로만 판단하므로, 공격자가 이를 임의로 조작해 웹쉘(.jsp)을 업로드할 수 있음
- **③ 뚫리는 방법(How · 개념 PoC)**: 웹쉘 파일(`evil.jsp`)을 Content-Type: image/jpeg로 위장해 업로드 → 업로드 경로가 웹루트라면 URL 직접 호출로 서버 명령 실행(RCE). 방어 학습 목적의 개념 설명이며 실제 무기화 금지.
- **④ 해결방법(Fix)**: 화이트리스트 확장자 검증 + 매직바이트 교차검증 + 웹루트 밖 저장
  ```java
  // 허용 확장자 화이트리스트
  private static final Set<String> ALLOWED = Set.of("pdf","hwp","docx","xlsx","jpg","png","gif","zip");
  String ext = getExt(file.getOriginalFilename()).toLowerCase();
  if (!ALLOWED.contains(ext)) throw new BusinessException(ErrorCode.BAD_REQUEST, "허용되지 않은 파일 형식");
  // 매직바이트 교차검증은 FileValidator.matchesMagic() 참고
  // 저장: 웹루트 밖 경로 + UUID 파일명
  String savedName = UUID.randomUUID() + "." + ext;
  file.transferTo(Path.of(uploadBasePath, savedName));  // uploadBasePath는 웹루트 밖
  ```
- 참조: CWE-434, OWASP A04:2021, OWASP A05:2021

## 의도된 예외 (확인 필요)
- [Info] 썸네일 이미지 업로드가 이미지 MIME + 매직바이트 양방 검증 후 웹루트 static/thumb/ 에 저장되는 경우 — CDN 서빙 목적이라면 실행 파일 저장 위험은 낮음, 단 Content-Disposition: attachment 응답 헤더 권장

## 오탐 제외
- BoardFileServiceImpl.java:63 — FileUtils.validateFile() 호출 후 저장(확장자 화이트리스트+매직바이트 검증 확인), 저장 경로가 ${file.upload.path}(웹루트 밖) → 안전
```

## Verification (검사 자체의 신뢰성 확인)

- [ ] 파일 업로드를 수행하는 **모든** 컨트롤러/서블릿 메서드를 탐지했는가
- [ ] 각 업로드 처리 코드에서 확장자 화이트리스트·매직바이트·저장 경로 세 가지를 모두 확인했는가
- [ ] 저장 경로가 웹루트 밖인지 설정 파일(application.yml, web.xml) 수준까지 추적했는가
- [ ] ZIP 업로드 시 압축 해제 경로 검증(ZipSlip) 여부를 확인했는가
- [ ] 각 확정 취약점에 파일:라인 + 증거 코드 스니펫이 붙어 있는가

## Key Concepts

| 용어 | 설명 |
|---|---|
| CWE-434 | 위험한 파일 형식의 비제한 업로드 — 웹쉘 업로드를 통한 RCE의 근본 원인 |
| 웹쉘(Webshell) | 웹 서버에 업로드된 스크립트 파일(.jsp, .php 등)로 HTTP 요청만으로 서버 명령 실행 가능 |
| 확장자 화이트리스트 | 허용할 확장자만 명시적으로 나열 — 블랙리스트보다 안전(신규 위험 확장자 자동 차단) |
| 매직바이트(파일 시그니처) | 파일 선두 수 바이트로 실제 형식 식별 — 확장자 위장 공격 차단 |
| 이중 확장자 | `evil.jsp.jpg` 형태로 우회 시도 — 마지막 확장자만 검사하면 뚫림 |
| ZipSlip | ZIP 압축 해제 시 `../` 포함 경로명으로 임의 파일 덮어쓰기 |
| 웹루트 밖 저장 | 업로드 경로를 WAS 서버의 `webapp` 디렉토리 밖에 두어 URL 직접 접근 차단 |

## Tools & Systems

- Semgrep (룰: `rules/file-upload.yml`) · grep 폴백
- Spring MultipartFile, Apache Commons FileUpload
- 참고: `references/stack-patterns.md`
