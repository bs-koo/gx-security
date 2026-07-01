---
name: detecting-path-traversal
description: >-
  SQIsoft 웹 애플리케이션에서 경로 탐색(Path Traversal / Directory Traversal) 취약점을 검사한다.
  파일 다운로드·뷰어·첨부파일 조회 기능에서 사용자 입력이 파일 경로에 그대로 삽입되어
  ../를 이용한 임의 파일 접근(WEB-INF/web.xml, /etc/passwd 등) 또는 임의 파일 다운로드를
  허용하는 패턴을 탐지한다. CWE-22, OWASP A01:2021 대응.
  spring-modern(@RequestParam 파일명 → Resource/Path 직접 반환, ZipSlip)과
  jsp-legacy(download.do?filePath= 파라미터 경로 필터링 미흡) 두 스택을 지원한다.
domain: cybersecurity
subdomain: web-application-security
tags:
  - path-traversal
  - directory-traversal
  - cwe-22
  - owasp-a01
  - file-download
  - zipslip
  - spring-boot
  - jsp
  - servlet
  - sqisoft
cwe: [CWE-22]
owasp: [A01:2021-Broken-Access-Control]
stacks: [spring-modern, jsp-legacy]
version: "0.2.1"
author: sqisoft-security
license: Proprietary
---

# 경로 탐색(Path Traversal) 취약점 검사 (CWE-22 / Improper Limitation of a Pathname)

## When to Use

다음 중 하나라도 해당하면 이 스킬을 실행한다.

- SQIsoft 프로젝트(예: `sqisoft-sef-2026`, `Gseed_Web_Renew`)에 **파일 다운로드·뷰어·첨부파일 조회** 기능이 있는 경우
- `@RequestParam`으로 받은 파일명/경로를 `new File()`, `Paths.get()`, `Resource` 등에 그대로 사용하는 코드가 보일 때
- 다운로드 URL이 `?file=`, `?filePath=`, `?fileName=` 같은 경로 파라미터를 노출할 때
- ZIP·tar 등 압축 파일을 서버에서 해제하는 코드가 있는 경우(ZipSlip)
- 보안 코드 리뷰에서 `canonicalPath`, `normalize()`, `startsWith()` 같은 경로 검증이 없는 파일 I/O 코드가 보일 때

**이 스킬을 쓰지 않을 때:** 파일 경로를 사용자 입력으로 받지 않는 경우, 또는 파일 업로드 검증 이슈(→ `detecting-file-upload-vulnerabilities` 스킬 사용).

## Prerequisites

- 대상 프로젝트 소스에 대한 읽기 접근
- (선택, 권장) `semgrep` 설치 — 없으면 `scripts/scan_pathtraversal.py`가 grep 폴백으로 동작
- 스택 판별 참고: `references/stack-patterns.md`

## Workflow

### 0단계 — 스택 자동 감지

| 스택 | 감지 신호 | 적용 룰 |
|---|---|---|
| `spring-modern` | `build.gradle.kts`/`settings.gradle*`, `@Controller`/`@RestController`, `@RequestParam` | `rules/path-traversal.yml`의 spring 룰 |
| `jsp-legacy` | `**/WEB-INF/web.xml`, `*.jsp`, `@RequestMapping("/download.do")` 형태 | `rules/path-traversal.yml`의 jsp 룰 + AI 패턴 검사 |

```bash
python skills/detecting-path-traversal/scripts/scan_pathtraversal.py "$TARGET" --json
```

### 1단계 — 스캐너 1차 탐지

스크립트가 스택을 감지해 Semgrep 룰 또는 grep 폴백으로 후보를 수집한다.
출력: `{file, line, rule_id, stack, snippet}` 목록.

### 2단계 — AI 컨텍스트 검증 (핵심)

스캐너 후보는 출발점이다. 각 후보를 아래 기준으로 코드를 직접 열어 검증한다.

**spring-modern 검증 포인트**

1. `@RequestParam String fileName`(또는 `filePath`, `name` 등)을 받아 `Paths.get(base, fileName)` 또는 `new File(base, fileName)`에 넣을 때:
   - **`Path.normalize()` 또는 `getCanonicalPath()` 호출 후 기준 경로(`startsWith(base)`)를 검증**하는지 확인.
   - `sqisoft-sef-2026`의 `BoardFileServiceImpl.downloadBoardFile()` 패턴이 표준:
     ```java
     String canonicalPath = file.getCanonicalPath();
     String allowedBase   = new File(uploadPath).getCanonicalPath();
     if (!canonicalPath.startsWith(allowedBase)) throw new BusinessException(FORBIDDEN, ...);
     ```
   - 이 패턴이 있으면 → **안전(오탐)**. 없으면 → **확정 취약**.
2. `Resource`(`FileSystemResource`, `UrlResource`) 직접 반환 시: 경로 검증 없이 `@RequestParam`을 경로에 넣으면 취약.
3. DB에서 꺼낸 경로를 사용하는 경우: DB 값도 신뢰할 수 없음(2차 인젝션 또는 IDOR 체인). 경로 검증 필요.
4. ZipSlip: `ZipEntry.getName()`을 `new File(base, entry.getName())`에 넣고 `getCanonicalPath()` 검증 없으면 취약.

**jsp-legacy 검증 포인트**

1. `download.do?filePath=` 패턴에서:
   - 기준 경로 prefix 검사(`filePath.toLowerCase().startsWith(allowedBase)`)가 있는지.
   - `blockchar[]` 블랙리스트 방식(`..`, `../`, `..\`)만 사용하는 경우: **우회 가능** — URL 인코딩(`%2e%2e%2f`), 이중 인코딩(`%252e`), 유니코드 우회 가능성 확인.
   - `Gseed_Web_Renew`의 `FileController.download()`:
     ```java
     // blockchar 블랙리스트 + startsWith("/home/was/gseed_files") 조합
     // 블랙리스트만으로는 인코딩 우회 가능 → Medium으로 기록 후 권고
     ```
2. DB에서 꺼낸 `filePath`를 그대로 `new File(filePath)` 에 넣는 경우: IDOR와 결합하면 임의 파일 접근 가능.
3. `request.getParameter("fileName")`을 `new File(baseDir + param)`에 문자열 연결로 사용: 취약.

**공통 — 누락 보강(스캐너가 못 잡는 것)**

- **화이트리스트 ID 매핑 패턴**: `fileId` → DB 조회 → 실제 경로. 경로를 외부에 노출하지 않음 → 가장 안전.
- **IDOR 체인**: 파일 ID는 있으나 소유권 검증 없음 → Path Traversal 없이도 타인 파일 접근 가능(별도 기록).

### 3단계 — 사업부 표준 리포트

확정된 항목만 아래 Output Format으로 출력한다.

## Output Format

```markdown
# 경로 탐색(Path Traversal) 취약점 점검 리포트
- 대상: <프로젝트/경로>   | 감지 스택: <spring-modern | jsp-legacy | mixed>
- 스캐너: <semgrep vX.Y | grep-fallback>   | 점검일: <YYYY-MM-DD>

## 요약
- 확정 취약: N건 (High n / Medium n / Low n)
- 의도된 예외: M건   | 오탐 제외: K건

## 확정 취약점

### [Medium] 다운로드 경로 블랙리스트만 적용 — FileController.java:102
- 스택 / 위치: jsp-legacy / FileController.java:102
- **① 취약한 점(What)**: `download.do?filePath=` 파라미터의 `../` 필터가 문자열 블랙리스트만 적용됨.
  허용 기준 경로 prefix 검사(`startsWith`)는 있으나 블랙리스트 단계에서 인코딩 우회 가능성 존재.
- **② 취약한 이유(Why)**: `blockchar` 배열(`.."`, `"../"`, `..\`)은 URL 디코딩 후 적용하므로 서블릿 컨테이너가
  `%2e%2e%2f`를 사전 디코딩하면 블랙리스트를 통과한다. `startsWith` 검사가 최후 방어선이지만
  정규화 없이 비교하므로 심볼릭 링크·대소문자 우회 가능성도 있다.
- **③ 뚫리는 방법(How · 개념 PoC)**: `/download.do?filePath=%2e%2e%2f%2e%2e%2fetc%2fpasswd&fileRealName=passwd`
  → 서블릿이 URL 디코딩 후 블랙리스트 비교 시 `../` 아닌 `%2e%2e%2f`가 blockchar에 없어 통과 가능.
  방어 학습 목적의 개념 설명이며 실제 공격 사용 금지.
- **④ 해결방법(Fix)**: 블랙리스트 제거 후 `getCanonicalPath()` + 기준 경로 검증으로 교체
  ```java
  File requested = new File(filePath);
  String canonical = requested.getCanonicalPath();
  String allowedBase = new File("/home/was/gseed_files").getCanonicalPath();
  if (!canonical.startsWith(allowedBase + File.separator)) {
      response.sendError(HttpServletResponse.SC_FORBIDDEN);
      return null;
  }
  ```
- 참조: CWE-22, OWASP A01:2021

## 의도된 예외 (확인 필요)
- [Info] DB 저장 filePath를 직접 File()에 넣는 경우 — 경로가 시스템이 생성한 값이고 사용자가
  직접 조작 불가하다면 위험 낮음. 단 IDOR(파일 접근 권한 검증) 함께 확인 권고.

## 오탐 제외
- BoardFileServiceImpl.java:119 — getCanonicalPath() + startsWith(allowedBase) 검증 완비 → 안전
```

## Verification (검사 자체의 신뢰성 확인)

- [ ] 사용자 입력(쿼리 파라미터, 경로 변수, 폼 필드)이 파일 경로에 사용되는 **모든** 지점을 탐지했는가
- [ ] 각 지점에서 `getCanonicalPath()` 또는 `Path.normalize()` + 기준 경로 `startsWith` 검증이 있는지 확인했는가
- [ ] JSP 다운로드에서 블랙리스트 방식(`../` 문자열 치환/필터)만 사용하는 경우 인코딩 우회 가능성을 기록했는가
- [ ] ZipSlip 위험이 있는 ZIP 처리 코드를 별도로 확인했는가
- [ ] DB에서 조회한 경로를 신뢰하는 코드가 있는 경우 IDOR 체인 가능성을 함께 기록했는가

## Key Concepts

| 용어 | 설명 |
|---|---|
| Path Traversal (CWE-22) | 사용자 입력의 `../` 시퀀스를 이용해 기준 경로를 벗어나 임의 파일 접근 |
| `getCanonicalPath()` | 심볼릭 링크·`..` 등을 해석해 절대 정규 경로를 반환 — 경로 검증의 표준 |
| `Path.normalize()` | `..`을 해석하지만 심볼릭 링크는 해석 안 함 — `toRealPath()`와 병행 권장 |
| 블랙리스트 필터 | `../` 문자열을 제거/차단 — URL 인코딩·유니코드 정규화 우회로 무력화 가능 |
| ZipSlip (CWE-22) | ZIP 엔트리명에 `../` 포함 → 압축 해제 기준 경로 밖에 파일 생성 |
| 화이트리스트 ID 매핑 | 파일 경로 대신 불투명한 ID를 외부에 노출하고 서버가 경로로 변환 — 가장 안전 |
| IDOR | 파일 ID/경로는 유효하나 접근 권한 검증 부재 — Path Traversal 없이도 타인 파일 접근 |

## Tools & Systems

- Semgrep (룰: `rules/path-traversal.yml`) · grep 폴백
- Java `File.getCanonicalPath()`, `Path.normalize()`, `Path.toRealPath()`
- 참고: `references/stack-patterns.md`
