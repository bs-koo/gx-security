# 스캐너 오탐 감축 (정밀도 향상) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 실제 프로젝트(Gseed_Web_Renew·sef-2026) 스캔에서 실측된 8개 오탐 근본 원인을 제거해 정적 스캐너의 정밀도(precision)를 올린다.

**Architecture:** 각 오탐은 (a) semgrep 룰(`skills/*/rules/*.yml`), (b) grep-fallback 스캐너(`skills/*/scripts/scan_*.py`) 두 경로에서 발생한다. 대부분의 오탐은 **fallback엔 이미 방어가 있는데 semgrep 경로에만 없다**. 각 태스크는 오탐 케이스를 `tests/fixtures/<scanner>/safe/`에 fixture로 추가해 골든셋(`tests/test_scanner_goldenset.py`)이 `candidate_count==0`을 강제하게 만든 뒤(실패 재현), 룰/스캐너를 수정해 통과시킨다(회귀 가드 동반 TDD).

**Tech Stack:** Python 3.11+, semgrep(YAML 룰), pytest/unittest, PYTHONUTF8(cp949 대응)

## Global Constraints

- **골든셋 dual-engine 불변식**: 모든 수정 후 각 스캐너는 `tests/fixtures/<scanner>/vuln`에서 후보 ≥1, `tests/fixtures/<scanner>/safe`에서 후보 ==0 을 **semgrep·grep-fallback 양쪽 모두** 만족해야 한다. (`TestSemgrepGoldenset`, `TestGoldensetAllScanners`)
- **semgrep 실행은 항상 `PYTHONUTF8=1`** 로 한다(Windows cp949에서 UTF-8 룰 로드 실패 방지). 예: `PYTHONUTF8=1 py -3.12 -m pytest ...`. 로컬 인터프리터는 `py -3.12`(semgrep 1.172 설치처)를 쓴다.
- **룰 파싱 게이트**: 룰(.yml) 수정 후 `tests/test_rules.py`(semgrep `--validate` 상당)가 통과해야 한다 — 파싱 에러는 파일 전체를 폴백 강등시킨다.
- **fixture 명명 규약**: MyBatis Mapper XML fixture는 파일명에 `Mapper` 포함 또는 `sqlmap`/`mybatis` 경로 하위여야 `_is_mybatis_xml()`을 통과한다. 반대로 "비-Mapper 설정 XML" 오탐 fixture는 `log4j2.xml`처럼 `_is_mybatis_xml()`이 명시적으로 제외하는 파일명을 쓴다.
- **커밋 메시지**: 한국어 + conventional prefix(`fix:`/`test:`), 끝에 `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- **작업 브랜치**: `fix/semgrep-cp949-and-rule-drift`에 이어서 작업하거나 `fix/scanner-fp-reduction` 새 브랜치. 새 브랜치면 `main`이 아닌 현재 브랜치에서 분기.

---

## File Structure

수정/생성 대상 (태스크별):

| 태스크 | 오탐 | 룰(.yml) | 스캐너(.py) | 신규 fixture |
|---|---|---|---|---|
| 1 | SQLi MyBatis 오판 | — | `scan_sqli.py` (semgrep 경로 필터 이식) | `tests/fixtures/sqli/safe/log4j2.xml` |
| 2 | 벤더 JS 미제외 | — | `scan_xss.py` (semgrep 경로 exclude) | `tests/fixtures/xss/safe/jquery-vendorsample.js` |
| 3 | jwt `.parse()` 광범위 | `auth-session.yml` | — | `tests/fixtures/auth/safe/DateParse.java` |
| 4 | 상수명 오판 | `sensitive-data.yml` | `scan_secrets.py` | `tests/fixtures/secrets/safe/JobConst.java` |
| 5 | request DTO 오판 | `sensitive-data.yml` | — | `tests/fixtures/secrets/safe/VerifyPasswordRequest.java` |
| 6 | 주석 키워드 오판 | `sensitive-data.yml` | `scan_secrets.py` | `tests/fixtures/secrets/safe/uiComment.jsp` |
| 7 | EL 비출력 컨텍스트 | `xss.yml` | `scan_xss.py` | `tests/fixtures/xss/safe/JstlNonOutput.jsp` |
| 8 | IDOR 권한검증 미인식 | `access-control.yml` | — | `tests/fixtures/access/safe/PreAuthCtrl.java` |

각 태스크는 독립적으로 테스트·리뷰·커밋 가능하다. 우선순위 순(오탐률 높은 것 먼저)으로 배치했다.

---

### Task 1: SQLi — semgrep 경로에 MyBatis 판별 필터 이식

실측: Gseed 20/20 + sef 12/12 = **100% 오탐** (`log4j2.xml`·`context-*.xml`·`checkstyle-rules.xml`의 `${}`를 MyBatis SQL로 오인). grep-fallback은 `_is_mybatis_xml()`로 이미 걸러내지만 semgrep 경로엔 필터가 없다.

**Files:**
- Modify: `skills/detecting-sql-injection/scripts/scan_sqli.py` (함수 `run_semgrep`, 82-92행 근처)
- Create: `tests/fixtures/sqli/safe/log4j2.xml`
- Test: `tests/test_scanner_goldenset.py`(기존 — 수정 불필요, safe fixture가 자동 검증됨)

**Interfaces:**
- Consumes: 기존 모듈 함수 `_is_mybatis_xml(path: str) -> bool` (scan_sqli.py 163행, 이미 존재)
- Produces: 없음(내부 필터). `run_semgrep`의 반환 계약(`(findings, err)`) 불변.

- [ ] **Step 1: 오탐 재현 fixture 추가**

Create `tests/fixtures/sqli/safe/log4j2.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!-- log4j2 설정 파일: ${}는 log4j 변수 치환이며 MyBatis SQL이 아니다(오탐이면 안 됨) -->
<Configuration status="WARN">
  <Appenders>
    <Console name="console" target="SYSTEM_OUT">
      <PatternLayout pattern="${consoleLayout}"/>
    </Console>
    <RollingFile name="file" fileName="${logDir}/${logFileName}.log"/>
  </Appenders>
</Configuration>
```

- [ ] **Step 2: 골든셋을 돌려 오탐(FAIL) 확인**

Run: `PYTHONUTF8=1 py -3.12 -m pytest "tests/test_scanner_goldenset.py::TestSemgrepGoldenset::test_safe_clean_by_semgrep" -q`
Expected: FAIL — `sqli: semgrep 룰이 안전 픽스처를 오탐하면 안 된다` (log4j2.xml의 `${logDir}` 등이 후보로 잡힘)

- [ ] **Step 3: semgrep 경로에 필터 이식**

Modify `run_semgrep` in `scan_sqli.py` — findings 조립 루프를 다음으로 교체:

```python
    findings = []
    for r in data.get("results", []):
        rid = r.get("check_id", "").split(".")[-1]
        path = r.get("path")
        # MyBatis ${} 룰은 실제 Mapper XML만 대상 — Spring/log4j/checkstyle 설정 XML의
        # ${} placeholder 오탐을 제거한다(grep 폴백의 _is_mybatis_xml 필터를 semgrep 경로에 이식).
        if rid == "sqisoft-mybatis-xml-dollar-interpolation" and not _is_mybatis_xml(path or ""):
            continue
        findings.append({
            "file": path,
            "line": r.get("start", {}).get("line"),
            "rule_id": rid,
            "stack": r.get("extra", {}).get("metadata", {}).get("stack", "?"),
            "confidence": r.get("extra", {}).get("metadata", {}).get("confidence") or "needs-context",
            "snippet": (r.get("extra", {}).get("lines", "") or "").strip()[:200],
        })
    return findings, None
```

- [ ] **Step 4: 골든셋 재실행 — 통과 확인 (오탐 0 + 진짜 탐지 유지)**

Run: `PYTHONUTF8=1 py -3.12 -m pytest "tests/test_scanner_goldenset.py::TestSemgrepGoldenset" "tests/test_scanner_goldenset.py::TestGoldensetAllScanners" -q`
Expected: PASS (sqli safe==0, sqli vuln≥1 — `tests/fixtures/sqli/vuln`의 실제 Mapper `${}`는 여전히 탐지)

- [ ] **Step 5: 커밋**

```bash
git add skills/detecting-sql-injection/scripts/scan_sqli.py tests/fixtures/sqli/safe/log4j2.xml
git commit -m "fix: SQLi semgrep 경로에 MyBatis XML 판별 필터 이식 (설정 XML ​\${} 오탐 제거)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: XSS — semgrep 경로에서 벤더 JS 라이브러리 제외

실측: Gseed `js-innerhtml` 85건 중 **82건(96%)이 jquery-*.js·chosen.jquery.js 등 벤더 라이브러리**. grep-fallback은 `_EXCLUDE_DIRS`(jquery/lib/vendor/pubRes)·`_EXCLUDE_FILE_PATTERNS`로 이미 제외하지만 semgrep 경로는 `--exclude .dev .omc .humanize`만 있다.

**Files:**
- Modify: `skills/detecting-xss-vulnerabilities/scripts/scan_xss.py` (함수 `run_semgrep`, 68-69행 `cmd` 정의)
- Create: `tests/fixtures/xss/safe/jquery-vendorsample.js`
- Test: `tests/test_scanner_goldenset.py`(기존)

**Interfaces:**
- Consumes: 없음
- Produces: 없음. `run_semgrep` 반환 계약 불변.

- [ ] **Step 1: 오탐 재현 fixture 추가**

Create `tests/fixtures/xss/safe/jquery-vendorsample.js`:

```javascript
// 서드파티 라이브러리 모사(jquery* 파일명) — 스캔 대상이 아니어야 한다(오탐이면 안 됨).
function appendHtml(el, v) { el.innerHTML = v; }
```

(파일명이 `jquery`로 시작하므로 grep-fallback의 `_EXCLUDE_FILE_PATTERNS`(`jquery.*\.js`)에 이미 걸려 fallback에선 0이다. semgrep 경로만 오탐.)

- [ ] **Step 2: 골든셋을 돌려 오탐(FAIL) 확인**

Run: `PYTHONUTF8=1 py -3.12 -m pytest "tests/test_scanner_goldenset.py::TestSemgrepGoldenset::test_safe_clean_by_semgrep" -q`
Expected: FAIL — `xss: semgrep 룰이 안전 픽스처를 오탐하면 안 된다` (`el.innerHTML = v`가 후보로 잡힘)

- [ ] **Step 3: semgrep cmd에 벤더 exclude 추가**

Modify `run_semgrep` in `scan_xss.py` — `cmd` 정의를 다음으로 교체:

```python
    # 서드파티/빌드 산출물 제외 — grep 폴백의 _EXCLUDE_DIRS/_EXCLUDE_FILE_PATTERNS와 동기화.
    # semgrep --exclude 는 파일·디렉토리 glob를 반복 지정한다.
    _SEMGREP_EXCLUDES = [
        ".dev", ".omc", ".humanize", ".nuxt", ".output", "coverage",
        "lib", "vendor", "assets", "pubRes",
        "*.min.js", "jquery*.js", "bootstrap*.js", "datatables*.js",
        "tinymce*.js", "codemirror*.js", "highcharts*.js",
    ]
    cmd = ["semgrep", "--config", RULES, "--json", "--quiet"]
    for _ex in _SEMGREP_EXCLUDES:
        cmd += ["--exclude", _ex]
    cmd.append(target)
```

- [ ] **Step 4: 골든셋 재실행 — 통과 확인**

Run: `PYTHONUTF8=1 py -3.12 -m pytest "tests/test_scanner_goldenset.py::TestSemgrepGoldenset" "tests/test_scanner_goldenset.py::TestGoldensetAllScanners" -q`
Expected: PASS (xss safe==0, xss vuln≥1 유지)

- [ ] **Step 5: 커밋**

```bash
git add skills/detecting-xss-vulnerabilities/scripts/scan_xss.py tests/fixtures/xss/safe/jquery-vendorsample.js
git commit -m "fix: XSS semgrep 경로에 벤더 JS 제외 이식 (jquery 등 라이브러리 오탐 제거)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Auth — JWT parse 룰을 JWT 라이브러리 컨텍스트로 한정

실측: sef `jwt-parse-without-verify`가 `SimpleDateFormat.parse()`·`jsonParser.parse()`를 JWT로 오인. 원인은 semgrep 룰의 `$P.parse($TOKEN)` 패턴이 모든 `.parse()`를 매치. (grep-fallback은 이미 `\.parseClaimsJwt\(|Jwts\.parser\(\)\.parse\(`로 좁아 오탐 없음 → 룰만 수정.)

**Files:**
- Modify: `skills/detecting-auth-session-weaknesses/rules/auth-session.yml` (룰 `sqisoft-spring-jwt-parse-without-verify`, 35-53행)
- Create: `tests/fixtures/auth/safe/DateParse.java`
- Test: `tests/test_scanner_goldenset.py`, `tests/test_rules.py`

**Interfaces:**
- Consumes: 없음
- Produces: 룰 id `sqisoft-spring-jwt-parse-without-verify` 유지(참조 안정성).

- [ ] **Step 1: 오탐 재현 fixture 추가**

Create `tests/fixtures/auth/safe/DateParse.java`:

```java
import java.text.SimpleDateFormat;
import java.util.Date;

// 날짜 파싱 — JWT와 무관(오탐이면 안 됨).
class DateParse {
    Date toDate(String s) throws Exception {
        return new SimpleDateFormat("yyyy-MM-dd").parse(s);
    }
}
```

- [ ] **Step 2: 골든셋을 돌려 오탐(FAIL) 확인**

Run: `PYTHONUTF8=1 py -3.12 -m pytest "tests/test_scanner_goldenset.py::TestSemgrepGoldenset::test_safe_clean_by_semgrep" -q`
Expected: FAIL — `auth: semgrep 룰이 안전 픽스처를 오탐하면 안 된다` (`.parse(s)`가 후보로 잡힘)

- [ ] **Step 3: 룰을 JWT 전용 시그니처로 좁힘**

Replace rule `sqisoft-spring-jwt-parse-without-verify` in `auth-session.yml` `patterns:` block:

```yaml
    patterns:
      - pattern-either:
          # jjwt 앵커가 붙은 파싱만 대상 — bare '.parse()'(SimpleDateFormat/JSON 등) 오탐 제거
          - pattern: Jwts.parser().build().parse($TOKEN)
          - pattern: Jwts.parser().parse($TOKEN)
          - pattern: $P.parseClaimsJwt($TOKEN)      # unsigned 파싱(항상 위험)
      - pattern-not-inside: |
          Jwts.parser().verifyWith(...).build().$M($TOKEN)
      - pattern-not-inside: |
          Jwts.parser().setSigningKey(...).build().$M($TOKEN)
```

- [ ] **Step 4: 룰 파싱 + 골든셋 통과 확인**

Run: `PYTHONUTF8=1 py -3.12 -m pytest "tests/test_rules.py::TestRuleFilesSemgrepLoadable" "tests/test_scanner_goldenset.py::TestSemgrepGoldenset" -q`
Expected: PASS (auth-session.yml 파싱 OK, auth safe==0, auth vuln≥1 — vuln은 sha256/plaintext 룰이 담당하므로 유지)

- [ ] **Step 5: 커밋**

```bash
git add skills/detecting-auth-session-weaknesses/rules/auth-session.yml tests/fixtures/auth/safe/DateParse.java
git commit -m "fix: JWT parse 룰을 jjwt 앵커로 한정 (SimpleDateFormat/JSON .parse 오탐 제거)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Sensitive — 하드코딩 자격증명 룰에서 식별자 상수 제외

실측: sef `PASSWORD_CHANGE_JOB = "passwordChangeExpiry"`(배치 job 이름 상수)를 비밀번호로 오인. 변수명에 `PASSWORD`가 들어갔을 뿐 값은 식별자. semgrep 룰 `sqisoft-hardcoded-password-assignment`와 grep-fallback `hardcoded-credential-java-string` 양쪽에 대응 필요.

**Files:**
- Modify: `skills/detecting-sensitive-data-exposure/rules/sensitive-data.yml` (룰 `sqisoft-hardcoded-password-assignment`, 10-35행)
- Modify: `skills/detecting-sensitive-data-exposure/scripts/scan_secrets.py` (fallback 룰 `hardcoded-credential-java-string`, 141-160행 근처)
- Create: `tests/fixtures/secrets/safe/JobConst.java`
- Test: `tests/test_scanner_goldenset.py`, `tests/test_rules.py`

**Interfaces:**
- Consumes: 없음
- Produces: 룰 id 유지.

- [ ] **Step 1: 오탐 재현 fixture 추가**

Create `tests/fixtures/secrets/safe/JobConst.java`:

```java
// 배치 job 식별자 상수 — 비밀번호 값이 아니다(오탐이면 안 됨).
class JobConst {
    private static final String PASSWORD_CHANGE_JOB = "passwordChangeExpiry";
    private static final String TOKEN_CLEANUP_JOB = "tokenCleanupDaily";
}
```

- [ ] **Step 2: 골든셋을 돌려 오탐(FAIL) 확인**

Run: `PYTHONUTF8=1 py -3.12 -m pytest "tests/test_scanner_goldenset.py::TestSemgrepGoldenset::test_safe_clean_by_semgrep" "tests/test_scanner_goldenset.py::TestGoldensetAllScanners::test_safe_clean" -q`
Expected: FAIL — semgrep(그리고 확인 후 fallback도) `secrets` safe에서 후보>0

- [ ] **Step 3a: semgrep 룰의 값·변수명 규칙 강화**

In `sensitive-data.yml` rule `sqisoft-hardcoded-password-assignment`, replace the two `metavariable-regex` blocks:

```yaml
      - metavariable-regex:
          metavariable: $VAR
          # 식별자 상수(대문자_JOB/_NAME/_TYPE/_KEY/_ID/_CODE 접미사)는 비밀번호가 아니므로 제외
          regex: '^(?i)(?!.*_(JOB|NAME|TYPE|KEY|ID|CODE|CRON)$)(?=.*(password|passwd|pwd|secret|secretKey|apiKey|api_key|token|authKey|privateKey|credentials)).*$'
      - metavariable-regex:
          metavariable: $VALUE
          # 6자 이상, ${...} placeholder 제외, 순수 camelCase 식별자(job명 등) 제외 —
          # 실제 비밀번호는 보통 숫자/특수문자를 포함한다.
          regex: '^(?!\$\{)(?!(?:[a-z]+[A-Z][a-zA-Z]*)$).{6,}$'
```

- [ ] **Step 3b: fallback 룰의 값 규칙 강화**

In `scan_secrets.py`, the `hardcoded-credential-java-string` 정규식(141-160행 근처)에 값이 순수 camelCase 식별자면 제외하도록 negative lookahead를 추가한다. 현재 값 부분 `"([^"]{6,})"` 를 다음으로 교체:

```python
        # 값이 순수 camelCase 식별자(예: passwordChangeExpiry)면 비밀번호 아님 → 제외
        re.compile(
            r'(?i)\b(?:password|passwd|pwd|secret|secretKey|apiKey|api_key|authKey|'
            r'privateKey|credentials)\s*=\s*"(?![a-z]+[A-Z][a-zA-Z]*")([^"]{6,})"',
        ),
```

(정확한 앵커·기존 변수명 접미사 조건은 `scan_secrets.py`의 해당 튜플을 열어 원래 정규식에 맞춰 병합한다. 원 정규식의 변수명 부분은 유지하고 값 부분에만 `(?![a-z]+[A-Z][a-zA-Z]*")` lookahead를 추가하는 것이 최소 변경이다.)

- [ ] **Step 4: 파싱 + 골든셋 통과 확인**

Run: `PYTHONUTF8=1 py -3.12 -m pytest "tests/test_rules.py::TestRuleFilesSemgrepLoadable" "tests/test_scanner_goldenset.py::TestSemgrepGoldenset" "tests/test_scanner_goldenset.py::TestGoldensetAllScanners" "tests/test_scan_secrets_fallback.py" -q`
Expected: PASS (secrets safe==0 양엔진, secrets vuln≥1 유지 — `tests/fixtures/secrets/vuln/app.properties`의 실제 평문 비밀번호는 `properties` 룰이 담당하므로 영향 없음)

- [ ] **Step 5: 커밋**

```bash
git add skills/detecting-sensitive-data-exposure/rules/sensitive-data.yml skills/detecting-sensitive-data-exposure/scripts/scan_secrets.py tests/fixtures/secrets/safe/JobConst.java
git commit -m "fix: 하드코딩 자격증명 룰에서 식별자 상수(_JOB 등) 오탐 제거

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Sensitive — DTO 노출 룰에서 요청 DTO·서비스 계층 제외

실측: sef `VerifyPasswordRequest`(요청 DTO — 입력용, 응답 직렬화 노출 아님)와 service impl 클래스의 `password` 필드를 응답 노출로 오인. semgrep 룰 `sqisoft-dto-password-field-no-ignore` 전용(fallback엔 대응 룰 없음).

**Files:**
- Modify: `skills/detecting-sensitive-data-exposure/rules/sensitive-data.yml` (룰 `sqisoft-dto-password-field-no-ignore`, 112-139행)
- Create: `tests/fixtures/secrets/safe/VerifyPasswordRequest.java`
- Test: `tests/test_scanner_goldenset.py`, `tests/test_rules.py`

**Interfaces:**
- Consumes: 없음
- Produces: 룰 id 유지.

- [ ] **Step 1: 오탐 재현 fixture 추가**

Create `tests/fixtures/secrets/safe/VerifyPasswordRequest.java`:

```java
package com.sqisoft.sef.modules.user.dto.request;

// 요청 DTO(입력 전용) — 응답에 직렬화되지 않으므로 @JsonIgnore 불필요(오탐이면 안 됨).
public class VerifyPasswordRequest {
    private String password;
}
```

- [ ] **Step 2: 골든셋을 돌려 오탐(FAIL) 확인**

Run: `PYTHONUTF8=1 py -3.12 -m pytest "tests/test_scanner_goldenset.py::TestSemgrepGoldenset::test_safe_clean_by_semgrep" -q`
Expected: FAIL — `secrets` safe에서 `password` 필드가 후보로 잡힘

- [ ] **Step 3: 룰에 요청 DTO·서비스 경로 제외 추가**

In `sensitive-data.yml` rule `sqisoft-dto-password-field-no-ignore`, add a `paths.exclude` block (룰의 `metadata:` 아래, `patterns:` 위에):

```yaml
    paths:
      exclude:
        - "**/dto/request/**"
        - "**/dto/req/**"
        - "**/service/**"
        - "**/serviceimpl/**"
        - "**/batch/**"
        - "**/scheduler/**"
```

(응답 직렬화 대상인 `**/dto/response/**`·`**/vo/**`·엔티티는 계속 검사됨.)

- [ ] **Step 4: 파싱 + 골든셋 통과 확인**

Run: `PYTHONUTF8=1 py -3.12 -m pytest "tests/test_rules.py::TestRuleFilesSemgrepLoadable" "tests/test_scanner_goldenset.py::TestSemgrepGoldenset" -q`
Expected: PASS (secrets safe==0, secrets vuln≥1 유지)

- [ ] **Step 5: 커밋**

```bash
git add skills/detecting-sensitive-data-exposure/rules/sensitive-data.yml tests/fixtures/secrets/safe/VerifyPasswordRequest.java
git commit -m "fix: DTO 노출 룰에서 요청 DTO·서비스 계층 제외 (입력 DTO 오탐 제거)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: Sensitive — 주석 자격증명 룰을 "키워드=값" 형태로 한정

실측: Gseed 39건 대부분이 `<!-- BEGIN: 비밀번호 영역 -->` 같은 UI 섹션 주석의 한글 단어에 반응. semgrep 룰 `sqisoft-jsp-comment-credential`과 grep-fallback `jsp-comment-credential`·`jsp-comment-credential-multiline` 양쪽 수정.

**Files:**
- Modify: `skills/detecting-sensitive-data-exposure/rules/sensitive-data.yml` (룰 `sqisoft-jsp-comment-credential`, 160-175행)
- Modify: `skills/detecting-sensitive-data-exposure/scripts/scan_secrets.py` (fallback `jsp-comment-credential` 187-192행, `jsp-comment-credential-multiline` 240-245행)
- Create: `tests/fixtures/secrets/safe/uiComment.jsp`
- Test: `tests/test_scanner_goldenset.py`, `tests/test_rules.py`, `tests/test_scan_secrets_fallback.py`

**Interfaces:**
- Consumes: 없음
- Produces: 룰 id 유지.

- [ ] **Step 1: 오탐 재현 fixture 추가**

Create `tests/fixtures/secrets/safe/uiComment.jsp`:

```jsp
<%-- UI 섹션 구분 주석 — 자격증명 값이 없다(오탐이면 안 됨). --%>
<!-- BEGIN: 비밀번호 영역 -->
<div class="password-wrap"><input type="password" name="pwd"/></div>
<!-- END: 비밀번호 영역 -->
```

- [ ] **Step 2: 골든셋을 돌려 오탐(FAIL) 확인**

Run: `PYTHONUTF8=1 py -3.12 -m pytest "tests/test_scanner_goldenset.py::TestSemgrepGoldenset::test_safe_clean_by_semgrep" "tests/test_scanner_goldenset.py::TestGoldensetAllScanners::test_safe_clean" -q`
Expected: FAIL — semgrep·fallback 양쪽에서 `secrets` safe>0 (`<!-- BEGIN: 비밀번호 영역 -->`가 잡힘)

- [ ] **Step 3a: semgrep 룰 정규식을 "키워드=값"으로 한정**

In `sensitive-data.yml` rule `sqisoft-jsp-comment-credential`, replace `pattern-regex`:

```yaml
    pattern-regex: '(?i)(<!--[^>]*(password|passwd|pwd|계정|아이디|비밀번호|id/pw)\s*[:=]\s*[^\s<>]{3,}[^>]*-->|//\s*(password|passwd|pwd)\s*[:=]\s*\S+)'
```

- [ ] **Step 3b: fallback 두 정규식도 동일 규칙으로**

In `scan_secrets.py`, `jsp-comment-credential`(단일 라인) 정규식을:

```python
        re.compile(
            r'(?i)<!--[^>]*(?:password|passwd|pwd|id/pw|계정|비밀번호|아이디)\s*[:=]\s*[^\s<>]{3,}[^>]*-->',
        ),
```

그리고 `jsp-comment-credential-multiline` 정규식을:

```python
        re.compile(
            r'(?i)<!--.*?(?:password|passwd|pwd|id/pw|계정|비밀번호|아이디)\s*[:=]\s*[^\s<>]{3,}.*?-->',
            re.DOTALL,
        ),
```

- [ ] **Step 4: 파싱 + 골든셋 + fallback 테스트 통과**

Run: `PYTHONUTF8=1 py -3.12 -m pytest "tests/test_rules.py::TestRuleFilesSemgrepLoadable" "tests/test_scanner_goldenset.py::TestSemgrepGoldenset" "tests/test_scanner_goldenset.py::TestGoldensetAllScanners" "tests/test_scan_secrets_fallback.py" -q`
Expected: PASS (secrets safe==0 양엔진). `test_scan_secrets_fallback.py`에 주석 자격증명 vuln 케이스가 있으면 `키워드=값` 형태인지 확인하고, 아니면 그 테스트 fixture를 `<!-- pwd=admin123 -->` 형태로 맞춘다(값 있는 진짜 케이스는 계속 탐지되어야 함).

- [ ] **Step 5: 커밋**

```bash
git add skills/detecting-sensitive-data-exposure/rules/sensitive-data.yml skills/detecting-sensitive-data-exposure/scripts/scan_secrets.py tests/fixtures/secrets/safe/uiComment.jsp
git commit -m "fix: 주석 자격증명 룰을 키워드=값 형태로 한정 (UI 섹션 주석 오탐 제거)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: XSS — EL 미이스케이프 룰에서 JSTL 비출력 컨텍스트 제외

실측: Gseed `el-unescaped-model-attr`가 `<c:forEach items="${x.y}">`·`<c:if test="${x.y}">`(반복/조건 대상 — HTML 출력 아님)를 출력으로 오인. semgrep 룰 `sqisoft-jsp-el-unescaped-model-attr`와 grep-fallback `jsp-el-unescaped-model` 후처리 양쪽 수정.

**Files:**
- Modify: `skills/detecting-xss-vulnerabilities/rules/xss.yml` (룰 `sqisoft-jsp-el-unescaped-model-attr`, 194-211행)
- Modify: `skills/detecting-xss-vulnerabilities/scripts/scan_xss.py` (fallback 후처리 `jsp-el-unescaped-model`, 199-202행)
- Create: `tests/fixtures/xss/safe/JstlNonOutput.jsp`
- Test: `tests/test_scanner_goldenset.py`, `tests/test_rules.py`, `tests/test_scan_xss_fallback.py`

**Interfaces:**
- Consumes: 없음
- Produces: 룰 id 유지.

- [ ] **Step 1: 오탐 재현 fixture 추가**

Create `tests/fixtures/xss/safe/JstlNonOutput.jsp`:

```jsp
<%-- JSTL 비출력 컨텍스트 — EL이 반복/조건 대상일 뿐 HTML로 출력되지 않는다(오탐이면 안 됨). --%>
<c:forEach var="item" items="${board.list}">
  <c:if test="${board.visible}">visible</c:if>
</c:forEach>
```

- [ ] **Step 2: 골든셋을 돌려 오탐(FAIL) 확인**

Run: `PYTHONUTF8=1 py -3.12 -m pytest "tests/test_scanner_goldenset.py::TestSemgrepGoldenset::test_safe_clean_by_semgrep" "tests/test_scanner_goldenset.py::TestGoldensetAllScanners::test_safe_clean" -q`
Expected: FAIL — semgrep·fallback 양쪽에서 `xss` safe>0 (`items="${board.list}"` 등이 잡힘)

- [ ] **Step 3a: semgrep 룰에 비출력 속성 제외 추가**

In `xss.yml` rule `sqisoft-jsp-el-unescaped-model-attr`, add a `pattern-not-regex` (기존 `pattern-regex`·`pattern-not-regex`와 함께 `patterns:` 리스트에):

```yaml
      # JSTL 비출력 컨텍스트(반복 items·조건 test·set) 안의 EL은 HTML 출력이 아님 → 제외
      - pattern-not-regex: '<c:(?:if|forEach|choose|when|set)\b[^>]*\b(?:test|items|select|var|target)\s*=\s*"[^"]*\$\{'
```

- [ ] **Step 3b: fallback 후처리에 동일 제외 추가**

In `scan_xss.py` `run_fallback`, the `jsp-el-unescaped-model` 후처리 블록(199-202행)을 다음으로 교체:

```python
                                # FR-4 — 저장형 모델 EL은 c:out/escapeXml로 래핑되면 안전 → 후보 제외.
                                # 또한 JSTL 비출력 컨텍스트(c:if test / c:forEach items / c:set)의
                                # EL은 HTML 출력이 아니므로 제외한다(반복/조건 대상 오탐 제거).
                                if rule_id == "jsp-el-unescaped-model" and (
                                    re.search(r'escapeXml|<c:out', line) or
                                    re.search(r'<c:(?:if|forEach|choose|when|set)\b[^>]*\b'
                                              r'(?:test|items|select|var|target)\s*=\s*"[^"]*\$\{', line)
                                ):
                                    continue
```

- [ ] **Step 4: 파싱 + 골든셋 + fallback 테스트 통과**

Run: `PYTHONUTF8=1 py -3.12 -m pytest "tests/test_rules.py::TestRuleFilesSemgrepLoadable" "tests/test_scanner_goldenset.py::TestSemgrepGoldenset" "tests/test_scanner_goldenset.py::TestGoldensetAllScanners" "tests/test_scan_xss_fallback.py" -q`
Expected: PASS (xss safe==0 양엔진, xss vuln≥1 유지 — `${board.title}` 직접 출력형 vuln fixture는 계속 탐지)

- [ ] **Step 5: 커밋**

```bash
git add skills/detecting-xss-vulnerabilities/rules/xss.yml skills/detecting-xss-vulnerabilities/scripts/scan_xss.py tests/fixtures/xss/safe/JstlNonOutput.jsp
git commit -m "fix: EL 미이스케이프 룰에서 JSTL 비출력 컨텍스트(c:if/c:forEach) 제외

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 8: Access Control — IDOR 룰에 @PreAuthorize 권한검증 인식

실측: sef `BoardController`의 `@PreAuthorize("hasMenuAuthority(#menuId,'R')")`·`@AuthenticationPrincipal`로 권한/소유권이 검증되는 핸들러를 IDOR로 오인. semgrep 룰 `sqisoft-spring-pathvariable-id-no-ownership-check`·`sqisoft-spring-pathvariable-annotated-id` 대상(fallback은 `_PREAUTH_ENFORCE` 후처리로 이미 처리).

**Files:**
- Modify: `skills/detecting-broken-access-control/rules/access-control.yml` (룰 `sqisoft-spring-pathvariable-id-no-ownership-check` 39-67행, `sqisoft-spring-pathvariable-annotated-id` 69-88행)
- Create: `tests/fixtures/access/safe/PreAuthCtrl.java`
- Test: `tests/test_scanner_goldenset.py`, `tests/test_rules.py`

**Interfaces:**
- Consumes: 없음
- Produces: 룰 id 유지.

- [ ] **Step 1: 오탐 재현 fixture 추가**

Create `tests/fixtures/access/safe/PreAuthCtrl.java`:

```java
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.security.access.prepost.PreAuthorize;

// @PreAuthorize로 메뉴 권한을 검증하는 핸들러 — IDOR 아님(오탐이면 안 됨).
class PreAuthCtrl {
    @PreAuthorize("hasMenuAuthority(#menuId, 'R')")
    @GetMapping("/{bbsSq}")
    public String get(@PathVariable Long bbsSq) {
        return boardService.getBoardDetail(bbsSq);
    }
}
```

- [ ] **Step 2: 골든셋을 돌려 오탐(FAIL) 확인**

Run: `PYTHONUTF8=1 py -3.12 -m pytest "tests/test_scanner_goldenset.py::TestSemgrepGoldenset::test_safe_clean_by_semgrep" -q`
Expected: FAIL — `access` safe에서 `@PathVariable Long bbsSq` 핸들러가 후보로 잡힘

- [ ] **Step 3: 두 룰에 @PreAuthorize/@Secured 제외 추가**

In `access-control.yml`, rule `sqisoft-spring-pathvariable-id-no-ownership-check` — add to its `patterns:` list:

```yaml
      # 메서드/클래스 레벨 권한 표현식이 있으면 접근통제가 집행되므로 제외(오탐 방지)
      - pattern-not-inside: |
          @PreAuthorize(...)
          $RET $METHOD(...) { ... }
      - pattern-not-inside: |
          @PostAuthorize(...)
          $RET $METHOD(...) { ... }
      - pattern-not-inside: |
          @Secured(...)
          $RET $METHOD(...) { ... }
```

Rule `sqisoft-spring-pathvariable-annotated-id` — add the same three `pattern-not-inside` blocks to its `patterns:` list.

- [ ] **Step 4: 파싱 + 골든셋 통과 확인**

Run: `PYTHONUTF8=1 py -3.12 -m pytest "tests/test_rules.py::TestRuleFilesSemgrepLoadable" "tests/test_scanner_goldenset.py::TestSemgrepGoldenset" "tests/test_scanner_goldenset.py::TestGoldensetAllScanners" -q`
Expected: PASS (access safe==0, access vuln≥1 유지 — `tests/fixtures/access/vuln/Ctrl.java`는 @PreAuthorize 없으므로 계속 탐지)

- [ ] **Step 5: 커밋**

```bash
git add skills/detecting-broken-access-control/rules/access-control.yml tests/fixtures/access/safe/PreAuthCtrl.java
git commit -m "fix: IDOR 룰에 @PreAuthorize/@Secured 권한검증 인식 (게시판 권한핸들러 오탐 제거)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 9: 최종 회귀 검증 + 실제 프로젝트 재측정

모든 오탐 수정 후 전체 스위트와 실제 프로젝트로 개선 효과를 정량 확인한다.

**Files:**
- Test only (변경 없음)

- [ ] **Step 1: 전체 테스트 스위트 통과 확인**

Run: `PYTHONUTF8=1 py -3.12 -m pytest -q`
Expected: PASS (신규 safe fixture 포함 전체 green, 0 failed)

- [ ] **Step 2: 실제 프로젝트 재스캔 — 오탐 감소 정량화**

```bash
SP="D:/Temp/claude/.../scratchpad"   # 세션 scratchpad 경로
PYTHONUTF8=1 py -3.12 scan_all.py "D:/SQ/GSEED/source/Gseed_Web_Renew/src" --json > "$SP/scan_gseed_after.json"
PYTHONUTF8=1 py -3.12 scan_all.py "D:/SQ/sqisoft-sef-2026/public" --json > "$SP/scan_sef_after.json"
```
Expected(정성): sef SQLi 12→0, Gseed XSS js-innerhtml 85→~3, SQLi 20→0, auth jwt-parse 오탐 대폭 감소. before/after 후보 수를 리포트로 비교.

- [ ] **Step 3: 최종 커밋(측정 리포트, 선택)**

```bash
git add docs/superpowers/plans/2026-08-04-scanner-fp-reduction.md
git commit -m "docs: 스캐너 오탐 감축 계획 및 before/after 측정 기록

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**1. Spec coverage:** 조사에서 확정한 오탐 8개 근본 원인 ↔ 태스크 매핑:
- ① SQLi 파일타입 → Task 1 ✅
- ④ 벤더 JS → Task 2 ✅
- ② jwt-parse 광범위 → Task 3 ✅
- ⑧ 상수명 오판 → Task 4 ✅
- ⑦ request DTO → Task 5 ✅
- ③ 주석 키워드 → Task 6 ✅
- ⑤ EL 비출력 → Task 7 ✅
- ⑥ IDOR 권한검증 → Task 8 ✅
- 전체 회귀/재측정 → Task 9 ✅
모든 원인이 태스크로 커버됨.

**2. Placeholder scan:** 각 태스크에 실제 fixture 내용·수정 코드·검증 명령을 명시. 단 Task 4 Step 3b와 Task 6 Step 4는 "원 정규식에 병합" 지시가 있어 실행자가 해당 스캐너 파일을 열어 기존 정규식과 대조해야 한다(원 정규식이 커밋마다 미세히 다를 수 있어 전체 치환 대신 최소 변경을 지시). 이는 파괴적 전체치환 회피를 위한 의도된 안내다.

**3. Type consistency:** 룰 id는 전 태스크에서 원본과 동일하게 유지(참조 안정성). 스캐너 함수 시그니처(`run_semgrep`, `run_fallback`, `_is_mybatis_xml`) 불변. golden set 테스트 이름(`TestSemgrepGoldenset`, `TestGoldensetAllScanners`, `test_safe_clean_by_semgrep`, `test_safe_clean`)은 실제 `tests/test_scanner_goldenset.py`와 일치 확인함.

**주의(리스크):** 룰을 좁히면 진짜 취약을 놓칠(미탐) 위험이 생긴다. 각 태스크의 vuln fixture가 계속 탐지되는지(≥1) 반드시 확인하며, 근본적으로 정적 판별이 불가한 케이스(IDOR 서비스레이어 검증, 커스텀 JWT 래퍼)는 동적 `exploiting-*`·AI 검증이 보완함을 SKILL.md에 유지한다.
