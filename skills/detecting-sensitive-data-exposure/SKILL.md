---
name: detecting-sensitive-data-exposure
description: >-
  SQIsoft 웹 애플리케이션에서 민감정보 노출(Sensitive Data Exposure) 취약점을 검사한다.
  하드코딩 시크릿(DB 비밀번호·API 키·JWT 시크릿·초기 비밀번호), 개인정보(주민번호·이메일·전화번호)
  평문 저장·로그 출력, 응답 DTO 과다 필드 노출, 예외 스택트레이스 사용자 노출을 탐지한다.
  properties/yml/xml/.java/.jsp 전 계층을 검사하며 환경변수·Vault placeholder는 오탐 제외한다.
  CWE-200(정보노출), CWE-798(하드코딩 자격증명), OWASP A02:2021(암호화 실패)에 대응.
domain: cybersecurity
subdomain: web-application-security
tags:
  - sensitive-data-exposure
  - hardcoded-secret
  - hardcoded-credentials
  - secret-leak
  - personal-information
  - pii
  - cwe-200
  - cwe-798
  - owasp-a02
  - spring-security
  - jsp
  - properties
  - sqisoft
cwe: [CWE-200, CWE-798]
owasp: [A02:2021-Cryptographic-Failures]
stacks: [spring-modern, jsp-legacy]
version: "0.3.0"
author: sqisoft-security
license: Proprietary
---

# 민감정보 노출 검사 (Sensitive Data Exposure / Hardcoded Secrets)

## When to Use

다음 중 하나라도 해당하면 이 스킬을 실행한다.

- SQIsoft 프로젝트(`sqisoft-sef-2026`, `Gseed_Web_Renew`)의 **설정 파일·소스 코드에 DB 비밀번호·API 키·JWT 시크릿이 평문으로 박혀 있는지** 점검할 때
- **로그(log.info/System.out.println)에 비밀번호·주민번호·개인정보가 출력**되는지 확인할 때
- 응답 DTO나 REST API 응답에 **비밀번호 해시·내부 필드가 불필요하게 포함**되는지 검토할 때
- **예외 스택트레이스가 사용자에게 그대로 노출**되는지 확인할 때
- 보안 코드 리뷰·출시 전 점검·형상관리(SVN/Git) 커밋 전 시크릿 스캔

**이 스킬을 쓰지 않을 때:** SQL 인젝션·XSS·CSRF 등 다른 취약점 클래스(→ 해당 스킬 사용).

## Prerequisites

- 대상 프로젝트 소스에 대한 읽기 접근
- (선택, 권장) `semgrep` 설치 — 없으면 `scripts/scan_secrets.py`가 grep-fallback으로 동작
- 스택 판별 참고: `references/stack-patterns.md`

## Workflow

### 0단계 — 스택 자동 감지

대상 경로의 루트 신호를 확인해 스택을 판별한다.

| 스택 | 감지 신호 | 중점 검사 위치 |
|---|---|---|
| `spring-modern` | `build.gradle.kts`, `src/main/java`, `application.yml` | `application*.yml`, `@Value` 기본값, Java 소스 |
| `jsp-legacy` | `WEB-INF/web.xml`, `*.jsp`, `globals.properties`, `pom.xml` | `globals.properties`, `context-datasource.xml`, JSP 주석 |

### 1단계 — 스캐너 1차 탐지 (재현 가능)

```bash
python skills/detecting-sensitive-data-exposure/scripts/scan_secrets.py <TARGET> --json
```

스크립트는 스택을 감지해 Semgrep 룰을 실행하고, Semgrep이 없으면 grep-fallback으로 후보를 잡는다.
출력은 `{file, line, rule_id, stack, snippet}` 목록.

### 2단계 — AI 컨텍스트 검증 (핵심)

스캐너 후보는 **출발점일 뿐**이다. 각 후보를 다음 기준으로 직접 검증한다.

**하드코딩 시크릿 검증 포인트**

1. `password=값` 형태를 발견하면 → **실제 평문 값인지, `${ENV_VAR}` placeholder인지** 구분.
   - `Globals.Password=Db@ssw0rd!` 처럼 실제 값 → 즉시 **확정 취약점(Critical/High)**.
   - `password: ${DB_PASSWORD}` 처럼 환경변수 참조 → **오탐 제외**.
2. `@Value("${key:기본값}")` 에서 기본값이 실제 시크릿이면 → High (운영 환경변수 미설정 시 노출).
3. API 키 패턴(`confmKey`, `gbcsApiKey`, `recaptcha.secretKey` 등)은 길이·형식을 보고 실제 키인지 확인.
4. `Member.InitPassword` 같은 초기 비밀번호는 소스에 있으면 **그 자체가 취약** (관리자 계정 탈취 가능).

**로그 개인정보 검증 포인트**

1. `log.info("... userId={}", userId)` — userId가 이메일·주민번호이면 로그 파일에 개인정보 기록.
2. `log.debug("인증 실패: 사용자 {} 의 비밀번호가 일치하지 않음", lgnId)` — 실패 사유 노출은 사용자 열거 위험.
3. `System.out.println` 포함 여부 확인(레거시 JSP 프로젝트에서 흔함).

**응답 DTO 과다 노출 검증 포인트**

1. `@JsonIgnore` 없이 `password`·`encryptedPwd` 필드가 DTO 클래스에 있는지 확인.
2. REST API 응답 JSON 샘플이나 VO 클래스 반환 필드를 점검.

**예외 스택트레이스 검증 포인트**

1. `@ExceptionHandler` 또는 Spring `BasicErrorController` 설정이 없으면 스택트레이스가 사용자에게 노출됨.
2. JSP 레거시: `web.xml`에 `<error-page>` 미설정 시 WAS 기본 오류 페이지(스택트레이스 포함) 노출.

**공통 — 스캐너가 못 잡는 것(AI 보강)**
- 주석 내 계정 정보 (`<!-- DB: id/pw -->`, `// 테스트 계정: admin/1234` 등)
- Base64 인코딩된 자격증명 (`QVBJX0tFWV9QTGFj...` — Base64 디코딩 후 확인)
- XML `<property name="password" value="실제값"/>` 형태

### 3단계 — 사업부 표준 리포트

확정된 항목만 아래 양식으로 출력한다.

## Output Format

```markdown
# 민감정보 노출 점검 리포트
- 대상: <프로젝트/경로>   | 감지 스택: <spring-modern | jsp-legacy | mixed>
- 스캐너: <semgrep vX.Y | grep-fallback>   | 점검일: <YYYY-MM-DD>

## 요약
- 확정 취약: N건 (Critical n / High n / Medium n / Low n)
- 의도된 예외: M건   | 오탐 제외: K건

## 확정 취약점

### [Critical] DB 비밀번호 하드코딩 — globals.properties:25
- 스택 / 위치: jsp-legacy / globals.properties:25
- **① 취약한 점(What)**: `Globals.Password=Db@ssw0rd!` — PostgreSQL DB 비밀번호가 소스 파일에 평문으로 박혀 있음
- **② 취약한 이유(Why)**: 형상관리(SVN/Git)에 커밋되면 리포지토리 접근자 전원이 DB 자격증명을 획득. 로컬 개발자 PC, 빌드 서버, 로그 등 어디서든 유출 가능
- **③ 뚫리는 방법(How · 개념 PoC)**: SVN/Git 이력에서 globals.properties를 조회하면 현재 값뿐 아니라 과거 변경 이력도 평문으로 확인 가능. 내부망 접근 권한을 가진 공격자가 `jdbc:postgresql://10.0.0.5:5432/appdb`에 `gseed/Db@ssw0rd!`로 직접 접속해 전체 DB를 열람·변조 가능
- **④ 해결방법(Fix)**: 환경변수 또는 외부 시크릿 저장소로 분리
  ```properties
  # globals.properties
  Globals.Password=${DB_PASSWORD}
  ```
  운영 서버 환경변수: `export DB_PASSWORD=실제비밀번호`  
  또는 HashiCorp Vault / AWS Secrets Manager 연동
- 참조: CWE-798, OWASP A02:2021

### [High] API 키 하드코딩 — globals.properties:52
- 스택 / 위치: jsp-legacy / globals.properties:52
- **① 취약한 점(What)**: `Globals.gbcsApiKey=0123456789abcdef0123456789abcdef` — GBCS 외부 API 키 평문 하드코딩
- **② 취약한 이유(Why)**: 소스 접근자가 API 키를 획득해 무단 API 호출 가능. 키 교체 시 재배포 필요해 운영 부담 증가
- **③ 뚫리는 방법(How · 개념 PoC)**: 유출된 키로 GBCS API(`https://api.example.go.kr/api/`)에 무제한 호출 → 서비스 요금 폭탄, 데이터 무단 조회
- **④ 해결방법(Fix)**: `Globals.gbcsApiKey=${GBCS_API_KEY}` 로 환경변수 참조
- 참조: CWE-798, OWASP A02:2021

## 의도된 예외 (확인 필요)
- [Info] `Globals.recaptcha.siteKey` — reCAPTCHA 사이트키는 공개값이므로 소스 포함 정상. 단 secretKey는 별도 관리 필요

## 오탐 제외
- application.yml:27 `password: ${DB_PASSWORD}` — 환경변수 참조, 하드코딩 아님
```

## Verification (검사 자체의 신뢰성 확인)

- [ ] `*.properties`, `*.yml`, `*.xml`, `*.java`, `*.jsp`, `*.jsp` 전 파일을 대상으로 스캔했는가
- [ ] `${...}` placeholder와 실제 평문 값을 구분했는가
- [ ] Base64 인코딩 문자열을 디코딩해 자격증명 여부를 확인했는가
- [ ] 주석 내 계정 정보를 별도로 확인했는가
- [ ] 로그 출력에 개인정보(이메일·주민번호·전화번호)가 포함되는지 확인했는가
- [ ] 응답 DTO에 `@JsonIgnore` 없이 비밀번호·내부 필드가 직렬화되는지 확인했는가
- [ ] 예외 처리 설정(`@ExceptionHandler`, `web.xml error-page`)이 있는지 확인했는가

## Key Concepts

| 용어 | 설명 |
|---|---|
| 하드코딩 자격증명 | 소스 코드·설정 파일에 평문으로 직접 쓴 비밀번호·키. 형상관리에 커밋되면 영구 유출 |
| CWE-798 | 하드코딩된 자격증명 사용 — 소스에 평문 시크릿이 존재 |
| CWE-200 | 중요 정보 노출 — 로그·응답·오류 메시지에 민감정보가 포함 |
| placeholder | `${DB_PASSWORD}` 형태의 환경변수 참조 — 안전 패턴 |
| PII | 개인식별정보(주민번호·이메일·전화번호) — 로그 출력·평문 저장 금지 |
| `@JsonIgnore` | 응답 직렬화 제외 어노테이션 — DTO 비밀번호 필드에 필수 |
| `@Value` 기본값 | `@Value("${key:기본값}")` 의 기본값에 실제 시크릿 사용 금지 |
| 초기 비밀번호 | `Member.InitPassword` 등 관리자 초기 비밀번호 하드코딩 — 계정 탈취 직결 |

## Tools & Systems

- Semgrep (룰: `rules/sensitive-data.yml`) · grep-fallback
- 참고: `references/stack-patterns.md`
- 관련 도구: truffleHog, git-secrets, detect-secrets (CI/CD 파이프라인 연동 권장)
