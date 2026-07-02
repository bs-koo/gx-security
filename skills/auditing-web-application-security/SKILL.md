---
name: auditing-web-application-security
description: >-
  SQIsoft 웹 애플리케이션을 정적·동적 한 번에 통합 점검하는 오케스트레이터 스킬.
  소스 경로(필수)와 실행 중인 스테이징/로컬 URL(선택)을 받아, 9종 취약점(CSRF·XSS·SQLi·
  파일업로드·Path Traversal·접근통제·인증세션·민감정보·SSRF)을 정적 스캐너로 일괄 도출하고
  AI가 오탐을 거른 뒤, 대상 URL이 있으면 실제 페이로드를 발사해 악용을 확정하여 통합 리포트를
  만든다. "전체 점검", "보안 점검", "취약점 다 봐줘" 요청 시 이 스킬을 쓴다.
domain: cybersecurity
subdomain: web-application-security
tags: [audit, owasp, sast, dast, orchestrator, sqisoft, full-scan]
stacks: [spring-modern, jsp-legacy]
version: "0.2.1"
author: sqisoft-security
license: Proprietary
---

# 웹 애플리케이션 보안 통합 점검 (정적 + 동적 한 번에)

이 스킬은 개별 `detecting-*`(정적)·`exploiting-*`(동적) 스킬을 **하나로 오케스트레이션**한다.
사용자가 "이 프로젝트 전체 점검해줘"라고 하면 단계별 호출 없이 이 스킬 하나로 끝까지 수행한다.

## When to Use

- 프로젝트 전체 또는 특정 도메인을 **한 번에** 보안 점검할 때 (커밋 전·PR 전·릴리스 전)
- 정적만이 아니라 **실제 악용 가능성까지** 확인하고 싶을 때(실행 중인 스테이징/로컬이 있을 때)
- "보안 점검", "취약점 다 봐줘", "OWASP 점검" 같은 포괄 요청

특정 취약점 한 종류만 볼 때는 개별 `detecting-<X>` / `exploiting-<X>` 스킬을 직접 쓴다.

## Prerequisites

- **소스 경로**(필수): 예 `D:\SQ\sqisoft-sef-2026`
- **대상 URL**(선택, 동적까지 하려면): 실행 중인 **스테이징/로컬**. 예 `http://localhost:8080`
  - 운영 환경 금지 — `tools/scope_guard.py`가 코드로 차단한다. → [ATTACK_SAFETY.md](../../ATTACK_SAFETY.md)
- Python 3. (선택) `semgrep` 설치 시 정적 정밀도 향상, 없으면 grep 폴백.

## Workflow

### 0단계 — 입력 확인
- 소스 경로 확보. 동적까지 할지(대상 URL 유무) 결정.
- 대상 URL이 운영처럼 보이면 중단하고 사용자에게 스테이징/로컬을 요청.

### 1단계 — 통합 엔진 실행 (정적 + 동적 일괄)
```bash
# 정적만
python skills/auditing-web-application-security/scripts/audit.py "<소스경로>" --json
# 정적 + 동적(실행 중 대상)
python skills/auditing-web-application-security/scripts/audit.py "<소스경로>" \
    --target "http://localhost:8080" --params id,q,search --json
```
→ `phases.static`(9종 후보) + `phases.dynamic`(실제 발사 결과)를 한 번에 받는다.

### 2단계 — 정적 후보 AI 검증 (오탐 제거)
후보가 많은 취약점 클래스부터, 해당 `detecting-<X>` 스킬의 2단계(컨텍스트 검증) 기준으로
실제 소스를 읽어 **오탐을 제거하고 확정 취약점만 남긴다**. (예: `csrf().disable()`이 STATELESS면 의도된 예외)
- 참조: 각 `skills/detecting-<X>/references/stack-patterns.md`

### 3단계 — 동적 결과 종합 (악용 확정)
대상 URL이 있었다면 `phases.dynamic`의 결과로 **실제 악용 여부**를 확정한다.
미확정 후보 중 중요한 것은 해당 `exploiting-<X>` 스킬로 추가 발사(파라미터 지정)한다.
- **접근통제(IDOR/BFLA)**는 정적 후보(`by_skill`)를 받아 연계하며, **테스트 계정(권한 교차용) 유무**로 판정 수준이 갈린다 — `run_access_dynamic`이 계정이 없으면 정적 후보만 남기는 `static-only`, 계정이 있으면 실제 권한 교차 호출로 확정하는 `dynamic`으로 구분한다.
- **인증·세션·JWT**도 마찬가지로 `run_auth_dynamic`이 **계정과 보호 엔드포인트(`--probe`) 유무**로 판정 수준이 갈린다 — probe와 로그인 계정이 모두 있으면 JWT 변조·토큰 재사용·쿠키 속성을 실제 발사하는 `dynamic`, **로그인 계정(`--user-a-id/pw`)만 있고 probe가 없으면** 로그인 응답 쿠키 속성만 발사하는 `partial`(JWT·재사용은 정적 추정), 계정이 전무하면 발사하지 않는 `static-only`로 구분한다. **`--token-a`(토큰 직접 주입)는 로그인을 생략해 Set-Cookie가 없으므로 쿠키 검사도 건너뛴다** — probe가 없으면 발사 0건인 `static-only`이고(probe가 있으면 JWT·재사용은 발사되어 `dynamic`), 따라서 `partial`은 실제 로그인(`--user-a-id/pw`)일 때만 성립한다.
- **SSRF/오픈 리다이렉트**도 `run_ssrf_dynamic`이 **표적과 계정 유무**로 판정 수준이 갈린다 — 표적(`--redirect-target`/`--ssrf-target`)과 계정(`--token-a` 또는 `--user-a-id/pw`)이 **모두** 있으면 리다이렉트 파라미터·SSRF 주입점에 실제 발사하는 `dynamic`, 표적이나 계정이 하나라도 없으면 발사하지 않는 `static-only`로 구분한다(표적을 우선 판정한다). 확정은 `Location`이 외부 호스트면 오픈 리다이렉트, OOB canary 콜백 수신이면 블라인드 SSRF까지 잡는다(비파괴 GET).
- XSS는 저장·DOM형이면 Playwright MCP로 브라우저 실제 실행까지 확인한다.

### 4단계 — 통합 리포트 작성·저장
모든 취약점 클래스를 **하나의 리포트**로 통합한다. `reports/audit-<프로젝트>.md`에 저장.

## Output Format

```markdown
# 보안 통합 점검 리포트 — <프로젝트>
- 소스: <경로> | 감지 스택: <spring-modern|jsp-legacy|mixed> | 대상 URL: <URL 또는 정적만>
- 정적 엔진: <semgrep|grep-fallback> | 점검일: <YYYY-MM-DD>

> ⚠ **정적 엔진이 `grep-fallback`이면** 아래 경고를 리포트 본문에 반드시 포함한다:
> recall(탐지율)이 낮아 미탐 위험이 큼 · `pip install semgrep` 설치 권장 · **후보 0건이 안전을 의미하지 않음**.

## 대시보드 (심각도 × 취약점 클래스)
| 취약점 | 후보 | 확정 | 동적 악용 | 최고 심각도 |
|---|---|---|---|---|
| SQLi | 0 | 0 | - | - |
| XSS  | 3 | 1 | 🔴 확정 | High |
| ... | | | | |

## 확정 취약점 (심각도순)
### [High] 저장형 XSS — commentView.jsp:42
- 스택/위치: jsp-legacy / commentView.jsp:42
- ① 취약한 점(What): ...
- ② 취약한 이유(Why): ...
- ③ 뚫리는 방법(How): <개념 PoC, 동적 확정 시 실제 페이로드>
- ④ 해결방법(Fix): <수정 코드>
- Evidence(동적 시): 주입 페이로드·실행 스크린샷·응답
- 참조: CWE-79 / OWASP A03

## 의도된 예외 / 오탐 제외
- ...
```

## Verification
- [ ] 소스의 스택이 정확히 감지됐는가(혼합 시 디렉토리별 처리)
- [ ] 후보가 많은 클래스를 빠짐없이 AI 검증했는가(오탐 제거 근거 명시)
- [ ] 대상 URL이 있었다면 동적 결과(악용 확정/증거)를 반영했는가
- [ ] 동적은 스테이징/로컬에만 발사했는가(운영 차단 확인)
- [ ] 통합 리포트가 `reports/`에 저장됐는가

## 구성 (오케스트레이션 대상)
- 정적: `scan_all.py` → 9개 `detecting-*` 스캐너
- 동적: `exploiting-*` (sql-injection, xss, broken-access-control, auth-session, ssrf-and-open-redirect) + `tools/scope_guard.py` 안전게이트
- 산출물: `reports/audit-<프로젝트>.md`
