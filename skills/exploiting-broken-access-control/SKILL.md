---
name: exploiting-broken-access-control
description: >-
  SQIsoft 웹 애플리케이션에서 BFLA(Broken Function-Level Authorization)·IDOR(Insecure
  Direct Object Reference)을 실제로 발사해 악용 가능성을 동적으로 확정한다.
  일반 사용자 토큰으로 관리자 API를 호출(BFLA)하거나, 타인 토큰으로 A 소유 리소스를
  조회(IDOR)해 HTTP 상태코드로 판정한다. 발사 전 scope_guard를 강제 통과하며 비파괴가 기본이다.
  IDOR에서 403이면 즉시 오탐으로 확정한다 — 정적 추론만으로 High를 올리지 않는다.
domain: cybersecurity
subdomain: web-application-security
tags:
  - broken-access-control
  - idor
  - bfla
  - dast
  - cwe-639
  - cwe-285
  - owasp-a01
  - sqisoft
cwe:
  - CWE-639
  - CWE-285
owasp:
  - A01:2021-Broken-Access-Control
stacks:
  - spring-modern
  - jsp-legacy
version: "0.3.0"
author: sqisoft-security
license: Proprietary
---

# 동적 접근통제 침투 (BFLA / IDOR)

> ⚠️ **권한 있는 사내 보안 테스트(펜테스트) 전용.** 자사 소유 + 격리된 스테이징/로컬만 대상.
> `tools/scope_guard.py`가 운영(`prod`/`www`/공인)·IP 위장을 코드로 차단한다.

## When to Use

- `detecting-broken-access-control` 정적 진단에서 BFLA/IDOR **후보**가 나왔고, 실제 악용 가능 여부를 확정하고 싶을 때
- 관리자 API(`/adm/v1/**`)가 역할 없이 인증만으로 열리는지(BFLA) 실증할 때
- `@PathVariable id` 엔드포인트가 타인 리소스를 노출하는지(IDOR) 실증할 때
- 정적 추론으로 IDOR을 High로 올렸는데 **실제로는 도메인 계층에서 막는지**(오탐) 동적으로 반증할 때

## Prerequisites

- 실행 중인 스테이징/로컬 대상 (앱이 떠 있어야 함)
- **사용자가 사전 생성한 테스트 계정 2개**:
  - A = 일반 사용자 (BFLA용: 이 토큰으로 관리자 API 호출)
  - B = A와 다른 일반 사용자 (IDOR용: A의 리소스에 접근 시도)
- **IDOR**: A가 소유/생성한 리소스 ID 1개 (`--resource-id`)
- (선택) `detecting-broken-access-control`의 `scan_access.py --json` 결과 (표적 자동 생성용)

## Workflow

### 0단계 — 안전 범위 확인 (강제)

```bash
python tools/scope_guard.py <base_url>     # 예: http://localhost:7171
```

`ALLOW`가 떠야 진행한다. 운영/공인/IP 위장이면 차단되며 발사하지 않는다.

### 1단계 — 실제 발사

```bash
python skills/exploiting-broken-access-control/scripts/attack_access.py \
    http://localhost:7171 \
    --scan reports/scan_access.json \
    --user-a-id <일반A_id> --user-a-pw <pw> \
    --user-b-id <타인B_id> --user-b-pw <pw> \
    --resource-id <A가_소유한_리소스ID> \
    --json
```

- 토큰을 이미 갖고 있으면 로그인 생략: `--token-a <A토큰> --token-b <B토큰>`
- 로그인 형식이 sef-2026과 다르면: `--login-path`, `--body-template '{"lgnId":"{id}","password":"{pw}"}'`, `--token-path data.accessToken`
- 스크립트 흐름: scope 확인 → 로그인(토큰 2개) → 표적 생성 → BFLA/IDOR GET 발사 → 결과 JSON

### 2단계 — 판정 (상태코드 기반)

| 결과 | 판정 |
|---|---|
| `2xx` | **취약 후보** (BFLA: 역할우회 / IDOR: 타인 노출) |
| `401`·`403` | **방어(정상)** |

> **IDOR에서 B가 `403` → 즉시 오탐 확정.** 정적 스캐너가 `@PathVariable id`를 IDOR 후보로 올렸어도, 도메인 메서드(`validateOwner` 등)가 막으면 403이 나온다. 이 스킬의 핵심 가치는 그 오탐을 자동 반증하는 것이다.

### 3단계 — AI 컨텍스트 검증 + 리포트

`2xx` 취약 후보만 실제 코드(서비스→도메인 캡슐화)로 재확인한 뒤, 확정 항목을 4요소로 정리해 `reports/pentest-access-<대상>.md`에 저장한다.

## 비파괴 정책

- 기본은 **GET만** 발사(읽기) — 관리자 데이터 조회·타인 리소스 조회로 권한 우회를 입증한다.
- 쓰기 확정(`PUT /adm/v1/users/{id}/role`, `DELETE ...`)은 `--allow-destructive` + **사람 승인** 후 별도 발사한다. 격리된 스테이징에서만.

## Output Format

신뢰도(confidence)는 동적 발사 결과이므로 **`동적 확정(dynamic)`**으로 기록한다 — 정적 진단의 `정적 추정(static-only)`과 구분한다(개선 E). audit.py 통합 시 이 값이 `phases.access_dynamic.confidence`로 전달된다.

```markdown
# 동적 접근통제 침투 리포트
- 대상: <base_url>   | 점검일: <YYYY-MM-DD>   | 신뢰도: 동적 확정(dynamic)

## 확정 취약점
### [High] BFLA — 관리자 API 역할 미검증 — GET /adm/v1/users
- **① 취약한 점**: 일반 사용자 토큰으로 관리자 엔드포인트 호출 시 200 반환
- **② 이유**: 인증만 요구하고 역할 검증이 없음(@PreAuthorize 무력 또는 부재)
- **③ 뚫리는 방법(Evidence)**: `GET /adm/v1/users` + 일반 토큰 → HTTP 200 (응답에 전체 사용자)
- **④ 해결방법**: @EnableMethodSecurity(prePostEnabled=true) + adminPaths를 hasAuthority("ROLE_ADM")로

## 오탐 제외 (동적 반증)
- IDOR 후보 GET /api/v1/comments/{id} — B 토큰 → HTTP 403 (도메인 validateOwner 방어). 오탐.
```

## 안전 (ATTACK_SAFETY.md 계승)

- 모든 발사 전 `scope_guard.assert_in_scope()` 강제(fail-closed).
- 토큰·자격은 로그/리포트에서 마스킹(`dyn_session.mask_token`).
- 발사한 요청·응답·상태코드를 Evidence로 남긴다.
- **자격 노출 주의**: 토큰·비밀번호를 CLI 인자(`--token-a`·`--user-a-pw`)로 넘기면 프로세스 목록
  (작업관리자/`ps`)에 노출될 수 있다. 공유·멀티유저 호스트를 피하고 단일 운영자 환경에서 테스트 계정으로만 실행한다.

## Tools & Systems

- 공용 엔진: `tools/dyn_session.py` (로그인·인증 HTTP·scope 위임·표준 출력)
- 안전 게이트: `tools/scope_guard.py`
- 정적 연계: `detecting-broken-access-control/scripts/scan_access.py`
- 페이로드/시나리오: `references/payloads.md`
