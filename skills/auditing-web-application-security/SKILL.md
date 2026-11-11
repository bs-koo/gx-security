---
name: auditing-web-application-security
description: >-
  SQIsoft 웹 애플리케이션의 기존 audit.py 전문가 경로를 다루는 보조 스킬.
  정적 9종의 후보와 명시적으로 승인된 동적 관찰을 모으고 근거·미확정·미검사 범위를
  보고한다. 일반적인 보안 점검·출시 점검은 gx-security 통합 스킬을 우선 사용한다.
  URL 제공만으로 동적 실행이나 취약 확정을 부여하지 않으며 새 출시 판정을 대신하지 않는다.
domain: cybersecurity
subdomain: web-application-security
tags: [audit, owasp, sast, dast, orchestrator, sqisoft, full-scan]
stacks: [spring-modern, jsp-legacy]
version: "0.10.3"
author: sqisoft-security
license: Proprietary
---

> Release-check contract: use the common gxsec CLI for developer checks and release evidence. Legacy commands below are expert/reference paths, not proof of release completion. Preserve candidate vs verified vs incomplete states; never treat status 200, reflection, a helper name, or an annotation alone as a confirmed exploit/defense. Credentials use references/stdin; no plain passwords/tokens in argv or chat. Required scope/readiness/authentication/confinement evidence is enforced by the new release path.

업무 의도·허용 역할·자료 공개 범위만 모호하면 코드와 기존 답변을 먼저 확인한 뒤 호스트 질문 도구(없으면 대화)로 필요한 내용만 묻는다. 답변에 따라 실제 경로·대조 증거를 더 조사하고, 답변 자체로 검증·반증·위험 수용을 확정하지 않는다. 정적 점검과 보고서 읽기에는 동적 계정을 요구하지 않는다.


SEF 또는 공통 방어가 관련된 후보는 [공유 SEF 문맥 검토](../checking-release-security/references/sef-context.md)를 읽고 공통 CLI 결과를 사용한다. 아래 전문가용 판정·오탐 표기는 검토 제안이며 원본 finding의 검증 상태·심각도·ID를 바꾸거나 보호된 독립 검토를 대체하지 않는다.

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

### 0단계 — 입력 확인 · 스캔 루트 탐색(모노레포 대응)
- 소스 경로 확보. 동적 실행은 대상 URL과 명시적 승인·준비 조건을 함께 확인해 결정한다.
- 대상 URL이 운영처럼 보이면 중단하고 사용자에게 스테이징/로컬을 요청.
- **다중 루트 자동 탐색**: 모노레포일 수 있으므로 스캔 루트를 나눠 찾는다(`node_modules`·`dist`·`.nuxt`·`.output` 제외).
  - **백엔드 루트**(9종 풀스캔): `build.gradle*`/`pom.xml`이 있는 디렉토리. 예 sef-2026 → `private/backend`, `public`.
  - **프론트엔드 루트**(XSS frontend 모드 전용): `nuxt.config.*`/`vite.config.*`가 있는 디렉토리. 예 sef-2026 → `private/frontend`, `public/frontend`.
  - **AskUserQuestion**으로 발견한 루트 목록을 확인한다("이 루트들이 스캔 대상 맞나요?", 자유서술 칸 상시). 백엔드 루트엔 9종, 프론트 루트엔 `detecting-xss` frontend 모드만 돌린 뒤 **하나의 통합 리포트**로 병합한다.

### 1단계 — 정적 엔진 실행 (항상 수행)
```bash
# 정적만 먼저 — 완전 안전(읽기 전용). 동적은 1.5단계 게이트 통과 후에만.
python skills/auditing-web-application-security/scripts/audit.py "<소스경로>" --json
```
→ `phases.static`(9종 후보)를 받는다. 동적은 아래 게이트에서 옵트인한다.

### 1.5단계 — 동적 게이트 (AskUserQuestion — 대상 실행 여부 확인)

정적은 항상 수행하고, **동적(모의침투)은 여기서 옵트인**한다. 정적 완료 후 사용자에게 묻는다.

1. 정적 점검만 요청했다면 동적 실행·계정 질문을 건너뛴다. 동적 점검을 요청했으나 대상·실행 범위가 미결정인 경우에만 호스트 질문 도구로 필요한 내용을 묻는다. 이미 유효한 대상·승인·답변은 재사용한다.
   - 옵션: `예 — URL 있음` / `아니오 — 정적만` / `지금 띄울게요(대기)` + **항상 자유서술("직접 입력") 칸**을 노출.
   - `아니오`면 동적을 건너뛰고 정적 결과만으로 4단계 리포트를 쓴다(모든 미확정은 "정적 추정"으로 표기).
2. **라이브니스 프로브** — `예`면 발사 전 대상이 실제로 떠 있는지 1회 확인(비파괴 GET). scope 통과 필수.
   ```bash
   python tools/scope_guard.py "<대상URL>"      # ALLOW 여야 진행(운영/공인은 코드 차단)
   curl -sS -o /dev/null -w "%{http_code}\n" "<대상URL>"   # 200/302 등 응답이면 가동
   ```
   죽어 있으면 "대기/재시도"를 안내하고, 사용자가 띄운 뒤 다시 프로브한다.
3. **DB 격리 게이트 (동적 검사 전 필수 — 개발 DB 오염·실데이터 노출 방지)**

   `scope_guard`는 대상 **URL 호스트**만 검증하고 그 서버가 바라보는 **DB는 모른다.** 서버가 로컬이어도 **공유 개발 DB(실데이터)**에 연결돼 있으면, 동적 검사가 실데이터를 노출(IDOR로 실제 PII 회수)하거나 오염(테스트 계정·픽스처가 개발 DB에 쌓임)시킬 수 있다. **발사 전 반드시 DB 격리 여부를 확인한다.**

   **① 자동 힌트** — 서버 설정의 datasource url로 추정한다(참고용, 확정 아님):
   ```bash
   grep -rEn "jdbc:|datasource|url:" <소스>/src/main/resources/ | grep -iE "url|jdbc" | head
   # localhost/127.0.0.1/도커포트(5433 등) → 격리 추정 / 원격 IP·사내 호스트 → 개발 DB 추정
   ```

   **② 격리 근거 확인** — 보호된 환경 근거와 기존 답변을 먼저 확인한다. 실제로 모를 때만 "이 서버의 DB가 격리/더미 DB인가요, 공유 개발 DB인가요?"를 묻는다. 사용자 답변·localhost·Docker 포트만으로 격리를 입증하지 않는다.
   - 옵션: `격리/더미(도커·로컬 전용)` / `공유 개발 DB(실데이터 있음)` / `모름` + 자유서술 칸.
   - **`모름`·불확실 → 개발 DB로 간주(fail-safe).**

   **③ 분기**
   - **[격리/더미 DB]** → 유효한 환경 근거·승인된 정확한 표적·계정·합성 fixture 범위를 확인한 작업만 진행한다. 격리라는 답변만으로 계정·DB 데이터를 자유 생성하거나 전체 동적으로 확대하지 않는다.
   - **[공유 개발 DB]** → ⚠️ **오염 방지 모드**. AI는 **계정·픽스처를 생성하지 않는다.** 대신:
     - **(가) 권장: 로컬 격리 DB 전환 안내** — 로컬이면 도커로 격리 DB를 띄우면 격리 경로로 전환된다.
       ```bash
       # 프로젝트에 로컬 도커 DB 구성이 있으면(예: sef-2026 = localdocker 프로필 + 5433)
       docker compose up -d <db-service>      # 또는 docker run ... postgres
       # 서버를 격리 DB 프로필로 재기동한 뒤 위 ②를 '격리'로 다시 확정
       ```
     - **(나) 개발 DB 그대로 쓸 경우: 기존 테스트 계정 요청** — AI가 계정을 만들지 않으므로 **이미 존재하는 테스트 계정**을 사용자에게 받는다(아래 4번 계정 입력 = `read -rs` env). 이때 AI는 **가입 구조를 알 필요 없이 로그인만** 하며, 로그인 방법은 `--login-profile`(없으면 로그인 컨트롤러 소스만 읽어 프로필 초안 작성 후 사용자 확인)로 해결한다.
     - **파괴적/쓰기 차단** — 계정 가입·픽스처 삽입·파일 업로드(`--allow-destructive`)를 **금지**하고 **비파괴 읽기 검사만** 수행한다. IDOR 등 읽기도 **실데이터 회수 주의**를 리포트에 명시한다.

4. **계정 입력 — 무엇을 어디에 (비밀은 대화·argv·파일에 남기지 않는다)**

   동적 확정에 필요한 값을 **비밀/비-비밀로 나눠** 입력한다. 비밀(비밀번호·토큰)만 인터랙티브 env로 받는다:

   | 값 | 비밀? | 넣는 곳 | 방법 |
   |----|:---:|--------|------|
   | 로그인 형식(경로·바디·필드) | ❌ | `profiles/<앱>.json` 파일 | sef-2026 기본 제공, 다르면 파일 작성 |
   | 아이디(user_a_id·user_b_id) | ❌ | 명령 인자 | `--user-a-id` 등 |
   | resource_id·주입점 | ❌ | 명령 인자 | `--resource-id`·`--ssrf-target` 등 |
   | **비밀번호·토큰** | ✅ | **환경변수(인터랙티브)** | `read -rs` → `--*-env` |

   **비밀번호는 인터랙티브 env로** — 화면·셸 history·argv·디스크 어디에도 안 남긴다:
   ```bash
   read -rs GXSEC_USER_A_PW; export GXSEC_USER_A_PW     # 입력이 화면에 안 보임
   read -rs GXSEC_USER_B_PW; export GXSEC_USER_B_PW
   python skills/auditing-web-application-security/scripts/audit.py "<소스경로>" \
       --target "http://localhost:8080" --login-profile sef-2026 \
       --user-a-id <A> --user-a-pw-env GXSEC_USER_A_PW \
       --user-b-id <B> --user-b-pw-env GXSEC_USER_B_PW \
       --resource-id <A소유ID> --probe /api/v1/users/me --params id,q --json
   ```
   - **⛔ 금지**: 비밀번호를 **채팅창 입력**(트랜스크립트 영구 기록)·`--user-a-pw <값>` 직접 인자(argv·history 노출)·아무 **파일 저장**(디스크 평문).
   - **📄 파일은 로그인 "형식"에만** — `profiles/<앱>.json`에 `login_path`·`body_template`·`token_path`·`id_field`·`pw_field`만. `{id}`/`{pw}`는 실행 시 env에서 치환되며 **비밀번호는 파일에 넣지 않는다**.
   - `--creds-stdin`은 안전한 비밀 입력 도구가 생성한 JSON 파이프로 전달한다. 원문 비밀을 담은 echo 명령은 history에 남으므로 만들지 않는다.

   → `phases.dynamic` 및 클래스별 `*_dynamic` 결과를 받아 3단계로 종합한다.

5. **미입력 시 범위 안내** — 요청된 동적 작업에 필요한 계정/주입점이 없으면 무엇이 미확정으로 남는지 알린다. 기존 정적 선택·거절을 다시 묻지 않고 추가 검증이 요청된 경우에만 빠진 입력을 확인한다:
   ```
   [사전 경고] 현재 준비 상태 → 다음은 정적 추정(static-only)으로 남습니다:
     · 접근통제(IDOR/BFLA)  — user_a/user_b + resource_id 필요
     · 인증세션(JWT·재사용) — user_a + --probe 필요
     · SSRF/경로/업로드     — 주입점(--ssrf-target 등) 필요
   지금 준비해 확정할까요, 아니면 이대로 정적 추정으로 진행할까요?
   ```

6. **(선택) Burp 프록시 경유(하이브리드)** — `--burp-proxy http://127.0.0.1:8080`을 더하면 모든 동적 발사가
   Burp 프록시를 경유해 트래픽이 Burp 히스토리에 축적된다(판정·`scope_guard` 불변). 발사 전
   `tools/burp_preflight.py`가 Burp 가동을 확인하고, 미가동이면 설치 온보딩을 출력한 뒤 기존 스크립트
   경로로 폴백한다(`--burp-proxy-strict`면 폴백 대신 중단). Burp 고유 심화(JWT 변조·Collaborator)는
   `exploiting-with-burp` 스킬을 참조한다. ⚠ Burp Proxy > Intercept는 OFF여야 발사가 멈추지 않는다.

### 2단계 — 정적 후보 AI 검증 (오탐 제거)
후보가 많은 취약점 클래스부터, 해당 `detecting-<X>` 스킬의 2단계(컨텍스트 검증) 기준으로
실제 소스를 읽어 **후보·확인한 근거·미확정과 반대 근거를 구분해 기록한다**. `csrf().disable()`과 STATELESS 설정만으로 CSRF 방어의 적용 불가를 확정하지 않고 실제 인증 경로를 확인한다. 공식 반증·위험 수용에는 보호된 검토 절차를 적용한다.
- 참조: 각 `skills/detecting-<X>/references/stack-patterns.md`

### 3단계 — 동적 관찰과 판정 근거 종합
승인된 동적 실행이 있었다면 `phases.dynamic`의 관찰을 정상 대조군·실제 소스·검사 범위와 대조해 **확정·미확정·미검사**를 구분한다.
미확정 후보 중 중요한 것은 해당 `exploiting-<X>` 스킬로 추가 발사(파라미터 지정)한다.
- **접근통제(IDOR/BFLA)**는 정적 후보(`by_skill`)를 받아 연계하며, 계정이 없으면 `static-only`, 계정이 있어 실제 권한 교차 호출을 수행하면 `dynamic`으로 표시한다. 실행 표시는 취약점 확정이 아니며 신원·객체 귀속·권한 의도·응답 oracle을 별도로 검토한다.
- **인증·세션·JWT**도 마찬가지로 `run_auth_dynamic`이 **계정과 보호 엔드포인트(`--probe`) 유무**로 판정 수준이 갈린다 — probe와 로그인 계정이 모두 있으면 JWT 변조·토큰 재사용·쿠키 속성을 실제 발사하는 `dynamic`, **로그인 계정(`--user-a-id/pw`)만 있고 probe가 없으면** 로그인 응답 쿠키 속성만 발사하는 `partial`(JWT·재사용은 정적 추정), 계정이 전무하면 발사하지 않는 `static-only`로 구분한다. **`--token-a`(토큰 직접 주입)는 로그인을 생략해 Set-Cookie가 없으므로 쿠키 검사도 건너뛴다** — probe가 없으면 발사 0건인 `static-only`이고(probe가 있으면 JWT·재사용은 발사되어 `dynamic`), 따라서 `partial`은 실제 로그인(`--user-a-id/pw`)일 때만 성립한다.
- **SSRF/오픈 리다이렉트**는 승인된 표적과 계정이 준비된 경우에 실행한다. `dynamic`은 실행 경로 표시다. 오픈 리다이렉트는 실제 리디렉션 상태와 입력에 연결된 외부 목적지를 확인하고 정책을 검토한다. SSRF는 실행별 nonce 콜백과 발생 주체를 확인하며, 콜백 미수신은 미확정으로 보존한다.
- **경로조작/파일업로드**도 승인된 표적과 계정이 있을 때만 실행한다. 경로조작은 정상 대조군과 구분되는 2xx 응답의 해당 표적 파일 시그니처를 확인한다. 미검출·오류·차단은 안전 확정이 아니다. **업로드는 `--allow-destructive` 없이는 실행하지 않는다.** 무해한 `.jsp` 마커의 수용·회수는 파일 제공 관찰이며 코드 실행이나 High 확정 증거가 아니다. 제공 정책·실행 설정을 별도로 검토하고, 응답 유실을 포함해 남을 수 있는 마커의 정리 상태를 보존한다. 삭제 경로를 추측하거나 자동 삭제하지 않는다.
- XSS는 저장·DOM형이면 Playwright MCP로 브라우저 실제 실행까지 확인한다.

#### static-only 보강 재실행 (승인된 계정 확보 후 추가 조사)

1차 audit 리포트의 **`static_only_summary`** 필드에 계정/주입점 미제공으로 **정적 추정으로 남은 동적 클래스**가 담긴다(예: `["접근통제(IDOR/BFLA)", "인증세션(JWT·재사용)"]`). 승인된 계정을 확보하면 **그 항목만** 추가 조사하며, 근거가 부족하면 미확정으로 남긴다:

1. 1차 리포트의 `static_only_summary`를 사용자에게 그대로 보여준다("이 항목들이 정적 추정으로 남았습니다").
2. 승인된 동적 확인에 계정이 실제 필요한 경우에만 위 env 입력을 사용한다. 기존 정적 후보와 당시 source/revision을 보존하고 필요한 동적 검증을 실행한다. 정적 검사를 했다는 사실을 취약 확정으로 해석하지 않는다.
3. `static-only → dynamic`은 요청 실행 경로의 변경이다. 정상 대조군·신원/객체/응답 oracle과 source/revision이 맞는지 확인한 뒤 기존 관찰에 연결한다. 계정 입력이나 실행 표시만으로 검증 완료를 부여하지 않는다.

#### 미확정 사람 확인 프로토콜 (④ — evidence_expectation 카드)

자동 판정이 상태코드·반사만으로는 확정 못 하는 finding(`undetermined` · `verdict: needs-confirmation` · 접근통제 soft-200)에는 스크립트가 `evidence_expectation` 카드를 제공한다. 코드로 확인할 수 있는 내용부터 조사하고 사용자만 아는 의도·관찰을 질문해 추가 근거를 모은다. 필요한 승인 범위 안의 PoC만 제시한다.

1. 카드의 `poc`를 사람이 실행(브라우저/터미널)하도록 제시한다.
2. **AskUserQuestion** — "아래 PoC를 실행하면 결과가 어느 쪽인가요?"
   - 정형 옵션: `취약 신호 관찰(alert 실행 / 지연 / 실제 데이터 노출)` / `방어(차단·이스케이프·거부)` / `판단 불가`
   - **자유서술("직접 입력") 칸을 주 채널로** 둔다 — 사람이 관찰한 것을 그대로 적게 한다(예: "alert는 안 떴는데 응답 본문에 A의 이메일이 그대로 보임").
3. 답변은 주장·관찰 자료로 기록하고 실제 코드·정상 대조군·요청별 oracle과 대조한다. 새 모호함이 생기면 필요한 질문만 이어간다. 답변만으로 검증·오탐 제외·위험 수용을 부여하지 않는다. 불충분하면 미확정으로 보존하고 공식 승격·반증은 보호된 독립 검토를 따른다.

| 클래스 | 예상 증거 카드(요지) |
|---|---|
| XSS(저장/DOM) | `board/[id]`에 `<img src=x onerror=alert(document.domain)>` 저장 후 조회 → alert 뜨면 저장형 XSS 확정 |
| 접근통제 soft-200 | B 토큰으로 A 리소스 GET → 본문이 A의 실제 데이터면 취약 / '권한없음' 응답이면 방어(HTTP 200이어도) |
| 파일 업로드 | 해당 실행의 고유 마커 회수·제공 위치·허용 파일 정책 확인. 텍스트 회수만으로 실행 가능성이나 High 확정 금지 |

### 4단계 — 통합 리포트 작성·저장
모든 취약점 클래스를 **하나의 리포트**로 통합한다. `reports/audit-<프로젝트>.md`에 저장.

## 프리셋 자동 점검 미커버 범위

`audit.py` 기본 프리셋 실행만으로는 아래 항목이 **자동으로 확정되지 않는다**. 리포트에 "미커버/미확정"으로 명시하고, 필요 시 수동 보강한다. **자동 점검 0건이 안전을 의미하지 않는다.**

| 항목 | 미커버 사유 | 수동 보강 |
|---|---|---|
| 저장형·DOM XSS 브라우저 실행 | `attack_xss.py`는 HTTP 응답 반사만 검사 — 저장 후 조회 시 실행·클라이언트 DOM 조작은 서버 응답에 반사되지 않아 미확인 | `exploiting-xss` 2단계-b의 Playwright MCP로 브라우저 실제 실행 확인 |
| 접근통제/인증 교차검증 | 권한 교차용 테스트 계정(A/B)이 없으면 실제 교차 호출 불가 → `static-only`(정적 후보만) | `--user-a-id/pw`·`--user-b-id/pw` 또는 `--token-a-env`/`--token-b-env`로 계정 제공해 `dynamic` 판정 |
| 파괴적 파일업로드 | `--allow-destructive` 게이트가 없으면 미발사, 있어도 `--retrieve-base`가 없으면 회수(웹루트 저장) 미확인 → **미확정** | 격리 스테이징에서 `--allow-destructive` + `--retrieve-base` 지정(전용 테스트 계정) |
| 비-sef 로그인 흐름 | 프리셋 로그인 시퀀스는 sef-2026 기준 — 비표준 로그인 앱은 자동 로그인이 실패해 인증·접근통제 동적이 `login-failed`/`static-only`로 남음 | `--login-path`·`--body-template`·`--token-path` 등으로 앱별 로그인 오버라이드 지정. 템플릿에는 비밀 대신 `{id}`/`{pw}`만 사용 |
| grep-폴백 낮은 탐지율 | `semgrep` 미설치 시 정규식 폴백 — recall(탐지율)이 낮아 미탐 위험이 큼 | `pip install semgrep` 설치 후 재실행(**후보 0건 ≠ 안전**) |

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
- [ ] 승인된 동적 실행의 확정·미확정·미검사 및 근거를 반영했는가
- [ ] 동적은 스테이징/로컬에만 발사했는가(운영 차단 확인)
- [ ] 통합 리포트가 `reports/`에 저장됐는가

## 구성 (오케스트레이션 대상)
- 정적: `scan_all.py` → 9개 `detecting-*` 스캐너
- 동적: `exploiting-*` (sql-injection, xss, broken-access-control, auth-session, ssrf-and-open-redirect, path-traversal-upload) + `tools/scope_guard.py` 안전게이트
- 산출물: `reports/audit-<프로젝트>.md`
