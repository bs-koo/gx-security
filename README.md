<div align="center">

# gx-security

**GX 사업본부 웹 애플리케이션 보안 점검 플러그인 — 소스 진단부터 모의 침투까지**

정적 분석(SAST) + 동적 모의침투(DAST) 하이브리드 · 스택 자동 감지 · AI 오탐 제거

`커맨드 3` · `스킬 16` (통합 1 · 진단 9 · 침투 6) · `v0.5.0` · Proprietary

</div>

---

## 목차

- [개요](#개요)
- [설치](#설치)
- [빠른 시작](#빠른-시작)
- [점검 흐름](#점검-흐름)
- [커맨드별 동작 프로세스](#커맨드별-동작-프로세스)
- [스킬 카탈로그](#스킬-카탈로그)
- [지원 스택](#지원-스택)
- [검사하는 취약점](#검사하는-취약점)
- [설정](#설정)
- [안전](#안전)
- [한계](#한계)
- [테스트](#테스트)
- [문서 지도](#문서-지도)
- [저장소 구성](#저장소-구성)

---

## 개요

`gx-security`는 SQIsoft GX 사업본부의 웹 애플리케이션(Spring Boot 모던 / JSP·Servlet 레거시)을 대상으로, 소스 코드에서 취약점 후보를 찾아내고(정적) 필요하면 실행 중인 스테이징/로컬에 실제 페이로드를 발사해(동적) 악용 가능성을 확정하는 보안 점검 플러그인입니다.

- **스택 자동 감지** — 저장소 안에 두 스택이 섞여 있어도 디렉토리별로 판별해 맞는 룰을 적용합니다.
- **AI 컨텍스트 검증** — 정적 스캐너(Semgrep 우선, 없으면 grep 폴백)가 도출한 후보를 Claude가 실제 코드 문맥으로 읽어 오탐을 거릅니다.
- **fail-closed 안전 게이트** — 동적 발사 전 `tools/scope_guard.py`가 대상을 검증하고 운영/공인 대상은 코드 수준에서 차단합니다.
- **4요소 리포트** — 확정 취약점마다 **① 취약한 점 · ② 이유 · ③ 뚫리는 방법 · ④ 해결법**을 심각도순으로 `reports/`에 정리합니다.

## 설치

```bash
# Claude Code CLI에서 실행
/plugin marketplace add bs-koo/gx-security
/plugin install gx-security@gx-security
```

### 정적 정밀도 표준 (권장)

정적 진단은 semgrep이 있을 때 정밀도(recall)가 크게 오릅니다. **사업부 공통 도입 시 semgrep 설치를 표준으로 합니다.** semgrep이 없으면 grep 폴백으로 동작하되 미탐 위험이 커지며, 스캐너가 `[!] 폴백 경고`를 출력합니다.

```bash
# Linux/macOS
bash scripts/install-dev.sh
# Windows PowerShell
powershell -ExecutionPolicy Bypass -File scripts\install-dev.ps1
# 또는 직접
pip install -r requirements-dev.txt
```

> Windows 기본 실행정책(Restricted)에서는 `scripts\install-dev.ps1`을 직접 실행하면 `PSSecurityException`으로 막힙니다. 위처럼 `-ExecutionPolicy Bypass`를 붙이거나, `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`로 계정 실행정책을 변경한 뒤 실행하세요.

> Windows는 semgrep 네이티브 휠 부재로 `semgrep --version`에서 설치 스크립트가 비정상 종료하는 것이 정상이며, 정적 진단은 grep 폴백으로 계속 동작합니다(정밀도는 낮아집니다).

## 빠른 시작

커맨드 세 개로 정적 진단과 동적 모의 침투를 수행합니다. 자연어로 말해도 의도에 맞는 스킬이 발동됩니다.

| 커맨드 | 하는 일 | 대상 |
|---|---|---|
| `/gx-security:gx-diagnose <소스>` | 취약점 진단 (정적 분석) | 소스 코드 |
| `/gx-security:gx-pentest <URL>` | 모의 침투 (실제 공격) | 실행 중인 스테이징/로컬 |
| `/gx-security:gx-audit <소스> [URL]` | 진단 + 침투 통합 점검 | 둘 다 |

```bash
# 취약점 진단 — 소스만 분석, 앱을 띄울 필요 없음
/gx-security:gx-diagnose D:\SQ\GSEED\source\Gseed_Web_Renew

# 전체 점검 — 진단 후 실행 중인 로컬에 실제 공격까지
/gx-security:gx-audit D:\SQ\sqisoft-sef-2026 http://localhost:8080
```

자연어로도 됩니다 — "gx-security로 sef-2026 점검해줘".
CLI로 단독 실행도 됩니다 — `python scan_all.py <소스>` (Claude 없이, CI 연동 가능).

> 상세 옵션·시나리오별 명령은 [USAGE.md](USAGE.md)를 참고하세요.

## 점검 흐름

진단으로 취약점 후보를 넓게 찾고 침투로 실제 악용 가능성을 확인한 뒤, 발견한 취약점을 네 가지로 정리해 리포트합니다.

1. **진단(정적)** — 소스에서 취약점 후보를 도출합니다. 안전하며 앱이 필요 없습니다.
2. **검증** — AI가 코드를 읽어 오탐을 거릅니다.
3. **침투(동적)** — 스테이징/로컬에 실제 페이로드를 발사해 악용 가능 여부를 확정합니다.
4. **리포트** — 취약점마다 **취약한 점 · 이유 · 뚫리는 방법 · 해결법**을 정리해 `reports/`에 저장합니다.

## 커맨드별 동작 프로세스

세 커맨드는 같은 파이프라인(**감지 → 스캔/발사 → 검증 → 리포트**)을 공유하되, 책임지는 단계가 다릅니다.

### `gx-diagnose` — 정적 진단 (SAST)

```
소스 경로 ─▶ ① 스택 감지 ─▶ ② 정적 스캔 ─▶ ③ AI 검증 ─▶ ④ 리포트
                          (scan_all.py)   (오탐 제거)   diagnose-*.md
```

| 단계 | 무슨 일을 하나 | 무엇으로 |
|---|---|---|
| ① 스택 감지 | `build.gradle.kts`·`settings.gradle` → spring-modern / `WEB-INF/web.xml`·`*.jsp` → jsp-legacy. 디렉토리별로 판별해 스택에 맞는 룰만 적용 | 각 스캐너 내장 |
| ② 정적 스캔 | 9개 `detecting-*` 스캐너를 각각 실행해 취약 후보(파일·라인·룰ID·스니펫)를 도출. Semgrep 룰을 우선 쓰고, 없으면 grep 정규식으로 폴백 | `scan_all.py` → `scan_*.py` + `rules/*.yml` |
| ③ AI 검증 | Claude가 각 후보의 실제 코드를 읽어 오탐 제거. 예: MyBatis `#{}`면 안전, `getCanonicalPath()+startsWith()` 있으면 안전, Jasypt `ENC()`는 평문 아님, `csrf().disable()`이 STATELESS면 의도된 예외 | `references/stack-patterns.md` 기준 |
| ④ 리포트 | 확정 취약점만 심각도순 + 4요소로 정리 | `reports/diagnose-<프로젝트>.md` |

네트워크로 아무것도 보내지 않습니다(소스 읽기 전용). 앱이 떠 있을 필요가 없습니다.

### `gx-pentest` — 동적 모의침투 (DAST)

```
대상 URL ─▶ ⓪ 범위 확인 ─▶ ① 실제 발사 ─▶ ② 악용 확정 ─▶ ③ 리포트
           (scope_guard)   (attack_*.py)  (반사·지연·실행)  pentest-*.md
            차단 시 중단
```

| 단계 | 무슨 일을 하나 | 무엇으로 |
|---|---|---|
| ⓪ 범위 확인 | 대상이 발사 허용 범위인지 **먼저 강제 검증**. 운영(`prod`/`www`/공인)·IP 위장(정수·IPv6 매핑)은 차단, loopback/등록된 스테이징만 통과. 모든 비허용은 차단으로 수렴(fail-closed) | `tools/scope_guard.py` |
| ① 실제 발사 | 취약점 클래스별 페이로드를 실제로 발사합니다(실재 6종은 [스킬 카탈로그](#스킬-카탈로그) 참고) | `attack_*.py` (+ 공용 `tools/dyn_session.py`) |
| ② 악용 확정 | 클래스별 판정 기준으로 악용을 확정합니다(마커 반사·시간지연·상태코드·OOB 콜백 등) | Playwright MCP · `dyn_session` |
| ③ 리포트 | 4요소 + **Evidence**(실제 요청·응답·지연시간·스크린샷 경로) | `reports/pentest-<대상>.md` |

기본은 **비파괴**(탐지 페이로드만)입니다. 데이터 변조·삭제는 `--allow-destructive` + 사람 승인이 있어야 합니다.

### `gx-audit` — 통합 점검 (SAST + DAST)

```
소스[+URL] ─▶ ① 스택 감지 ─▶ ② 정적 9종 ─▶ ③ AI 검증 ─▶ ④ 동적 발사 ─▶ ⑤ 통합 리포트
                            (scan_all)    (오탐 제거)  (URL 있을 때만)   audit-*.md
```

`audit.py` 하나가 위 두 커맨드를 엮습니다. ②는 `scan_all.py`를 호출해 9종 후보를 모으고 ④는 **대상 URL이 주어졌을 때만** `attack_*.py`를 발사합니다(이때도 각 발사가 `scope_guard`를 통과해야 함). URL이 없으면 정적만 수행(완전 안전).

④의 동적 발사는 취약점 클래스마다 **표적 옵션 + 테스트 계정이 모두 주어진 조합에서만** 발동하며 그 결과가 `dynamic`(전체 발사) / `partial`(일부만) / `static-only`(정적 추정 유지) 3단계로 갈립니다. 예를 들어 인증·세션·JWT는 로그인 계정과 `--probe`가 모두 있어야 `dynamic`이고 SSRF/오픈 리다이렉트·경로조작/업로드는 각각의 표적 옵션(`--ssrf-target` 등)과 계정이 모두 있어야 발사됩니다(업로드는 파괴적이라 `--allow-destructive`도 추가로 필요). **정확한 옵션 조합·판정 표는 [USAGE.md §4](USAGE.md#4-시나리오별-사용)를 참고하세요.**

> **원격 대상은 콜백 미수신이 곧 '안전'을 뜻하지 않습니다.** SSRF 검사에 쓰는 canary는 127.0.0.1 루프백에만 바인딩되므로, 원격 스테이징에서는 대상 서버가 자기 loopback으로 실제 아웃바운드 요청을 시도했더라도 그 결과가 audit 실행기로 돌아오지 않을 수 있습니다. 원격 대상의 블라인드 SSRF를 확정하려면 `attack_ssrf.py`를 단독 실행하고 `--canary-host`를 지정하세요.

> 셋 다 ②~④의 자동 산출물은 **1차 후보(오탐 포함)** 이며 확정 취약/오탐 판정과 4요소 리포트는 Claude Code의 **AI 검증 단계에서 완성**됩니다. CLI 단독 실행은 ②까지만 수행합니다.

## 스킬 카탈로그

### 통합 (1개)

| 스킬 | 설명 | 스크립트 |
|---|---|---|
| `auditing-web-application-security` | 진단 9종 + AI 검증 + (대상 URL이 있으면) 침투까지 한 번에 수행하는 오케스트레이터. `gx-audit` 커맨드가 사용 | `scripts/audit.py` |

### 진단 — `detecting-*` (9개, 정적/SAST — 소스만 읽음, 완전 안전)

| 스킬 | `--only` 키 | 검사 대상 | CWE / OWASP |
|---|---|---|---|
| `detecting-csrf-vulnerabilities` | `csrf` | 상태변경 엔드포인트의 토큰 미보호, `csrf().disable()`, 토큰 없는 JSP form, SameSite 미설정 쿠키 | CWE-352 |
| `detecting-xss-vulnerabilities` | `xss` | 반사형·저장형·DOM XSS — JSP scriptlet/미이스케이프 EL, `th:utext`, `@ResponseBody` HTML, `dangerouslySetInnerHTML`, `innerHTML` | CWE-79 |
| `detecting-sql-injection` | `sqli` | 문자열 연결 쿼리 — JSP `Statement` 연결, MyBatis `${}`(vs 안전한 `#{}`), JPA `@Query`/`JdbcTemplate` 연결, 동적 정렬·검색 컬럼명 | CWE-89 |
| `detecting-file-upload-vulnerabilities` | `file-upload` | 웹쉘 업로드 — 확장자 화이트리스트 부재, 매직바이트 미검증, 웹루트 내부 저장, Content-Type만 신뢰, 이중 확장자 우회 | CWE-434 |
| `detecting-path-traversal` | `path-traversal` | `../` 임의 파일 접근·다운로드, ZipSlip — `Resource`/`Path` 직접 반환, `filePath=` 파라미터 필터링 미흡 | CWE-22 / A01 |
| `detecting-broken-access-control` | `access-control` | IDOR/BFLA/강제 브라우징 — PathVariable 소유권 미검증, `@PreAuthorize` 누락, `adminPaths` 미보호, 메뉴 숨김에만 의존 | A01 |
| `detecting-auth-session-weaknesses` | `auth` | 세션 고정(재발급 누락), 약한 해시(BCrypt 미사용), JWT 시크릿 하드코딩·서명검증 우회, 쿠키 보안속성 누락, 세션 타임아웃 미설정 | CWE-287 / CWE-384 |
| `detecting-sensitive-data-exposure` | `secrets` | 하드코딩 시크릿(DB·API 키·JWT), 개인정보 평문 저장·로그 출력, DTO 과다 필드 노출, 예외 스택트레이스 노출 | CWE-200 / CWE-798 |
| `detecting-ssrf-and-open-redirect` | `ssrf` | 검증 없는 서버측 요청(`RestTemplate`/`WebClient`/`HttpURLConnection`), 미검증 리다이렉트(`sendRedirect`, `returnUrl`) | CWE-918 / CWE-601 |

각 스킬은 `python skills/detecting-<종류>/scripts/scan_*.py <소스>` 로 단독 실행할 수도 있습니다(`references/stack-patterns.md`가 AI 검증 기준).

### 침투 — `exploiting-*` (6개, 동적/DAST — 실행 중인 대상에 실제 발사, `scope_guard` fail-closed 강제)

| 스킬 | 확정 방식 | 스크립트 |
|---|---|---|
| `exploiting-sql-injection` | Error-based → Boolean-based Blind → Time-based Blind 순차 시도. sqlmap 설치 시 우선 사용, 없으면 수동 PoC 폴백 | `scripts/attack_sqli.py` |
| `exploiting-xss-vulnerabilities` | 고유 마커 페이로드 주입 → HTTP 응답 반사 확인 + Playwright로 브라우저 실제 실행 확인(저장형·DOM) | `scripts/attack_xss.py` |
| `exploiting-broken-access-control` | 타 계정 토큰으로 관리자 API 호출(BFLA)·타인 리소스 조회(IDOR) → `2xx`=취약, `401/403`=방어(즉시 오탐 확정) | `scripts/attack_access.py` |
| `exploiting-auth-session` | JWT 변조(`alg=none`·서명 제거·역할 변조·만료) 발사, 로그아웃 후 토큰 재사용, 쿠키 보안속성(Secure/HttpOnly/SameSite) 점검 | `scripts/attack_auth.py` |
| `exploiting-ssrf-and-open-redirect` | 루프백 OOB canary 리스너로 콜백 수신 시 블라인드 SSRF 확정, `Location` 헤더가 외부 호스트면 오픈 리다이렉트 확정(모두 비파괴 GET) | `scripts/attack_ssrf.py` (+ `oob_canary.py`) |
| `exploiting-path-traversal-upload` | 경로조작은 응답 본문 파일 시그니처로 인밴드 확정(읽기전용). 업로드는 `--allow-destructive`일 때만 무해 마커(.jsp, 코드 없음)로 위험확장자 수용·웹루트 회수 확인 | `scripts/attack_pathupload.py` |

각 스킬은 `python skills/exploiting-<종류>/scripts/attack_*.py <URL> --param p` 로 단독 실행할 수 있습니다(`ATTACK_SAFETY.md`의 안전 게이트가 모든 발사 전에 강제됨).

## 지원 스택

대상 프로젝트의 스택을 자동으로 감지해 각각에 맞는 룰을 적용합니다. 한 저장소에 둘이 섞여 있어도 디렉토리별로 판별합니다.

| 스택 | 감지 신호 | 대표 프로젝트 |
|---|---|---|
| Spring (모던) | `build.gradle.kts`, `@RestController` | sqisoft-sef-2026 |
| JSP/Servlet (레거시) | `WEB-INF/web.xml`, `*.jsp`, `pom.xml` | Gseed_Web_Renew |

## 검사하는 취약점

OWASP 핵심 9종을 다룹니다. 진단(정적)은 9종 전체, 침투(동적)는 그중 실제 발사가 구현된 6종을 다룹니다.

| 취약점 | CWE / OWASP | 정적 진단 | 동적 침투 |
|---|---|:---:|:---:|
| SQL Injection | CWE-89 | ✅ | ✅ |
| XSS | CWE-79 | ✅ | ✅ |
| 접근통제 (IDOR/BFLA) | A01:2021 | ✅ | ✅ |
| 인증·세션·JWT | CWE-287 | ✅ | ✅ |
| SSRF / 오픈 리다이렉트 | CWE-918 / CWE-601 | ✅ | ✅ |
| 경로조작 / 파일 업로드 | CWE-22 / CWE-434 | ✅ | ✅ |
| CSRF | CWE-352 | ✅ | 정적 전용 |
| 민감정보 노출 | CWE-200 / CWE-798 | ✅ | 정적 전용 |

## 설정

동적 모의 침투의 대상 허용 범위는 환경변수로 제어합니다. 기본값만으로 로컬(`localhost`)·스테이징에서 동작하며 운영 대상은 코드로 차단됩니다.

| 변수 | 동작 |
|---|---|
| `SECURITY_PLUGIN_ALLOW_HOSTS` | 허용할 사내 스테이징 호스트 등록 (쉼표구분, 정확매칭·suffix) |
| `SECURITY_PLUGIN_ALLOW_PRIVATE=1` | 사설망 IP(10/172.16/192.168) 허용 (기본은 차단) |
| `SECURITY_PLUGIN_DENY_HOSTS` | 추가로 차단할 호스트 등록 |
| `SECURITY_PLUGIN_AUTHORIZED=1` | 공인 대상 허용 (`--authorized` 플래그와 동시 충족 시) |

## 안전

- **진단(정적)은 소스를 읽기만 합니다.** 대상에 아무것도 보내지 않습니다.
- **침투(동적)는 운영을 코드로 차단합니다.** `tools/scope_guard.py`가 운영(`prod`/`www`/공인 대상)과 IP 위장(정수·IPv6 매핑 등)을 거르고 로컬/스테이징만 허용합니다.
- 비파괴가 기본입니다. 데이터를 변경하는 페이로드는 `--allow-destructive` 와 사람 승인이 필요합니다.
- 점검 산출물(`reports/`)은 `.gitignore`로 제외됩니다.

> 공격 기능은 권한 있는 사내 보안 테스트(펜테스트) 목적에 한합니다. 자격증명 CLI 인자 노출 등 상세 수칙은 [ATTACK_SAFETY.md](ATTACK_SAFETY.md)를 참고하세요.

## 한계

best-effort 보조 도구이며 사람의 코드 리뷰나 전문 SAST/DAST·의존성 스캔·침투 테스트를 대체하지 않습니다. 오탐과 미탐이 발생할 수 있고 언어·프레임워크·환경에 따라 결과가 달라질 수 있습니다. 발견 결과는 보증이 아니라 검토 대상으로 다뤄야 합니다.

동적(침투) 엔진에는 다음 **구조적 한계**가 있어 사용 전 표적을 직접 준비해야 합니다:

1. **크롤링/엔드포인트 자동탐색이 없습니다.** 공격할 URL·파라미터를 사용자가 직접 지정해야 하며 앱의 엔드포인트를 스스로 수집하지 않습니다.
2. **GET·form-urlencoded POST만 지원합니다.** 이 두 방식의 요청에만 페이로드를 주입합니다.
3. **JSON 바디 주입은 불가합니다.** `application/json` 요청 본문에는 페이로드를 삽입하지 못합니다.

## 테스트

```bash
pytest tests/
```

스캐너 골든셋·룰 검증(`test_scanner_goldenset.py`, `test_rules.py`)부터 각 `attack_*.py`의 발사·판정 로직, `scope_guard`/`dyn_session` 공용 엔진까지 pytest로 회귀 검증합니다.

## 문서 지도

| 문서 | 용도 |
|---|---|
| **README.md** (이 문서) | 개요, 설치, 빠른 시작, 스킬/커맨드 카탈로그 |
| [USAGE.md](USAGE.md) | 실전 사용 가이드 — 시나리오별 명령, 옵션 조합별 동적 발동 조건, FAQ |
| [ATTACK_SAFETY.md](ATTACK_SAFETY.md) | 공격형(`exploiting-*`) 스킬 안전 수칙 — scope_guard, 자격증명 노출, 법적 고지 |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | 운영정책 — 스테이징 허용 등록·자격증명 취급·격리 호스트 규정 |
| [docs/RUNBOOK-dynamic.md](docs/RUNBOOK-dynamic.md) | 동적 점검 실전 런북 — 자격증명 안전 입력·로그인 프로파일·클래스별 점검 사이클·판정 해석 |
| [docs/severity-rubric.md](docs/severity-rubric.md) | 심각도(Critical/High/Medium/Low) 판정 기준 |
| [CHANGELOG.md](CHANGELOG.md) | 버전별 변경 이력 |

## 저장소 구성

```
security-plugin/
├── commands/                # 슬래시 커맨드 3개 — gx-audit · gx-diagnose · gx-pentest
├── skills/                  # 스킬 16개
│   └── <skill-name>/
│       ├── SKILL.md         # 트리거 조건 · AI 검증 기준
│       ├── scripts/         # scan_*.py (정적) / attack_*.py (동적)
│       ├── rules/           # Semgrep 룰 (detecting-* 일부)
│       └── references/      # stack-patterns.md · payloads.md
├── tools/
│   ├── scope_guard.py       # 동적 발사 안전 게이트 (fail-closed)
│   └── dyn_session.py       # 동적 공용 엔진 — 로그인 자동화 · 토큰 보관 · 인증 HTTP
├── tests/                   # pytest 스위트
├── docs/                    # severity-rubric.md 등 내부 판정 기준
├── reports/                 # 점검 산출물 (.gitignore 제외)
├── scan_all.py              # 정적 통합 CLI 진입점
└── README.md / USAGE.md / ATTACK_SAFETY.md / CHANGELOG.md
```

---

<sub>Proprietary · GX 사업본부 사내용 · v0.5.0</sub>
