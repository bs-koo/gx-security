# GX Security 실행 참고서

[제품 소개로 돌아가기](README.md) · [실전 사용 가이드](USAGE.md)

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

> **Windows(cp949) 환경 필수 안내**: `tools/io_utf8.py`가 콘솔 인코딩을 UTF-8로 강제하고 `PYTHONUTF8=1`을 자식 프로세스에 자동 전파하므로, 스캐너 경유 semgrep은 cp949 환경에서도 UTF-8 룰을 정상 로드합니다. 이 전파가 없으면 semgrep이 한글 message가 담긴 UTF-8 룰을 cp949로 읽다 실패해 **정밀 진단이 grep 폴백(저정밀)으로 강등**됩니다. 다만 `semgrep`을 **직접 CLI로 실행**할 때는 이 자동 전파가 적용되지 않으므로 `setx PYTHONUTF8 1`(또는 세션에서 `$env:PYTHONUTF8=1`)로 직접 설정하세요. 파이프·리다이렉션·CI 캡처의 한글 출력 안정성도 함께 좋아집니다.

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
| ① 실제 발사 | 취약점 클래스별 페이로드를 실제로 발사합니다(실재 6종은 [스킬 카탈로그](README.md#스킬-구성) 참고) | `attack_*.py` (+ 공용 `tools/dyn_session.py`) |
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
3. **JSON 바디 주입은 SQLi만 지원합니다.** `exploiting-sql-injection`은 `--content-type json --inject-path`로 `application/json` 본문에 페이로드를 주입하지만, 나머지 동적 스킬(XSS·접근통제·인증·SSRF·경로/업로드)은 GET·form-urlencoded만 지원합니다.

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
├── skills/                  # 스킬 17개 (통합 1 · 진단 9 · 침투 7)
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

<sub>Proprietary · GX 사업본부 사내용 · v0.8.2</sub>
