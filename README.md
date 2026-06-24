<div align="center">

# gx-security

**GX 사업본부 웹 애플리케이션 보안 점검 플러그인 — 소스 진단부터 모의 침투까지**

</div>

---

## 설치

```bash
# Claude Code CLI에서 실행
/plugin marketplace add bs-koo/gx-security
/plugin install gx-security@gx-security
```

## 사용법

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

## 점검 흐름

진단으로 취약점 후보를 넓게 찾고, 침투로 실제 악용 가능성을 확인한 뒤, 발견한 취약점을 네 가지로 정리해 리포트합니다.

1. **진단(정적)** — 소스에서 취약점 후보를 도출합니다. 안전하며 앱이 필요 없습니다.
2. **검증** — AI가 코드를 읽어 오탐을 거릅니다.
3. **침투(동적)** — 스테이징/로컬에 실제 페이로드를 발사해 악용 가능 여부를 확정합니다.
4. **리포트** — 취약점마다 **취약한 점 · 이유 · 뚫리는 방법 · 해결법**을 정리해 `reports/`에 저장합니다.

## 지원 스택

대상 프로젝트의 스택을 자동으로 감지해 각각에 맞는 룰을 적용합니다. 한 저장소에 둘이 섞여 있어도 디렉토리별로 판별합니다.

| 스택 | 감지 신호 | 대표 프로젝트 |
|---|---|---|
| Spring (모던) | `build.gradle.kts`, `@RestController` | sqisoft-sef-2026 |
| JSP/Servlet (레거시) | `WEB-INF/web.xml`, `*.jsp`, `pom.xml` | Gseed_Web_Renew |

## 검사하는 취약점

OWASP 핵심 9종을 다룹니다.

CSRF · XSS · SQL Injection · 파일 업로드(웹쉘) · Path Traversal · 접근통제(IDOR/BFLA) · 인증·세션·JWT · 민감정보 노출 · SSRF/오픈 리다이렉트

진단(정적)은 9종 전체, 침투(동적)는 현재 SQL Injection · XSS를 지원합니다.

## 설정

동적 모의 침투의 대상 허용 범위는 환경변수로 제어합니다. 기본값만으로 로컬(`localhost`)·스테이징에서 동작하며, 운영 대상은 코드로 차단됩니다.

| 변수 | 동작 |
|---|---|
| `SECURITY_PLUGIN_ALLOW_HOSTS` | 허용할 사내 스테이징 호스트 등록 (쉼표구분, 정확매칭·suffix) |
| `SECURITY_PLUGIN_ALLOW_PRIVATE=1` | 사설망 IP(10/172.16/192.168) 허용 (기본은 차단) |
| `SECURITY_PLUGIN_DENY_HOSTS` | 추가로 차단할 호스트 등록 |
| `SECURITY_PLUGIN_AUTHORIZED=1` | 공인 대상 허용 (`--authorized` 플래그와 동시 충족 시) |

## 안전

- **진단(정적)은 소스를 읽기만 합니다.** 대상에 아무것도 보내지 않습니다.
- **침투(동적)는 운영을 코드로 차단합니다.** `tools/scope_guard.py`가 운영(`prod`/`www`/공인 대상)과 IP 위장(정수·IPv6 매핑 등)을 거르고, 로컬/스테이징만 허용합니다.
- 비파괴가 기본입니다. 데이터를 변경하는 페이로드는 `--allow-destructive` 와 사람 승인이 필요합니다.
- 점검 산출물(`reports/`)은 `.gitignore`로 제외됩니다.

> 공격 기능은 권한 있는 사내 보안 테스트(펜테스트) 목적에 한합니다. 자세한 수칙은 [ATTACK_SAFETY.md](ATTACK_SAFETY.md)를 참고하세요.

## 한계

best-effort 보조 도구이며, 사람의 코드 리뷰나 전문 SAST/DAST·의존성 스캔·침투 테스트를 대체하지 않습니다. 오탐과 미탐이 발생할 수 있고, 언어·프레임워크·환경에 따라 결과가 달라질 수 있습니다. 발견 결과는 보증이 아니라 검토 대상으로 다뤄야 합니다.

## 구성

- **커맨드 3** — `gx-audit` · `gx-diagnose` · `gx-pentest`
- **스킬 12** — 통합 1(`auditing-web-application-security`) · 진단 9(`detecting-*`) · 침투 2(`exploiting-*`)
- **엔진** — `scan_all.py`(정적 통합) · `tools/scope_guard.py`(동적 안전게이트)

자세한 사용법은 [USAGE.md](USAGE.md)를 참고하세요.

---

<sub>Proprietary · GX 사업본부 사내용 · v0.2.1</sub>
