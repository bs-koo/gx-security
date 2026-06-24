# 🛡️ gx-security

> **SQIsoft 사업부 웹앱 전용 AI 보안 점검 툴킷.**
> 소스에서 취약점을 **진단**하고, 실행 중인 대상에 **실제 모의 침투**해 "정말 뚫리는지"까지 증명한다.

JSP 레거시와 Spring 모던 스택을 **자동 감지**하고, 발견한 취약점을 항상
**① 취약한 점 · ② 이유 · ③ 뚫리는 방법 · ④ 해결법** 네 가지로 정리해 준다.

---

## ⚡ TL;DR

```
취약점 진단(정적) ─▶ 모의 침투(동적) ─▶ 4요소 리포트
   안전, 앱 불필요        실행 중 대상 필요      취약점·이유·공격법·해결법
```

가장 빠른 시작 — Claude Code에서 슬래시 커맨드 하나:

```
/gx-security:gx-audit  D:\SQ\sqisoft-sef-2026  http://localhost:8080
```

---

## 🚀 바로 쓰기 — 3개 커맨드

| 커맨드 | 한 일 | 안전도 |
|:--|:--|:--:|
| **`/gx-security:gx-diagnose`** `<소스>` | 취약점 **진단** (소스만 분석) | 🟢 안전 |
| **`/gx-security:gx-pentest`** `<URL>` | **모의 침투** (실제 공격) | 🟡 스테이징/로컬만 |
| **`/gx-security:gx-audit`** `<소스> [URL]` | **전체** (진단 + 침투 + 통합 리포트) | 🟡 URL 줄 때만 공격 |

```bash
# 진단만 — 앱 안 띄워도 됨, 완전 안전
/gx-security:gx-diagnose  D:\SQ\GSEED\source\Gseed_Web_Renew

# 특정 취약점만
/gx-security:gx-diagnose  D:\SQ\sqisoft-sef-2026  xss

# 모의 침투 — 실행 중인 로컬 대상에 실제 공격
/gx-security:gx-pentest  http://localhost:8080/board?id=1  sqli --param id
```

> 슬래시 커맨드 없이 **자연어**로도 됩니다 — *"gx-security로 sef-2026 점검해줘"*
> CLI로도 됩니다 — `python scan_all.py <소스>` (Claude 없이, CI 연동 가능)

---

## 🧠 어떻게 동작하나 — 하이브리드

**자동화 엔진**(스캐너·공격 스크립트)을 **AI가 운전**하는 구조다. 둘을 합쳐 정적의 넓은 커버리지와 동적의 확실한 증명을 모두 얻는다.

```
1. 진단 (정적/SAST)   소스에서 취약점 후보를 넓게 도출
        │
        ▼  AI가 코드를 읽어 오탐 제거
2. 침투 (동적/DAST)   스테이징/로컬에 실제 페이로드 발사 → 악용 확정
        │
        ▼
3. 리포트            취약점·이유·공격법·해결법 + 실제 증거 (reports/)
```

| 레이어 | 무엇 | 특징 |
|:--|:--|:--|
| ⚙️ 자동화 엔진 | `scan_all.py` · `audit.py` · `attack_*.py` · `scope_guard.py` | 독립 CLI, Claude 없이 동작 |
| 🤖 AI 플러그인 | `skills/*/SKILL.md` · `commands/*` | 엔진 운전 · 오탐 제거 · 리포트 |

---

## 📦 구성

**커맨드 3** + **스킬 12**

- 🎯 **통합** — `auditing-web-application-security` *(gx-audit이 호출)*
- 🔍 **진단 9종** *(gx-diagnose)* — CSRF · XSS · SQLi · 파일업로드 · Path Traversal · 접근통제 · 인증/세션 · 민감정보 · SSRF
- 💥 **침투 2종** *(gx-pentest)* — SQLi · XSS *(7종 확장 예정)*

---

## 🎯 지원 스택 (자동 감지)

| 스택 | 대표 프로젝트 | 감지 신호 |
|:--|:--|:--|
| `spring-modern` | sqisoft-sef-2026 | `build.gradle.kts` · `@RestController` |
| `jsp-legacy` | Gseed_Web_Renew | `WEB-INF/web.xml` · `*.jsp` · `pom.xml` |

한 저장소에 둘이 섞여도 **디렉토리별로 판별**해 각각에 맞는 룰을 적용한다.

---

## 🔒 안전장치

- **정적 진단은 안전** — 소스를 읽기만 한다.
- **동적 침투는 통제된 주의** — `tools/scope_guard.py`가 **운영(`prod`/`www`/공인) 대상을 코드로 차단**하고 **로컬/스테이징만 허용**한다.
- **비파괴 기본** — 파괴적 페이로드는 `--allow-destructive` + 사람 승인 필요.
- 점검 산출물 `reports/`는 `.gitignore`로 제외(민감).

> ⚠️ 공격 기능은 **권한 있는 사내 보안 테스트(펜테스트)** 목적에 한한다. → [ATTACK_SAFETY.md](ATTACK_SAFETY.md)

---

## 📁 구조

```
gx-security/
├── commands/        gx-audit · gx-diagnose · gx-pentest
├── skills/
│   ├── auditing-web-application-security/   통합 오케스트레이터
│   ├── detecting-*/   (9)   정적 진단
│   └── exploiting-*/  (2)   동적 침투
├── scan_all.py · tools/scope_guard.py
└── reports/         (gitignore, 민감)
```

---

## 📖 더 보기

- **[USAGE.md](USAGE.md)** — 설치 · 시나리오별 사용법 · 명령 레퍼런스 · FAQ
- **[ATTACK_SAFETY.md](ATTACK_SAFETY.md)** — 동적 공격 안전 수칙

---

<sub>Proprietary · SQIsoft 사내용 · v0.2.0</sub>
