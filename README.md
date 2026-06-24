# gx-security

> SQIsoft 사업부 웹앱(JSP 레거시 · Spring 모던) 전용 **보안 점검 툴킷**.
> 스택을 자동 감지해 **정적 스캔**으로 취약점 후보를 잡고, 실행 중인 스테이징/로컬에 **실제 공격(동적)**까지 발사하여 OWASP 핵심 취약점을 **"취약점 · 이유 · 공격법 · 해결법"** 으로 짚어준다.

**한 줄 정의:** 자동화 보안 엔진(스캐너·공격 스크립트)을 **AI가 운전**하는 정적+동적(SAST+DAST) 하이브리드 보안 점검 플러그인.

👉 **실전 사용법은 [USAGE.md](USAGE.md) 참고.**

---

## 정체성 — 하이브리드

두 레이어가 결합돼 있고, **둘 다로 쓸 수 있다.**

| 레이어 | 구성 | 성격 |
|---|---|---|
| **자동화 엔진** | `scan_all.py`, `audit.py`, `skills/*/scripts/*.py`, `tools/scope_guard.py` | 독립 실행 CLI. Claude 없이도 동작(CI 연동 가능) |
| **AI 플러그인** | `skills/*/SKILL.md`, `references/`, `payloads.md` | AI가 엔진을 운전 — 오탐 제거·컨텍스트 판단·리포트 작성 |

```
정적 detecting-* (소스에서 후보 도출)
        ↓  AI 검증(오탐 제거)
동적 exploiting-* (스테이징/로컬에 실제 페이로드 발사 → 악용 확정)
        ↓
통합 4요소 리포트 (취약점·이유·공격법·해결법 + 실제 증거)
```

## 대상 스택 (자동 감지)

| 스택 | 대표 | 감지 신호 |
|---|---|---|
| `spring-modern` | sqisoft-sef-2026 | `build.gradle.kts`, `@RestController`, `src/main/java` |
| `jsp-legacy` | GSEED/Gseed_Web_Renew | `WEB-INF/web.xml`, `*.jsp`, `pom.xml` |

한 리포에 둘이 섞여도 디렉토리별로 판별해 각각에 맞는 룰을 적용한다.

## 스킬 카탈로그 (12)

| 분류 | 스킬 | 비고 |
|---|---|---|
| 🎯 **통합(메인 진입점)** | `auditing-web-application-security` | 정적+동적을 **한 번에** 오케스트레이션 |
| 정적 (9) | `detecting-csrf-vulnerabilities` · `detecting-xss-vulnerabilities` · `detecting-sql-injection` · `detecting-file-upload-vulnerabilities` · `detecting-path-traversal` · `detecting-broken-access-control` · `detecting-auth-session-weaknesses` · `detecting-sensitive-data-exposure` · `detecting-ssrf-and-open-redirect` | 소스 점검(SAST) |
| 동적 (2) | `exploiting-sql-injection` · `exploiting-xss-vulnerabilities` | 실제 공격(DAST). 7종 확장 예정 |

모든 점검 리포트는 취약점마다 **4요소**(① 취약한 점 ② 취약한 이유 ③ 뚫리는 방법 ④ 해결방법)를 포함한다.

## 빠른 시작

```bash
# 통합 점검 한 방 (정적만)
python skills/auditing-web-application-security/scripts/audit.py "D:\SQ\sqisoft-sef-2026"

# 정적 + 동적 (실행 중인 로컬/스테이징 대상)
python skills/auditing-web-application-security/scripts/audit.py \
    "D:\SQ\sqisoft-sef-2026" --target "http://localhost:8080" --params id,q
```

또는 Claude Code에서 한 마디:
> "gx-security로 sef-2026 전체 점검해줘 (로컬 http://localhost:8080)"

자세한 시나리오·명령 레퍼런스는 **[USAGE.md](USAGE.md)**.

## 안전 (핵심)

- **정적은 안전** — 소스를 읽기만 한다.
- **동적은 통제된 주의** — 실제 공격이므로 `tools/scope_guard.py`가 **운영(`prod`/`www`/공인 대상)을 코드로 차단**하고, **로컬/스테이징만 허용**한다.
- 비파괴 기본(파괴적 페이로드는 `--allow-destructive` 필요), `reports/`는 `.gitignore`로 제외.
- 상세: [ATTACK_SAFETY.md](ATTACK_SAFETY.md)

> ⚠️ 본 도구의 공격 기능은 **권한 있는 사내 보안 테스트(펜테스트)** 목적에 한한다.

## 디렉토리 구조

```
gx-security/  (security-plugin)
├── .claude-plugin/plugin.json
├── README.md · USAGE.md · ATTACK_SAFETY.md · .gitignore
├── scan_all.py                     # 정적 통합 런처
├── tools/scope_guard.py            # 동적 안전게이트
├── skills/
│   ├── auditing-web-application-security/   # 통합 오케스트레이터 + audit.py
│   ├── detecting-*/   (9)          # 정적: SKILL.md + references + rules + scripts
│   └── exploiting-*/  (2)          # 동적: SKILL.md + references/payloads + scripts
└── reports/  (gitignore, 민감)
```

## 라이선스

Proprietary — SQIsoft 사내용.
