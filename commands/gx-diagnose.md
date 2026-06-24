---
description: 취약점 진단 — 정적 분석(SAST)으로 소스에서 취약점 후보 도출 (안전, 앱 불필요) (gx-security)
argument-hint: <소스경로> [취약점종류: csrf|xss|sqli|file-upload|path-traversal|access-control|auth|secrets|ssrf]
---

gx-security의 **`detecting-*`** 정적 진단 스킬로 취약점을 진단하라. **소스를 읽기만 하므로 안전**하며 실행 중인 앱이 필요 없다.

입력: `$ARGUMENTS`
- 첫 번째 = 진단할 **소스 경로** (예: `D:\SQ\GSEED\source\Gseed_Web_Renew`)
- 두 번째(선택) = **특정 취약점 종류**. 생략하면 9종 전체.

수행 절차:
1. **스택 자동 감지** (spring-modern / jsp-legacy)
2. **정적 스캔**:
   - 전체: `python scan_all.py "<소스>" --json`
   - 특정 종류: `python skills/detecting-<종류>/scripts/scan_*.py "<소스>" --json` (또는 `scan_all.py "<소스>" --only <종류>`)
3. **AI 컨텍스트 검증** — 각 `detecting-*`의 검증 기준(예: `csrf().disable()`이 STATELESS면 의도된 예외)으로 실제 소스를 읽어 **오탐 제거**
4. **리포트** — 확정 취약점을 심각도순 + 4요소(① 취약점 ② 이유 ③ 뚫리는 방법(개념 PoC) ④ 해결방법)로 출력. `reports/diagnose-<프로젝트>.md`에 저장.

이 커맨드는 **실제 공격을 하지 않는다**(정적 분석만). 실제 악용 확인이 필요하면 `/gx-security:gx-pentest`를 사용하라.
