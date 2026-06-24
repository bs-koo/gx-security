---
description: 전체 보안 점검 — 정적 취약점 진단 + 동적 모의침투를 한 번에 (gx-security)
argument-hint: <소스경로> [대상URL]
---

gx-security의 **`auditing-web-application-security`** 스킬을 사용해 전체 보안 점검을 수행하라.

입력: `$ARGUMENTS`
- 첫 번째 = 점검할 **소스 경로** (예: `D:\SQ\sqisoft-sef-2026`)
- 두 번째(선택) = 실행 중인 **스테이징/로컬 대상 URL** (예: `http://localhost:8080`). 주어지면 동적 모의침투까지 수행.

수행 절차:
1. **스택 자동 감지** — `build.gradle.kts`/`WEB-INF` 신호로 spring-modern / jsp-legacy 판별
2. **정적 진단** — `python skills/auditing-web-application-security/scripts/audit.py "<소스>" [--target <URL>] [--params id,q] --json` 실행 (정적 9종 일괄 + 대상 있으면 동적 발사)
3. **AI 컨텍스트 검증** — 후보가 많은 클래스부터 각 `detecting-*`의 검증 기준으로 실제 소스를 읽어 오탐 제거
4. **동적 결과 종합** — 대상 URL이 있었다면 `exploiting-*` 결과로 실제 악용 여부 확정 (필요 시 파라미터 지정해 추가 발사)
5. **통합 리포트** — `reports/audit-<프로젝트>.md`에 심각도순 + 4요소(① 취약점 ② 이유 ③ 뚫리는 방법 ④ 해결방법 + Evidence) 저장

안전:
- 동적(모의침투)은 `tools/scope_guard.py`가 허용한 **스테이징/로컬만**. 대상 URL이 운영(`prod`/`www`/공인)으로 보이면 **중단**하고 스테이징/로컬을 요청하라.
- 대상 URL이 없으면 정적 진단만 수행한다(완전 안전).
