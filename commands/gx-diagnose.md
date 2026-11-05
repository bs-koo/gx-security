---
description: 정적 중심 보안 점검 — 공통 엔진·이력·공유 결과
argument-hint: <소스경로>
---

기존 진단 명령의 호환 진입점이다. `checking-release-security` 스킬로 다음을 실행한다.
`python <실제플러그인루트>/gxsec.py release <소스경로> --profile static-release --json`
입력: `$ARGUMENTS`. 검사 범위·gate·run ID와 생성된 공유본을 전달한다.
기존 scan_all.py는 전문가용 후보 수집이다. 결과 0건이나 정규식 대체 실행을 정밀 검사 통과로 설명하지 않는다.
