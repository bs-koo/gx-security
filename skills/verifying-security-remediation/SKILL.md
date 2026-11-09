---
name: verifying-security-remediation
description: 이전 보안 발견사항을 동일 ID로 이어 수정 후 재검증하고 해결·재발·미확정을 구분할 때 사용한다.
version: "0.10.1"
---

# 보안 수정 재검증

[통합 진입점](../gx-security/SKILL.md)과 [공통 런타임 안내](../gx-security/references/runtime.md)를 적용한다. 저장된 run ID·finding ID·원래 프로파일과 상태 저장소·실행 경로를 확인하고 그대로 이어간다. 새로운 기본 상태 저장소나 일반 스캔으로 바꾸지 않는다.
검증된 native는 `python -I <플러그인루트>/gxsec.py retest <finding-id> --source <source> --profile <원래프로파일> --state-dir <이전상태> [--run-id <이전실행>] --json`을 사용한다. Docker는 공통 안내의 `-Action retest -FindingId ...`와 확인한 같은 `-Output`·원래 프로파일을 사용한다. 준비는 내부에서 확인하며 별도 setup을 요구하지 않는다.
현재 재검사는 보수적인 동일 프로파일 재실행이다. 이전 정적 결과나 동적 세션이 최신이라고 추정하지 않는다.

이전 결함이 보이지 않더라도 엔진·규칙·범위가 같고 완전한 재검사인지 확인한다. secret은 소스 삭제 외에 키 회전·폐기 근거가 필요하다. 동적 결함은 같은 자원·역할·oracle과 정상 기능 확인이 필요하다.
엔진 실패·범위 축소·미발사·인증 실패는 해결로 처리하지 않는다. 기존 finding ID·이전/신규 revision·증거·조치 상태를 QA와 공유한다.

SEF 또는 문맥 근거가 포함된 finding은 [SEF 문맥 검토](../checking-release-security/references/sef-context.md)를 읽는다. 최신 snapshot의 근거와 검토 묶음을 비교하고, 기반·설정·호출 경로 변경 시 이전 보호 근거가 여전히 적용되는지 확인한다. 문맥 제안만으로 해결 처리하지 않는다.

이전 framework finding이 현재 검사에서 사라진 사실만으로 `fixed-verified` 처리하지 않는다. `remediation-proposed`·`undetermined`와 독립 검토 필요 상태로 남긴다. 현재 부재의 hash는 소스가 그대로면 안정적이며 소스 변경 후에는 이전 승인 근거를 다시 확인한다.

이전 질문과 답변이 있다면 역사적 의도로 읽고 현재 수정·역할·경로에도 적용되는지 확인한다. 중요 모호함이 남으면 [질문 기반 심층 검토](../gx-security/references/discussion.md)를 현재 run/finding의 새 세션으로 수행한다. 답변만으로 해결·반증·예외를 기록하지 않고 실제 조사 결과와 남은 조건을 구분한다.
