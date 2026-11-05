---
description: 출시 전 전체 프로파일 검사와 개발자·QA·PM 공유 결과 생성
argument-hint: <소스경로>
---

`gx-security` 스킬의 **출시 점검**으로 `$ARGUMENTS`를 처리한다. 목적이 명확하면 다시 묻지 않고 필요한 준비는 내부에서 확인한다. 별도 setup 호출을 요구하지 않는다.
기존 상태·선택한 실행 환경을 유지하며 기본 `static-release` 점검을 수행한다.
전체 출시 프로파일은 `--profile release`로 선택하며, 기본은 동적 계획만 생성한다.
네트워크 실행은 소스 밖의 신뢰하는 조직 정책과 전용 테스트 계정·합성 데이터·배포 버전 증거가 준비되고 해당 범위의 실행이 승인됐을 때만 `--policy <외부정책> --execute-dynamic`으로 수행한다.
이미 유효한 범위 승인이 있으면 반복 확인하지 않는다. 누락된 조건은 INCOMPLETE와 준비 목록으로 보고한다.
PASS/BLOCK/INCOMPLETE/PASS_WITH_EXCEPTION과 검사 범위를 그대로 전달한다. 외부 업로드·배포를 자동 수행하지 않는다.
