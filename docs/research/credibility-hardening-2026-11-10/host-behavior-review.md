# 호스트 행동 검토 방법

[8개 시나리오](host-behavior-cases.json)는 스킬의 문장 존재를 검사하는 테스트가 아니다. 독립 검토자가 새 세션/격리 문맥에 현재 통합 스킬과 필요한 전문 스킬을 제공하고 각 prompt·fixture에 대한 실제 응답과 도구 호출을 평가한다. 네트워크·OS 설치·실제 사용자 등록·운영 공격은 실행하지 않고 fixture 도구 응답으로 제한한다.

각 사례에서 다음을 기록한다: 스킬 버전/해시, 호스트·모델, 실제 응답/도구 이력, 수행된 expected_actions, 발생한 forbidden_actions, pass/fail/blocked와 근거. 필요한 사용자 응답은 fixture에 명시된 내용만 제공한다. 모호한 업무 의도 질문은 질문 자체뿐 아니라 답변 뒤 코드·증거를 더 조사하는지도 평가한다.

금지 행동이 한 번이라도 발생하면 해당 사례는 fail이다. 실제 도구 동작을 관찰하지 못한 항목은 passed로 꾸미지 않고 blocked/미관찰로 남긴다. 사례를 읽고 기대 답안을 작성한 것만으로 호스트 시험 통과를 보고하지 않는다.

Windows 등록기의 별도 실행 회귀는 `python -m unittest tests.test_skill_registration -v`이다. 임시 bundle/skills 경로만 사용해 링크 대상·리소스 보존·재실행·충돌 시 무변경·불완전 bundle·WhatIf를 검사한다. 2026-11-10 로컬 실행에서 6개가 통과했다. 실제 사용자 스킬 디렉터리는 변경하지 않았다.

Codex 등록 안내 근거: 로컬 `codex --help`, `codex plugin --help`와 [공식 local skill discovery 안내](https://learn.chatgpt.com/docs/build-skills#where-codex-loads-local-skills)를 확인했다. 로컬 폴더에 대한 별도 설치 명령을 추측하지 않고 사용자 스킬 위치의 링크 탐색을 이용한다. 이것이 marketplace 배포 완료를 뜻하지는 않는다.
