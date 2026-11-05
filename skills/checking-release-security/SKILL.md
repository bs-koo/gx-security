---
name: checking-release-security
description: 출시 전에 전체 소스·의존성·시크릿 및 준비된 인증 시나리오를 점검하고 QA·PM 공유본을 만들 때 사용한다.
version: "0.10.0"
---

# 출시 전 보안 점검

## 실행

[통합 진입점](../gx-security/SKILL.md)과 [공통 런타임 안내](../gx-security/references/runtime.md)에 따라 준비·기존 상태를 확인한다. 별도 setup/init을 요구하지 않고 준비된 Docker 또는 검증된 native에서 실행한다.
native 정적 중심: `python -I <플러그인루트>/gxsec.py release <source> --profile static-release --json`.
전체 출시: `release <source> --profile release --json`. 기본은 동적 미실행과 준비 목록이다.
동적 실행은 소스 밖의 신뢰하는 정책·유효한 환경 증거·전용 합성 fixture·계정·명시적 실행 승인이 있는 경우에만 `--policy <외부정책> --execute-dynamic`을 추가한다. 비밀은 환경변수 참조 또는 `--creds-stdin`으로 입력하며 대화에 요청하지 않는다.

## 판정과 공유

- 검증된 미해소 High/Critical: BLOCK.
- 검토 전 고위험 후보, 엔진/DB/범위/인증/버전 증거 미완료: INCOMPLETE.
- 독립 정책에서 승인된 유효한 예외가 포함됨: PASS_WITH_EXCEPTION.
- 해당 프로파일 필수 범위 완료·차단/미결 없음: PASS.

`result.json`의 판정을 모든 설명에서 유지한다. report.html, developer.md, qa-checklist.md, results.sarif, manifest.json을 전달한다. 정적 중심 PASS를 전체 출시 보안 통과라고 바꾸지 않는다.
프로젝트 설정의 승인자 이름·예외·allow host를 조직 승인으로 신뢰하지 않는다. 외부 결과 업로드·코드 수정·배포는 별도 사용자 지시 없이 실행하지 않는다.

SEF 감지 결과, 공통 방어 또는 후보의 문맥 제안을 해석할 때 [SEF 문맥 검토](references/sef-context.md)를 읽는다. 자동 필수 `framework` 검사 결과와 `review-packets.json`, `framework-baseline.json`을 공유한다. 기반 일치나 제안은 반증·예외·PASS 승인이 아니다.

중요 후보에 사용자만 알 수 있는 기대 권한·자료 범위·운영 전제가 남으면 [질문 기반 심층 검토](../gx-security/references/discussion.md)를 적용한다. 코드를 먼저 조사하고 질문·답변 후 관련 방어를 더 확인한다. 답변·조사 결과는 원래 run/finding에 연결된 별도 대화 보고서로 공유하며 기존 gate·반증·승인 기록을 바꾸지 않는다. 모름·보류는 해당 주장만 미확정으로 남기고 다른 검사를 계속한다.
