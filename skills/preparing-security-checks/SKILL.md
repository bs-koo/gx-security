---
name: preparing-security-checks
description: 개발자가 보안 점검을 처음 준비하거나 엔진 설치·버전·프로젝트 프로파일을 확인할 때 사용한다.
version: "0.10.2"
---

# 보안 점검 준비

일반 보안 요청의 진입점은 [gx-security](../gx-security/SKILL.md)다. 이 절차는 준비만 요청하거나 호환 `gx-setup`을 호출했을 때 사용한다. 사용자가 프로젝트마다 setup을 먼저 호출할 필요는 없다.

1. source와 기존 설정·상태를 확인한다. 소비 프로젝트를 플러그인 설치 루트로 가정하지 않는다.
2. [공통 런타임 안내](../gx-security/references/runtime.md)에 따라 준비된 Docker 또는 검증된 native의 `doctor`를 사용한다. Python·의존성이 없는 호스트에서 CLI를 무조건 실행하지 않는다.
3. 설정이 없어도 기본 설정으로 검사할 수 있다. 영구 설정을 명시적으로 요청한 경우만 `init`을 사용하며 기존 파일을 덮어쓰지 않는다.
4. 기본값은 local-only다. 미설치·DB·resolved dependency 자료 부족은 실제 준비 항목으로 안내한다. 설치·이미지 준비가 필요한 경우만 기존 승인을 존중해 일회성 선택을 묻는다.
5. 준비 확인만 요청했다면 여기서 끝낸다. 실제 검사 요청이 있으면 통합 진입점에서 목적에 맞게 진행한다.

비밀번호·키·토큰을 대화·파일·argv에 적지 않는다. 네트워크 실행·외부 모델·프로젝트 build hook을 준비 과정에서 자동 활성화하지 않는다.

SEF 감지 결과나 공통 보안 기반이 관련되면 [SEF 문맥 검토](../checking-release-security/references/sef-context.md)를 읽는다. `doctor`의 프레임워크 감지는 알려진 제어 파일명·빌드 신호만 고르는 `known-framework-signatures` 방식의 부분 준비 정보이며 보안 통과가 아니다. 이름이 바뀐 제어 파일은 unknown으로 보일 수 있으므로 필수 `check`·`release` 분석 결과를 확인한다.
