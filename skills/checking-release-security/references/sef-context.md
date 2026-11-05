# SEF와 후보 문맥 검토

`check`, `release`, `retest`의 기존 명령과 프로파일을 그대로 사용한다. 필수 `framework` 검사는 검증된 source snapshot 안의 inventory 대상만 읽는다. 별도 SEF 실행 옵션이나 외부 모델은 필요하지 않다. `doctor --source <source> --json`은 `known-framework-signatures`로 알려진 제어 파일명·빌드 신호만 선택한 부분 준비 미리보기다. 전체 저장소 자산을 hash하거나 Git 이력을 복사하지 않으며, 이름이 바뀐 제어 파일은 unknown으로 보일 수 있다. 필수 `check`·`release`의 전체 분석 범위를 대신하지 않는다.

## 결과를 읽는 순서

1. `result.json`의 gate·프로파일·필수 검사 coverage를 먼저 확인한다. SEF가 아니어도 일반 정적·의존성·시크릿 검사를 계속한다. `framework`의 탐지 평가 완료는 애플리케이션 안전 판정이 아니다.
2. `framework` 검사 메타데이터의 `family`, `variant`, `modules`, `contracts`, `baseline_manifest`, `limitations`를 확인한다. `variant`는 `public`, `private`, `mixed`, `undetermined`다. 패키지나 helper 이름 하나를 보호 기능의 실효성으로 읽지 않는다.
3. 원본 finding의 ID·위치·심각도·validation을 유지하면서 `context`와 `review-packets.json`을 읽는다. 공격 경로의 근거와 가장 강한 반대 근거를 구분하고, `unresolved`·`limitations`에 남은 조건을 확인한다. 파일·라인·hash 참조로 같은 snapshot의 근거인지 확인한다.
4. `context.proposal`의 `confirmed`, `not_actionable`, `needs_review`는 분석기의 검토 제안이다. `confirmed`도 공식 `source-verified`가 아니며, `not_actionable`도 `refuted`나 자동 제외가 아니다. 런타임 `${}` 발견만으로 SQL 주입이 확정되지 않는다.
5. 문맥이 붙은 발견의 검토·반증·위험 수용 기록에는 `review-packets.json` 또는 `result.json`에서 현재 `normalized_result_hash`를 복사하고 기존 `source_revision`, `scope_hash`, 보호된 역할·digest 승인 근거를 유지한다. 이 hash는 `analysis_contract_hash`의 엔진·coverage 서명과 문맥을 묶으므로 분석기·근거 변경 후 이전 승인을 재사용하지 않는다. 필요한 정적 근거·실행 조건을 개발자와 QA에 남긴다. High/Critical 반증·예외는 기존 보호된 독립 검토를 따른다. 업무 의도는 [질문 기반 검토](../../gx-security/references/discussion.md)로 확인할 수 있지만 답변은 승인 기록과 분리하고 기존 정책의 승인 권한을 대신하지 않는다.

## 근거의 적용 범위

관리자 변경에는 같은 변경을 막는 실효 권한 검사가, 토큰에는 발급·소비 목적의 일치가, 메뉴·객체에는 같은 요청의 귀속 관계가 필요하다. 어노테이션·sanitizer·소유권 helper의 존재만으로 보호된 경로라고 결론 내리지 않는다. 파일 경로 보호는 문자열 prefix뿐 아니라 실제 경계와 실행 환경의 전제도 구분한다.

동적 URL 설정은 모듈별 검토 질문으로 읽고 경로별 우회 확정으로 바꾸지 않는다. 미지원 매핑·verb 조합의 coverage 미완료를 확인한다.

분석기는 제한된 소스 문법을 관찰한다. private의 JPA·MyBatis hybrid를 구분하고 cross-namespace include의 비한정 참조는 원래 statement의 builder namespace로 해석한다. DOMPurify 반대 근거는 실제 import와 단순한 변경 없는 표현식에 한정된다. Vue는 script-setup과 명시적 computed import가 필요하며 Nuxt autoimport·Options API는 미확정이다. MyBatis include/property와 SQL 바인딩, Vue/JS 주석·DOMPurify 근거가 있어도 전역 호출 그래프나 모든 입력→sink 경로를 증명하지 않는다. 동적 OGNL·refid·SpEL·조건부 bean·proxy·생성 코드·사용자 wrapper·DB 권한 데이터·배포 설정은 지원 범위 밖이거나 미확정일 수 있다. 소스·XML·빌드·표현식을 실행해 빈 근거를 채우지 않는다. 실패·제한·미지원 경로를 완료나 안전으로 바꾸지 않는다.

`framework-baseline.json`은 현재 관측한 입력 파일 path/hash의 비교 근거다. 정확한 과거 기반 revision이나 계보를 식별한 기록이 아니다. 프로젝트의 자체 SEF 표시나 기반 일치가 조직 승인 권한을 만들지 않는다. 관련 소스·설정·호출자·binding·분석기가 달라지면 이전 근거를 재검토한다. 그룹으로 보여도 원본 finding과 개별 검토 상태를 보존한다. 재검사에서 framework finding이 사라졌다는 사실만으로 `fixed-verified` 처리하지 않는다. `remediation-proposed`·`undetermined`와 독립 검토 필요 상태로 남긴다. 부재를 나타내는 현재 hash는 소스가 같으면 안정적이며 소스 변경은 이전 승인 근거를 무효화한다.

보고서에는 마스킹된 근거와 참조만 전달한다. 원문 자격증명·사업부 소스 발췌를 대화나 외부 서비스에 복사하지 않는다. 전체 지원 범위와 한계는 [SEF 점검 범위](../../../docs/SEF-CHECKS.md)를 참고한다.
