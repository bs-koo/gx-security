# SEF 소스 점검 범위 — 0.10.0

기존 `doctor`, `check`, `release`, `retest` 명령으로 SEF 감지와 후보 문맥 근거를 확인합니다. 별도 명령이나 외부 추론 서비스가 필요하지 않습니다. 이 기능은 검증된 source snapshot의 inventory 대상 파일만 읽으며 사업부 애플리케이션·빌드·XML 표현식·DB를 실행하지 않습니다.

## 프레임워크 검사

`framework`는 프로파일의 필수 검사입니다. SEF 감지는 여러 소스 신호를 조합하고 public/private/혼합 구성을 모듈별로 기록합니다. 내부 `family`는 `SEF` 또는 `unknown`, `variant`는 `public`, `private`, `mixed`, `undetermined`입니다. 미감지 소스에서도 탐지 평가를 수행하되 일반 검사와 전체 필수 coverage 계약은 계속 적용됩니다. 탐지 평가 한 건의 완료가 해당 프로젝트의 보안을 검증한 것은 아닙니다.

관찰 대상은 다음 다섯 경계입니다. 결과는 한국어 제목과 소스 사실·반대 근거·필요 전제를 포함한 후보이며 실행 중 악용을 입증한 결과가 아닙니다.

| 규칙 | 구현된 관찰과 한계 |
|---|---|
| `SEF-ADM-01` | 직접 관리자 변경과 활성화된 정확한 ADM 역할 검사를 비교합니다. 메서드 조건은 클래스 조건을 덮어씁니다. 실제 연결된 advisor·manager·handler와 bean을 확인하며 사용자 정의 이름만으로 방어를 인정하지 않습니다. |
| `SEF-JWT-01` | access/refresh 발급과 직접 인증 소비를 연결합니다. 단일 String 입력에 대한 초기 직접 parser 목적 요구와 같은 입력의 소비만 제한적으로 인정하며 복잡한 흐름·키 분리는 미확정일 수 있습니다. |
| `SEF-OBJ-01` | 메뉴 predicate와 직접 객체 서비스 호출을 관찰합니다. 메뉴 ID를 전달해도 저장소의 귀속 결합은 증명되지 않아 후보가 유지됩니다. |
| `SEF-ROUTE-01` | 입증 가능한 literal 미매칭 경로를 관찰합니다. 동적 URL 설정·모호한 chain 범위는 영향 진입점 근거를 묶은 모듈별 검토 질문 하나로 남기며 경로마다 우회를 단정하지 않습니다. 미지원 매핑·HTTP verb 조건 조합은 coverage 미완료가 될 수 있습니다. |
| `SEF-FILE-01` | canonical String 경로 둘을 문자열 startsWith로 비교하는 패턴을 조건부 후보로 남깁니다. 경로 통제·이웃 prefix·다른 경계 검사 부재가 필요하며 Path.startsWith는 이 패턴과 구분합니다. |

URL 역할 방어는 지원되는 단일 unscoped SecurityFilterChain과 주 운영 소스 집합의 근거에 한정됩니다. 테스트·불명확한 소스 집합은 보호 근거가 아니며 임의 filter-chain 순서·Spring 실행 의미를 해석하지 않습니다. `doctor`가 보여주는 엔진 준비 상태와 프레임워크 감지는 출시 판정이 아닙니다. 프레임워크 미리보기는 `known-framework-signatures` 선택 방식으로 알려진 제어 파일명·빌드 신호만 읽는 부분 준비 정보입니다. 전체 저장소 자산의 hash나 Git 이력 복사를 수행하지 않습니다. 제어 파일명이 바뀐 경우 unknown으로 보일 수 있으며, 필수 `check`·`release`의 전체 분석기는 계속 기존 범위를 검사합니다.

## 후보 문맥과 공유 파일

기존 finding을 삭제하거나 ID·심각도·위치·validation을 바꾸지 않고 `context`를 추가합니다. 문맥에는 분석기와 분류, 찬반 근거, 미해결 조건, 호출별 관찰, 한계와 `binding_digest`가 포함됩니다.

| 산출물 | 읽는 목적 |
|---|---|
| `result.json`의 `framework` 검사 메타데이터 | family·variant·모듈·계약 관찰·기반 파일 hash·한계 |
| finding의 `context` | 발견과 반증 제안을 구분하고 동일 입력·대상의 근거인지 검토 |
| `review-packets.json` | 원본 발견별 주장·찬반 근거·누락 사실·제안·연결 digest 공유 |
| `framework-baseline.json` | 관측한 기반 사실과 소스·범위·분석기의 비교 근거 보존 |

`confirmed`, `not_actionable`, `needs_review`는 문맥의 **제안**입니다. 각각 공식 검증·공식 반증·위험 수용과 구분합니다. 특히 런타임 `${}`만으로 SQL 주입이 확정되지 않으며, 정적 include property나 sanitizer 관찰만으로 애플리케이션 전체를 안전하다고 결론 내리지 않습니다.

0.10의 문맥이 붙은 발견을 검토·반증·위험 수용할 때는 `review-packets.json` 또는 `result.json`의 **현재 `normalized_result_hash`를 복사**하고 기존 `source_revision`, `scope_hash`, 보호된 역할·digest 승인 근거를 함께 유지합니다. 이 hash는 문맥과 엔진·coverage 서명의 `analysis_contract_hash`를 묶으므로 분석기나 근거가 바뀌면 이전 승인을 그대로 재사용할 수 없습니다. 기존 보호된 검토 기록을 사용하며 별도 승인 인터뷰를 추가하지 않습니다.

기반 일치나 framework 소속은 승인 권한이 없습니다. 감지는 정확한 과거 기반 revision이나 계보를 식별하지 않습니다. manifest는 현재 관측된 입력의 path/hash입니다. 보호된 조직 정책의 비교 입력을 사용하더라도 개별 finding 승인과 최신 근거 검토를 우회하지 않습니다. 고위험 후보가 검토되지 않았거나 필수 범위·증거가 부족하면 기존 정책에 따라 INCOMPLETE가 유지됩니다. 정적 중심 프로파일의 결과를 전체 출시 보안 통과로 바꾸지 않습니다.

재검사에서 이전 framework finding이 사라져도 자동으로 `fixed-verified`가 되지 않습니다. `remediation-proposed`·`undetermined`와 독립 검토 필요 상태로 남깁니다. 부재의 현재 hash는 소스가 그대로면 안정적이며 소스 변경은 이전 승인을 무효화합니다.

## 지원 문법과 잔여 한계

SEF private는 JPA와 MyBatis가 함께 있는 hybrid 구성을 포함합니다. 문맥 분석은 제한된 MyBatis XML node/include/property 해석으로 정적 property와 런타임 치환을 구분합니다. 다른 namespace의 fragment를 포함하더라도 중첩된 비한정 refid는 원래 statement의 builder namespace 기준으로 해석합니다. XML·OGNL은 실행하지 않습니다. namespace·중첩 include·미해결 참조·순환·잘못된 XML·리소스 제한은 근거 또는 한계로 남깁니다. 정적 fragment의 `not_actionable` 제안에는 모든 발견된 호출의 정적 해석과 완전한 선택 XML 색인이 필요합니다. 런타임 치환에는 공격자 통제·guard·실행 도달 증명이 남아 `confirmed`를 제안하지 않습니다. 바인딩의 원문 값은 보고하지 않습니다.

SQL 반대 근거는 고정 JPA/JPQL literal의 같은 로컬 receiver named parameter binding과 고정 JDBC prepared SQL의 대응 setter를 제한적으로 지원합니다. 동적 쿼리·조건부 setter·다른 receiver·사용자 wrapper는 미확정입니다.

Vue/JS는 실제 DOMPurify import와 변경 없는 단순 표현식을 제한적으로 지원합니다. Vue 변수·computed에서 v-html로 이어지는 근거는 단일 실제 script-setup 블록과 template 범위에 한정하며 computed는 Vue의 명시적 import가 필요합니다. Nuxt autoimport·일반 script/Options API 노출·shadowing·sanitize 옵션·변경·재결합·loop/slot alias는 보호된 경로로 확정하지 않습니다. 문맥의 실제 현재 출력은 `not_actionable` 또는 `needs_review`이며 `confirmed`는 허용된 제안 값이지만 이번 분석에서 생성하지 않습니다.

이는 완전한 Java·XML·JavaScript 파서, 전역 호출 그래프 또는 전체 데이터 흐름 검증이 아닙니다. 동적 OGNL/refid/SpEL, 조건부 bean·proxy 활성화, 사용자 정의 wrapper, 생성 코드, 동적 sanitizer 구성, DB 권한 데이터와 배포·파일시스템 전제는 미확정일 수 있습니다. annotation·helper 이름 하나, 소스 테스트의 존재, HTTP 응답만으로 방어 또는 악용을 확정하지 않습니다. 읽기 실패나 미지원 문법을 안전 근거로 바꾸지 않습니다.

원본 소스·비밀값을 외부 서비스로 보내지 않습니다. 산출물은 마스킹된 근거와 위치·hash 참조를 사용합니다. 평가 fixture·변형 테스트 성적은 실제 사업부 취약점 정확도나 조직 승인으로 환산하지 않습니다. 실제 검증 결과와 실행 한계는 [구현 현황](IMPLEMENTATION-STATUS.md)을 확인하세요.
