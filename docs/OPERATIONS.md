# gx-security 운영 0.10.1

## 배포와 업데이트

프리뷰를 로컬 또는 승인된 CI에서 사용합니다. 원격 저장소 push·서비스 배포·자동화 등록은 이 도구의 기본 동작이 아닙니다. Python bundle·엔진·규칙·DB는 각각 버전과 해시를 기록하며 검사 도중 자동 업데이트하지 않습니다.

Windows 기본 경로는 고정 Linux 컨테이너입니다. source는 읽기 전용으로 연결하고 결과와 state는 별도 쓰기 경로에 둡니다. Docker socket을 검사 컨테이너에 제공하지 않습니다. --network none은 정적 경로의 기본이며 DB는 검사 전에 준비합니다.

## 통합 세션 진입점

사용자는 등록된 통합 스킬 `gx-security`로 요청합니다. Claude Code의 명시 호출은 `/gx-security:gx-security`, Codex의 명시 호출은 `$gx-security`입니다. 호스트가 스킬을 제공하는 환경에서는 관련 자연어 요청으로도 선택될 수 있습니다. 폴더를 여는 것만으로 플러그인이 설치되거나 모든 세션에 강제 적용된다고 가정하지 않습니다. 현재 0.10.1 공개 프리뷰의 배포·등록 상태는 실제 설치본에서 확인합니다.

프로젝트마다 setup 호출이나 설정 파일 생성은 요구하지 않습니다. 실제 검사 전에 가벼운 준비 확인을 수행하고 기존 설정·상태를 사용하며 설정이 없으면 기본값으로 실행합니다. 저장된 setup 완료 플래그를 실행 파일·버전·승인 근거 대신 사용하지 않습니다. 무관한 개발 작업은 이 흐름을 적용하지 않고, 결과 설명 요청은 기존 보고서만 읽습니다.

기존 실행 경로·상태를 우선 존중합니다. 준비된 Windows Docker 이미지가 있으면 호스트 Python 없이 사용할 수 있고, 직접 실행은 필요한 Python·패키지·보호된 runtime 근거를 확인한 뒤 선택합니다. Docker 실행기는 daemon·로컬 Linux 이미지 가용성을 확인하고 누락 시 준비 필요로 종료하며 자동 pull을 하지 않습니다. doctor는 결과 폴더를 만들지 않습니다. OS 도구 설치·고정 이미지 준비·DB 다운로드는 별도의 준비 행동이며, 기존 승인을 재사용하고 미결정 선택만 확인합니다.

통합 스킬을 포함한 22개 스킬 중 기존 네 목적 명령은 호환 진입점으로 유지합니다. 의도가 명확한 검사·재검증을 시작하기 위해 반복 인터뷰를 요구하지 않습니다. 질문 없이 준비를 확인하는 동작이 동적 실행·외부 전송·위험 수용 권한을 새로 부여하지는 않습니다.

## 신뢰 정책

프로젝트 gxsec.yaml은 비밀 없는 요청 설정입니다. 필수 검사 제거·엔진 실행 파일 변경·외부 전송·위험 수용을 승인할 수 없습니다. --policy는 검사 source 밖의 보호된 파일을 가리켜야 합니다. 해당 파일과 그 생성·승인 권한은 조직이 보호해야 합니다. CLI가 승인자의 실제 신원을 대신 인증하지 않습니다.

trusted_approvals는 승인 대상 record_id·canonical JSON digest·kind·역할을 묶습니다. 검토·예외 기록은 revision과 scope_hash,근거를 포함합니다. dirty tree에는 commit 대신 working-tree content hash를 사용해 승인을 재사용하지 못하게 합니다.

0.10의 문맥이 붙은 발견은 현재 `normalized_result_hash`도 검토·반증·위험 수용 기록에 연결합니다. 문맥·분석기·coverage 계약이 바뀌면 이전 승인은 재사용되지 않습니다. `review-packets.json`은 검토 제안이고 `framework-baseline.json`은 현재 소스 관측입니다. 조직 baseline 일치만으로 발견을 승인하거나 면제하지 않습니다.

공식 release에는 clean checkout·artifact digest·보호된 CI 근거와 필수 수동 검토가 필요합니다. 기본 수동 항목은 role-matrix,sensitive-data,external-side-effects,business-logic입니다. 단순 이름 입력이나 프로젝트 내부 JSON은 승인 증거가 아닙니다.

## 권한과 조치

개발자가 수정·분석·근거 초안을 작성하고 QA/독립 기술 검토자가 시나리오와 적용 불가를 확인합니다. High/Critical 반증에는 security-reviewer 역할이, 위험 수용에는 security-owner+project-owner 역할이 필요합니다. 역할은 보호된 승인 절차에서 매핑합니다.

예외는 finding·revision·scope에 한정되며 담당·사유·만료가 필요합니다. 만료나 범위 변경을 자동 통과시키지 않습니다. baseline은 이력 표시 기준이며 기존 고위험 항목의 면제가 아닙니다.

## 결과 보관과 공유

직접 실행의 상태는 `.gxsec/state.sqlite3`와 runs snapshot, 공유본은 `.gxsec/reports/<run-id>`입니다. Windows Docker 실행기의 기본 상태는 `.gxsec-container/state`, 최신 공유본은 `.gxsec-container/report`입니다. 별도 Output을 사용했다면 그 아래의 `state`와 `report`를 그대로 사용합니다. 재검증 시 실행 경로만 보고 새 상태 저장소로 전환하지 않습니다.

공유본은 마스킹된 result.json에서 동일한 판정으로 생성합니다. snapshot은 불변이며 변경은 새 run으로 기록합니다. 상태·key·DB·보고서 경로의 저장소 유도 symlink를 거부합니다. 기존 결과를 설명할 때는 해당 결과의 시각·revision·범위를 밝히며 현재 소스가 다시 검사된 것으로 표현하지 않습니다.

원문 자격증명을 대화·파일·argv에 넣지 않습니다. 보존기한과 접근권한은 사내 규정으로 설정합니다. 로컬 개발 결과를 공식 승인으로 재포장하지 않습니다. 외부 파일 공유는 수신자·권한이 정해진 별도 절차로 수행합니다.

## 유지보수

core/schema,규칙,동적 정책과 릴리스의 담당을 지정하고 최소 2인 리뷰 체계를 권장합니다. 정기 업데이트에서는 기존 회귀·실제 엔진 smoke·새 품질 corpus를 확인합니다. 정확도·시간 목표는 실제 사업부 holdout/사용자 파일럿 전에는 달성했다고 표기하지 않습니다.
