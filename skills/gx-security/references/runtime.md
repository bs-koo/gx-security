# 실행 환경과 이력 연결

이 안내는 준비된 엔진을 찾고 기존 실행 상태를 잇는 절차다. 설치가 끝났다는 추측, 프로젝트 내부의 승인·setup 완료 플래그, 파일 이름만으로 실행 권한이나 검사 완료를 만들지 않는다.

## 1. 경로와 기존 결과

호스트가 제공한 이 스킬 파일의 실제 설치 경로를 확인한다. 정상 패키지는 `<plugin>/skills/gx-security/SKILL.md`와 `<plugin>/gxsec.py`, `<plugin>/scripts/gxsec.ps1`을 함께 갖는다. 이동·링크된 설치는 실제 패키지 경로를 먼저 해석하고 그 경로에서만 실행한다. 불완전한 설치면 필요한 패키지 위치를 확인한다. 검사할 프로젝트에서 동명 실행기를 찾아 대신 실행하지 않는다.

처음 Codex에 등록할 때는 [사용법의 일회성 등록](../../../USAGE.md#codex-첫-등록--pc에서-한-번)을 따른다. `register-codex-skills.ps1`은 전체 bundle을 유지한 채 사용자 스킬 위치에 링크를 만들고 기존 다른 스킬은 덮어쓰지 않는다. 등록·링크 해석은 엔진 준비나 보안 승인과 별개다.

검사 대상은 사용자가 지정한 폴더 또는 현재 프로젝트다. 다음 기존 결과를 읽어 경로·발견 ID·이전 실행 ID·프로파일을 확인한다.

- native 기본: `<project>/.gxsec/reports/<run-id>/result.json`, 상태 `<project>/.gxsec`.
- PowerShell Docker 기본: `<project>/.gxsec-container/report/result.json`, 상태 `<project>/.gxsec-container/state`.
- 사용자가 기존 결과 경로를 지정했으면 그 경로를 우선한다. `-Output <folder>`의 Docker 결과는 `<folder>/report`, 상태는 `<folder>/state`다.

결과 해석만 요청했다면 여기서 저장된 검사·대화 자료를 설명하고 끝낸다. 결과가 없으면 위치를 확인한다. 질문·새 세션·기록·준비 검사를 시작하지 않는다. 사용자가 후보 심층 검토나 이전 질문 계속을 명시했으면 확인한 기존 run·state·세션에 [질문 기반 검토](discussion.md)를 적용한다. 과거 결과를 현재 소스의 새 검사 결과라고 말하지 않는다. 경로가 다른 상태 저장소를 병합·복제하거나 임의로 새 이력을 만들지 않는다.

재검증은 해당 발견 ID가 있는 이전 실행과 원래 프로파일·상태를 연결한다. 여러 저장소에 같은 ID가 있고 요청만으로 선택할 수 없으면 하나를 고르게 한다. 발견 ID가 최신 실행에 없다면 확인한 이전 run ID를 지정한다. 과거 `check` 프로파일은 `check` 그대로 유지한다. 준비된 native가 생겼어도 이전 Docker 상태를 놓고 새 native 기본 저장소로 갈아타지 않는다.

## 2. 가벼운 내부 준비 확인

이미 같은 세션에서 같은 설치·실행 경로의 준비를 확인했고 조건이 바뀌지 않았다면 중복 안내와 설치 질문을 생략한다. 새로운 검사 전에 필요한 도구 가용성과 경로는 확인하되 매번 전체 자산·Git 이력을 복사하는 준비 작업을 하지 않는다. 실행기의 본 검사·입력 무결성 검증은 그대로 수행한다.

기존 상태와 명시한 실행 환경을 우선한다. 새 프로젝트의 Windows 환경에서는 사용 가능한 고정 Linux Docker 이미지가 있으면 호스트 Python 없이 그 경로를 선택할 수 있다. 사용자가 선택한 준비된 native 환경은 그대로 사용한다.

### Windows Docker

호스트의 명령 확인 기능으로 PowerShell과 Docker가 있는지 먼저 살핀다. 아래 실행기는 Docker·daemon·로컬 Linux 이미지 존재를 제한된 시간 안에 확인한다. 이미지가 없을 때 자동 pull/build를 하지 않는다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "<plugin>/scripts/gxsec.ps1" -Source "<project>" -Action doctor -Json
```

doctor는 결과 폴더나 프로젝트 설정을 만들지 않는다. 성공은 실행 준비와 제한된 프레임워크 미리보기이며 보안 통과가 아니다. 보고된 준비 실패는 원인을 설명한 뒤 해결하며 같은 명령을 무작정 반복하지 않는다.

준비됐으면 실제 요청한 작업만 실행한다. 필요하면 확인한 기존 `-Output`을 모든 검사에 동일하게 전달한다.

```powershell
# 일반/출시 전: 기본 프로파일은 static-release
powershell -NoProfile -ExecutionPolicy Bypass -File "<plugin>/scripts/gxsec.ps1" -Source "<project>" -Action release -Json

# 변경 점검: -Base는 사용자가 제공했거나 근거가 있는 경우만
powershell -NoProfile -ExecutionPolicy Bypass -File "<plugin>/scripts/gxsec.ps1" -Source "<project>" -Action check -Json

# 이전 상태의 발견 재검증
powershell -NoProfile -ExecutionPolicy Bypass -File "<plugin>/scripts/gxsec.ps1" -Source "<project>" -Action retest -FindingId "<finding-id>" -Profile "<original-profile>" -Json
```

변경 점검의 프로파일은 `check`다. 재검증의 `-Profile`은 기존 결과를 그대로 사용하며 필요하면 `-RunId`를 추가한다. 경로·ID·기준 커밋은 각각 인자로 전달한다. 사용자 문자열을 명령문으로 합성하거나 실행하지 않는다.

SEF 포크라는 사용자 설명·프로젝트 문서 근거가 있으면 실제 검사에 `-ExpectedFramework SEF`를 추가한다. 일반 프로젝트 또는 `doctor`에는 적용하지 않는다. 새 프로젝트 설정 파일을 만들 필요는 없다.

보호된 조직 입력이 준비된 검사는 소스 밖의 `-Policy <정책JSON>`, `-Database <DB폴더>`를 사용한다. 읽기 전용 연결 경로는 `/trusted/policy.json`, `/advisories`이며 정책의 `sca.offline_db`는 `/advisories`다. `-ReviewRecords <검토JSON>`은 `-Policy`와 함께 사용하며 `/trusted/reviews.json`으로 연결된다. 이 옵션은 check/release/retest 전용이다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "<plugin>/scripts/gxsec.ps1" -Source "<project>" -Action release -ExpectedFramework SEF -Policy "<outside>/policy.json" -Database "<outside>/osv-db" -Json
```

검토 기록 파일 연결 자체는 승인이 아니다. 일반 SAST의 수정 종결은 `fixed-verified`와 `source-verified`/`runtime-verified`, reason·evidence_refs·source_revision·scope_hash·normalized_result_hash 및 보호 정책의 `remediation-validation` 승인이 필요하다. `independent-reviewer`가 검토하고 High/Critical/미분류에는 `security-reviewer`도 필요하다. 상세 형식은 [운영 안내](../../../docs/OPERATIONS.md)를 따른다.

출력의 `/results/report/report.html`은 기본적으로 `<project>/.gxsec-container/report/report.html`이다. state는 같은 상위 폴더의 `state`다. 최신 공유본은 갱신되고 저장된 실행 이력은 이어진다.

결과의 `execution_context`는 실행 경로·프로파일·state를 잇는 안내 정보다. 보안 승인으로 취급하지 않고 실제 설치와 경로를 확인한다. 재검증은 기존 run/state를 보존하며 새 run으로 연결한다.

### Native 또는 다른 OS

호스트의 명령 확인 기능으로 프로젝트 밖의 Python 실행 파일과 3.10 이상을 먼저 확인한다. 의존성 확인은 검증한 플러그인 설치 폴더에서 해당 실행 파일의 격리 모드(`-I`)로 수행해 프로젝트의 `yaml.py`·`requests.py`나 `PYTHONPATH`를 읽지 않게 한다. 필요한 `yaml`·`requests`와 소스 밖의 보호된 `GXSEC_RUNTIME_MANIFEST`가 없으면 바로 `gxsec.py`를 실행해 초기 import 오류를 반복하지 않는다. 엔진 이름이 PATH에 있는 것만으로 준비됐다고 판단하지 않는다.

조건이 갖춰진 native는 검증한 플러그인 폴더에서 `<python> -I <plugin>/gxsec.py doctor --source <project> --json`으로 준비를 확인한다. 실제 `release`, `check`, `retest`, `init`도 같은 격리 모드·작업 폴더와 프로젝트의 절대 경로로 실행한다. 재검증은 확인한 `--state-dir`, 원래 `--profile`, 필요한 `--run-id`를 보존한다. 새 프로젝트의 기본 설정은 메모리에서 생성되므로 `init`은 필수가 아니다. 영구 설정을 명시적으로 요청했을 때만 `init`을 사용한다.

Windows 실행기를 다른 OS에서 쓸 수 있다고 가정하지 않는다. 다른 OS에서 Docker를 쓰려면 같은 네트워크 차단·읽기 전용 소스·별도 상태/보고서 mount·임시 공간 계약으로 구성해야 한다. 현재 확인할 수 없는 경로는 준비됐다고 표시하지 말고 실제 지원되는 경로를 선택한다.

## 3. 준비가 부족한 새 노트북

입력 규모는 `-Action plan`으로 먼저 확인한다. 앱 검사에서 제외하기로 사용자가 선택한 디렉터리만 `-ExcludeSourcePath @('db/docker/dumps','backend/src/main/resources/log','outputs')`처럼 전달한다. 이 경로는 예시이며 모든 프로젝트에 일괄 적용하지 않는다. 운영 미사용 프로토타입 제외는 별도 보안 점검 과제와 구분해 기록한다. `-MaxDurationSeconds`와 `-MaxInputBytes`는 전체 작업 예산이며 기본값은 1200초·4GiB다. `-TemporarySize`는 Docker 임시 공간 상한으로 전체 작업 시간·용량 예산과 다르다. Native는 `plan`, `--exclude-source-path` 반복 인자, `--max-duration-seconds`, `--max-input-bytes`를 사용한다. 재검증은 원래 선택 범위와 상태 저장소를 보존한다.

| 확인한 상태 | 다음 행동 |
|---|---|
| 플러그인/스킬이 호스트에 등록되지 않음 | 먼저 해당 호스트의 일회성 설치·등록 안내. 프로젝트를 열었다고 자동 등록됐다고 하지 않음 |
| Python 없음, Windows Docker 경로 준비됨 | 위 Docker 실행기 사용. Python 설치를 선행 요구하지 않음 |
| Docker 설치됐으나 daemon이 꺼짐 | 시작이 필요함을 안내. 기존 실행 승인 안에서 시작 가능한지 확인하고 준비 확인 재시도 |
| daemon 준비됐으나 로컬 이미지 없음 | 기존 승인과 배포 경로를 확인한 뒤 고정 패키지 준비 방법을 한 번 선택. 승인한 trusted checkout의 Dockerfile build 또는 조직이 제공한 고정 이미지 사용; 임의 latest pull 금지 |
| Python은 있지만 의존성·보호된 엔진 환경 부족 | 준비된 Docker 대안부터 확인. 없으면 한 번 필요한 설치 경로를 안내·확인하고 그 범위만 진행 |
| 둘 다 없음 | 현재 준비가 불가능한 항목을 알리고 지원되는 일회성 설치 방법을 선택하게 함. 실제 OS 도구 설치를 이미 수행했다고 말하지 않음 |

필요한 질문 예: “이 노트북에는 검사 실행 환경이 없습니다. Docker 기반 실행 환경을 준비할까요?” 승인·거절은 같은 범위에서 유지한다. 설치 준비를 거절했으면 반복 설치나 다른 도구의 임의 설치로 우회하지 않는다. 빠진 정보가 승인이라면 무응답을 승인으로 해석하지 않는다.

Docker 이미지가 있어도 최신 승인된 취약점 DB·확정 의존성 자료·검토 기록은 별도다. 필요한 조직 입력은 위 PowerShell 옵션 또는 준비된 native 경로로 전달하고 기존 보호된 정책을 따른다. 이미지·네트워크 차단·doctor 동작은 유지하며 DB를 자동 다운로드하지 않는다. 정적 검사 가능과 전체 출시 완료를 구분하고 미완료 사유를 숨기지 않는다.

## 4. 질문 기반 검토의 준비

`discuss`는 저장된 실행의 별도 대화 자료를 읽고 기록하며 새 검사를 실행하지 않는다. [질문 기반 검토](discussion.md)의 명령과 실제 이전 state를 사용한다. question/assessment 기록에는 현재 전체 소스가 저장된 입력과 일치해야 한다. 이 기록의 소스 확인은 앱·빌드·DB 실행이 아니다. 기존 이미지에 새 명령이 포함됐는지 확인하고, 불일치 시 승인된 최신 로컬 패키지 준비 경로를 따른다. 보고서 읽기나 업무 질문을 이유로 무조건 이미지를 새로 만들거나 도구를 설치하지 않는다.
