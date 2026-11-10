# gx-security 사용법 0.10.3

## 1. 프로젝트 세션에서 통합 스킬 사용

플러그인·스킬이 등록된 Claude Code 또는 Codex에서 대상 프로젝트 폴더를 엽니다. 현재 로컬 0.10.3 작업본이 원격 marketplace나 다른 사람의 호스트에 이미 배포됐다고 가정하지 않습니다.

```text
Claude Code: /gx-security:gx-security 현재 프로젝트 보안 점검해줘
Codex:       $gx-security 현재 프로젝트 보안 점검해줘
```

호스트가 스킬을 발견할 수 있으면 자연어 요청으로도 선택될 수 있습니다. 사용자에게 여러 전문 스킬 이름이나 매 프로젝트의 setup 호출을 요구하지 않습니다. 보안과 무관한 개발 요청을 가로채지는 않습니다.

검사 전 파일 규모를 확인합니다. DB 백업·실행 로그·연구 산출물의 포함 여부가 애매하면 질문하고 선택한 제외 범위를 기록합니다. 실행 중에는 단계·경과 시간·처리량이 표시됩니다. 실패나 시간 제한에 걸리면 이유와 부분 결과를 남기며, 선택 범위의 검사 완료를 전체 출시 승인으로 표시하지 않습니다.

| 요청 | 통합 진입점의 처리 |
|---|---|
| “출시 전에 점검해줘” | 실행 준비를 확인한 뒤 기본 정적 출시 점검 |
| “이번 변경사항 점검해줘” | 변경 기준을 기록하고 보수적으로 소스 재검사 |
| “이 항목 수정했어, 다시 확인해줘” | 기존 발견 ID·프로파일·상태 저장소를 이어 재검증 |
| “지난 보고서 설명만 해줘” | 저장된 보고서를 읽고 결과·미완료 사유 설명 |

명시한 경로 또는 현재 작업 폴더를 검사 대상으로 사용합니다. 목적과 대상이 분명하면 바로 진행합니다. 빈 호출의 목적, 여러 프로젝트·발견 중 선택, 처음 필요한 도구 설치 방식처럼 실제로 미결정인 정보만 묻습니다. 기존의 유효한 사용자 선택·승인을 다시 요구하지 않습니다.

실제 검사 전에 실행 준비를 내부에서 확인합니다. 기존 설정이 있으면 읽고, 없으면 기본 설정으로 실행하므로 `gxsec.yaml` 생성은 필수 단계가 아닙니다. 설정 저장을 요청하지 않았는데 `init`을 실행하거나 `.gitignore`를 변경하지 않습니다. 기존 보고서 해석만 요청했을 때는 준비 확인·검사·설치를 시작하지 않습니다.

Windows에서는 사용할 수 있는 기존 Docker 경로와 상태를 존중하고, 준비된 로컬 고정 이미지가 있으면 호스트 Python 없이 실행할 수 있습니다. 직접 실행 경로는 Python·필요 패키지·보호된 runtime manifest와 검사 엔진이 실제 준비됐는지 확인합니다. 환경이 없으면 준비 항목과 가능한 방법을 설명하고 필요한 선택만 확인합니다. OS 도구 설치·이미지 pull·취약점 DB 다운로드를 묵시적으로 수행하지 않습니다. 환경 확인이 보안 점검 완료를 의미하지는 않습니다.

기존 `gx-setup`, `gx-check`, `gx-release`, `gx-retest`와 네 목적 스킬은 호환 진입점입니다. 통합 스킬을 포함한 22개 스킬 중 사용자가 평소 기억할 진입점은 `gx-security` 하나입니다.

### Codex 첫 등록 — PC에서 한 번

이미 플러그인으로 설치되어 `gx-security`가 보이면 추가 등록하지 않습니다. 로컬 배포본을 쓰는 Windows에서는 신뢰하는 **전체 bundle**을 고정 폴더에 보관한 뒤 사용자 스킬 위치에 연결합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "D:\tools\gx-security\scripts\register-codex-skills.ps1" -BundleRoot "D:\tools\gx-security"
```

등록기는 기본 `%USERPROFILE%\.agents\skills`에 각 스킬의 junction을 만들고 전체 bundle의 실행기·규칙·references를 유지합니다. 기존 이름의 다른 스킬이나 다른 배포본 링크가 있으면 전체 사전 검사에서 중단하며 덮어쓰지 않습니다. 같은 bundle 재등록은 변경하지 않습니다. 미리보기는 `-WhatIf`, 별도 시험 경로는 `-SkillsDirectory <임시폴더>`입니다. bundle을 이동·삭제하면 링크가 깨지므로 경로를 유지합니다. 등록은 엔진 설치·검사 실행·보안 승인이 아닙니다.

등록 후 프로젝트 세션에서 `$gx-security`를 선택합니다. 보이지 않으면 Codex를 다시 시작합니다. 매 프로젝트 setup은 필요 없습니다. 스킬 디렉터리만 따로 복사하면 상위 실행기·도구 경로가 끊어집니다. 호스트는 링크의 실제 대상 경로를 해석한 뒤 bundle의 실행기와 references를 사용합니다. 사용자 스킬 위치와 링크 탐색은 [OpenAI 공식 스킬 안내](https://learn.chatgpt.com/docs/build-skills#where-codex-loads-local-skills)로 확인했습니다.

macOS/Linux도 전체 bundle을 보관하고 사용자 스킬 위치에 각 `skills/<이름>`을 심볼릭 링크로 연결합니다. 기존 항목은 덮어쓰지 않습니다. 위 등록기는 PowerShell이 있는 환경에서 사용하며, 다른 호스트에 자동 배포되었다고 가정하지 않습니다.

## 2. 고정 컨테이너

```text
docker build --platform linux/amd64 -t gx-security:0.10.3 .
```

통합 스킬이 실행 경로를 선택하며 다음 명령은 직접 실행하거나 환경을 준비하는 담당자용입니다. Windows는 `scripts/gxsec.ps1 -Source <source>`를 사용합니다. 실행 전에 Docker 상태와 로컬 Linux 이미지를 확인하고, 이미지가 없으면 자동 pull 없이 준비 필요로 종료합니다. 소스는 읽기 전용이고 검사 컨테이너는 네트워크를 사용하지 않습니다. 신규 OSV DB는 별도 준비하고 읽기 전용 mount로 연결합니다. 컨테이너 내부 경로와 PC 경로는 다르므로 프로파일의 DB 경로도 맞춰야 합니다.

```powershell
powershell -ExecutionPolicy Bypass -File scripts/gxsec.ps1 -Source D:\project -Action doctor -Json
powershell -ExecutionPolicy Bypass -File scripts/gxsec.ps1 -Source D:\project -Action release -Json
powershell -ExecutionPolicy Bypass -File scripts/gxsec.ps1 -Source D:\project -Action check -Base HEAD~1 -Json
powershell -ExecutionPolicy Bypass -File scripts/gxsec.ps1 -Source D:\project -Action retest -FindingId <finding-id> -Profile <original-profile> -RunId <previous-run-id> -Json
```

사용자가 SEF 포크라고 알려줬거나 프로젝트 문서에 근거가 있으면 실제 점검에 `-ExpectedFramework SEF`를 추가합니다. 별도 설정 생성 없이 필수 공통 경계를 엄격하게 확인합니다. 일반 프로젝트에는 일괄 적용하지 않고 `doctor`에는 전달하지 않습니다. native는 `--expected-framework SEF`입니다.

`doctor`는 준비 정보만 출력하며 결과·상태 폴더를 만들지 않습니다. 실제 점검의 기본 보고서는 `<source>/.gxsec-container/report/report.html`, 상태는 `<source>/.gxsec-container/state`입니다. `-Output D:\security-results\project`를 지정하면 보고서는 그 아래 `report/report.html`, 상태는 `state`에 저장됩니다. `-Output`은 최종 HTML 파일이나 `report` 폴더 자체가 아니라 상위 결과 폴더입니다. 같은 대상·Output으로 재실행하면 상태 이력을 이어가며 `report`는 최신 공유본으로 갱신합니다.

큰 소스 사본에는 `-TemporarySize 1g`, `2g`, `4g`로 점검용 임시 공간 상한을 선택할 수 있습니다. 기본은 `512m`이며 허용된 네 값만 받습니다. 이 공간은 사용량에 따라 메모리를 소비하고 검사 엔진의 메모리는 별도로 필요합니다. 재검증은 원래 실행에 저장된 크기를 이어받고, 명시한 `-TemporarySize`가 우선합니다.

직접 Python 실행은 Python 3.10 이상과 requests/PyYAML, 보호된 실행 환경이 준비된 경우에 사용합니다.

```text
python gxsec.py doctor --source <source> --json
python gxsec.py check <source> [--base <commit>]
python gxsec.py release <source> --profile static-release
```

직접 실행의 기본 보고서는 `<source>/.gxsec/reports/<run-id>/report.html`, 상태는 `<source>/.gxsec/state.sqlite3`와 runs에 저장됩니다. 재검증은 이전 실행의 저장소를 그대로 사용합니다. Docker 결과를 직접 실행으로 이어 읽는 경우에도 기존 저장소를 명시해야 하며 새 저장소로 바꾸지 않습니다. `init <source>`은 설정 저장을 명시적으로 원할 때만 사용합니다. 비밀 없는 `gxsec.yaml`을 만들고 출력 폴더의 Git 제외 설정을 보완하며 기존 파일은 덮어쓰지 않습니다.

준비 부족은 `INCOMPLETE` 또는 실행 전 준비 오류로 안내합니다. Python이나 필수 패키지가 없는 직접 실행에서 정상적인 doctor 보고서를 얻었다고 설명하지 않습니다. 직접 정규식 스크립트는 탐색용이며 release PASS의 근거가 아닙니다.

많은 파일을 Windows 공유 폴더에서 직접 읽으면 파일별 무결성 검증이 느릴 수 있습니다. 실제 2천여 파일 파일럿에서도 이 병목을 확인했습니다. 반복 실행은 WSL/Linux 파일시스템의 작업 사본을 권장합니다. 전송용 묶음으로 옮기는 경우 원본 경로·파일 목록·해시를 보존하고, 안전하게 푼 뒤 같은 해시를 다시 검증해야 합니다. 임의 선별 사본을 전체 출시 증거로 사용하지 않습니다.

고정 bundle 갱신은 기록된 Python image에서 `uv pip compile requirements-bundle.in --python-version 3.12 --generate-hashes -o requirements-bundle.lock`으로 수행한 후 규칙·품질 시험을 재실행합니다. 자동으로 latest를 채택하지 않습니다.

## 3. SCA 입력과 오프라인 DB

OSV는 resolved lockfile·SBOM을 사용합니다. pom.xml 선언만으로 전이 의존성 완료를 주장하지 않습니다. `sca`에는 source_revision, input_hashes(파일 경로→SHA256), modules, runtime_complete가 필요합니다. 전체 release에는 독립적으로 검증된 artifact_digest도 필요합니다.

SCA의 실행 근거는 프로젝트가 스스로 승인할 수 없습니다. `--policy`로 소스 밖의 보호된 조직 정책을 지정합니다. 정책의 `sca`에는 `offline_db`, `db_manifest_sha256`, `provenance`가 필요합니다. provenance는 `id`, 실제 `source_revision`, `scope_hash`, `input_hashes`, `modules`, `runtime_complete`, 배포물 `artifact_digest`를 담고, 별도의 `trusted_approvals`에서 해당 내용의 digest를 `dependency-provenance` 종류와 `protected-ci` 역할로 승인해야 합니다. 프로젝트의 `tools.osv.offline_db`와 `sca` 선언만으로 외부 파일을 읽거나 완료 처리하지 않습니다.

고정 버전 2.7.0의 실제 실행에서 확인한 DB 캐시는 `osv-scalibr/<생태계>/all.zip`입니다. DB 디렉터리에 다음 `snapshot.json`을 함께 둡니다. 이전 문서의 `osv-scanner/` 경로를 그대로 사용하면 이 버전에서 매칭되지 않습니다.

```json
{"schema_version":1,"generated_at":"2026-11-05T00:00:00+00:00","advisory_as_of":"2026-11-05","files":{"osv-scalibr/Maven/all.zip":"<sha256>"}}
```

위 값은 형식 예시입니다. 실제 다운로드된 자료의 시각·파일 해시로 생성합니다. 프로젝트가 선언한 DB 시각만으로 신선도를 인정하지 않으며, 기본 유효기간은 72시간입니다. scanner 실행 중 DB를 자동 다운로드하지 않습니다.

잠금 파일에서 패키지 이름·버전만 읽힌 것과 취약점 매칭은 다릅니다. 예를 들어 npm의 `resolved` 출처가 없으면 엔진이 로컬 패키지로 분류하고 공개 DB 매칭을 건너뛸 수 있습니다. 실제 패키지 출처와 생태계별 DB 사용을 확인하지 못하면 0건이어도 완료로 인정하지 않습니다.

표준 Maven SBOM은 출처 분류자를 생략해도 고정 엔진에서 좌표 기반 매칭이 수행됨을 실제 시험으로 확인했습니다. 출처를 임의로 공개 레지스트리라고 표시하지 않고, 승인된 배포물·확정 의존성 근거와 실제 생태계 DB 사용을 확인합니다. 엔진이 매칭을 생략한 패키지를 단순 파싱 수에 포함해 통과시키지 않습니다.

PowerShell 실행기는 소스 밖의 보호 정책·DB를 `-Policy`, `-Database`로 읽기 전용 연결합니다. 컨테이너 경로는 `/trusted/policy.json`, `/advisories`이므로 정책의 `sca.offline_db`를 `/advisories`로 작성합니다. 검토 기록은 `-ReviewRecords`로 전달하며 `-Policy`가 함께 필요합니다. 이 세 옵션은 `check`, `release`, `retest` 전용이고 `doctor`에는 쓰지 않습니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/gxsec.ps1 -Source "D:\project" -Action release -ExpectedFramework SEF -Policy "D:\security-trust\policy.json" -Database "D:\security-trust\osv-db" -ReviewRecords "D:\security-trust\reviews.json" -Json
```

위 예시는 입력이 실제 준비된 SEF 프로젝트용입니다. 검토 기록이 없으면 `-ReviewRecords`는 생략합니다. 검토 기록은 `/trusted/reviews.json`에 연결되며 보호 정책의 digest·역할 검증을 통과해야 적용됩니다. 파일 연결만으로 승인되지 않습니다. 이미지·네트워크 차단·doctor 동작은 동일하며 DB를 자동 다운로드하지 않습니다.

컨테이너는 설치된 실행 파일의 절대 경로·SHA256·버전을 기록한 `GXSEC_RUNTIME_MANIFEST`를 제공합니다. 호스트에서 실행할 때도 소스 밖의 보호된 동일 형식 manifest가 필요합니다. PATH에 이름이 있다는 이유만으로 검사기를 실행하지 않습니다. `doctor`는 이 근거와 실제 버전을 함께 확인합니다.

정적 검사는 최초 파일 목록과 해시에 맞는 별도 읽기 전용 사본을 만들어 실행합니다. Git 이력도 로컬 사본으로 분리하며 외부 원격 저장소에서 가져오지 않습니다. 임시 공간이 부족하거나 사본·이력 검증이 실패하면 미완료입니다. Windows 실행기의 기본 임시 공간은 512MiB이며 `-TemporarySize`로 최대 4GiB까지 선택합니다. 그보다 큰 입력은 충분한 임시 공간을 갖춘 별도 실행 환경이 필요합니다. 현재 사용자 지정 `exclusions` 선언은 실행 범위를 좁히지 않으며, 기본 생성물·도구 상태 제외만 적용합니다.

기본 제외에는 검사 루트 직하 `.claude/worktrees`의 자동 생성 작업 복사본도 포함됩니다. 제외 경로는 검사 기록에 남으며, 일반 `worktrees` 폴더, 중첩된 `module/.claude/worktrees`와 `.claude` 설정은 계속 검사합니다. 작업 복사본 자체를 소스 루트로 선택하면 그 프로젝트를 정상 검사합니다. 이 제외 계약을 반영한 범위는 이전 버전의 범위와 구분하므로 과거 결과를 같은 검사 범위로 간주해 자동 종결하지 않습니다.

## 4. 결과와 재검증

```text
python gxsec.py report <run-id> --state-dir <source>/.gxsec --output <destination>
python gxsec.py retest <finding-id> --source <source> --state-dir <previous-state-dir> --profile <original-profile> --run-id <previous-run-id>
```

`--config`는 프로젝트 설정 파일 경로이며 프로파일 이름이 아닙니다. 검사 종류는 `--profile`로 전달합니다. Docker 이력을 native로 읽으면 `--state-dir <previous-output>/state`, 기존 native라면 `<source>/.gxsec`를 유지합니다.

run snapshot은 불변입니다. 재검증은 새 run을 생성하고 이전 finding ID와 연결합니다. 변경분 검사·미완료 검사·엔진이나 규칙 변경은 기존 발견사항의 해결 증거가 아닙니다. 심각도와 검증 상태는 별도입니다.

통합 스킬은 기존 결과를 읽는 요청과 새 결과를 생성하는 요청을 구분합니다. 보고서 설명만 요청했다면 저장된 결과의 날짜·범위·판정을 밝히고 읽기만 합니다. 오래된 보고서를 현재 소스의 검사 결과로 바꾸어 설명하지 않습니다. 재검증할 발견 ID나 저장소가 여러 개로 모호하면 필요한 선택만 확인합니다.

필수 `framework` 검사는 SEF public/private/혼합 구성과 다섯 소스 경계를 관찰합니다. `doctor`의 감지는 알려진 제어 파일·빌드 신호의 부분 미리보기이며 정식 검사 완료가 아닙니다. 새 `review-packets.json`은 원본 후보별 주장·찬반 근거·미해결 질문을, `framework-baseline.json`은 현재 기반 관측을 제공합니다. 문맥의 `not_actionable`은 공식 반증이나 자동 삭제가 아닙니다. 이전 framework 후보가 사라져도 독립 검토 전에는 자동 해결하지 않습니다. 지원 범위는 [SEF 점검](docs/SEF-CHECKS.md)을 참고하세요.

## 5. 검토와 예외

`--review-records <records.json>`은 reviews/exceptions 배열을 받습니다. 기록의 id·내용 digest·역할·revision·scope가 외부 정책의 trusted_approvals와 일치해야 효력이 있습니다. 이름만 적은 승인, 만료된 예외, 다른 버전의 기록은 통과 근거가 아닙니다.

검토 결과는 새 run에 적용합니다. source-verified/runtime-verified 승격과 refuted 반증은 각각 허용된 독립 역할과 evidence_refs가 필요합니다. 위험 수용에는 보안 책임자와 프로젝트 책임자 역할이 필요합니다. 자동화가 승인자를 대신하지 않습니다.

일반 SAST 수정 완료는 `decision=fixed-verified`, `validation=source-verified|runtime-verified`와 `reason`, `evidence_refs`, `source_revision`, `scope_hash`, `normalized_result_hash`를 기록합니다. 보호 정책의 `kind=remediation-validation` 승인은 `independent-reviewer`가 필요하고 High/Critical/미분류는 `security-reviewer`도 필요합니다. 상세 형식은 [운영 안내](docs/OPERATIONS.md)를 확인합니다. 사용자 답변이나 `execution_context`의 실행 안내 정보는 이 승인을 대신하지 않습니다.

0.10의 문맥이 붙은 발견을 검토·반증·위험 수용할 때는 현재 `review-packets.json` 또는 `result.json`의 `normalized_result_hash`도 기록에 포함해야 합니다. 이 값은 문맥·분석기·검사 범위에 연결되므로 이전 결과의 hash를 재사용하지 않습니다. 기존 revision·scope·보호된 승인 조건도 함께 적용됩니다.

## 6. 전체 출시·동적 프로파일

```text
python gxsec.py release <source> --profile release --policy <external-policy> --json
```

기본 실행은 계획과 준비 상태를 보고하며 동적 발사를 하지 않습니다. 승인된 정확한 범위와 계정·데이터·버전 증거가 있을 때만 `--execute-dynamic`을 추가합니다. 비밀은 환경변수 참조 또는 `--creds-stdin`으로 공급합니다. argv에 비밀번호·토큰 값을 넣지 않습니다.

외부 실행 허가서를 미리 발급하는 경우 `--execution-id <고유 ID>`를 지정하고 허가서의 run_id와 일치시킵니다. 이 ID가 저장 결과와 모든 동적 엔진에 공통으로 적용됩니다. `retest --run-id`는 이전 실행을 선택하는 옵션이며 새 실행 ID와 구분합니다.

동적 정책·시나리오 구조와 선택 엔진의 실행 조건은 [동적 운영](docs/RUNBOOK-dynamic.md)을 참고하세요. URL 이름이나 사설 IP는 격리 DB의 증거가 아닙니다. 기존 expert 공격 도구의 실행을 새 release 프로파일 완료로 자동 채택하지 않습니다.

## 7. 상태와 자동화

PASS=0, BLOCK=1, INCOMPLETE=2, PASS_WITH_EXCEPTION=3입니다. 일반 셸에서 3은 성공 코드가 아닙니다. 조직 정책으로 유효한 예외를 검증한 CI 어댑터만 조건부 성공으로 처리할 수 있습니다. 취소는 130과 불완전 snapshot을 남깁니다.

보고서는 마스킹된 결과를 공유하기 위한 자료입니다. 공식 출시 증거는 보호된 CI checkout·artifact·정책·승인 기록과 연결해야 합니다.
