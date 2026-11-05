# 동적 점검 운영 절차 0.9.0

## 준비

1. 실제 source와 배포 revision을 일치시킵니다. source는 clean checkout이어야 합니다.
2. source 밖의 보호된 policy에 exact origin,paths,allowed_ips를 설정합니다.
3. readiness에는 status=verified,synthetic_data=true,isolated=true,source_revision,deployment_revision,expires_at,evidence_ref를 둡니다.
4. auth.identities는 사용자별 secret_ref와 expected_id를,auth.verification은 보호된 identity endpoint와 JSON 필드를 가리킵니다.
5. scenarios는 A 소유 resource를 B/익명으로 조회하는 GET·유일한 fixture nonce·명시적 거부 oracle을 정의합니다.

## 정책 예시의 구조

```yaml
dynamic:
  enabled: true
  target:
    origin: http://127.0.0.1:18080
    paths: [/me, /boards/test-fixture]
    allowed_ips: [127.0.0.1]
  readiness:
    status: verified
    synthetic_data: true
    isolated: true
    source_revision: <clean-source-revision>
    deployment_revision: <same-revision>
    expires_at: <UTC-ISO-time>
    evidence_ref: <protected-readiness-record>
  auth:
    verification: {path: /me, identity_field: '$.id'}
    identities:
      a: {secret_ref: GXSEC_A, expected_id: A}
      b: {secret_ref: GXSEC_B, expected_id: B}
  scenarios:
    - id: board-owner-read
      kind: authorization
      path: /boards/test-fixture
      method: GET
      owner: a
      subject: b
      oracle:
        json_pointer: /nonce
        expected: <unique-fixture-nonce>
  budgets: {max_requests: 50, max_duration_seconds: 60, requests_per_second: 2}
```

값은 형식 예시입니다. secret_ref 환경변수의 내용은 token 또는 cookies 객체를 가진 JSON이며 값을 대화나 버전 관리 파일에 적지 않습니다. source 안의 정책은 신뢰하지 않습니다. 정확한 시나리오 분모는 보호된 정책이 소유합니다.

## 실행과 확인

```text
python gxsec.py release <source> --profile release --policy <external-policy> --json
python gxsec.py release <source> --profile release --policy <external-policy> --execute-dynamic --json
```

첫 실행은 계획/준비 상태만 만듭니다. 두 번째는 이미 허용된 범위에 한해 실행합니다. A와 B의 기대 identity를 전후로 검증하며 A의 정상 resource nonce가 확인돼야 교차 응답을 판정합니다. 200 오류 wrapper·로그인 화면·다른 자기 정보는 성공 데이터가 아닙니다.

## ZAP·브라우저 선택 경로

scripts/gxsec-confined-runner.py를 보호된 source 밖 실행 위치에 설치하고 실제 engine·runner 파일의 SHA256/version을 고정합니다. 정책 dynamic.zap/browser에는 required,version,digest,executable,runner.path,runner.sha256,bundle,broker,confinement를 설정합니다.

confinement record는 id,status=verified,origin,paths,allowed_ips,source_revision,engine_digest,runner_digest,bundle_digest,broker,broker_evidence_refs,firewall_evidence_refs,expires_at을 포함합니다. 상위 trusted_approvals가 해당 기록의 canonical digest와 network-confinement 종류,protected-ci+security-owner 역할을 승인해야 합니다. readiness와 confinement 만료는 전체 예정 실행 기한 이후여야 하며 결과 수락 직전에도 다시 확인합니다.

bundle은 Python 실행 파일과 gxsec·PyYAML의 전체 패키지 파일, 브라우저 사용 시 Playwright의 Node 드라이버·JavaScript·데이터 파일까지 포함합니다. ZAP은 아래처럼 ZAP 설치 전체와 Java 설치 전체도 고정합니다. core JAR, lib JAR, add-on archive, template, Java executable·native library·module image 중 하나라도 manifest에서 빠지거나 내용이 바뀌면 실행하지 않습니다. 파일과 설치 경로는 source 밖의 절대 경로이며 심볼릭 링크·junction을 포함하지 않아야 합니다.

```yaml
bundle:
  immutable: true
  runtime_evidence_ref: protected-ci/runtime-build-record
  zap_runtime:
    zap_root: /opt/gxsec/zap
    java_home: /opt/gxsec/java
    java_executable: /opt/gxsec/java/bin/java
  files:
    /opt/gxsec/zap/zap.sh: <sha256>
    /opt/gxsec/zap/zap-<version>.jar: <sha256>
    /opt/gxsec/java/bin/java: <sha256>
    # ZAP·Java 설치 전체 및 interpreter·Python 패키지의 모든 파일을 기재
  digest: <runtime_bundle_digest(bundle)>
```

`gxsec.dynamic.runtime_bundle_digest`는 digest 필드 자체를 제외한 bundle 전체의 canonical hash를 계산합니다. files뿐 아니라 runtime_evidence_ref, 설치 경로, immutable 값도 승인 digest에 묶입니다. manifest는 설치 트리 밖에 보관합니다. parent와 reference runner가 실제 설치 파일을 실행 직전에 다시 해시하고 ZAP launcher가 승인된 zap_root 안에 있는지 확인합니다. runner는 승인된 JAVA_HOME/JRE_HOME과 Java bin 우선 경로를 사용하며, 버전 조회와 scan 모두 임시 `-dir`을 지정해 사용자 홈의 add-on·template·설정이 추가되지 않도록 합니다.

broker에는 lease_path,receipt_path,claim_dir,key_ref를 지정하고 같은 객체를 confinement.broker에 둡니다. 보호된 parent만 key_ref 환경변수의 검증 키를 읽으며 이 키는 runner/engine에 전달하지 않습니다. 보호된 broker가 발급한 HMAC-SHA256 `enforcing-network-lease`가 실행 전에 필요합니다. lease는 run_id, scope/source/engine/bundle digest, 전체 process tree의 제한과 만료를 묶고 한 번만 소비됩니다.

실행 후에는 같은 broker의 인증된 `network-execution-receipt`가 실제 인증 신원·관측 경로·native job 증거와 process tree 전체의 요청 수·응답 바이트·속도·동시성·실행 시간을 plan/result digest에 묶어야 합니다. child가 복사한 경로 목록이나 빈 ZAP report는 완료 증거가 아닙니다. 직접 HTTP와 각 engine은 남은 전체 예산만 공유하며, receipt가 없거나 검증에 실패한 실행 뒤에는 남은 불명확 예산을 재사용하지 않습니다. broker를 제공하지 않는 환경은 선택 engine을 unsupported로 남깁니다.

실행기는 이미 격리된 호스트에서 --gxsec-plan/--gxsec-result 프로토콜로 동작합니다. 자체적으로 broker/firewall을 설치하지 않습니다. ZAP은 허용 요청·passive 분석, 브라우저는 반사 nonce 검증만 수행합니다. 실제 ZAP·Chromium과 외부 방화벽/프로세스 수명 제어는 조직 환경에서 별도로 시험해야 합니다.

## 미지원과 중단

기본 출시 시나리오의 쓰기·업로드 정리·원격 canary는 미지원입니다. 기존 전문가용 attack 도구의 결과를 자동으로 새 release 완료로 옮기지 않습니다. 인증 상실·예산 소진·불명확 oracle·정리 실패는 incomplete/partial입니다. 기본 안전 설정을 끄고 재시도하지 않습니다.

전문가용 Burp 프록시도 TLS 검증을 유지합니다. 별도 CA는 SECURITY_PLUGIN_BURP_CA로 로컬 신뢰 번들을 지정하며 verify=False를 표준으로 사용하지 않습니다.
