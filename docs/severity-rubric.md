# 심각도와 검증 수준

심각도는 악용 조건과 영향으로 산정합니다. 검증 수준·신뢰도·조치 상태와 별도입니다.

| 심각도 | 기준 예시 |
|---|---|
| Critical | 인증/테넌트 경계 전면 우회, 광범위한 코드 실행·민감정보 피해 |
| High | 조건을 갖추면 의미 있는 개인정보/권한/데이터 침해 |
| Medium | 범위가 제한되거나 추가 조건이 필요한 의미 있는 위험 |
| Low/Info | 제한적인 영향 또는 보강·정보성 항목 |

동적 발사를 하지 않았다는 이유로 등급 상한을 두지 않습니다. 소스로 입증한 운영 키 노출도 심각할 수 있습니다. 반대로 2xx·반사·도구 경고만으로 악용을 확정하지 않습니다.

검증 상태는 candidate/source-verified/runtime-verified/refuted/undetermined입니다. High/Critical candidate·undetermined와 severity 미분류는 검토 전 INCOMPLETE입니다. 입증된 High/Critical은 유효한 예외가 없으면 BLOCK입니다.

방어 함수명·권한 어노테이션·STATELESS 설정·canonical 호출만으로 안전을 선언하지 않습니다. 실제 입력→사용 경로와 객체 소유권·출력 문맥·실효 설정을 확인합니다. 반증에는 파일/심벌/근거와 독립 검토가 필요합니다.

같은 근본원인은 묶되 영향받은 위치·endpoint·관측은 보존합니다. 기존 baseline이나 gitignore는 위험 수용 승인이 아닙니다.
