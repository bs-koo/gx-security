# GX Security

## 코드에서 찾고, 실행 근거로 확인하세요.

Spring·JSP 웹 애플리케이션의 취약점 후보를 찾고, 필요한 경우 승인된 로컬·스테이징 환경에서 재현 여부를 확인합니다.
결과는 **취약점 · 발생 원인 · 재현 절차 · 대응 방안**으로 정리합니다.

**Claude Code 플러그인 · 커맨드 3개 · 스킬 17개**

[동작 방식](#어떻게-동작하나요) · [스킬](#스킬-구성) · [설치](#설치하고-시작하기) · [실전 가이드](USAGE.md)

## 어떻게 동작하나요?

**소스 진단 → 코드 문맥 검토 → 선택적 동적 검증 → 보고서**

1. **후보를 찾습니다.** 기술 스택을 식별하고 9개 정적 진단 스킬로 소스를 분석합니다.
2. **코드 문맥을 검토합니다.** Claude가 입력·처리·출력 경로와 보안 설정을 읽어 후보를 검토합니다.
3. **실행으로 확인합니다.** URL·표적 옵션·계정 등 조건이 갖춰진 항목은 대상 범위 확인 후 동적으로 검증합니다.
4. **근거를 남깁니다.** 발견 사항과 재현 근거·대응 방안을 `reports/`에 정리합니다.

### 무엇부터 실행하면 되나요?

| 필요한 작업 | 커맨드 | 입력 |
|---|---|---|
| 소스에서 취약점 후보 찾기 | `/gx-security:gx-diagnose` | 소스 경로 |
| 실행 중인 앱의 후보 검증 | `/gx-security:gx-pentest` | 승인된 대상 URL·표적 옵션 |
| 진단과 검증을 함께 요청 | `/gx-security:gx-audit` | 소스 경로, 선택적 대상 URL |

동적 검증은 승인된 대상과 필요한 입력이 있을 때 수행합니다. 실행하지 못한 항목은 정적 추정·미검증 상태로 구분합니다.
CLI 스캐너의 후보 출력과 Claude 검토를 거친 최종 보고서는 구분해야 합니다.

## 스킬 구성

### 통합 점검 · 1개

[`auditing-web-application-security`](skills/auditing-web-application-security/SKILL.md)가 소스 진단과 선택적 동적 검증을 연결하고 결과를 통합합니다.

### 정적 진단 · 9개

실행 중인 앱 없이 소스 코드와 설정에서 취약점 후보를 찾습니다.

| 스킬 | 확인하는 내용 |
|---|---|
| [`detecting-csrf-vulnerabilities`](skills/detecting-csrf-vulnerabilities/SKILL.md) | CSRF 보호 설정과 상태 변경 요청 |
| [`detecting-xss-vulnerabilities`](skills/detecting-xss-vulnerabilities/SKILL.md) | 출력 경로·이스케이프·DOM XSS |
| [`detecting-sql-injection`](skills/detecting-sql-injection/SKILL.md) | SQL 조립과 파라미터 바인딩 |
| [`detecting-file-upload-vulnerabilities`](skills/detecting-file-upload-vulnerabilities/SKILL.md) | 파일 형식 검증·저장 경로·파일명 처리 |
| [`detecting-path-traversal`](skills/detecting-path-traversal/SKILL.md) | 파일 조회·다운로드의 경로 검증 |
| [`detecting-broken-access-control`](skills/detecting-broken-access-control/SKILL.md) | 객체 소유권과 기능별 접근 권한 |
| [`detecting-auth-session-weaknesses`](skills/detecting-auth-session-weaknesses/SKILL.md) | 인증·세션·JWT·쿠키 설정 |
| [`detecting-sensitive-data-exposure`](skills/detecting-sensitive-data-exposure/SKILL.md) | 자격증명·개인정보·응답과 로그 노출 |
| [`detecting-ssrf-and-open-redirect`](skills/detecting-ssrf-and-open-redirect/SKILL.md) | 외부 요청 URL과 리다이렉트 목적지 |

### 동적 검증 · 7개

대상 범위를 확인한 뒤 요청·응답과 실행 결과를 관찰합니다. Burp 연계 스킬은 기존 검증을 심화하는 역할입니다.

| 스킬 | 확인하는 내용 |
|---|---|
| [`exploiting-sql-injection`](skills/exploiting-sql-injection/SKILL.md) | 응답·조건·시간 차이로 SQLi 후보 검증 |
| [`exploiting-xss-vulnerabilities`](skills/exploiting-xss-vulnerabilities/SKILL.md) | 마커 반사와 브라우저 실행을 구분해 확인 |
| [`exploiting-broken-access-control`](skills/exploiting-broken-access-control/SKILL.md) | 역할·소유자별 접근 결과 비교 |
| [`exploiting-auth-session`](skills/exploiting-auth-session/SKILL.md) | 토큰·로그아웃·쿠키 동작 확인 |
| [`exploiting-ssrf-and-open-redirect`](skills/exploiting-ssrf-and-open-redirect/SKILL.md) | 콜백 수신과 리다이렉트 응답 확인 |
| [`exploiting-path-traversal-upload`](skills/exploiting-path-traversal-upload/SKILL.md) | 경로 탐색·업로드 후보 검증 |
| [`exploiting-with-burp`](skills/exploiting-with-burp/SKILL.md) | Burp Suite MCP·프록시 연계 검증 |

## 설치하고 시작하기

Claude Code에서 설치합니다.

```text
/plugin marketplace add bs-koo/gx-security
/plugin install gx-security@gx-security
```

프로젝트 소스를 지정해 정적 진단부터 시작할 수 있습니다.

```text
/gx-security:gx-diagnose ./my-app
```

소스와 승인된 로컬 앱을 함께 제공하면 통합 점검을 요청할 수 있습니다.

```text
/gx-security:gx-audit ./my-app http://localhost:8080
```

동적 검증에는 항목별 URL·파라미터·테스트 계정 등의 추가 입력이 필요합니다.
자세한 조합은 [사용 가이드](USAGE.md)를 참고하세요.

CLI로 정적 후보를 수집할 수도 있습니다.

```bash
python scan_all.py ./my-app
```

정적 스캔은 Semgrep을 우선 사용하며 없으면 기본 스캐너로 동작합니다. 진단 범위와 결과가 달라질 수 있으므로
[설치·Windows 실행 안내](REFERENCE.md#정적-정밀도-표준-권장)를 확인하세요.

## 사용 전 알아둘 점

- 동적 검증은 권한 있는 보안 테스트에 사용합니다. `scope_guard`가 허용 범위를 검사하며, 데이터 변경 작업은 별도 허용과 사람 승인이 필요합니다.
- 엔드포인트를 자동 수집하지 않습니다. URL·파라미터 등 표적을 직접 제공해야 합니다.
- JSON 본문 주입은 SQLi만 지원하며, 다른 동적 검증은 GET·form 요청을 사용합니다.
- 결과에는 오탐·미탐이 있을 수 있습니다. 미검증 항목이나 콜백 미수신을 안전 판정으로 해석하지 않습니다.
- 보고서와 증적은 민감정보를 포함할 수 있어 기본 형상관리 대상에서 제외합니다.

## 더 알아보기

| 문서 | 내용 |
|---|---|
| [실전 사용 가이드](USAGE.md) | 옵션·시나리오·동적 검증 조건·FAQ |
| [실행 참고서](REFERENCE.md) | 설치 환경·커맨드별 상세 동작·지원 범위·설정·테스트 |
| [안전 수칙](ATTACK_SAFETY.md) | 대상 범위와 자격증명 취급 |
| [운영 정책](docs/OPERATIONS.md) | 스테이징 등록·격리 환경 관리 |
| [동적 점검 런북](docs/RUNBOOK-dynamic.md) | 계정 입력·로그인·항목별 검증 절차 |
| [심각도 기준](docs/severity-rubric.md) | Critical·High·Medium·Low 판정 |
| [변경 이력](CHANGELOG.md) | 버전별 변경 사항 |

<sub>Proprietary · GX 사업본부 사내용 · v0.8.2</sub>
