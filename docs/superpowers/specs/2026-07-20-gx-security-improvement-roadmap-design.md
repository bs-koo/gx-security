# gx-security 개선 통합 로드맵 — 설계

- **작성일**: 2026-07-20
- **전략**: A — 도입 우선 (정적을 먼저 사업부 공통 배포 → 동적을 안전장치 뒤 파일럿 → 커버리지 확대 → 신뢰·조직)
- **입력 자료**: [docs/AUDIT-REPORT-2026-07-20.md](../../AUDIT-REPORT-2026-07-20.md) (전수조사 보고서)
- **범위**: 코드·도구 + 운영 정책 + 조직 과제 전부
- **산출물 성격**: 마스터 로드맵. 각 Phase는 독립 릴리스이며, 큰 작업 단위는 착수 시 개별 스펙(`YYYY-MM-DD-<topic>-design.md`)으로 승격한다.

---

## 1. 배경·목표

전수조사 결론: **정적 진단은 지금 사업부 공통 도입이 가능**하나(단 semgrep 설치 표준화 전제), **동적 침투는 조건부**다(자격증명 평문노출·로그인 프리셋 하드코딩·JSON 바디 주입 불가 등). 본 로드맵은 이 격차를 **도입을 막는 것부터** 순차 해소해 gx-security를 사업부 공통 도구로 정착시킨다.

## 2. 설계 원칙

1. **정적 먼저**: 읽기전용이라 리스크가 최소인 정적 진단을 먼저 배포한다.
2. **동적은 안전장치 뒤**: 자격증명·프리셋 이식성을 갖춘 뒤에야 격리 호스트에서 파일럿한다.
3. **Phase = 독립 릴리스**: 각 Phase는 그 자체로 배포 가능한 응집된 가치 묶음.
4. **YAGNI**: 대형 항목(크롤링·taint)은 백로그로 분리 — 도입에 불필요.
5. **운영·조직 과제는 각 Phase에 분산** — 코드 개선과 함께 굴러가게.
6. **회귀 불변**: 기존 335 테스트 green을 모든 변경에서 유지한다(수용 기준의 공통 전제).

## 3. 로드맵 개요

| Phase | 릴리스 | 목표 | 작업 단위 |
|---|---|---|---|
| **P1 배포 게이트** | v0.4.0 | 정적 진단을 사업부 공통 배포 | S1 semgrep 설치 표준화 · S2 Windows semgrep CI · O1 운영정책 문서 · O3 버전/CHANGELOG 규율 |
| **P2 동적 파일럿** | v0.5.0 | 동적을 격리 호스트에서 안전 운영 | D1 자격증명 env/stdin · D2 로그인 프리셋 이식성 · O2 동적 런북 |
| **P3 커버리지** | v0.6.0 | 최신 스택(JSON REST) 탐지 확대 | D4 JSON 바디 주입 · D3 SQLi/XSS 인증 지원 · D6 jsp-legacy 접근통제 표적 |
| **P4 신뢰·조직** | v0.7.0 | 신뢰성·지속가능성 | V1 실앱 E2E · V2 검증 공백 5건 · S3 룰 이식성 · S4 scan_all 병렬화 · O4 버스팩터 · O5 리포트 중앙화 |
| **백로그** | 미정 | 대형/선택 | D7 크롤링 · S6 taint 룰 · D5 canary 원격 · D8 동적판정 검증 보강 · S5 잔여 폴백 테스트 |

**의존 순서**: P1 → P2 → P3 → P4. 조직 항목(O4/O5)은 앞 Phase와 병행 가능.
**노력 표기**: S(≈1일) · M(2~4일) · L(1주+).

---

## 4. 작업 단위 상세

### Phase 1 — 배포 게이트 (v0.4.0)

#### S1. semgrep 설치 표준화 — 노력 S
- **문제**: semgrep이 선택 설치라 미설치 시 grep 폴백(recall↓)이 실질 운영 경로가 된다. 표준 실행 환경조차 semgrep이 없어 "0건=안전" 오독 위험이 실재했다(전수조사 §4).
- **해결**: (a) `requirements-dev.txt`(또는 `pyproject` optional-deps)에 `semgrep==1.95.0` 핀 추가, (b) `scripts/install.(sh|ps1)` 또는 README에 원클릭 설치 절차, (c) `scan_all.py`/각 스캐너가 semgrep 부재 시 출력하는 경고를 **도입 문서에서 필수 설치로 승격**.
- **수용 기준**: 문서/스크립트로 semgrep 설치가 원클릭 · README "설치"에 semgrep을 표준 요건으로 명시 · 미설치 시 경고 문구 유지 확인.
- **영향**: `README.md`, `USAGE.md`, 신규 `requirements-dev.txt`/`scripts/install.*`.

#### S2. Windows semgrep CI — 노력 S~M
- **문제**: `semgrep-tests` 잡이 `ubuntu-latest` 전용이라 **Windows에서 semgrep 실탐지 정확도가 CI로 한 번도 검증되지 않는다**. 도입 환경이 Windows이므로 사각지대(전수조사 §3.3 공백 1).
- **해결**: `.github/workflows/ci.yml`의 `semgrep-tests` 잡에 `windows-latest` 매트릭스 추가. semgrep Windows 설치가 불안정하면 **폴백 방침**: Windows는 골든셋 semgrep 잡을 best-effort(비차단)로 두되 최소 1회 실행 로그를 남긴다.
- **수용 기준**: CI에서 Windows semgrep 골든셋이 실행됨(green 또는 문서화된 비차단) · 결과가 Actions 로그에 관측 가능.
- **영향**: `.github/workflows/ci.yml`.

#### O1. 운영정책 문서 — 노력 S
- **문제**: 자격증명 취급·`ALLOW_HOSTS` 등록·격리 호스트 원칙이 팀 규정으로 명문화되어 있지 않다(도구는 문서 권고에만 의존).
- **해결**: `docs/OPERATIONS.md` 신설(또는 `ATTACK_SAFETY.md` 확장) — 사내 스테이징 `SECURITY_PLUGIN_ALLOW_HOSTS` 등록 절차, 전용 테스트 계정·격리 호스트 규정, `ALLOW_PRIVATE` 정책 결정 가이드.
- **수용 기준**: 운영자가 문서만 보고 스테이징을 안전 범위에 등록하고 동적 점검을 규정대로 수행할 수 있다.
- **영향**: `docs/OPERATIONS.md`.

#### O3. 버전/CHANGELOG 규율 — 노력 S
- **문제**: v0.3.0 태그 이후 결함수정 5건(F3~Gemini 리뷰)이 CHANGELOG·버전에 미반영 — 성숙도가 과소 표기된다(전수조사 §4 부록 A).
- **해결**: CHANGELOG에 0.3.0 이후 변경 소급 정리 + `v0.4.0` 항목 신설, `plugin.json`/`marketplace.json` 버전 bump, 릴리스 체크리스트 문서화.
- **수용 기준**: CHANGELOG가 실제 코드 상태를 반영 · 버전 표기가 3개 파일에서 일치 · 릴리스 절차 문서 존재.
- **영향**: `CHANGELOG.md`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`.

**P1 완료(릴리스 게이트)**: semgrep CI가 Win+Linux에서 실행 · 설치 원클릭 · 운영정책 문서화 · CHANGELOG 최신화 · 기존 테스트 green.

### Phase 2 — 동적 파일럿 (v0.5.0)

#### D1. 자격증명 env/stdin 입력 — 노력 M
- **문제**: `--token-a`/`--user-a-pw` 등이 프로세스 목록·셸 히스토리에 평문 노출된다. `ATTACK_SAFETY.md`가 스스로 "미해결"로 인정 · env/stdin 미지원.
- **해결**: 6개 `attack_*.py`(+ `dyn_session`)에 자격증명 입력 경로 추가 — `--token-a-env <VAR>`(환경변수 이름 참조) 및 `--creds-stdin`(stdin JSON). 기존 CLI 인자는 하위호환 유지하되 사용 시 경고.
- **수용 기준**: env/stdin 경로로 넘긴 토큰·비밀번호가 프로세스 인자에 나타나지 않음(테스트로 확인) · 기존 인자 경로 회귀 없음.
- **영향**: `tools/dyn_session.py`, `skills/exploiting-*/scripts/attack_*.py`(6), `ATTACK_SAFETY.md`.

#### D2. 로그인 프리셋 이식성 — 노력 M
- **문제**: 로그인 바디(`lgnId/password`)·경로(`/api/v1/auth/login`)·토큰 경로(`data.accessToken`)가 sef-2026 하드코딩 — 타 프로젝트는 4종 동적이 `static-only`로 주저앉는다.
- **해결**: 로그인 프로파일을 설정 파일/프리셋으로 외부화 — `--login-profile <name|path>`가 `login-path`·`body-template`·`token-path`·`id-field`/`pw-field`·`auth-mode`를 묶어 로드. 저장소에 `sef-2026`/`jsp-form` 등 기본 프로파일 동봉.
- **수용 기준**: 비-sef 프로젝트를 프로파일 지정만으로 로그인 성공 · 기본값은 기존 동작과 동일(회귀 없음).
- **영향**: `tools/dyn_session.py`, `skills/exploiting-*/scripts/attack_*.py`, `audit.py`, 신규 `profiles/`.

#### O2. 동적 런북 — 노력 S
- **문제**: 동적 발동 조건(계정×표적 옵션 조합)이 복잡해 실침투 인원에게 학습곡선이 크다.
- **해결**: `docs/RUNBOOK-dynamic.md` — 스택별(Spring/JSP) 시나리오, 옵션 조합 표, 판정 해석, 정리(leftover 삭제) 절차.
- **수용 기준**: 신규 운영자가 런북만 보고 표준 동적 점검 1사이클을 수행할 수 있다.
- **영향**: `docs/RUNBOOK-dynamic.md`.

**P2 완료**: 자격증명 비노출 입력 경로 · 프로파일로 비-sef 로그인 성공 · 런북 완비 · 테스트 green.

### Phase 3 — 커버리지 (v0.6.0)

#### D4. JSON 바디 주입 — 노력 L
- **문제**: 동적 엔진이 GET·form-urlencoded만 지원, `application/json` 바디 주입 불가. 사업부 최신 스택(sef-2026 JWT+JSON REST)에서 동적 활용도가 제한되는 핵심 모순.
- **해결**: 주입 계층에 JSON 모드 추가 — `--content-type json` + JSON 포인터(예 `--inject-path $.query`)로 지정 경로에 페이로드 주입. 우선 SQLi·XSS부터, 이후 공용화. **범위 관리**: 임의 스키마 자동탐색은 백로그(D7 계열), 최소 스펙은 "지정 경로 주입".
- **수용 기준**: JSON REST 엔드포인트 대상 SQLi/XSS 페이로드 주입·반사/지연 확정 · 착수 시 개별 스펙으로 승격.
- **영향**: `attack_sqli.py`, `attack_xss.py`, `tools/dyn_session.py`, `audit.py`.

#### D3. SQLi/XSS 인증 지원 — 노력 M~L
- **문제**: SQLi·XSS 공격 스크립트가 `dyn_session`을 쓰지 않아 로그인 뒤 화면을 못 본다(인증 미지원).
- **해결**: `attack_sqli.py`·`attack_xss.py`를 `dyn_session`에 통합해 bearer/cookie 세션을 주입 요청에 부착. `--auth-mode`·프로파일(D2) 공유.
- **수용 기준**: 인증 필요한 엔드포인트에 세션을 얹어 발사·확정 · 비인증 경로 회귀 없음.
- **영향**: `attack_sqli.py`, `attack_xss.py`.
- **의존**: D1·D2(세션·프로파일 기반).

#### D6. jsp-legacy 접근통제 표적 추출 — 노력 M
- **문제**: `attack_access.py`의 표적 추출 정규식이 Spring `@Mapping` 전용이라 jsp-legacy 스택은 접근통제 동적 표적이 아예 안 뽑힌다.
- **해결**: jsp/서블릿 URL 매핑(`web.xml` `<servlet-mapping>`, `.do`/`.jsp` 경로, `@WebServlet`) 추출기 추가.
- **수용 기준**: jsp-legacy 픽스처에서 접근통제 동적 표적이 1건 이상 추출됨.
- **영향**: `attack_access.py`, 관련 fixtures.

**P3 완료**: JSON 대상 SQLi/XSS 확정 · 인증 뒤 화면 발사 · jsp 표적 추출 · 테스트 green.

### Phase 4 — 신뢰·조직 (v0.7.0)

#### V1. 실앱 E2E — 노력 L
- **문제**: 실제 취약 웹앱 대상 E2E가 전무하다. 모든 동적 테스트가 mock 판정 로직 단위테스트(전수조사 §3.3 공백 2).
- **해결**: 최소 취약 테스트앱(Spring 또는 JSP, docker-compose)을 만들거나 채택해 "로그인→토큰→발사→확정" 파이프라인 1개 이상 실서버 스모크. CI에서는 선택 잡(수동/nightly).
- **수용 기준**: 취약앱 대상 E2E 스모크 1개 이상 통과 · 재현 가능한 기동 절차 문서.
- **영향**: 신규 `tests/e2e/`, `docker-compose.yml`.

#### V2. 검증 공백 5건 — 노력 M
- **문제**: partial 판정·auth scope_blocked·SQLi/XSS 로직·scan_pathtraversal 폴백·vacuous 골든셋 테스트가 미검증/무효(전수조사 §3.3).
- **해결**: 5건 각각 테스트 추가·실질화 — audit `partial` 케이스, auth `scope_blocked`, `attack_sqli`/`attack_xss` 핵심 경로 + scope 배선, `scan_pathtraversal` 폴백 전용 테스트, FR-4/FR-7 vacuous 어서션을 실측 기대값으로 교체.
- **수용 기준**: 5건 모두 회귀를 실제로 잡는 어서션 보유.
- **영향**: `tests/test_audit.py`, `tests/test_attack_sqli_*.py`, `tests/test_attack_xss.py`, 신규 `tests/test_scan_pathtraversal_fallback.py`, `tests/test_scanner_goldenset.py`.

#### S3. 룰 이식성 — 노력 M
- **문제**: file-upload 등 룰이 sef-2026/Gseed 실제 헬퍼 메서드명을 하드코딩해 신규 프로젝트에서 오탐 급증 위험.
- **해결**: 검증 헬퍼 allowlist를 프로젝트별 설정(`gxsec.config`/YAML)로 외부화하고 룰은 설정 참조. 기본값은 현행 유지.
- **수용 기준**: 헬퍼명이 다른 신규 프로젝트에서 설정만으로 오탐 억제 · 기존 골든셋 green.
- **영향**: `skills/detecting-file-upload-vulnerabilities/rules/*.yml`, 스캐너 설정 로딩.

#### S4. scan_all 병렬화 — 노력 S~M
- **문제**: 9개 스캐너 순차 실행 + 파일트리 9번 중복 순회로 대형 리포에서 벽시계 시간이 선형 누적.
- **해결**: `concurrent.futures`로 스캐너 병렬 실행. 출력 스키마·경고 집계 불변.
- **수용 기준**: 대형 대상에서 실행 시간 단축 · 결과가 순차 실행과 동일(결정론).
- **영향**: `scan_all.py`.

#### O4. 버스팩터 해소 — 노력 S(문서·프로세스)
- **문제**: 전 커밋이 단일 작성자(bs-koo) — 사업부 공통 도구로 확산 시 유지보수 리스크.
- **해결**: `CODEOWNERS` + 2인 리뷰 규율, 기여 가이드(`CONTRIBUTING.md`), 아키텍처 개요 문서로 인수인계성 확보.
- **수용 기준**: 최소 2인이 리뷰 권한 · 신규 기여자가 문서로 온보딩 가능.
- **영향**: `.github/CODEOWNERS`, `CONTRIBUTING.md`, `docs/`.

#### O5. 리포트 중앙화 — 노력 S~M
- **문제**: `reports/`가 gitignore라 점검 결과가 로컬에만 산재 — 중앙 이력관리·티켓 연동 없음.
- **해결**: 점검 리포트 중앙 보관 방안 결정(별도 저장소/티켓 첨부/사내 위키 연동) + 익스포트 절차.
- **수용 기준**: 점검 결과를 팀이 조회 가능한 중앙 위치에 남기는 절차 확립.
- **영향**: 운영 프로세스 문서, (선택) 익스포트 스크립트.

**P4 완료**: 취약앱 E2E 스모크 통과 · 검증 공백 5건 실질화 · 룰 설정 외부화 · 병렬화 · 2인 리뷰 체계.

### 백로그 (개별 스펙 승격 대상)
- **D7 크롤링/엔드포인트 자동탐색** (L) — 표적 수동지정 한계 해소.
- **S6 taint 분석 룰** (L) — 함수·파일 경계 넘는 데이터흐름.
- **D5 canary 원격 지원** (M) — 원격 스테이징 블라인드 SSRF 확정(현재 127.0.0.1 고정).
- **D8 동적판정 검증 보강** (M) — U2-Q1(time-based baseline) 등 이월 항목.
- **S5 잔여 폴백 테스트** (S) — 케이스 2건뿐인 스캐너 보강.

---

## 5. 리스크·완화

| 리스크 | 영향 | 완화 |
|---|---|---|
| S2 Windows semgrep 설치 불안정 | CI green 실패 | Windows는 비차단(best-effort) 관측으로 격하, Linux는 하드 게이트 유지 |
| D4 JSON 주입 범위 팽창 | P3 지연 | 최소 스펙(지정 경로 주입)으로 착수, 자동 스키마 탐색은 백로그 |
| D1 자격증명 경로가 6개 스크립트에 분산 | 일관성 결여 | `dyn_session`에 공용 로더 두고 각 스크립트는 위임 |
| Phase 순차 의존 | 앞 Phase 지연이 파급 | 조직 항목(O4/O5)·V2는 병행 착수로 유휴 흡수 |
| 회귀 | 기존 335 테스트 파괴 | 모든 작업 단위 수용 기준에 "기존 테스트 green" 공통 포함 |

## 6. 릴리스 계획

| 릴리스 | 포함 | semver 근거 |
|---|---|---|
| v0.4.0 | P1 | 배포 요건·CI 강화(기능 추가) |
| v0.5.0 | P2 | 동적 안전 입력·프로파일(기능 추가) |
| v0.6.0 | P3 | JSON·인증·jsp 표적(기능 추가) |
| v0.7.0 | P4 | E2E·검증·조직(기능+품질) |

## 7. 열린 결정사항 (문서화된 기본값 — 필요 시 변경)

1. **실행 주체**: 단독 작성자(버스팩터 1) 현실 반영 — 순차 Phase, O4로 2인 체계 조기 착수 권장. (팀 배분 가능하면 전략 C로 재편)
2. **S2 Windows semgrep**: 설치 불안정 시 비차단 관측으로 격하(위 리스크표).
3. **O5 중앙화 방식**: 별도 저장소/티켓/위키 중 택1은 P4 착수 시 결정.

## 8. 다음 단계

이 설계 승인 후 **writing-plans 스킬**로 P1(v0.4.0)의 상세 구현 계획을 먼저 작성한다. 이후 각 Phase는 착수 시점에 개별 plan으로 잇는다.
