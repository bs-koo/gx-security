# gx-security 전수조사 보고서

- **대상**: `D:\SQ\security-plugin` (gx-security **v0.3.0**)
- **작성일**: 2026-07-20
- **조사 범위**: 커맨드 3 · 스킬 16 · 파이썬 스크립트 20 · Semgrep 룰 9 · 테스트 28파일(335 케이스) 전수
- **방법**: 4개 영역 병렬 코드리뷰(정적·동적·검증·문서/이력) + **직접 실행 실측**(테스트 스위트·안전게이트·스캐너 실발사)

> 본 문서는 gx-security 플러그인 자체에 대한 **메타 평가**다. 점검 대상 앱의 취약점 리포트(`reports/`)와는 별개다.

---

## 종합 판정

| 기능 | 사업부 공통 도입 | 근거 |
|---|---|---|
| **정적 진단 `gx-diagnose`** | ✅ **지금 가능** | 읽기전용(완전 안전), 테스트 335건 green, AI 검증으로 오탐 제거. **단 semgrep 설치 표준화 전제** |
| **동적 침투 `gx-pentest`·`gx-audit`** | ⚠️ **조건부** | 안전게이트는 견고하나 자격증명 평문노출·로그인 프리셋 하드코딩·JSON 바디 주입 불가로 최신 스택 활용 제한 |

**최대 실무 리스크**: semgrep 미설치 시 동작하는 **grep 폴백** — recall이 낮고, 과거 룰 전역이 파탄난 이력이 있으며, 표준 실행 환경조차 semgrep이 없다.

---

## 1. 구성 — 무엇으로 이루어져 있나

커맨드 3개가 스킬 16개(스크립트 20개)를 오케스트레이션하는 SAST+DAST 하이브리드.

| 커맨드 | 담당 | 사용 스킬 | 진입 스크립트 | 안전성 |
|---|---|---|---|---|
| `gx-diagnose <소스>` | 정적 진단(SAST) | `detecting-*` 9종 | `scan_all.py` | 완전 안전(소스 읽기전용) |
| `gx-pentest <URL>` | 동적 침투(DAST) | `exploiting-*` 6종 | `attack_*.py` | scope_guard 통과 대상만 |
| `gx-audit <소스> [URL]` | 통합(정적→동적) | `auditing-*` 1종 | `audit.py` | URL 없으면 정적만(안전) |

**취약점 커버리지** — OWASP 핵심 9종 정적 진단, 그중 6종 동적 침투:

| 취약점 | SQLi | XSS | 접근통제 | 인증/세션/JWT | SSRF/리다이렉트 | 경로조작/업로드 | CSRF | 민감정보 |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| 정적 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 동적 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 정적전용 | 정적전용 |

**공용 인프라**: `tools/scope_guard.py`(안전게이트) · `tools/dyn_session.py`(로그인·세션) · `oob_canary.py`(SSRF 콜백)

---

## 2. 어떻게 동작하는가

모든 커맨드가 **감지 → 스캔/발사 → AI 검증 → 4요소 리포트** 파이프라인 공유.

### 2.1 스택 자동 감지
- `build.gradle`·`pom.xml` → **spring-modern**, `WEB-INF/web.xml`·`*.jsp` → **jsp-legacy**.
- **파일명만 보고 내용은 파싱하지 않음**(의도된 설계, `test_stack_pom.py` "BR-4"). → Maven 레거시가 spring으로 과다 분류될 수 있음.
- **결정적 사실**: 감지된 스택은 룰 실행을 거의 게이팅하지 않는다(룰은 파일 확장자로만 필터). "스택별 룰 분기"는 대체로 표시 라벨 수준.

### 2.2 정적 진단(gx-diagnose)
- **이중 엔진**: `semgrep`(AST 기반, 룰 총 82개) 우선, 없으면 `grep 폴백`(라인 정규식, 스캐너당 4~14패턴). **폴백은 조건부 로직을 표현 못 함**(예: 업로드 "검증 헬퍼 선행 없을 때만"을 폴백은 판단 불가 → `transferTo()` 전량 후보화).
- **후보 생성기이지 판정 엔진이 아님**: semgrep 룰 82개 중 `confidence:high` 8개뿐, **90%가 스스로 `needs-context`** 선언. 폴백은 사실상 전량 `needs-context`.
- **심각도는 스캐너가 매기지 않음**: YAML `severity`는 JSON 산출물에 전파되지 않고 버려지며, Critical~Low 등급은 **AI 검증 단계**에서 `docs/severity-rubric.md`로 부여. CLI 단독 출력은 "1차 후보(오탐 포함)".

### 2.3 동적 침투(gx-pentest)
6종 모두 발사 전 `scope_guard` 통과 강제(fail-closed), 기본 비파괴.

| 공격 | 발사 | 악용 확정 근거 | 파괴성 |
|---|---|---|---|
| SQLi | `--param`에 Error→Boolean→Time 순차 | DB오류 정규식 / 길이차 / 2초 지연 재현. sqlmap 우선, 없으면 수동PoC | 비파괴(SELECT) |
| XSS | `--param`에 7종 컨텍스트 페이로드 | 마커가 HTML엔티티 아닌 원문 반사 + (저장형·DOM은) Playwright 브라우저 실행 | 비파괴 |
| 접근통제 | 무토큰 vs 토큰 대조 | 일반토큰 2xx **AND** 무토큰 non-2xx. 403이면 즉시 오탐 확정 | 비파괴(GET) |
| 인증/JWT | JWT 4변형(alg=none·서명제거·역할·만료) 재발사 | 변조토큰 2xx=취약. 무상태 JWT 재사용은 "미확정" 처리 | 비파괴 |
| SSRF/리다이렉트 | OOB canary URL 주입 / evil.test 리다이렉트 | **콜백 수신** 시 SSRF 확정, `Location` 외부호스트면 리다이렉트 확정 | 비파괴(GET) |
| 경로조작/업로드 | `../`×인코딩×깊이 / `.jsp` 무해마커 | 응답에 파일 시그니처(`root:.*:0:0:` 등) / 업로드 2xx+회수성공 | 업로드만 파괴적 |

### 2.4 통합(gx-audit) — 발사조건 매트릭스
`audit.py`는 **표적 옵션 + 테스트 계정이 모두 주어진 조합에서만** 동적 발사, 3단계 라벨링.

| 클래스 | 발사 조건 | 판정 |
|---|---|---|
| 인증/JWT | 계정+`--probe` 모두 | **dynamic** / 계정만·probe없음 → **partial**(쿠키만) / 계정없음 → **static-only** |
| 접근통제·SSRF·경로조작 | 각 표적옵션+계정 모두 | 발사 성공 **dynamic** / 아니면 **static-only** |
| 업로드 | +`--allow-destructive` (audit·스크립트 이중 게이트) | 없으면 발사 자체 안 함 |
| **SQLi·XSS** | `--params`만 | **계정 개념 없어 3단계 미적용** — 로그인 뒤 화면 발사 불가 |

### 2.5 안전게이트(scope_guard) — 직접 실측 결과
`prod`/`www`/공인/사설망/IP위장을 fail-closed 차단. 10개 대상 실발사 검증:

| 대상 | 판정 | 대상 | 판정 |
|---|---|---|---|
| `localhost`, `app.test` | ALLOW | `2130706433`·`0x7f000001`(정수/16진 위장) | ALLOW(loopback 간파) |
| `prod-api…`, `www.…` | 차단 | `169.254.169.254`(클라우드 메타데이터) | 차단 |
| `10.0.0.5`(사설)·`8.8.8.8`(공인) | 권한필요 | 파싱 실패 | deny 수렴 |

공인 대상은 `--authorized` 플래그 **AND** `SECURITY_PLUGIN_AUTHORIZED=1` 환경변수 **동시 충족**해야만 허용. 문서-코드 괴리 없음, 코드리뷰로 반복 단련된 게이트.

---

## 3. 어떻게 검증할 수 있는가

### 3.1 테스트 스위트 — 직접 실측
CI와 동일한 명령을 표준 환경에서 실행:

```
$ python -m unittest discover -s tests -p "test_*.py"
Ran 335 tests in 22.3s → OK (skipped=7)     # 0 failures, 0 errors
```
- **335건 전부 green**, skip 7건은 **전부 semgrep 미설치 사유**(정밀 경로는 CI에 위임).
- 테스트 성장 이력: 187 → 198 → 200 → 224 → 257 → 293 → **335**.
- `scan_all.py`를 골든셋에 실행 → 스택 자동감지(jsp-legacy)·grep폴백·13후보·**"폴백은 recall 낮음, 0건이 안전 아님" 경고**까지 정직 출력 확인.

### 3.2 검증 방법론
| 계층 | 방식 | 강도 |
|---|---|---|
| 안전게이트 | `scope_guard` IP위장·메타데이터·fail-closed exhaustive | **강**(mock 없음) |
| 정적 골든셋 | `safe/vuln` 픽스처 vuln≥1·safe==0, `GXSEC_NO_SEMGREP=1`로 폴백 강제 | 강(픽스처가 각 1파일·5~10줄로 얇음) |
| semgrep 룰 | 구조검증(상시) + 실로드 파싱에러 검증(semgrep 설치시만) | 중(의미 매칭은 미검증) |
| 동적 공격 | `dyn_session.request` **mock** 지배적, 실서버 E2E는 2건뿐 | 중 |
| CI | `test`(ubuntu+**windows**, semgrep無) + `semgrep-tests`(ubuntu만, 1.95.0 핀) | — |

### 3.3 검증 공백 Top 5
1. **semgrep 실탐지는 Windows CI에서 미검증**(semgrep-tests 잡 ubuntu 전용). Windows 도입 환경에서 룰 정확도 무보증.
2. **실제 취약 웹앱 E2E 전무** — 모두 mock 판정 로직 단위테스트. "로그인→토큰→BFLA 실발사" 전 파이프라인 검증 없음.
3. **일부 골든셋 테스트가 vacuous**(`assertGreaterEqual(count,0)` — 항상 통과) → 룰 깨져도 green.
4. **audit `partial` 판정·auth `scope_blocked`·사람이 읽는 요약 출력 미검증** — 리팩터 중 조용히 깨질 수 있음.
5. **SQLi/XSS 공격 핵심 로직 미검증** — error/boolean-blind·페이로드·sqlmap 선택, 그리고 **이 둘만 scope 배선 테스트조차 없음**. `scan_pathtraversal` 폴백 전용 테스트도 부재.

> **신뢰의 근거**: CI가 스스로 "semgrep 룰 저장소 전역 파탄"을 발견해 PR#26에서 근본 수정한 이력(은폐 없는 자기검증). 반대로 그 파탄이 한동안 방치됐다는 사실은 폴백 의존 리스크의 실증.

---

## 4. 사업부 공통 사용 가능성

### 강점
- **실제 이중 스택(Spring 모던/JSP 레거시)에 정확 대응** — 표본 리포트가 `sqisoft-sef-2026`·`Gseed_Web_Renew` 실코드 스캔 결과로 실증(파일:라인·클래스명·수정 diff 포함).
- 단련된 fail-closed 안전게이트, 규율 있는 개발(PRD→설계→TDD→리뷰), 배포 한 줄(`/plugin marketplace add`), 의존성 최소(requests·PyYAML), Windows/PowerShell CI 검증.

### 도입 장벽
| 장벽 | 내용 | 영향 |
|---|---|---|
| **grep 폴백이 실질 기본값** | semgrep 선택 설치. 미설치 시 recall↓, 과거 룰 전역 파탄 이력, 표준 환경도 semgrep 없음 | "0건=안전" 오독 위험 |
| **JSON 바디 주입 불가** | 동적 엔진이 GET·form-urlencoded만 지원 | sef-2026(JWT+JSON REST)은 **동적 침투 활용도 제한** ★모순 |
| **로그인 프리셋 하드코딩** | `lgnId/password`·`/api/v1/auth/login`·`data.accessToken`이 sef-2026 고정 | 타 프로젝트는 매번 오버라이드 필요 |
| **SQLi/XSS 인증 미지원** | 이 둘은 `dyn_session` 미사용 → 로그인 뒤 화면 못 봄 | 사내 로그인 시스템 자동 커버 제한 |
| **자격증명 CLI 평문노출** | `--token-a` 등이 프로세스목록·셸히스토리 노출. env/stdin 미지원(문서가 "미해결" 인정) | **단일 운영자 격리호스트 필수** |
| **크롤링 부재** | URL·파라미터 수동 지정 | 엔드포인트 많으면 운영자 시간 선형 증가 |
| 성숙도·유지보수 | v0.3.0 태그 이후 결함수정 5건 미반영(성숙도 과소표기), **단일 작성자(버스팩터 1)**, `reports/`가 gitignore(중앙 이력관리 없음) | 조직 확산 리스크 |

### 필요 준비물
- **설치**: Python 3.11 + `requests`/`PyYAML`. **semgrep 설치를 전사 표준화**(정밀도 핵심).
- **운영정책**: 사내 스테이징을 `SECURITY_PLUGIN_ALLOW_HOSTS`에 등록, 사설망 허용 정책 결정, 동적 침투 시 **전용 계정·격리 호스트** 규정 명문화.
- **교육**: 정적은 진입장벽 낮음(자연어). 동적은 옵션 조합(계정×표적) 복잡 → **런북 필요**.

---

## 5. 구조적 한계

- **정적**: 후보 생성기(판정 아님) · taint(데이터흐름) 분석 없음 · 룰 1개 문법오류가 파일 전체 무력화 · file-upload 룰이 **사업부 헬퍼명 하드코딩**(이식성↓) · `scan_all` 순차 실행(파일트리 9번 중복 순회).
- **동적**: 크롤링 없음 · GET·form만·**JSON 불가** · SQLi/XSS 인증 미지원 · canary 127.0.0.1 고정(**원격 스테이징 블라인드 SSRF 영구 미확정**) · 로그인 프리셋 하드코딩 · **jsp-legacy는 접근통제 동적 표적이 아예 안 뽑힘**(정규식이 Spring `@Mapping` 전용).
- **공통**: best-effort 보조도구 — 사람 코드리뷰·전문 SAST/DAST를 대체하지 않음. 오탐·미탐 상존.

---

## 6. 권고 — 롤아웃 3단계

1. **즉시**: `gx-diagnose`(정적)를 **전 사업부 공통 도입**. 단 **semgrep 설치를 CI/개발환경 표준으로 강제**. 커밋 전/PR 게이트로 활용.
2. **파일럿**: `gx-pentest`·`gx-audit`(동적)은 **보안 담당 1~2인이 격리 호스트에서** 운영. JSON REST는 동적 자동화 한계를 인지하고 수동 PoC 보완, 프로젝트별 로그인 프리셋 오버라이드 런북 작성.
3. **조직 정비**: 버전/CHANGELOG 관리 재개, **유지보수 인력 2인 이상 확보**, 점검 리포트 중앙 보관 체계 마련, 검증 공백 5건 백로그화.

---

## 부록 A. 개발 이력 · 알려진 결함 복구

| 버전 | 추가 내용 |
|---|---|
| v0.1.0 | 정적 9종 + 동적 2종(SQLi·XSS) + 오케스트레이터 + scope_guard |
| v0.2.0 | 슬래시 커맨드 3종 |
| v0.2.1 | scope_guard 강화(TLD 우회 차단·fail-closed·사설망 기본차단) |
| v0.3.0 | 동적 6종 완비 + `dyn_session` + 전 익스플로잇터 scope_guard fail-closed |
| v0.3.0 이후(미태깅) | F3(SAST 미탐 9패턴 보강)·M5/M7/M9(CI+semgrep 골든셋)·**M5-semgrep(룰 전역 파탄 복구)**·U1~U4·Gemini 리뷰 반영 — **CHANGELOG·버전 미반영** |

주요 복구: **PR#26** — ssrf/upload/pathtraversal 3개 룰이 문법오류로 파일 전체 파싱실패(폴백 강등), access 룰 `@PathVariable` 오인식 미검출 → 문법 교정 + `test_rules`에 semgrep `errors[]` 하드검증 추가 + 골든셋을 하드 재현율 게이트로 승격.

## 부록 B. 실측 원자료

- **테스트**: `python -m unittest discover -s tests` → 335 tests, 0 fail/error, 7 skip(전부 semgrep 미설치). 22.3초.
- **실행 환경**: Python 3.11.15, requests 2.33.0, PyYAML 6.0.3 존재 / **pip·pytest·semgrep 부재** → 기본 grep 폴백.
- **scope_guard**: 10개 대상 실발사 → 명세 100% 일치(§2.5).
- **scan_all**: `tests/fixtures` 스캔 → jsp-legacy 감지·grep폴백·9클래스 13후보·폴백 경고 출력.
- **CI**: `.github/workflows/ci.yml` — `test`(ubuntu+windows·semgrep無)·`semgrep-tests`(ubuntu·semgrep 1.95.0 핀).

## 부록 C. 근거 파일 인덱스

- 진입점: `scan_all.py`, `skills/auditing-web-application-security/scripts/audit.py`
- 정적 스캐너: `skills/detecting-*/scripts/scan_*.py` (9) + `rules/*.yml` (9)
- 동적 공격: `skills/exploiting-*/scripts/attack_*.py` (6)
- 공용: `tools/scope_guard.py`, `tools/dyn_session.py`, `skills/exploiting-ssrf-and-open-redirect/scripts/oob_canary.py`
- 검증: `tests/` (28파일·335케이스), `tests/fixtures/**`, `.github/workflows/ci.yml`
- 문서: `README.md`, `USAGE.md`, `ATTACK_SAFETY.md`, `CHANGELOG.md`, `docs/severity-rubric.md`
