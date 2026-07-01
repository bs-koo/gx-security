# gx-security 안정화 → 동적 6종 완성 — 설계서

- **작성일**: 2026-07-01
- **대상 레포**: `D:\SQ\security-plugin` (플러그인 `gx-security`, 현재 `0.2.1`)
- **목표 릴리스**: `0.3.0` (Phase 5에서 minor 승격)
- **배경 근거**: 2026-07-01 플러그인 전수조사 결과 (아래 §0)

---

## §0. 배경 — 전수조사에서 확정된 사실

현재 `main`의 실제 구현은 **정적 9종 + 동적 3종(SQLi·XSS·접근통제)** 이다. 접근통제 동적은 이미 통합되어 있으며, 남은 미머지 동적은 3종이다. 그러나:

1. **README(0.2.1)가 코드에 아직 없는 것을 "존재·동작"으로 과장** — "동적 스킬 6종 모두 존재·동작", "스킬 16개". 코드는 여전히 동적 3종·총 13스킬. (반면 "`tools/dyn_session.py` 엔진", "gx-audit이 접근통제 자동 발사"는 접근통제 통합으로 **이미 사실이 됨** — 더 이상 허위가 아니므로 그대로 유지하되 범위를 3종으로 정확히 기술해야 한다.)
2. **미머지 동적 익스플로잇터는 3종**이 완성되어 feature 브랜치에 대기 중이다. 접근통제는 이미 `main`에 통합됨(선형 누적 라인의 첫 단계 완료). 남은 라인:
   ```
   main (접근통제 통합 완료 = dyn_session.py·attack_access.py·run_access_dynamic)
        → feat/exploiting-auth-session (+auth)
        → feat/exploiting-ssrf-redirect (+ssrf/redirect+oob)
        → feat/exploiting-path-traversal-upload (+path/upload)
   ```
3. **접근통제는 `audit.py:run_access_dynamic`로 정적→동적 연계가 이미 구현됨**(`DYNAMIC` dict의 `{sql-injection, xss}`와는 별도 경로). 그러나 **미머지 3종(auth/ssrf/path)은 어느 브랜치도 오케스트레이터에 연결하지 않았다** — 익스플로잇터 스크립트는 있으나 등록이 빠져 gx-audit이 그 3종을 발사하지 않는다.
4. **공용 엔진 `tools/dyn_session.py`** 는 접근통제 통합과 함께 **이미 `main`에 존재**한다. 남은 auth/ssrf/path 익스플로잇터가 이 엔진에 의존.
5. **부수 결함**: (a) `audit.py:run_dynamic`이 `--params` 없이 호출되면 `attack_*.py`가 `--param` 필수라 argparse 에러(exit 2)로 죽는데, `audit.py`가 빈 stdout을 `json.loads("{}")`로 삼켜 **조용히 "미확인"으로 표시** — 한 발도 안 쐈는데 "동적 미탐"처럼 보임. (b) semgrep 미설치 시 쓰는 grep-fallback SQLi 정규식(`scan_sqli.py:101-110`)이 `\S+` 때문에 `"...WHERE id=" + input` 교과서 SQLi를 **미탐** → 리포트의 "정적 0건=안전" 논리를 약화. (c) 접근통제 통합과 함께 `tests/`에 회귀 테스트가 도입됨(`test_audit.py`·`test_dyn_session.py`·`test_attack_access.py`) — 단 미머지 3종(auth/ssrf/path)용 테스트는 각 통합 phase에서 동반 복구 필요. (d) SKILL.md frontmatter `version: "0.1"` 방치.
6. **CSRF 동적 익스플로잇터는 전 브랜치 통틀어 없음**(진짜 미개발). CSRF는 정적 전용이 맞고 문서도 그렇게 유지.

---

## §1. 핵심 설계 원칙

> **문서는 "머지된 코드의 진실"만 반영한다.**
> README에 "동적 6종"을 미리 못박지 않는다. 각 취약점이 실제 통합될 때마다 그 취약점을 문서에 "동적 지원"으로 승격한다. 지금의 허위 과장 재발 방지.

- **통합 방식**: **파일 단위 cherry-pick** (`git checkout <branch> -- <paths>`). 브랜치 통째 머지 금지 — 브랜치에 섞인 부풀린 README가 Phase 0에서 고친 문서를 되살리기 때문.
- **완료 정의(DoD)**: 각 동적 phase는 ①파일 통합 ②`DYNAMIC` 등록 ③테스트 복구·통과 ④문서 승격 ⑤`scope_guard`·로컬 회귀 검증 5가지를 모두 만족해야 "완료".
- **안전 불변식**: 모든 `attack_*.py`는 발사 전 `assert_in_scope()` 강제 통과. Phase마다 이 게이트가 우회되지 않는지 재확인.

---

## §2. Phase 구조

**로드맵**: `P0 안정화 → P1 접근통제(이미 완료) → P2 인증·세션 → P3 SSRF → P4 경로/업로드 → P5 마무리`.
접근통제(P1)는 `main`에 이미 통합되어 있으므로 실제 신규 작업은 P0 안정화와 P2~P4 동적 3종 통합, 그리고 P5 정합이다.

### Phase 0 — 안정화 (선행 필수)
main을 **"코드 실상 100% 일치 + 알려진 버그 제거"** 로. 기능 추가 없음.

- **P0-1 문서 진실화**: README/USAGE/`auditing-web-application-security/SKILL.md`에서 과장 제거.
  - "동적 6종"→"동적 3종(SQLi·XSS·접근통제)", "스킬 16"→"13". `dyn_session.py 엔진`·"gx-audit 접근통제 자동발사"는 **이미 사실이므로 유지**하되, 발사 범위를 정확히 3종으로 기술.
  - 스캐너 3대 구조적 한계 명시: **크롤링/엔드포인트 자동탐색 없음 · GET과 form-urlencoded POST만 · JSON 바디 주입 불가**.
- **P0-2 `audit.py` param 가드**: `run_dynamic`에서 `param`이 없을 때 조용한 "미확인" 대신 **명시적 skip 사유** 기록. `returncode≠0`을 사람이 읽는 요약에도 노출. (또는 `--params` 미지정 시 동적 단계를 "파라미터 필요" 안내로 스킵)
- **P0-3 정적 미탐 경고**: `scan_all.py` 요약·JSON과 리포트 템플릿에 "grep-fallback은 recall이 낮음 → semgrep 설치 권장, 후보 0건이 안전을 뜻하지 않음" 경고 추가. (선택) `scan_sqli.py` 폴백 정규식을 공백 허용 패턴으로 개선 + 최소 회귀 fixture.
- **P0-4 버전 정합**: 전 SKILL.md frontmatter `version` → 플러그인 버전과 일치.
- **DoD**: 문서 grep에 허위 문구 0건, `audit.py` param-누락 회귀 테스트 통과, `scope_guard` 셀프테스트 그린.

### Phase 1 — 접근통제(IDOR/BFLA) 동적 통합 — **이미 완료 (main 통합됨)**
- **상태**: `feat/dynamic-access-control`의 산출물이 **이미 `main`에 통합됨**. 재작업 불필요 — 아래는 완료 기록.
- **통합 완료 파일**: `skills/exploiting-broken-access-control/{SKILL.md,scripts/attack_access.py,references/payloads.md}`, **공용 엔진 `tools/dyn_session.py`**, `tests/{test_attack_access.py,test_dyn_session.py}`.
- **오케스트레이터 연계**: `audit.py:run_access_dynamic`가 정적→동적 접근통제를 연계(별도 경로, `DYNAMIC` dict와 무관).
- **문서**: 접근통제는 이미 "동적 지원"으로 승격됨.
- **의의**: 첫 동적 확장이자 공용 엔진 도입 지점 → `dyn_session.py` 계약(로그인·세션·HTTP 헬퍼)이 여기서 확정되어 이후 phase(P2~P4)가 이를 재사용.

### Phase 2 — 인증/세션/JWT 동적 통합
- **출처**: `feat/exploiting-auth-session`
- **가져올 파일**: `skills/exploiting-auth-session/{SKILL.md,scripts/attack_auth.py,references/payloads.md}`, `tests/test_attack_auth.py`
- **`DYNAMIC` 등록**: `"auth-session": .../exploiting-auth-session/scripts/attack_auth.py`
- **문서**: 인증/세션/JWT를 "동적 지원"으로 승격
- **특이**: JWT 변조·토큰 재사용·쿠키 속성 probe. 비파괴(로그아웃 3xx 인정 등) 재확인.

### Phase 3 — SSRF/오픈 리다이렉트 동적 통합
- **출처**: `feat/exploiting-ssrf-redirect`
- **가져올 파일**: `skills/exploiting-ssrf-and-open-redirect/{SKILL.md,scripts/attack_ssrf.py,scripts/oob_canary.py,references/payloads.md}`, `tests/{test_attack_ssrf.py,test_oob_canary.py}`
- **`DYNAMIC` 등록**: `"ssrf-and-open-redirect": .../exploiting-ssrf-and-open-redirect/scripts/attack_ssrf.py`
- **문서**: SSRF/오픈리다이렉트를 "동적 지원"으로 승격
- **특이**: **`oob_canary.py`(블라인드 SSRF용 loopback 콜백 리스너) 안전성 재검토** — 바인딩 주소·포트·수신 데이터 처리, 외부 노출 여부. `audit.py` 연계 시 리스너 수명주기 정의.

### Phase 4 — Path Traversal / 파일 업로드 동적 통합
- **출처**: `feat/exploiting-path-traversal-upload`
- **가져올 파일**: `skills/exploiting-path-traversal-upload/{SKILL.md,scripts/attack_pathupload.py,references/payloads.md}`, `tests/test_attack_pathupload.py`
- **`DYNAMIC` 등록**: `"path-traversal-upload": .../exploiting-path-traversal-upload/scripts/attack_pathupload.py`
- **문서**: Path Traversal/업로드를 "동적 지원"으로 승격
- **특이**: **파괴적 업로드 옵션(위험 확장자 수용 확정)의 안전 게이트·옵트인 재검토**. 무해 마커 원칙 준수 확인. multipart 전송 경로 검증.

### Phase 5 — 마무리·정합 (minor 승격 `0.3.0`)
- 동적 6종 완비 → README를 "**동적 6종 / 총 16스킬**"로 (이제 사실) 갱신. `dyn_session.py`를 공용 엔진으로 정식 문서화(P1에서 이미 실재).
- **CSRF는 정적 전용**임을 문서에 명확히(동적 미지원 명시).
- `tests/` 전체 복구 + 전 스캐너·전 익스플로잇터 회귀 그린.
- `plugin.json`/`marketplace.json`/README/전 SKILL.md 버전 `0.3.0` 일괄.
- CHANGELOG(있으면) 갱신.

---

## §3. 브랜치·머지 전략

- **작업 브랜치**: 각 phase는 `main`에서 딴 독립 브랜치 → 독립 PR → `main` 머지.
  - P0 `fix/stabilize-docs-and-bugs`, ~~P1 `feat/integrate-dyn-access`(이미 `main` 통합 완료)~~, P2 `feat/integrate-dyn-auth`, P3 `feat/integrate-dyn-ssrf`, P4 `feat/integrate-dyn-pathupload`, P5 `chore/release-0.3.0`.
- **순서 의존**: P0는 모든 phase의 선행. **P1(접근통제)은 이미 완료되어 `dyn_session.py` 계약이 `main`에 확정됨.** 남은 P2~P4는 그 엔진 위에서 논리상 순차(누적 라인 순서 권장)이나 상호 독립에 가깝다.
- **버전 번호**: P0~P4 커밋 중에는 `0.2.1` 유지, **P5에서 minor 승격(`0.3.0`)**.
- 원본 feature 브랜치(auth/ssrf/path)는 통합 완료 후에도 참조용으로 보존(삭제는 P5 이후 사용자 판단).

---

## §4. 위험 및 완화

| 위험 | 완화 |
|---|---|
| 브랜치 통째 머지로 부풀린 README 부활 | 파일 단위 cherry-pick만 사용(§1) |
| `dyn_session.py` 인터페이스 변화로 후속 phase 깨짐 | P1(완료)에서 공용 계약이 이미 `main`에 확정·테스트 고정됨 — P2~P4는 이 계약을 변경 없이 재사용 |
| `oob_canary.py` 리스너의 외부 노출/바인딩 위험 | P3에서 loopback 바인딩·수명주기 안전성 재검토 |
| 파괴적 업로드 옵션 오남용 | P4에서 옵트인·`scope_guard`·무해 마커 재검증 |
| DYNAMIC 등록 누락 반복 | 각 phase DoD ②에 명시, 통합 후 `audit.py --target` 실제 발사로 확인 |
| grep-fallback 미탐이 "안전"으로 오인 | P0-3 경고 문구 + (선택) 정규식 개선 |

---

## §5. 완료 기준 (전체)

- [ ] `audit.py`가 동적 6종 발사(`DYNAMIC` dict + `run_access_dynamic` 경로 합산), `--params` 지정 시 6종 모두 실발사 확인
- [ ] `tests/` 소스 복구 + 전체 통과(정적 스캐너 + 동적 익스플로잇터)
- [ ] 문서(README/USAGE/전 SKILL.md)가 코드 실상과 100% 일치, 허위 0건
- [ ] `scope_guard` 안전 게이트가 전 익스플로잇터에서 강제됨
- [ ] `plugin.json`/`marketplace.json`/문서 버전 `0.3.0` 일치
- [ ] CSRF 정적 전용·스캐너 3대 한계가 문서에 명시
