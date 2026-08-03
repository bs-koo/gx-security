# Changelog

이 프로젝트의 주요 변경 사항을 기록합니다.
형식은 [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/)를 따르며,
버전 체계는 [Semantic Versioning](https://semver.org/lang/ko/)을 준수합니다.

## [0.8.1] - 2026-08-03

> gx-audit DB 격리 게이트 — 동적 검사 전 서버가 바라보는 DB의 격리 여부를 확인해 공유 개발 DB 오염·실데이터 노출을 방지한다.

### Added
- **DB 격리 게이트(auditing 1.5단계)** — `scope_guard`가 검증하지 못하는 "서버 뒤의 DB"를 사용자 확인(fail-safe=개발DB)으로 게이트한다. **격리/더미 DB**는 AI가 소스 정독으로 계정·픽스처를 자유 생성(로컬 검증 방식), **공유 개발 DB**는 오염 방지 모드(계정·픽스처 생성 금지, 사용자 제공 계정으로 로그인만, 파괴적 작업 차단, 비파괴 읽기만)로 분기. 로컬 도커 격리 DB 전환 안내 + 기존 테스트 계정 요청 안내를 함께 제공한다. audit.py 코드 변경 없이 대화형 게이트로 구현.

## [0.8.0] - 2026-07-31

> Burp Suite MCP 하이브리드 연동. 기존 4종(접근통제·인증세션·SSRF·경로조작)을 Burp 프록시로 경유시켜 결정론·판정·`scope_guard`를 유지한 채 트래픽을 Burp 히스토리에 축적하고, 세션 스와핑 등 Burp 고유 심화는 MCP 도구로 얹는다. SQLi·XSS는 sqlmap·Playwright 우위라 기존 경로 유지.

### Added
- **Burp 프리플라이트·온보딩(`tools/burp_preflight.py`)** — 프록시(8080)/MCP(9876) 포트 프로브 + 미설정 시 설치 온보딩. `--require proxy|mcp|both`, `split_hostport`/`probe_port`/`check`/`onboarding_text`.
- **dyn_session 프록시 경유(`SECURITY_PLUGIN_BURP_PROXY`)** — env 지정 시 모든 requests 발사(`request`/`login`/`login_response`/`form_login`)가 Burp 프록시를 경유(+`verify=False`, `InsecureRequestWarning` 1회 억제), 미지정 시 기존과 바이트 동일. 로그인 프록시 오류 힌트.
- **audit `--burp-proxy`/`--burp-proxy-strict`** — 프리플라이트 게이트 + env 전파(자식 subprocess 상속), `report["burp_proxy"]` 노출. 미가동 시 온보딩 후 폴백, strict면 발사 중단(증거 없는 발사 방지).
- **`exploiting-with-burp` 스킬** — 하이브리드 워크플로 문서(프록시 경유 결정론 + MCP 보조 심화) + `references/burp-engine.md`. Intercept OFF·MCP scope fail-open 한계 명시.

### Notes (실물 검증 — 2026-07-31)
- **프록시 경유 end-to-end 확인** — Burp Community 2026.3.3에서 `dyn_session`→Burp 프록시→로컬 대상 왕복 성공.
- **MCP SSE 직결** — `claude mcp add --transport sse burp http://127.0.0.1:9876`(엔드포인트는 루트, stdio proxy 불필요). `send_http1_request` 실호출로 응답 회수 확인.
- **엣지 D 확정** — Burp `base64` 도구는 표준 base64만 지원(url-safe `-`/`_` 거부, 출력도 표준 패딩). JWT(base64url) 변조는 MCP base64로 불가 → `attack_auth.py` 프록시 경유로 처리.
- **엣지 H 실증** — 8080은 환경에 따라 Oracle TNSLSNR 등이 점유할 수 있어 "포트 열림 ≠ Burp". 대상 포트가 Burp인지 확인 필요(온보딩·SKILL에 경고 반영).

## [0.7.0] - 2026-07-30

> P4 커버리지. 정적 판정을 "충분히"로 승격하고 프론트엔드 XSS를 커버하며, 동적을 대화형·사람확인형으로 재편했다. (P3 0.6.0 미릴리스 시 이 릴리스가 P3 변경도 포함한다.)

### Added
- **접근통제 정적 정밀화(Task 2·3)** — `scan_access.py`가 소유권/권한 집행 신호(@Pre/PostAuthorize 소유권 표현·소유자 스코핑 조회·명시적 소유권 검사)를 같은 메서드 창에서 감지해 IDOR/BFLA 오탐을 억제하고, 남은 후보엔 `context`(method·annotations·delegates_to)를 부착한다. SKILL.md에 `secure/vulnerable/needs-runtime` 3-값 판정 사다리와 전 후보 판정 매트릭스 산출을 명문화. sef-2026 backend 65→57, 41건 context.
- **프론트엔드 XSS 커버(Task 4·5)** — `detecting-xss`에 frontend 모드 추가: Vue/Nuxt `.vue` 스택 감지, `node_modules/dist/.nuxt/.output` 제외, `v-html`(미새니타이즈, sanitize 래핑 제외)·`insertAdjacentHTML/outerHTML`·`eval/new Function` 폴백 룰 + `rules/xss-frontend.yml`. SKILL.md에 프론트 폴더 탐색 → AskUserQuestion 확인 → 스캔 워크플로우. sef-2026 public/frontend v-html 5건 검출(기존 미커버).
- **동적 대화형 게이트(Task 6)** — auditing·gx-pentest에 정적 우선 + AskUserQuestion 동적 게이트(대상 실행 여부 확인)·라이브니스 프로브·비밀 stdin 전달 원칙(자유서술 칸 상시).
- **사람확인 확정 프로토콜(Task 8, ④)** — `attack_access`(soft-200)·`attack_pathupload`(업로드 미확정)에 `evidence_expectation` 카드, auditing SKILL.md에 예상 증거 카드 → AskUserQuestion(자유서술 주 채널) → 최종 판정 프로토콜.
- **다중 루트(모노레포) 오케스트레이션(Task 9)** — 백엔드 루트(9종 풀스캔)·프론트 루트(XSS 전용)를 나눠 탐색·확인 후 단일 통합 리포트로 병합.

### Changed
- **XSS 과대표기 수정(Task 7)** — `attack_xss.py`가 반사만으로 `exploited:true`를 찍던 것을 제거. `reflected`/`verdict`(needs-confirmation|safe|unreached) + `evidence_expectation`을 방출하고 `exploited`는 브라우저 실행(Playwright) 확인 후 상위가 승격한다. 자기 SKILL.md 기준("반사=후보, 실행=확정")과 정합.

### Fixed
- **Windows(cp949) 인코딩 크래시 근본 수정(Task 1)** — 공용 `tools/io_utf8.py`(`configure()`·`emit_json()` UTF-8 바이트 직접 기록) 도입, 전 엔트리 스크립트가 JSON 계약을 콘솔 코덱에서 분리한다. cp949 회귀 테스트 추가.

## [0.5.0] - 2026-07-20

### Added
- 자격증명 안전 입력(D1) — `--creds-stdin`(stdin JSON, 프로세스 미노출·권장)과 `--user-a-pw-env`/`--token-a-env`(환경변수 이름 참조)를 attack 4종·`audit.py`에 추가. `audit.py`는 자식 subprocess에 비밀을 환경변수로 전달해 cmd 평문 노출을 제거한다.
- 로그인 프로파일 이식성(D2) — `--login-profile <name|path>`로 로그인 형식(경로·바디·토큰경로·필드·모드)을 외부화. 동봉 프로파일 `profiles/sef-2026.json`(Spring)·`profiles/jsp-form.json`(JSP form).
- 동적 점검 런북(O2) — `docs/RUNBOOK-dynamic.md`. `docs/OPERATIONS.md`·`ATTACK_SAFETY.md`의 자격증명 취급 서술을 지원 사실에 맞게 정합.

### Changed
- 자격증명 우선순위 stdin>env>direct 해석(`dyn_session.resolve_secret`). 기존 CLI 인자·동작은 100% 하위호환.

## [0.4.0] - 2026-07-20

### Added
- 정적 정밀도 표준화 — `requirements-dev.txt`(semgrep 1.95.0 핀)와 설치 스크립트, semgrep 미설치 시 grep 폴백 경고를 도입 문서에서 필수 설치로 승격.
- Windows semgrep CI — `semgrep-tests` 잡에 windows 매트릭스 추가(비차단 관측 폴백 포함).
- 운영정책 문서 `docs/OPERATIONS.md` — 스테이징 허용 등록·자격증명 취급·격리 호스트 규정.
- 버전 일치 회귀 테스트 `tests/test_version_consistency.py`.

### Changed
- 0.3.0 이후 누적분 반영: SAST 미탐 9패턴 보강, semgrep 골든셋 CI(semgrep 1.95.0), semgrep 룰 전역 파탄 복구, 동적 판정 정밀화, dyn_session 레거시(form/cookie) 이식성.

## [0.3.0] - 2026-07-02

### Added
- 동적 익스플로잇터 6종을 완비했습니다 — SQL 인젝션·XSS·접근통제(Broken Access Control)·인증세션·SSRF/오픈리다이렉트·경로조작/파일업로드. 정적 스캔 후보를 실행 중인 스테이징/로컬에 실제로 발사하는 SAST+DAST 하이브리드가 완성되었습니다.
- 동적 공용 엔진 `tools/dyn_session.py`(로그인 자동화·토큰 보관·인증 HTTP)를 도입해 접근통제·인증세션·SSRF·경로조작/업로드 익스플로잇터가 세션을 공유합니다. SSRF 익스플로잇터는 대역외(OOB) 콜백 확인을 위해 `skills/exploiting-ssrf-and-open-redirect/scripts/oob_canary.py`(루프백 canary 리스너)를 사용합니다.

### Changed
- 버전을 `0.2.1`에서 `0.3.0`으로 minor 승격했습니다 — `plugin.json`·`marketplace.json`(metadata·plugins)·`README` 푸터·전 SKILL.md(16종) 버전 표기를 정합했습니다.
- 전 익스플로잇터에서 `scope_guard` 안전 게이트를 fail-closed로 강제하여 운영 환경 발사를 코드로 차단합니다.

### Notes
- 이번 릴리스는 코드 로직 변경 없는 정합·릴리스 작업입니다. 버전 표기·문서 정합·CHANGELOG 신설에 한정됩니다.
- 구성: 커맨드 3(`gx-audit`·`gx-diagnose`·`gx-pentest`)·스킬 16(통합 1·진단 9·침투 6).

[0.7.0]: https://github.com/bs-koo/gx-security/releases/tag/v0.7.0
[0.5.0]: https://github.com/bs-koo/gx-security/releases/tag/v0.5.0
[0.4.0]: https://github.com/bs-koo/gx-security/releases/tag/v0.4.0
[0.3.0]: https://github.com/bs-koo/gx-security/releases/tag/v0.3.0
