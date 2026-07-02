# Changelog

이 프로젝트의 주요 변경 사항을 기록합니다.
형식은 [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/)를 따르며,
버전 체계는 [Semantic Versioning](https://semver.org/lang/ko/)을 준수합니다.

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

[0.3.0]: https://github.com/bs-koo/gx-security/releases/tag/v0.3.0
