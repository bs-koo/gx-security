# 동적 접근통제 — BFLA/IDOR 시나리오 카탈로그

실제 발사 시나리오와 상태코드 판정 기준. 모든 발사는 `scope_guard` 통과 후, 비파괴(GET) 기본.

---

## 판정 기준 (불변)

| HTTP 상태 | 판정 |
|---|---|
| `2xx` | **취약 후보** — 권한 우회/타인 노출 성공 |
| `401` | 미인증 (토큰 누락/만료) — 방어 |
| `403` | 인가 거부 — **방어(정상)**. IDOR이면 **즉시 오탐 확정** |
| `404` | 리소스 없음 — 표적/리소스 ID 재확인 |
| `3xx` | 리다이렉트 — `allow_redirects=False`로 원응답 확인(로그인 페이지 회피일 수 있음) |

---

## BFLA (Broken Function-Level Authorization)

**전제**: A = 일반 사용자 토큰. 관리자 권한이 없어야 한다.

| 시나리오 | 발사 | 취약(2xx) 의미 |
|---|---|---|
| 관리자 목록 조회 | `GET /adm/v1/users` + A토큰 | 일반 사용자가 전체 회원 열람 |
| 관리자 단건 조회 | `GET /adm/v1/users/{id}` + A토큰 | 타인 상세 열람 |
| 시스템 로그 조회 | `GET /adm/v1/logs/audit` + A토큰 | 감사 로그 노출 |
| 통계 조회 | `GET /adm/v1/users/statistics` + A토큰 | 관리자 전용 통계 노출 |

**쓰기 확정(옵션 — `--allow-destructive` + 승인)**:
| 시나리오 | 발사 | 의미 |
|---|---|---|
| 역할 변경(권한 상승) | `PUT /adm/v1/users/{self}/role` + A토큰, body `{"roleId":"<ADMIN>"}` | 자기 자신을 관리자로 승격 |
| 임의 삭제 | `DELETE /adm/v1/menus/notice/boards/{bbsSq}` + A토큰 | 관리자 자원 삭제 |

---

## IDOR (Insecure Direct Object Reference)

**전제**: A가 리소스를 소유/생성하고, B = A와 다른 일반 사용자 토큰.

| 시나리오 | 발사 | 취약(2xx) / 방어(403) |
|---|---|---|
| 타인 프로필 조회 | `GET /api/v1/users/{A_id}` + B토큰 | 2xx=노출 / 403=방어 |
| 타인 게시글 조회 | `GET /api/v1/boards/{A_board}` + B토큰 | 2xx=노출 / 403=방어 |
| 타인 댓글 수정(읽기 검증) | `GET /api/v1/comments/{A_comment}` + B토큰 | **403 기대** — 도메인 `validateOwner` 방어 |

> **오탐 반증 포인트**: 정적 스캐너가 `@PathVariable id`를 IDOR 후보로 올려도, 서비스가 `entity.update(userId)` → 도메인 `validateOwner(userId)`로 막으면 **403**이 나온다. 이때 정적 High는 **오탐**으로 확정한다. (sef-2026 `BoardComment.validateOwner` 실사례)

---

## 로그인 프리셋

| 스택/프로젝트 | login-path | body | token-path |
|---|---|---|---|
| sef-2026 (기본) | `/api/v1/auth/login` | `{"lgnId":"{id}","password":"{pw}"}` | `data.accessToken` |
| 커스텀 | `--login-path` | `--body-template '{"...":"{id}","...":"{pw}"}'` | `--token-path a.b.c` |

토큰을 미리 발급받았으면 `--token-a`/`--token-b`로 직접 주입(로그인 생략).
