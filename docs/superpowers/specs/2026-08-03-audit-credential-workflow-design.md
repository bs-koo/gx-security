# gx-audit 계정 입력 워크플로 개선 설계 (Spec)

**작성일:** 2026-08-03
**상태:** 확정 (브레인스토밍 완료 → 구현)

## 배경

`gx-audit` 동적 검사는 **테스트 계정·주입점이 있어야 `dynamic`(악용 확정)**, 없으면 `static-only`(정적 추정)로 남는다. 현재:
- 계정 입력 방법(`--creds-stdin`/`--*-env`)은 있으나 **"무엇을 어디에 어떻게 넣는지" 가이드가 불명확**하다.
- 계정 미입력의 영향은 **실행 후 `static-only` note로 사후 표기**될 뿐, 사전 예고가 없다.
- `static-only`로 남은 항목을 **나중에 계정 받아 마저 확정하는 경로**가 명시돼 있지 않다.

## 요구 (3)

1. **계정 입력 형식 — 확실한 가이드**: 비밀(비밀번호·토큰) vs 비-비밀(아이디·형식·주입점)을 나눠 각각 어디에 어떻게 넣는지. 비밀은 인터랙티브 env/stdin(트랜스크립트·argv·디스크 미노출).
2. **미입력 시 사전 경고**: 동적 발사 전에, 현재 준비 상태로 돌리면 무엇이 `static-only`로 남는지 예측 안내.
3. **static-only 재실행(보강)**: 1차 리포트에서 `static-only` 항목을 추출 → 계정 받아 **그 항목만** 동적으로 마저 확정 → 1차 정적 + 2차 동적 병합.

## 설계

### ① 계정 입력 가이드 (SKILL 1.5단계 강화)

**무엇을 어디에** (비밀/비-비밀 분리):
| 값 | 비밀? | 넣는 곳 | 방법 |
|----|:---:|--------|------|
| 로그인 형식(경로·바디·필드) | ❌ | `profiles/<앱>.json` 파일 | sef-2026 기본 제공, 다르면 파일 작성 |
| 아이디(user_a_id·user_b_id) | ❌ | 명령 인자 | `--user-a-id` 등 |
| resource_id·주입점 | ❌ | 명령 인자 | `--resource-id`·`--ssrf-target` 등 |
| 비밀번호·토큰 | ✅ | 환경변수(인터랙티브) | `read -rs` → `--*-env` |

**단계별(복붙 가능, sef-2026):**
```bash
read -rs GXSEC_USER_A_PW; export GXSEC_USER_A_PW
read -rs GXSEC_USER_B_PW; export GXSEC_USER_B_PW
python skills/auditing-web-application-security/scripts/audit.py <소스> \
    --target http://localhost:8080 --login-profile sef-2026 \
    --user-a-id <A> --user-a-pw-env GXSEC_USER_A_PW \
    --user-b-id <B> --user-b-pw-env GXSEC_USER_B_PW \
    --resource-id <A소유ID> --probe /api/v1/users/me --params id,q --json
```

**⛔ 금지**: 비밀번호를 채팅창 입력(트랜스크립트 영구)·`--user-a-pw <값>` 직접 인자(argv 노출)·파일 저장(디스크 평문).

**📄 파일은 로그인 "형식"에만** (`profiles/<앱>.json` — `login_path`·`body_template`·`token_path`·`id_field`·`pw_field`; `{id}`/`{pw}`는 런타임 치환, 비밀 미포함).

### ② 사전 경고 (실행 전 예측)

정적 스캔 후·동적 발사 전에, 현재 준비 상태로 무엇이 `static-only`로 남는지 예측 안내:
```
[사전 경고] 현재 준비 상태 → 다음은 정적 추정(static-only)으로 남습니다:
  · 접근통제(IDOR/BFLA)  — user_a/user_b + resource_id 필요
  · 인증세션(JWT·재사용) — user_a + --probe 필요
  · SSRF/경로/업로드     — 주입점(--ssrf-target 등) 필요
지금 준비해 확정하시겠어요, 아니면 이대로 정적 추정으로 진행할까요?
```

### ③ static-only 재실행(보강)

1차 완료 후 리포트에서 `confidence == static-only`인 클래스를 **자동 추출**해 보여주고, 계정을 준비했으면 **그 항목만** 동적으로 보강한다(1차 정적 재사용, 정적 재스캔 없음). `audit.py`는 계정을 주면 `static-only → dynamic` 전환되므로, SKILL이 1차 결과를 들고 계정만 추가해 재실행 → 1차 정적 + 2차 동적을 병합해 최종 리포트를 완성한다.

## 구현 위치 (최소 침습)

- **주 변경**: `skills/auditing-web-application-security/SKILL.md` — 1.5단계에 ① 계정 가이드·② 사전 경고 매트릭스·③ 보강 재실행 절차 추가
- **`audit.py`**: `static-only 요약`을 리포트에 추가 — `_static_only_classes(report)` 헬퍼 + `report["static_only_summary"]` + 사람요약 한 줄. (③ 추출을 스크립트가 직접 제공 → SKILL이 파싱 없이 소비)
- **테스트**: `_static_only_classes` 유닛 테스트(각 `*_dynamic` phase의 `confidence==static-only` 추출)

## 보안 원칙 (불변)

비밀(비밀번호·토큰)은 **env/stdin(인터랙티브)** 로만. 채팅·argv 평문·파일 저장 금지. 아이디·resource_id·주입점은 비밀이 아니므로 명령 인자로 무방.
