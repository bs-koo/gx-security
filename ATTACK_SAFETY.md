# 공격형(exploiting-*) 스킬 안전 수칙

`exploiting-*` 스킬은 **실제 공격 페이로드를 발사**하여 취약점의 실제 악용 가능성을 확정한다.
정적 `detecting-*`(소스 점검)와 달리 **실행 중인 대상**이 필요하며, 위험이 크므로 아래를 강제한다.

## 절대 규칙

1. **권한 있는 자산만** — SQIsoft 사업부가 소유하고 테스트가 승인된 시스템만 대상.
2. **운영 환경 금지** — 대상은 **로컬/스테이징**만. `tools/scope_guard.py`가 운영 의심 호스트(`prod`, `www.` 등)와 공인 대상을 코드로 차단한다.
3. **비파괴 기본** — 기본은 탐지용 페이로드(데이터 변조/삭제 금지). 파괴적 작업은 `--allow-destructive` 명시 + 사람 승인.
4. **격리** — 가능하면 운영과 분리된 데이터/계정으로 스테이징에서 수행.
5. **기록** — 발사한 페이로드·응답을 증거로 남긴다(리포트의 Evidence 필드).

## 안전 게이트 (코드 강제)

모든 `attack_*.py`는 페이로드 발사 전에 반드시 호출한다:

```python
from tools.scope_guard import assert_in_scope, ScopeError
try:
    assert_in_scope(target_url, authorized_flag=args.authorized)
except ScopeError as e:
    print(e); sys.exit(1)   # 범위 밖이면 발사하지 않음
```

- 로컬/사설(127.x, 10.x, 192.168.x)·스테이징(`*staging*`, `*.local`, `*dev*`) → 자동 허용
- 공인 도메인/IP → `SECURITY_PLUGIN_AUTHORIZED=1` 환경변수 + `--authorized` 플래그 동시 충족 시에만(소유자 책임)
- `prod`/`production`/`www.` → 항상 차단

## 워크플로우 (정적 → 동적 연계)

```
detecting-<X> (소스에서 후보 도출)
      │  후보 URL·파라미터
      ▼
exploiting-<X> (스테이징에 실제 발사)
   0. scope_guard 범위 확인
   1. 대상·후보 입력
   2. 실제 페이로드 발사 (sqlmap / Playwright / curl)
   3. 악용 확정 (마커 반사 · 시간지연 · 데이터 추출 · DOM 실행)
   4. 검증된 PoC + 4요소 + Evidence 리포트
```

## 법적 고지

본 스킬의 공격 기능은 **권한 있는 보안 테스트(사내 펜테스트)** 목적에 한한다.
타인 소유 시스템에 대한 무단 사용은 정보통신망법 등 관련 법 위반이며 금지된다.
