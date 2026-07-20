# 공격형(exploiting-*) 스킬 안전 수칙

`exploiting-*` 스킬은 **실제 공격 페이로드를 발사**하여 취약점의 실제 악용 가능성을 확정한다.
정적 `detecting-*`(소스 점검)와 달리 **실행 중인 대상**이 필요하며, 위험이 크므로 아래를 강제한다.

## 절대 규칙

1. **권한 있는 자산만** — SQIsoft 사업부가 소유하고 테스트가 승인된 시스템만 대상.
2. **운영 환경 금지** — 대상은 **로컬/스테이징**만. `tools/scope_guard.py`가 운영 의심 호스트(`prod`, `www.` 등)와 공인 대상을 코드로 차단한다.
3. **비파괴 기본** — 기본은 탐지용 페이로드(데이터 변조/삭제 금지). 파괴적 작업은 `--allow-destructive` 명시 + 사람 승인.
4. **격리** — 가능하면 운영과 분리된 데이터/계정으로 스테이징에서 수행.
5. **기록** — 발사한 페이로드·응답을 증거로 남긴다(리포트의 Evidence 필드).
6. **자격증명 인자 노출 금지(MUST)** — 토큰·비밀번호를 직접 값으로 CLI 인자(`--token-a`·`--user-a-pw`·`--user-a-id` 등, 하위호환용)에 전달하면 **평문으로 노출**된다.
   - **노출 경로**: 프로세스 목록(`ps aux`/`ps -ef`·작업관리자 `tasklist`), 리눅스 `/proc/<pid>/cmdline`, **셸 히스토리**(`~/.bash_history`·`~/.zsh_history`·PowerShell `PSReadLine` 히스토리 파일). 같은 호스트의 다른 사용자·후속 세션이 그대로 읽을 수 있다.
   - **v0.5.0부터 지원되는 안전 입력 경로**: attack 4종(`exploiting-auth-session`·`exploiting-broken-access-control`·`exploiting-ssrf-and-open-redirect`·`exploiting-path-traversal-upload`)과 `audit.py`는 아래 두 경로를 코드로 지원한다. `audit.py`는 이 경로로 받은 비밀을 내부에서 발사하는 자식 프로세스에도 cmd 인자 평문이 아니라 환경변수로 전달한다(단, `audit.py` 자신에 직접 인자로 비밀을 넘긴 경우는 그 시점에 이미 `audit.py` 자체 argv에 평문 노출된 뒤이므로 이 자식 위임의 이점에서 예외다).
     - ① **`--creds-stdin`(권장)** — stdin에서 JSON을 1회 읽어 처리하므로 프로세스 인자·환경변수 어디에도 비밀이 남지 않는다. 세 경로 중 프로세스 노출을 완전히 없애는 유일한 방식이다. 다만 `echo`로 비밀을 직접 타이핑해 입력하면 그 명령 자체가 셸 히스토리에는 남을 수 있다(프로세스 노출과는 별개 채널).
     - ② **`--user-a-pw-env`/`--token-a-env` 등(차선)** — 인자로 값이 아니라 환경변수 **이름**만 넘기므로 프로세스 목록·`cmdline` 노출은 없다. 다만 비밀값은 여전히 프로세스의 환경변수 블록에 실제로 존재해 환경변수 조회 경로(리눅스 `/proc/<pid>/environ` 등)로는 노출될 수 있고, 값을 최초로 설정하는 `export`/`$env:` 명령 자체가 히스토리에 남을 수 있다 — **프로세스 노출이 잔존**한다.
   - **무효한 완화책(착각 금지)**: 직접 인자에 셸 변수를 대입하는 방식(`--token-a "$TOKEN"`)은 **프로세스 목록 노출을 막지 못한다** — 셸이 `$TOKEN`을 execve **전에 실제 값으로 확장**하므로 `/proc/<pid>/cmdline`엔 평문이 그대로 실린다. **셸 히스토리 노출만** 일부 완화된다. 이 패턴 대신 위 ②(`--token-a-env TOKEN`처럼 변수 **이름**을 전달)를 쓴다.
   - **현재 유효한 완화책(입력 경로와 무관하게 필수)**: **단일 운영자 전용 격리 호스트 + 운영과 분리된 전용 테스트 계정**으로만 실행하고, 가능하면 히스토리에 남지 않게 처리(예: 히스토리 미기록 세션). 세 경로 중 **`--creds-stdin`을 기본으로 사용**하고, 자동화 스크립트 등에서 stdin 연결이 어려운 경우에만 ②로 대체하며, 하위호환을 위해 직접 인자를 써야 한다면 위 격리 조치를 반드시 병행한다.
   - 구체적 명령·플래그·로그인 프로파일은 [docs/OPERATIONS.md](docs/OPERATIONS.md) §4·[docs/RUNBOOK-dynamic.md](docs/RUNBOOK-dynamic.md) §2를 참고한다.

## 안전 게이트 (코드 강제)

모든 `attack_*.py`는 페이로드 발사 전에 반드시 호출한다:

```python
from tools.scope_guard import assert_in_scope, ScopeError
try:
    assert_in_scope(target_url, authorized_flag=args.authorized)
except ScopeError as e:
    print(e); sys.exit(1)   # 범위 밖이면 발사하지 않음
```

- 로컬 loopback(127.x)·예약 TLD(`.local`/`.test`) → 자동 허용
- 사설망(10.x/172.16/192.168)·사내 스테이징 호스트 → `SECURITY_PLUGIN_ALLOW_PRIVATE=1` 또는 `SECURITY_PLUGIN_ALLOW_HOSTS` 등록 시 허용 (기본은 차단)
- 공인 도메인/IP → `SECURITY_PLUGIN_AUTHORIZED=1` + `--authorized` 동시 충족 시에만 (소유자 책임)
- `prod`/`production`/`www.`·IP 위장(정수·IPv6 매핑) → 항상 차단

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
