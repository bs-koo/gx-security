# 운영정책 (Operations Policy)

gx-security를 사업부 공통으로 도입할 때 지켜야 하는 운영 규정. 대상 범위·스테이징 등록·자격증명 취급·파괴적 작업·산출물 보관을 다룬다. 안전 게이트의 실제 동작(`tools/scope_guard.py`)과 자격증명 노출 한계(`ATTACK_SAFETY.md`)를 그대로 반영하므로, 코드가 바뀌면 이 문서도 함께 갱신해야 한다. **동적(침투) 기능을 실행하기 전 반드시 숙지한다.**

## 1. 대상 범위 원칙

- 운영(production) 대상에는 **절대 사용 금지**. 로컬(loopback)과 사내에 등록한 스테이징만 대상으로 한다.
- 모든 동적 발사(`attack_*.py`)는 발사 전에 `tools/scope_guard.py`의 `assert_in_scope()`를 반드시 거친다. 내부 판정 함수 `classify()`는 4단계 우선순위로 동작하며, 먼저 해당하는 규칙이 항상 뒤 규칙보다 우선한다.

| 순서 | 판정 | 조건 | 결과 |
|---|---|---|---|
| ① deny | `prod`/`production`/`www.` 패턴 호스트, `SECURITY_PLUGIN_DENY_HOSTS` 등록 호스트, 링크로컬/클라우드 메타데이터(`169.254.0.0/16`), `0.0.0.0/8`, IPv6 링크로컬(`fe80::/10`) | 항상 차단 — `--authorized`+`SECURITY_PLUGIN_AUTHORIZED=1`로도 못 뚫음 |
| ② IP 판정 | loopback(`127.0.0.0/8`, `::1`)은 항상 허용. 사설망(`10/8`·`172.16/12`·`192.168/16`·`fc00::/7`)은 기본 `needs-authorization`(`SECURITY_PLUGIN_ALLOW_PRIVATE=1`이면 허용). 공인 IP는 `needs-authorization` | 정수/16진/8진 표기 위장(예 `127.0.0.1`→`2130706433`)과 IPv4-mapped IPv6(`::ffff:...`)도 실제 대역으로 환산해 판정한다 |
| ③ allow | `SECURITY_PLUGIN_ALLOW_HOSTS` 등록 호스트, `localhost`, 예약 TLD(`.localhost`/`.local`/`.test`/`.example`/`.invalid`) | 허용 |
| ④ needs-authorization (기본값) | 위 어디에도 해당하지 않는 공인 도메인/IP, `ALLOW_PRIVATE` 미설정 사설 IP | `--authorized` + `SECURITY_PLUGIN_AUTHORIZED=1` 이중 충족이 없으면 차단 |

- 호스트 파싱에 실패하는 입력(빈 문자열, URL이 아닌 값 등)도 deny로 수렴한다(fail-closed) — 판정이 애매하면 차단이 원칙이다.
- 공개 TLD(`.dev`/`.qa` 등)이거나 이름에 `staging`/`dev`가 들어 있다는 사실만으로는 자동 허용되지 않는다. 반드시 아래 §2·§3의 절차를 따른다.
- ③의 `SECURITY_PLUGIN_ALLOW_HOSTS`는 **호스트명 매칭에만 적용**된다. 대상 문자열이 IP로 파싱되면 ②에서 먼저 판정이 끝나므로, IP 리터럴을 `ALLOW_HOSTS`에 넣어도 사설망 기본 차단을 우회하지 못한다.

## 2. 사내 스테이징 등록 절차

사내에서 상시 점검하는 스테이징 호스트는 매번 `--authorized` 승인을 거치지 않도록 환경변수로 미리 등록한다.

```bash
# 쉼표로 여러 개 등록 가능. 정확매칭(단일 라벨 내부 호스트명 포함) 또는 .suffix(도메인) 매칭.
export SECURITY_PLUGIN_ALLOW_HOSTS="staging.gx-internal.com,intranet-app01"
```

- **정확매칭**: 목록 값과 호스트가 완전히 같으면 허용한다. 도메인이 없는 내부 호스트명(예 `intranet-app01`)도 이 방식으로 등록할 수 있다.
- **suffix 매칭**: 목록 값이 점(`.`)을 포함한 도메인이면 그 하위 서브도메인도 모두 허용한다(`staging.gx-internal.com` 등록 시 `foo.staging.gx-internal.com`도 허용).
- **과대 suffix 방지**: `com`처럼 라벨 하나만 등록해도 `evil.com`은 열리지 않는다 — suffix 매칭은 점을 포함한 등록값에만 적용되어 라벨 경계를 지킨다.

사설망(`10.x`/`172.16.x`/`192.168.x`) 스테이징은 별도 정책 결정이 필요하다:

- `SECURITY_PLUGIN_ALLOW_PRIVATE=1`은 **사설 대역 전체**를 한 번에 여는 스위치다. **사내 운영계가 사설망 IP를 쓸 수 있으므로**, 공인 IP가 아니라는 사실만으로 스테이징이라고 보장할 수 없다. 따라서 **기본적으로 설정하지 않는 것을 권고**한다.
- 대신 사설망 스테이징이라도 호스트/도메인이 고정돼 있으면 위 `SECURITY_PLUGIN_ALLOW_HOSTS`로 개별 등록하는 방식을 우선한다 — 어떤 대상이 열려 있는지 목록으로 남아 감사 가능하다.
- 사설 IP가 유동적(DHCP 등)이라 개별 등록이 불가능한 경우에만, 예외적으로 팀 합의 하에 `SECURITY_PLUGIN_ALLOW_PRIVATE=1`을 한시적으로 사용하고 점검이 끝나면 즉시 해제한다.
- `SECURITY_PLUGIN_ALLOW_PRIVATE=1`을 설정해도 링크로컬/메타데이터(`169.254.0.0/16`)는 열리지 않는다 — §1 ①에서 이미 절대 차단 대상이다.

## 3. 공인 대상 승인

공인 도메인/IP(사설망도 미등록 상태면 동일하게)는 기본 `needs-authorization`이며, 아래 두 가지를 **동시에** 충족해야 통과한다.

```bash
export SECURITY_PLUGIN_AUTHORIZED=1
python skills/exploiting-sql-injection/scripts/attack_sqli.py "https://api.company.com/search" --param q --authorized
```

1. 환경변수 `SECURITY_PLUGIN_AUTHORIZED=1`
2. 실행 시 `--authorized` 플래그

- 둘 중 하나만 있으면 여전히 차단된다(이중 게이트, 우발적 오발사 방지).
- **소유자 책임**: 이 이중 승인은 "권한 있는 대상임을 절차적으로 확인했다"는 코드 수준 게이트일 뿐, 실제 소유권과 테스트 승인 여부에 대한 책임은 실행한 운영자에게 있다. SQIsoft 사업부가 소유하지 않았거나 테스트 승인을 받지 않은 대상에는 이 옵션을 쓰지 않는다.
- §1 ①의 deny(운영 의심 호스트, 링크로컬/메타데이터)는 이 이중 승인으로도 뚫리지 않는다 — 항상 최우선으로 차단된다.

## 4. 자격증명 취급 규정 (MUST)

`attack_*.py`·`audit.py`는 계정 자격증명(비밀번호·토큰)을 세 경로로 받으며, 동시에 지정하면 **stdin > 환경변수 > 직접 인자** 순으로 우선한다. 경로마다 노출 정도가 다르다:

- **직접 인자**(`--token-a`, `--user-a-pw`, `--user-a-id` 등, 하위호환용)는 아래 경로로 **평문 노출**된다:
  - 프로세스 목록 — 리눅스/macOS `ps aux`·`ps -ef`, Windows 작업관리자/`tasklist`
  - 리눅스 `/proc/<pid>/cmdline`
  - 셸 히스토리 — `~/.bash_history`, `~/.zsh_history`, PowerShell `PSReadLine` 히스토리 파일

  같은 호스트를 쓰는 다른 사용자나 이후 세션이 그대로 읽을 수 있다.

- **환경변수 이름 전달**(`--user-a-pw-env <VAR>`·`--token-a-env <VAR>` 등)은 인자로 변수 **이름**만 넘기므로 위 프로세스 목록·`cmdline` 노출은 없다. 다만 비밀값은 여전히 프로세스의 환경변수 블록에 실제로 존재해 환경변수 조회 경로(리눅스 `/proc/<pid>/environ` 등)로는 노출될 수 있고, 값을 최초로 설정하는 `export`/`$env:` 명령 자체가 히스토리에 남을 수 있다 — **프로세스 노출이 잔존**한다.

- **`--creds-stdin`**은 stdin에서 JSON을 1회 읽어 처리하므로 프로세스 인자·환경변수 어디에도 비밀이 남지 않는다 — 세 경로 중 **프로세스 노출을 완전히 없애는 유일한 방식**이다. 다만 입력 시 `echo`로 비밀을 직접 타이핑하면 그 명령 자체가 셸 히스토리에는 남을 수 있다(프로세스 노출과는 별개 채널) — 완전히 피하려면 임시 파일 리다이렉트 등을 쓴다. 구체적 명령은 [RUNBOOK-dynamic.md](RUNBOOK-dynamic.md) §2를 참고한다.

**v0.5.0부터 지원됨**: 위 환경변수 이름 전달(`--user-a-pw-env`/`--token-a-env` 등)과 `--creds-stdin` 경로는 attack 4종(`exploiting-auth-session`·`exploiting-broken-access-control`·`exploiting-ssrf-and-open-redirect`·`exploiting-path-traversal-upload`)과 `audit.py`에 모두 배선되어 있다. `audit.py`는 이 경로로 받은 비밀을 내부에서 발사하는 자식 프로세스에도 cmd 인자 평문이 아닌 환경변수로 전달한다. **`--creds-stdin`을 기본으로 쓰고**, 자동화 스크립트 등에서 stdin 파이프 연결이 어려운 경우에만 `--*-env`로 대체한다(위 잔존 노출 한계를 감수하는 선택). 스택별 로그인 프로파일(`--login-profile`)을 포함한 전체 사용 절차는 [RUNBOOK-dynamic.md](RUNBOOK-dynamic.md)를 참고한다.

**현재 유효한 완화책(필수 — 입력 경로와 무관하게 적용)**:
- **단일 운영자 전용 격리 호스트**에서만 실행한다 — 공유·멀티유저 호스트에서는 절대 실행하지 않는다.
- 운영 계정과 분리된 **전용 테스트 계정**만 사용한다(실사용자 계정·운영 자격증명은 절대 사용 금지).
- 가능하면 히스토리를 남기지 않는 세션(예: `HISTFILE=` 비움, PowerShell 히스토리 비활성화)에서 실행한다.
- 가능하면 **`--creds-stdin`을 우선 사용**한다 — 프로세스 노출이 없는 유일한 입력 경로다.

**무효한 완화책(직접 인자에서 착각하지 말 것)**:
- 직접 인자에 셸 변수를 대입하는 방식(`--token-a "$TOKEN"`)은 프로세스 목록 노출을 막지 **못한다**. 셸이 실행(execve) 전에 `$TOKEN`을 실제 값으로 확장하므로 `/proc/<pid>/cmdline`에는 결국 평문이 그대로 실린다. 셸 히스토리 노출만 일부 완화될 뿐이다. 이 패턴 대신 **`--token-a-env TOKEN`**(값이 아니라 변수 **이름**을 전달)을 쓰면 최소한 `cmdline` 노출은 막을 수 있다 — 위 "환경변수 이름 전달" 항목을 따른다.

## 5. 파괴적 작업

기본은 **비파괴**다. 모든 `exploiting-*` 스킬은 원칙적으로 탐지용 페이로드만 발사하며 데이터를 변경·삭제하지 않는다. 유일한 예외는 `exploiting-path-traversal-upload`의 업로드 확인이며, 대상 서버에 실제 파일을 기록한다.

```bash
python skills/exploiting-path-traversal-upload/scripts/attack_pathupload.py \
    "https://staging.gx-internal.com" --upload-target "/api/v1/files" \
    --allow-destructive --authorized
```

- `--allow-destructive` 플래그가 없으면 업로드 검사 자체가 스킵된다(코드 레벨 차단 — `attack_pathupload.py`가 플래그 부재 시 검사를 건너뛰고 "--allow-destructive 필요"만 보고).
- **사람 승인 없이 이 플래그를 켜지 않는다** — 실행 전 운영자가 대상 소유권과 실행 필요성을 확인하고 승인한 뒤에만 실행한다.
- 업로드하는 마커 파일은 코드가 없는 무해한 표식이다: 파일명 `gxmarker_<6바이트 hex nonce>.jsp`, 내용은 `GXMARKER-<nonce>` 텍스트뿐(코드 실행 시도 없음).

**leftover 마커 파일 수동 삭제 절차** (자동 정리 기능은 없다):

1. 실행 결과(콘솔/`--json` 출력)의 `leftover` 필드 또는 `[정리 필요] 업로드된 마커 파일: ...` 메시지에서 업로드된 파일명(`gxmarker_*.jsp`)을 확인한다.
2. 대상 서버에 SSH/FTP/관리자 콘솔 등으로 접속해 업로드 디렉터리(또는 회수에 성공한 웹루트 경로)에서 해당 파일을 찾는다.
3. 파일을 수동으로 삭제한다 — 회수 조회(`--retrieve-base`)에 성공해 취약점이 확정된 경우에도 서버의 실물 파일은 스크립트가 지우지 않고 그대로 남는다.
4. 삭제 완료 여부를 점검 리포트(`reports/`)에 기록한다.

## 6. 점검 산출물 취급

- 점검 리포트(`reports/`)와 동적 공격 증거(`evidence/`, 스크린샷·HAR 등 `*.har`)는 `.gitignore`로 형상관리에서 제외된다 — 취약점 위치·시크릿 등 민감정보를 담고 있어 저장소에 커밋하지 않는다.
- 현재는 **로컬 보관만** 지원한다. 팀 단위 중앙 이력관리·티켓 연동은 아직 없다.
- 중앙 보관 방안(별도 저장소/티켓 첨부/사내 위키 연동 중 결정)은 **v0.7.0(Phase 4, 작업 O5)에서 확정 예정**이다.
- 그 전까지는 점검 완료 후 운영자가 필요 시 리포트를 수동으로 팀에 공유한다(예: 티켓 첨부).

---

관련 문서: [README.md](../README.md)(개요·설정) · [RUNBOOK-dynamic.md](RUNBOOK-dynamic.md)(동적 점검 실전 런북 — 이 정책을 실제 명령으로 구체화) · [ATTACK_SAFETY.md](../ATTACK_SAFETY.md)(공격형 스킬 안전 수칙 원문) · [severity-rubric.md](severity-rubric.md)(심각도 판정 기준)
