# 동적 점검 실전 런북 (RUNBOOK-dynamic)

`exploiting-*` 스킬(`attack_*.py`)과 통합 오케스트레이터(`audit.py`)로 **실제 동적(침투) 점검**을 안전하게 수행하는 절차. 자격증명 안전 입력(`--creds-stdin`/`--*-env`)과 스택별 로그인 프로파일(`--login-profile`)로 sef-2026 표준 스택 외의 프로젝트에도 동적 점검을 이식하는 방법을 다룬다.

실행 전 [OPERATIONS.md](OPERATIONS.md)(운영정책 전문)와 [../ATTACK_SAFETY.md](../ATTACK_SAFETY.md)(안전 수칙 원문)를 반드시 먼저 읽는다. 이 문서는 두 문서의 정책을 실제 명령으로 구체화한 것이며, 내용이 어긋나면 정책 문서가 우선한다. 명령 레퍼런스 전체는 [../USAGE.md](../USAGE.md)를 참고한다.

---

## 1. 사전 준비

- [ ] **격리 호스트** — 단일 운영자 전용 호스트에서만 실행한다. 공유·멀티유저 호스트에서는 절대 실행하지 않는다(OPERATIONS.md §4).
- [ ] **전용 테스트 계정** — 운영 계정·실사용자 계정을 절대 사용하지 않는다. 이후 예시의 `tester`/`alice`/`bob`은 모두 이런 전용 테스트 계정을 가리킨다.
- [ ] **히스토리 최소화** — 가능하면 셸 히스토리를 남기지 않는 세션에서 실행한다.

  ```bash
  # bash 예 — 이 세션만 히스토리 미기록
  unset HISTFILE
  ```
  ```powershell
  # PowerShell 예 — 이 세션만 히스토리 미기록
  Set-PSReadLineOption -HistorySaveStyle SaveNothing
  ```

- [ ] **대상 등록** — `tools/scope_guard.py`가 발사 전 대상을 반드시 검증한다(fail-closed). 대상 유형별로:

  | 대상 | 필요한 조치 |
  |---|---|
  | 로컬(`localhost`/`127.0.0.1`) | 없음 — 자동 허용 |
  | 사내 스테이징(호스트 고정) | `SECURITY_PLUGIN_ALLOW_HOSTS`에 등록 |
  | 사설망 IP(유동적이라 개별 등록 불가) | 팀 합의 하에 한시적으로만 `SECURITY_PLUGIN_ALLOW_PRIVATE=1` |
  | 공인 도메인/IP | `SECURITY_PLUGIN_AUTHORIZED=1` + 실행 시 `--authorized` 둘 다 필요(소유자 책임) |

  ```bash
  # bash — 사내 스테이징을 상시 허용 목록에 등록(세션 한정. 영구화하려면 셸 프로파일에 추가)
  export SECURITY_PLUGIN_ALLOW_HOSTS="staging.gx-internal.com"
  ```
  ```powershell
  # PowerShell
  $env:SECURITY_PLUGIN_ALLOW_HOSTS = "staging.gx-internal.com"
  ```

  세부 판정 규칙(우선순위·정수/IPv6 위장 차단 등)은 OPERATIONS.md §1을 참고한다.

- [ ] **대상 앱 기동 확인** — 동적 점검은 실행 중인 대상이 필요하다(정적 진단과 달리 소스만으로는 불가). 로컬이면 `./gradlew bootRun` 등으로 먼저 띄운다.
- [ ] **테스트 데이터 준비** — 위 전용 계정으로 로그인 가능한 상태인지, IDOR 점검용으로 A 계정 소유 리소스 ID가 있는지 미리 확보한다.

---

## 2. 자격증명 안전 입력

`attack_*.py`·`audit.py`는 비밀(비밀번호·토큰)을 3가지 경로로 받는다. 우선순위는 **stdin > env > direct**이며, 여러 경로를 동시에 지정하면 stdin이 이기고 `[!] 자격증명 다중 소스 — 우선순위(stdin>env>direct) 적용`이 stderr에 출력된다.

| 방식 | 플래그 | 프로세스 인자(`ps`/`tasklist`/`cmdline`) | 환경변수 조회 | 셸 히스토리 | 권장도 |
|---|---|:---:|:---:|:---:|---|
| stdin JSON | `--creds-stdin` | 노출 없음 | 노출 없음 | 입력 방식에 따라 다름(아래 참고) | **권장** |
| 환경변수 이름 | `--user-a-pw-env`/`--token-a-env` 등 | 노출 없음(이름만 전달) | **노출 가능**(잔존) | export 시점에 남을 수 있음 | 차선 |
| 직접 인자 | `--user-a-pw`/`--token-a` | **노출**(평문) | 해당없음 | **노출**(평문) | 하위호환용, 비권장 |

### 2.1 `--creds-stdin` (권장)

stdin으로 JSON 1회를 읽어 `user_a_pw`·`token_a`(attack_access.py는 `user_b_pw`·`token_b`도) 키로 매핑한다. 비밀이 CLI 인자로 전혀 넘어가지 않으므로 프로세스 목록·환경변수 조회 어디에도 남지 않는다.

```bash
echo '{"user_a_pw":"<테스트계정 비밀번호>","token_a":""}' \
  | python skills/exploiting-auth-session/scripts/attack_auth.py http://localhost:8080 \
      --creds-stdin --user-a-id tester --probe /api/v1/users/me
```

> **주의(히스토리)**: 위처럼 `echo`로 입력하면 프로세스 인자·환경변수는 안전하지만, **`echo` 명령 자체(비밀 포함)가 셸 히스토리에는 남을 수 있다** — 프로세스 노출과 히스토리 노출은 별개 채널이다. 히스토리까지 피하려면 자격증명을 임시 파일로 만들어 리다이렉트하고 즉시 삭제한다.

```bash
# bash — 히스토리에 비밀이 남지 않는 방식
cat > /tmp/creds.json <<'EOF'
{"user_a_pw":"<테스트계정 비밀번호>"}
EOF
python skills/exploiting-auth-session/scripts/attack_auth.py http://localhost:8080 \
    --creds-stdin --user-a-id tester --probe /api/v1/users/me --json < /tmp/creds.json
rm -f /tmp/creds.json
```

```powershell
# PowerShell — `<` 리다이렉트는 지원하지 않으므로 Get-Content로 파이프한다
'{"user_a_pw":"<테스트계정 비밀번호>"}' | Set-Content -NoNewline creds.json
Get-Content creds.json | python skills/exploiting-auth-session/scripts/attack_auth.py http://localhost:8080 `
    --creds-stdin --user-a-id tester --probe /api/v1/users/me --json
Remove-Item creds.json
```

접근통제(`attack_access.py`)는 A/B 두 계정을 동시에 stdin으로 넘길 수 있다:

```bash
echo '{"user_a_pw":"apw","user_b_pw":"bpw"}' \
  | python skills/exploiting-broken-access-control/scripts/attack_access.py http://localhost:8080 \
      --creds-stdin --user-a-id alice --user-b-id bob --resource-id <A소유리소스ID> \
      --scan reports/scan_access.json --json
```

### 2.2 `--user-a-pw-env`/`--token-a-env` (차선 — 프로세스 노출 잔존)

값이 아니라 **환경변수 이름**을 인자로 받는다.

```bash
export GXSEC_USER_A_PW="<테스트계정 비밀번호>"
python skills/exploiting-auth-session/scripts/attack_auth.py http://localhost:8080 \
    --user-a-id tester --user-a-pw-env GXSEC_USER_A_PW --probe /api/v1/users/me --json
```

```powershell
$env:GXSEC_USER_A_PW = "<테스트계정 비밀번호>"
python skills/exploiting-auth-session/scripts/attack_auth.py http://localhost:8080 `
    --user-a-id tester --user-a-pw-env GXSEC_USER_A_PW --probe /api/v1/users/me --json
```

> **한계(프로세스 노출 잔존)**: `ps aux`/`tasklist`나 `/proc/<pid>/cmdline` 같은 **명령행 인자 조회**로는 변수 이름만 보이고 값 자체는 보이지 않는다 — 값을 셸이 직접 인자로 확장해 넘기던 과거 `--token-a "$TOKEN"` 안티패턴보다는 개선된 방식이다. 다만 비밀값은 여전히 해당 프로세스의 **환경변수 블록**에 실제로 존재하므로, 환경변수를 조회할 수 있는 경로(리눅스 `/proc/<pid>/environ`, Windows는 관리자 권한의 프로세스 조사 도구 등)로는 노출될 수 있고, 그 값을 최초로 `export`/`$env:`로 설정하는 셸 명령 자체가 히스토리에 남을 수 있다. 즉 **명령행 인자 노출은 없지만 프로세스 노출이 완전히 사라지지는 않는다** — 완전한 비노출은 `--creds-stdin`뿐이다.

### 2.3 직접 인자 (하위호환 — 비권장)

```bash
python skills/exploiting-auth-session/scripts/attack_auth.py http://localhost:8080 \
    --user-a-id tester --user-a-pw "<테스트계정 비밀번호>" --probe /api/v1/users/me --json
```

프로세스 목록·`/proc/<pid>/cmdline`·셸 히스토리 모두에 평문 노출된다. 기존 스크립트·자동화와의 하위호환을 위해 유지될 뿐이며, 운영 절차에서는 사용하지 않는다.

### 2.4 audit.py 경유 — 자식 프로세스로 자동 전달

`audit.py`도 동일한 `--creds-stdin`/`--*-env`/직접 인자를 지원한다. `--creds-stdin`이나 `--*-env`로 받은 비밀은 `audit.py`가 내부에서 발사하는 4종 자식 프로세스(`attack_auth.py` 등)에도 **cmd 인자 평문이 아니라 환경변수로** 전달한다(자식 cmd에는 `--token-a-env GXSEC_TOKEN_A`만 실리고 실제 값은 자식의 `env`로만 넘어간다). 이 배선은 자동이라 운영자가 별도로 조작할 필요가 없다 — `audit.py`에도 stdin/env 플래그를 그대로 쓰면 된다(§4의 예시 참고).

---

## 3. 스택별 로그인 프로파일

`--login-profile <name|path>`로 로그인 형식(경로·바디·토큰 위치·인증 방식)을 외부화한다.

- **name 형태**(경로 구분자 없고 `.json`으로 끝나지 않음) → `profiles/<name>.json` 내장 프로파일을 로드한다.
- **path 형태**(`/`·`\` 포함 또는 `.json`으로 끝남) → 지정한 파일을 그대로 로드한다.
- 우선순위는 **개별 CLI 인자 > 프로파일 > 코드 기본값**이다 — 프로파일을 지정해도 `--auth-mode`처럼 개별 인자를 함께 주면 개별 인자가 이긴다.
- 허용 키는 `login_path`·`body_template`·`token_path`·`id_field`·`pw_field`·`auth_mode` 6개뿐이다. 다른 키가 있으면 즉시 `RuntimeError`로 거부된다(오탈자 방지).
- 4개 attack 스크립트(`attack_auth`/`attack_access`/`attack_ssrf`/`attack_pathupload`)와 `audit.py` 모두 동일하게 지원한다.

### 3.1 `sef-2026` — Spring Boot(Bearer)

`profiles/sef-2026.json`:

```json
{
  "login_path": "/api/v1/auth/login",
  "body_template": "{\"lgnId\":\"{id}\",\"password\":\"{pw}\"}",
  "token_path": "data.accessToken",
  "auth_mode": "bearer"
}
```

```bash
python skills/exploiting-auth-session/scripts/attack_auth.py http://localhost:8080 \
    --login-profile sef-2026 --user-a-id tester --user-a-pw-env GXSEC_USER_A_PW \
    --probe /api/v1/users/me --json
```

> sef-2026 프로파일 값은 attack 스크립트의 **코드 기본값과 동일**하므로, `--login-profile` 없이 실행해도 결과는 같다. 프로파일의 실질적 가치는 **sef-2026이 아닌 스택**(아래 jsp-form 등)을 이식할 때 나온다.

### 3.2 `jsp-form` — JSP/Servlet(폼 로그인 + 세션쿠키)

`profiles/jsp-form.json`:

```json
{
  "login_path": "/login.do",
  "id_field": "j_username",
  "pw_field": "j_password",
  "auth_mode": "cookie"
}
```

```bash
python skills/exploiting-auth-session/scripts/attack_auth.py http://localhost:8080 \
    --login-profile jsp-form --user-a-id tester --user-a-pw-env GXSEC_USER_A_PW \
    --success-path /main --json
```

> **`--success-path`는 프로파일 허용 키에 없어 반드시 CLI에서 직접 지정해야 한다.** cookie 모드는 로그인 성공을 응답 리다이렉트 `Location`이 `--success-path`와 일치하는지로 판정하므로, 이 값이 없으면 즉시 `RuntimeError`(로그인 실패)로 거부된다. cookie 모드에서는 Bearer 토큰이 없어 JWT 변조·토큰 재사용 검사는 자동으로 skip되고, 쿠키 속성·보호 엔드포인트 도달성만 검사한다.

### 3.3 커스텀 프로파일 작성

1. `profiles/<name>.json`으로 두면 내장 프로파일처럼 `--login-profile <name>`으로 쓸 수 있고, 임의 경로에 두면 `--login-profile <경로>`로 직접 지정한다.
2. 허용 키만 사용한다 — `login_path`(로그인 엔드포인트) · `body_template`(JSON 바디, `{id}`/`{pw}` 치환 — bearer 전용) · `token_path`(로그인 응답에서 토큰을 꺼낼 점(`.`) 표기 경로 — bearer 전용) · `id_field`/`pw_field`(폼 필드명 — cookie 전용) · `auth_mode`(`bearer`|`cookie`).
3. 예: 로그인 경로·바디가 다른 제3의 Spring 앱

   ```json
   {
     "login_path": "/auth/signin",
     "body_template": "{\"username\":\"{id}\",\"password\":\"{pw}\"}",
     "token_path": "accessToken",
     "auth_mode": "bearer"
   }
   ```

   저장 후 `--login-profile profiles/my-app.json`(또는 절대경로)로 사용한다.

---

## 4. 클래스별 동적 점검 시나리오 (최소 1사이클)

아래 4종은 모두 `scope_guard` 통과 → 로그인/토큰 확보 → 실제 발사 → 판정 순으로 동작한다. 계정은 §2의 안전 입력 방식(예시는 `--user-a-pw-env`)을 쓴다.

### 4.1 접근통제 — BFLA/IDOR

```bash
# 1) 정적 후보 도출
python skills/detecting-broken-access-control/scripts/scan_access.py "D:\SQ\sqisoft-sef-2026" --json > reports/scan_access.json

# 2) 동적 발사(단독 실행) — --scan 없이는 표적이 비어 있어 아무것도 발사되지 않으므로 필수
python skills/exploiting-broken-access-control/scripts/attack_access.py http://localhost:8080 \
    --scan reports/scan_access.json \
    --user-a-id alice --user-a-pw-env GXSEC_USER_A_PW \
    --user-b-id bob --user-b-pw-env GXSEC_USER_B_PW \
    --resource-id <A소유리소스ID> --json
```

audit 경유(정적 9종 + 접근통제 동적을 한 번에):

```bash
python skills/auditing-web-application-security/scripts/audit.py "D:\SQ\sqisoft-sef-2026" \
    --target http://localhost:8080 \
    --user-a-id alice --user-a-pw-env GXSEC_USER_A_PW \
    --user-b-id bob --user-b-pw-env GXSEC_USER_B_PW \
    --resource-id <A소유리소스ID> --json
```

**판정**: BFLA는 일반 토큰 2xx이면서 무토큰(anon) non-2xx일 때 취약(anon도 2xx면 공개 엔드포인트로 제외). IDOR는 B(타인) 토큰으로 A 소유 리소스 조회가 2xx면 취약 후보, 403이면 방어로 즉시 확정한다.

### 4.2 인증·세션·JWT

```bash
python skills/exploiting-auth-session/scripts/attack_auth.py http://localhost:8080 \
    --user-a-id tester --user-a-pw-env GXSEC_USER_A_PW \
    --probe /api/v1/users/me --json
```

audit 경유(동일 조건 + `--probe` 필수 — `--scan` 자동추출은 단독 실행 전용):

```bash
python skills/auditing-web-application-security/scripts/audit.py "D:\SQ\sqisoft-sef-2026" \
    --target http://localhost:8080 \
    --user-a-id tester --user-a-pw-env GXSEC_USER_A_PW \
    --probe /api/v1/users/me --json
```

**판정**: JWT 4변형(`alg=none`·서명 제거·역할 변조·`exp` 과거) 발사 후 2xx면 서명 미검증 취약, 401/403이면 방어. 로그아웃 후 토큰 재사용은 2xx면 취약이나, 구조적으로 무상태인 JWT는 서버측 즉시 폐기가 원천 불가능해 "미확정"으로 표기한다. 로그인 응답 쿠키의 Secure/HttpOnly/SameSite 누락도 함께 점검한다.

### 4.3 SSRF·오픈 리다이렉트

```bash
python skills/exploiting-ssrf-and-open-redirect/scripts/attack_ssrf.py http://localhost:8080 \
    --user-a-id tester --user-a-pw-env GXSEC_USER_A_PW \
    --redirect-target "/go?u=" --ssrf-target "/api/fetch?url=" --json
```

audit 경유:

```bash
python skills/auditing-web-application-security/scripts/audit.py "D:\SQ\sqisoft-sef-2026" \
    --target http://localhost:8080 \
    --user-a-id tester --user-a-pw-env GXSEC_USER_A_PW \
    --redirect-target "/go?u=" --ssrf-target "/api/fetch?url=" --json
```

**판정**: `Location` 응답 헤더가 외부 호스트를 가리키면 오픈 리다이렉트 취약. OOB canary(127.0.0.1 루프백에 자동 기동·자동 종료)로 콜백을 수신하면 블라인드 SSRF까지 확정한다. **원격 대상은 콜백 미수신이 "안전"을 뜻하지 않는다** — canary가 루프백 전용이라 대상이 자기 로컬로 실제 요청을 시도했어도 결과가 돌아오지 않을 수 있다(§5와 [USAGE.md §4](../USAGE.md#4-시나리오별-사용) 참고). 원격 스테이징의 블라인드 SSRF를 확정하려면 `attack_ssrf.py`를 단독 실행하고 `--canary-host`로 대상이 도달 가능한 광고 호스트를 지정한다.

### 4.4 경로조작 / 파일 업로드

경로조작(읽기전용, 비파괴):

```bash
python skills/exploiting-path-traversal-upload/scripts/attack_pathupload.py http://localhost:8080 \
    --user-a-id tester --user-a-pw-env GXSEC_USER_A_PW \
    --traversal-target "/download?filePath=" --json
```

파일 업로드(파괴적 — 대상 서버에 실제 파일을 기록하므로 `--allow-destructive` 명시 필요, 사람 승인 후에만 실행):

```bash
python skills/exploiting-path-traversal-upload/scripts/attack_pathupload.py http://localhost:8080 \
    --user-a-id tester --user-a-pw-env GXSEC_USER_A_PW \
    --upload-target "/api/v1/files" --allow-destructive \
    --retrieve-base "http://localhost:8080/files" --json
```

audit 경유(둘 다, 업로드는 `--allow-destructive` 동일하게 필요):

```bash
python skills/auditing-web-application-security/scripts/audit.py "D:\SQ\sqisoft-sef-2026" \
    --target http://localhost:8080 \
    --user-a-id tester --user-a-pw-env GXSEC_USER_A_PW \
    --traversal-target "/download?filePath=" \
    --upload-target "/api/v1/files" --allow-destructive \
    --retrieve-base "http://localhost:8080/files" --json
```

**판정**: 경로조작은 응답 본문에 파일 내용 시그니처(`root:.*:0:0:`·`<web-app`·`[fonts]`)가 나오면 취약. 2xx인데 시그니처가 없으면 방어, non-2xx·무응답은 "미확정(미도달/차단 추정)"으로 구분한다(엔드포인트 오지정을 방어로 오인하지 않기 위함). 업로드는 위험 확장자(`.jsp`, 코드 없는 무해 마커) 수용이 2xx면 취약(Medium), `--retrieve-base`로 회수까지 성공하면 웹루트 저장 확정(High)이다.

**leftover**: 업로드가 실제 수용(accepted)되면 대상 서버에 마커 파일(`gxmarker_<6바이트 hex nonce>.jsp`, 내용은 `GXMARKER-<nonce>` 텍스트뿐)이 남는다 — 자동 삭제 기능은 없다. 정리 절차는 §5 참고.

---

## 5. 판정 해석과 leftover 정리

### 5.1 단독 attack_*.py의 finding 판정

각 finding은 `vulnerable`(취약) / `undetermined`(미확정 — 증거 불충분, 방어로 오표기하지 않음) / `skipped`(미발사 — 조건 미충족) / `error`(발사 중 예외) 중 하나로 표기된다. `--json` 출력의 `findings` 배열을 직접 읽거나, 사람이 읽는 요약(`--json` 없이 실행)에서 `[취약 후보]`/`[방어/정상]`/`[미발사: …]`/`[발사실패: …]` 로 확인한다.

### 5.2 audit.py의 클래스별 confidence

`audit.py --json`의 `phases.access_dynamic`/`auth_dynamic`/`ssrf_dynamic`/`pathupload_dynamic`은 아래 핵심 3상태 중 하나를 `confidence` 필드로 보고한다:

| confidence | 의미 | 언제 나오나 |
|---|---|---|
| `dynamic` | 실제 발사 완료 — findings에 확정 판정 포함 | 표적(클래스별 필요 시)과 계정이 모두 제공되고 로그인에 성공, 그리고 최소 1건 이상 실제로 발사됨 |
| `partial` | 일부만 발사(**인증 클래스 전용** — 쿠키 속성만 발사되고 JWT 변조·재사용은 정적 추정에 머묾) | 로그인 계정은 있으나 `--probe` 미지정 |
| `static-only` | 발사 안 함 — 정적 후보/추정 유지 | 계정·표적 중 하나라도 없음, 업로드처럼 파괴적 게이트(`--allow-destructive`) 미충족, 또는 발사는 했으나 확정 finding이 0건(모두 skip) |

실제 발사 결과 예시(테스트 계정 미제공·대상 미기동 상태로 실행했을 때의 실측 출력):

```json
"auth_dynamic": {
  "confidence": "login-failed",
  "detail": "로그인 요청 실패: http://127.0.0.1:59991/api/v1/auth/login — ConnectionError",
  "returncode": 2
}
```
```json
"ssrf_dynamic": {
  "confidence": "static-only",
  "note": "SSRF/오픈리다이렉트 표적 미지정(--redirect-target/--ssrf-target) → 정적 추정. 주입점 지정 시 동적 확정."
}
```

위 두 상태는 핵심 3상태 외에 실제로 나타나는 보조 상태다 — 함께 알아두면 결과 해석이 빨라진다:

- **`login-failed`** — 로그인을 시도했으나 실패(연결 거부·자격 오류·응답 형식 오류 등). "취약/방어 미발견"과는 구분되는 상태다.
- **`blocked`**(`scope_guard`) — 대상이 안전 게이트에서 차단됨(운영 의심 호스트·미승인 공인 대상 등). `detail` 필드에 사유가 담긴다.
- **`error`** — 자식 프로세스가 비정상 종료됐거나 타임아웃 등으로 발사 자체가 실패. "방어"로 은폐하지 않고 정직하게 표기한다.
- **`skipped`** — 해당 클래스의 attack 스크립트 자체가 없거나(설치 이상), 정적 스캔 부분 실패로 동적 연계를 보류한 경우.

> **SSRF 원격 대상 주의**: `ssrf_dynamic`이 `dynamic`이어도 findings의 `ssrf` kind는 콜백 미수신 시 "방어"가 아니라 "미확정"으로 렌더링된다(원격/비동기 대상이면 실제로 취약해도 루프백 canary로는 콜백을 못 받을 수 있어서다). `dynamic`=발사 완료일 뿐, 개별 finding의 취약/방어는 따로 읽어야 한다.

### 5.3 leftover 정리 (업로드 마커 파일)

자동 정리 기능은 없다. 아래를 수동으로 수행한다:

1. 실행 결과(콘솔의 `[정리 필요] 업로드된 마커 파일: …` 또는 `--json` 출력에서 각 finding 안의 `leftover` 필드)에서 파일명(`gxmarker_*.jsp`)을 확인한다.
2. 대상 서버에 SSH/FTP/관리자 콘솔 등으로 접속해 업로드 디렉터리(또는 회수에 성공한 웹루트 경로)에서 해당 파일을 찾는다.
3. 파일을 수동으로 삭제한다 — 회수(`--retrieve-base`)에 성공해 취약점이 확정된 경우에도 서버의 실물 파일은 스크립트가 지우지 않는다.
4. 삭제 완료 여부를 점검 리포트(`reports/`)에 기록한다.

---

관련 문서: [../README.md](../README.md)(개요·설치) · [../USAGE.md](../USAGE.md)(전체 명령 레퍼런스·시나리오) · [OPERATIONS.md](OPERATIONS.md)(운영정책 — 대상범위·자격증명·파괴적 작업 전문) · [../ATTACK_SAFETY.md](../ATTACK_SAFETY.md)(공격형 스킬 안전 수칙 원문) · [severity-rubric.md](severity-rubric.md)(심각도 판정 기준)
