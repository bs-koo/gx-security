# P2 동적 파일럿 (v0.5.0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 동적 침투 엔진을 격리 호스트에서 안전하게 운영할 수 있도록, 자격증명을 프로세스 노출 없이 입력하고(env/stdin) 로그인 형식을 프로파일로 이식 가능하게 만들어 v0.5.0을 릴리스한다.

**Architecture:** 자격증명 해석과 로그인 프로파일 로딩을 `tools/dyn_session.py`에 **공용 헬퍼로 집약**하고, 4개 `attack_*.py`(auth/access/ssrf/pathupload)와 `audit.py`가 이를 위임한다. `audit.py`는 자식 subprocess에 자격증명을 **환경변수로 전달**(cmd 평문 회피)한다. 기존 CLI 인자·동작은 100% 하위호환 유지한다.

**Tech Stack:** Python 3.11 · requests · unittest · JSON 프로파일

## Global Constraints

- Python 3.11. 런타임 의존성 `requests`·`PyYAML`만(신규 의존성 금지).
- **하위호환 필수**: 기존 CLI 인자(`--user-a-pw`·`--token-a`·`--login-path`·`--body-template`·`--token-path`·`--auth-mode`·`--id-field`/`--pw-field`/`--success-path`)의 동작과 바이트 출력은 불변. 기존 attack/audit/dyn_session 테스트가 하나도 깨지면 안 된다.
- 기존 전체 스위트 green 유지: `python -m unittest discover -s tests -p "test_*.py"` (P1 기준 341 tests).
- **자격증명 미노출(D1 수용의 핵심)**: `--creds-stdin` 경로로 넘긴 값은 `sys.argv`에도, `audit.py`가 생성하는 **자식 subprocess의 cmd 리스트에도** 나타나지 않아야 한다(테스트로 강제).
- 커밋: 한국어 `type: 설명` + `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`. 모든 파일 UTF-8.
- SemVer 목표 **0.5.0**(P2 완료 시 버전 bump는 마지막 릴리스 정리 단계에서; `test_version_consistency.py`의 `EXPECTED`도 함께 갱신).

## 설계 결정 (모든 Task의 전제)

**자격증명 소스 우선순위**: `stdin > env > direct(CLI)`. 세 소스 중 하나만 값을 제공한다. 둘 이상 동시 지정 시 우선순위대로 쓰되 stderr 경고.
- `--creds-stdin`: stdin에서 JSON 1회 읽어 `{"user_a_pw":..,"token_a":..,"user_b_pw":..}` 등 키로 매핑. **프로세스 노출을 실제로 없애는 유일한 경로.**
- `--user-a-pw-env <VAR>`·`--token-a-env <VAR>` 등: 환경변수 **이름**을 받아 `os.environ`에서 값 로드. 셸 히스토리는 완화되나 `/proc/pid/cmdline` 노출은 못 막는다(셸이 execve 전 확장 — ATTACK_SAFETY 기존 서술과 일치).
- direct: 기존 `--user-a-pw`·`--token-a`(하위호환, 노출 있음).

**로그인 프로파일**: `{login_path, body_template, token_path, id_field, pw_field, auth_mode}`의 부분집합을 담은 JSON. `--login-profile <name|path>`로 로드하되, **명시된 개별 CLI 인자가 프로파일 값을 오버라이드**한다(개별 인자 > 프로파일 > 코드 기본값).

---

## Task 1: dyn_session 자격증명 해석 헬퍼

**Files:**
- Modify: `tools/dyn_session.py` (신규 함수 추가, 기존 함수 불변)
- Test: `tests/test_dyn_credentials.py` (신규)

**Interfaces:**
- Produces:
  - `read_stdin_creds() -> dict` — `sys.stdin`에서 JSON 1회 읽어 dict 반환. 비어있거나 파싱 실패 시 `RuntimeError`. TTY이면(파이프 없음) `RuntimeError`.
  - `resolve_secret(*, direct=None, env_var=None, stdin_creds=None, stdin_key=None) -> str|None` — 우선순위 `stdin_creds[stdin_key] > os.environ[env_var] > direct`. 둘 이상 소스가 값을 주면 `sys.stderr`에 `[!] 자격증명 다중 소스 — 우선순위(stdin>env>direct) 적용` 경고. 최종 값 없으면 None.

- [ ] **Step 1: 실패 테스트 작성** — `tests/test_dyn_credentials.py`

```python
"""자격증명 env/stdin 해석 헬퍼(D1) 단위 검증."""
import io
import os
import sys
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools import dyn_session


class TestResolveSecret(unittest.TestCase):
    def test_direct_only(self):
        self.assertEqual(dyn_session.resolve_secret(direct="pw1"), "pw1")

    def test_env_over_direct(self):
        with mock.patch.dict(os.environ, {"MY_PW": "envpw"}):
            self.assertEqual(
                dyn_session.resolve_secret(direct="pw1", env_var="MY_PW"), "envpw")

    def test_stdin_over_env(self):
        with mock.patch.dict(os.environ, {"MY_PW": "envpw"}):
            self.assertEqual(
                dyn_session.resolve_secret(
                    direct="pw1", env_var="MY_PW",
                    stdin_creds={"user_a_pw": "spw"}, stdin_key="user_a_pw"),
                "spw")

    def test_env_name_missing_falls_through(self):
        # env_var 이름이 환경에 없으면 direct로 폴백
        self.assertEqual(
            dyn_session.resolve_secret(direct="pw1", env_var="NOPE_XYZ"), "pw1")

    def test_none_when_no_source(self):
        self.assertIsNone(dyn_session.resolve_secret())


class TestReadStdinCreds(unittest.TestCase):
    def test_parses_json(self):
        with mock.patch.object(sys, "stdin", io.StringIO('{"token_a":"T"}')):
            with mock.patch.object(sys.stdin, "isatty", return_value=False, create=True):
                self.assertEqual(dyn_session.read_stdin_creds(), {"token_a": "T"})

    def test_raises_on_bad_json(self):
        with mock.patch.object(sys, "stdin", io.StringIO("not json")):
            with mock.patch.object(sys.stdin, "isatty", return_value=False, create=True):
                with self.assertRaises(RuntimeError):
                    dyn_session.read_stdin_creds()


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: 실행하여 실패 확인**

Run: `python -m unittest tests.test_dyn_credentials -v`
Expected: FAIL — `AttributeError: module 'tools.dyn_session' has no attribute 'resolve_secret'`

- [ ] **Step 3: dyn_session에 헬퍼 구현**

`tools/dyn_session.py`에 아래 두 함수를 추가한다(기존 함수 불변, `import os`는 이미 존재):

```python
def read_stdin_creds():
    """--creds-stdin 시 sys.stdin에서 JSON 1회 읽어 dict 반환.
    TTY(파이프 없음)·빈 입력·비-JSON은 RuntimeError."""
    if getattr(sys.stdin, "isatty", lambda: False)():
        raise RuntimeError("--creds-stdin은 stdin 파이프가 필요합니다(TTY 감지)")
    raw = sys.stdin.read()
    if not raw.strip():
        raise RuntimeError("--creds-stdin: stdin이 비어 있습니다")
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        raise RuntimeError("--creds-stdin: stdin JSON 파싱 실패")
    if not isinstance(data, dict):
        raise RuntimeError("--creds-stdin: JSON 객체(dict)여야 합니다")
    return data


def resolve_secret(*, direct=None, env_var=None, stdin_creds=None, stdin_key=None):
    """자격증명 한 개를 우선순위 stdin > env > direct 로 해석. 없으면 None.
    둘 이상 소스가 값을 주면 stderr 경고."""
    vals = {}
    if stdin_creds and stdin_key and stdin_creds.get(stdin_key) is not None:
        vals["stdin"] = str(stdin_creds[stdin_key])
    if env_var and os.environ.get(env_var) is not None:
        vals["env"] = os.environ[env_var]
    if direct is not None:
        vals["direct"] = direct
    if len(vals) > 1:
        print("[!] 자격증명 다중 소스 — 우선순위(stdin>env>direct) 적용", file=sys.stderr)
    for src in ("stdin", "env", "direct"):
        if src in vals:
            return vals[src]
    return None
```

- [ ] **Step 4: 실행하여 통과 확인**

Run: `python -m unittest tests.test_dyn_credentials -v`
Expected: PASS (7 tests)

- [ ] **Step 5: 회귀 확인 + 커밋**

Run: `python -m unittest discover -s tests -p "test_*.py"` → OK (기존 + 7)
```bash
git add tools/dyn_session.py tests/test_dyn_credentials.py
git commit -m "feat: dyn_session 자격증명 env/stdin 해석 헬퍼 추가(D1 기반)" -m "resolve_secret(stdin>env>direct)·read_stdin_creds로 프로세스 노출 없는 자격증명 입력 기반 마련. 기존 함수·동작 불변." -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: dyn_session 로그인 프로파일 로더 + 기본 프로파일

**Files:**
- Modify: `tools/dyn_session.py`
- Create: `profiles/sef-2026.json`, `profiles/jsp-form.json`
- Test: `tests/test_login_profile.py` (신규)

**Interfaces:**
- Consumes: 없음
- Produces: `load_login_profile(name_or_path) -> dict` — `name`이면 `<plugin_root>/profiles/<name>.json`, 경로 형태(`/`·`\`·`.json` 포함)면 그 파일을 로드. 허용 키만(`login_path`·`body_template`·`token_path`·`id_field`·`pw_field`·`auth_mode`) 반환, 그 외 키는 `RuntimeError`. 파일 없음/비-JSON도 `RuntimeError`.

- [ ] **Step 1: 실패 테스트 작성** — `tests/test_login_profile.py`

```python
"""로그인 프로파일 로더(D2) 단위 검증."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools import dyn_session

ROOT = Path(__file__).resolve().parent.parent


class TestLoadLoginProfile(unittest.TestCase):
    def test_builtin_sef_2026(self):
        prof = dyn_session.load_login_profile("sef-2026")
        self.assertEqual(prof["login_path"], "/api/v1/auth/login")
        self.assertEqual(prof["token_path"], "data.accessToken")

    def test_builtin_jsp_form(self):
        prof = dyn_session.load_login_profile("jsp-form")
        self.assertEqual(prof["auth_mode"], "cookie")

    def test_path_form(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "custom.json"
            p.write_text(json.dumps({"login_path": "/x"}), encoding="utf-8")
            self.assertEqual(dyn_session.load_login_profile(str(p))["login_path"], "/x")

    def test_unknown_key_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.json"
            p.write_text(json.dumps({"evil": 1}), encoding="utf-8")
            with self.assertRaises(RuntimeError):
                dyn_session.load_login_profile(str(p))

    def test_missing_name_raises(self):
        with self.assertRaises(RuntimeError):
            dyn_session.load_login_profile("nonexistent-xyz")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: 실행하여 실패 확인**

Run: `python -m unittest tests.test_login_profile -v`
Expected: FAIL — `load_login_profile` 없음

- [ ] **Step 3: 프로파일 파일 + 로더 구현**

`profiles/sef-2026.json`:
```json
{
  "login_path": "/api/v1/auth/login",
  "body_template": "{\"lgnId\":\"{id}\",\"password\":\"{pw}\"}",
  "token_path": "data.accessToken",
  "auth_mode": "bearer"
}
```

`profiles/jsp-form.json`:
```json
{
  "login_path": "/login.do",
  "id_field": "j_username",
  "pw_field": "j_password",
  "auth_mode": "cookie"
}
```

`tools/dyn_session.py`에 추가:
```python
_PROFILE_KEYS = {"login_path", "body_template", "token_path", "id_field", "pw_field", "auth_mode"}


def load_login_profile(name_or_path):
    """로그인 프로파일(dict) 로드. name이면 profiles/<name>.json, 경로면 그 파일.
    허용 키 외/파일없음/비-JSON은 RuntimeError."""
    if any(c in name_or_path for c in ("/", "\\")) or name_or_path.endswith(".json"):
        path = name_or_path
    else:
        path = os.path.join(_PLUGIN_ROOT, "profiles", name_or_path + ".json")
    if not os.path.isfile(path):
        raise RuntimeError(f"로그인 프로파일을 찾을 수 없음: {path}")
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (ValueError, OSError):
        raise RuntimeError(f"로그인 프로파일 로드 실패(JSON 확인): {path}")
    if not isinstance(data, dict):
        raise RuntimeError(f"로그인 프로파일은 JSON 객체여야 함: {path}")
    bad = set(data) - _PROFILE_KEYS
    if bad:
        raise RuntimeError(f"로그인 프로파일에 허용되지 않은 키: {sorted(bad)}")
    return data
```

- [ ] **Step 4: 통과 확인**

Run: `python -m unittest tests.test_login_profile -v`
Expected: PASS (5 tests)

- [ ] **Step 5: 회귀 + 커밋**

Run: `python -m unittest discover -s tests -p "test_*.py"` → OK
```bash
git add tools/dyn_session.py profiles/sef-2026.json profiles/jsp-form.json tests/test_login_profile.py
git commit -m "feat: dyn_session 로그인 프로파일 로더 + 기본 프로파일(D2 기반)" -m "load_login_profile(name|path)로 로그인 형식을 외부화. sef-2026·jsp-form 동봉." -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: attack_*.py 4종 배선 (D1 입력 + D2 프로파일)

**Files:**
- Modify: `skills/exploiting-auth-session/scripts/attack_auth.py`, `skills/exploiting-broken-access-control/scripts/attack_access.py`, `skills/exploiting-ssrf-and-open-redirect/scripts/attack_ssrf.py`, `skills/exploiting-path-traversal-upload/scripts/attack_pathupload.py`
- Test: `tests/test_attack_creds_wiring.py` (신규)

**Interfaces:**
- Consumes: `dyn_session.resolve_secret`·`read_stdin_creds`·`load_login_profile` (Task 1·2)
- Produces: 각 `_build_parser()`에 신규 인자, `main()`에서 cred/프로파일을 해석해 기존 흐름에 주입

**접근(4개 파일 공통 패턴 — 각 파일에 동일 적용):**
1. `_build_parser()`에 추가: `--user-a-pw-env`·`--user-b-pw-env`(access만)·`--token-a-env`·`--token-b-env`(access만)·`--creds-stdin`(`action="store_true"`)·`--login-profile`.
2. `main()` 진입부(argparse 파싱 직후, scope 검사 전)에서:
   - `stdin_creds = dyn_session.read_stdin_creds() if args.creds_stdin else None`
   - `prof = dyn_session.load_login_profile(args.login_profile) if args.login_profile else {}`
   - 프로파일 적용(개별 인자 우선): 각 프로파일 키에 대해 `if getattr(args, k) in (None, 파서기본값) and k in prof: setattr(args, k, prof[k])`. **주의:** `login_path`·`token_path`는 파서 기본값이 `"/api/v1/auth/login"`·`"data.accessToken"`이므로, "사용자가 명시했는지"를 구분하려면 이 두 인자의 파서 `default`를 `None`으로 바꾸고, 소비 지점에서 `args.login_path or "/api/v1/auth/login"`로 폴백한다(하위호환 유지: 미지정 시 동일값). `auth_mode`는 기본 `"bearer"`.
   - cred 해석: `args.user_a_pw = dyn_session.resolve_secret(direct=args.user_a_pw, env_var=args.user_a_pw_env, stdin_creds=stdin_creds, stdin_key="user_a_pw")` (token_a·user_b_pw·token_b도 동일 패턴). 이후 기존 `{"id":.., "pw":..}` 조립 코드는 변경 없이 재사용.
3. 기존 `--login-path`/`--body-template` 등 개별 인자는 그대로 둔다(하위호환).

**테스트 스펙(`tests/test_attack_creds_wiring.py`)** — 실제 네트워크 없이 argparse+해석만 검증:
- `--creds-stdin`으로 `{"token_a":"T"}`를 stdin에 주입하고 파서+해석을 거치면 `args.token_a == "T"`가 되며, **원래 `sys.argv`에 `"T"`가 없음**을 확인(각 4개 스크립트의 `_build_parser`를 import해 테스트).
- `--login-profile jsp-form`이면 `args.auth_mode == "cookie"`, `args.id_field == "j_username"`으로 채워지되, `--auth-mode bearer`를 함께 주면 개별 인자가 이겨 `"bearer"` 유지.
- `--user-a-pw-env MYVAR`(환경에 MYVAR=x) → `args.user_a_pw == "x"`.

각 스크립트가 위 해석 로직을 공유하므로, 헬퍼 `_apply_creds_and_profile(args, stdin_creds)`를 각 파일에 두거나(중복 최소) 테스트는 스크립트별로 파라미터화한다.

- [ ] **Step 1: 실패 테스트 작성** (위 스펙대로 4개 스크립트 파라미터화, 실제 코드는 테스트 파일에 명시)
- [ ] **Step 2: 실행 → 실패 확인** (`--creds-stdin` 인자 없음)
- [ ] **Step 3: 4개 파일에 위 접근 적용** (파일당 argparse 6~8줄 + main 진입부 해석 블록)
- [ ] **Step 4: 통과 확인** + **기존 attack 테스트 회귀 없음 확인**(`test_attack_auth`·`test_attack_access`·`test_attack_ssrf`·`test_attack_pathupload`·`test_attack_cookie_wiring` 모두 green)
- [ ] **Step 5: 커밋** — `feat: attack 4종에 자격증명 env/stdin·로그인 프로파일 배선(D1·D2)`

---

## Task 4: audit.py 배선 (env cred 수집 + 자식 env 포워딩 + 프로파일)

**Files:**
- Modify: `skills/auditing-web-application-security/scripts/audit.py`
- Test: `tests/test_audit_creds_forwarding.py` (신규)

**Interfaces:**
- Consumes: Task 1·2 헬퍼, Task 3의 자식 `--*-env`/`--creds-stdin` 인자
- Produces: audit이 자식 subprocess에 자격증명을 **환경변수로 전달**(cmd 평문 없음)

**접근(핵심 — 자식 cmd 평문 회피):**
1. `_build parser`에 `--user-a-pw-env`·`--token-a-env`(등)·`--creds-stdin`·`--login-profile` 추가.
2. creds 조립(현 L700-729)에서 `resolve_secret`으로 실제 값 해석(stdin/env/direct). 프로파일은 `load_login_profile`로 로드해 `login_path`/`body_template`/`token_path`/`auth_mode`/`id_field`/`pw_field` 기본값 채움(개별 인자 우선).
3. **자식 포워딩 변경(`_append_auth_mode`·각 `run_*_dynamic`)**: 자식 cmd에 `--token-a <값>`/`--user-a-pw <값>`을 직접 싣는 대신,
   - 자식별 `env` dict를 만들어 `GXSEC_TOKEN_A`·`GXSEC_USER_A_PW` 등에 값 대입,
   - 자식 cmd에는 `--token-a-env GXSEC_TOKEN_A`·`--user-a-pw-env GXSEC_USER_A_PW`만 싣고,
   - `subprocess.run(..., env={**os.environ, **child_env})`로 전달.
   - **단, `--user-a-id`(비밀 아님)는 기존대로 cmd에 평문 가능**(노출돼도 무해). 비밀(pw·token)만 env 경유.
4. 하위호환: `--creds-stdin`/`--*-env`를 안 쓰면 기존 direct 경로(`--token-a` 평문 cmd) 그대로 — 기존 audit 테스트 불변.

**테스트 스펙(`tests/test_audit_creds_forwarding.py`)** — subprocess 실발사 없이 cmd/env 구성만 검증(기존 `test_audit_login_forwarding.py` 패턴):
- `--creds-stdin`으로 `{"token_a":"SECRET"}` 주입 시, audit이 자식에 만드는 **cmd 리스트에 "SECRET"이 없고**, 자식 `env`에 `GXSEC_TOKEN_A=="SECRET"`이며 cmd에 `--token-a-env GXSEC_TOKEN_A`가 있음.
- `--login-profile jsp-form`이면 자식 cmd에 `--auth-mode cookie` 등 프로파일 값이 실림.
- 아무 신규 인자도 안 주면 기존 동작(direct `--token-a SECRET`이 cmd에 평문)과 동일 — 기존 `test_audit_login_forwarding` green.

- [ ] **Step 1: 실패 테스트 작성** (위 스펙, cmd/env 캡처)
- [ ] **Step 2: 실행 → 실패 확인**
- [ ] **Step 3: audit.py 배선 구현** (argparse + resolve + profile + 자식 env 포워딩)
- [ ] **Step 4: 통과 + `test_audit*` 전체 회귀 없음 확인**
- [ ] **Step 5: 커밋** — `feat: audit 자격증명 env/stdin 수집 + 자식 env 포워딩(cmd 평문 제거)`

---

## Task 5: 동적 런북 문서 (O2)

**Files:**
- Create: `docs/RUNBOOK-dynamic.md`
- Modify: `README.md`(문서 지도), `docs/OPERATIONS.md`(§4 자격증명 — env/stdin이 이제 지원됨을 반영)

- [ ] **Step 1: `docs/RUNBOOK-dynamic.md` 작성** — 다음을 모두 실제 명령과 함께:
  1. 사전 준비(격리 호스트·전용 계정·`SECURITY_PLUGIN_ALLOW_HOSTS` 등록)
  2. **자격증명 안전 입력** — `--creds-stdin`(권장, 프로세스 미노출) 사용 예: `echo '{"user_a_pw":"..","token_a":".."}' | python skills/.../attack_auth.py ... --creds-stdin`. `--*-env` 한계(프로세스 노출 잔존) 명시.
  3. **스택별 로그인 프로파일** — Spring(`--login-profile sef-2026`)·JSP(`--login-profile jsp-form`) 예시, 커스텀 프로파일 작성법.
  4. 클래스별 동적 점검 시나리오(접근통제·인증·SSRF·경로조작/업로드) 최소 1사이클씩.
  5. 판정 해석(dynamic/partial/static-only)·leftover 정리.
- [ ] **Step 2: README 문서 지도에 `RUNBOOK-dynamic.md` 행 추가, OPERATIONS.md §4에 "env/stdin 입력이 v0.5.0부터 지원됨" 반영**
- [ ] **Step 3: 링크 유효성 확인** (`test -f docs/RUNBOOK-dynamic.md && grep -q RUNBOOK README.md`)
- [ ] **Step 4: 커밋** — `docs: 동적 점검 런북(RUNBOOK-dynamic.md) 추가(O2)`

---

## 릴리스 마무리 (전체 Task 완료 후)

- [ ] **버전 0.5.0 bump**: `plugin.json`·`marketplace.json`·README·16 SKILL.md + `test_version_consistency.py`의 `EXPECTED="0.5.0"`, CHANGELOG `[0.5.0]` 항목(D1·D2·O2). `test_version_consistency` PASS 확인.
- [ ] **전체 회귀**: `python -m unittest discover -s tests -p "test_*.py"` → OK
- [ ] **수용 기준 대조**: 자격증명 비노출 입력(stdin) 동작 · 프로파일로 비-sef 로그인 성공 · 런북 완비 — 3개 충족.

## Self-Review 대상 (계획 작성자 체크리스트)

- 스펙 P2의 3작업(D1/D2/O2) → Task 1+3+4(D1) / Task 2+3+4(D2) / Task 5(O2)로 매핑.
- Placeholder 없음: 헬퍼·테스트는 완전 코드, 배선 Task는 정확한 파일·라인·접근·테스트 스펙 명시.
- 타입 일관성: `resolve_secret`·`read_stdin_creds`·`load_login_profile` 시그니처가 Task 1·2에서 정의되고 Task 3·4에서 동일하게 소비됨.
- 하위호환: 모든 배선 Task 수용 기준에 "기존 attack/audit 테스트 green" 포함.
