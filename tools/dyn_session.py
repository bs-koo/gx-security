#!/usr/bin/env python3
"""
tools/dyn_session.py — 동적 침투 스킬 공용 엔진.
로그인 자동화·토큰 보관·인증 HTTP·표준 출력·scope 위임을 제공한다.
모든 exploiting-* 스킬이 공유하며, 클래스별 공격 로직은 포함하지 않는다.
"""
import sys
import os
import json
import time

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

_HERE = os.path.dirname(os.path.abspath(__file__))
_PLUGIN_ROOT = os.path.normpath(os.path.join(_HERE, ".."))
if _PLUGIN_ROOT not in sys.path:
    sys.path.insert(0, _PLUGIN_ROOT)

from tools.scope_guard import assert_in_scope, ScopeError  # noqa: F401  (재노출)


def mask_token(tok):
    """토큰을 로그/출력용으로 마스킹. 앞 4·뒤 4만 노출."""
    if not tok:
        return "<none>"
    tok = str(tok)   # 비문자열(JSON int 등)이 와도 크래시하지 않게 방어
    if len(tok) <= 8:
        return "****"
    return tok[:4] + "…" + tok[-4:]


def extract_by_path(obj, path):
    """'data.accessToken' 점 표기로 중첩 dict에서 값 추출. 실패 시 None."""
    cur = obj
    for key in path.split("."):
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return None
    return cur


def set_by_path(obj, path, value):
    """'data.query' 점 표기 경로에 value 설정(중간 dict 자동 생성). obj를 반환.

    extract_by_path의 setter 대응 — D4 JSON 바디 주입 지점 지정(attack_sqli/xss)에 쓰인다.
    """
    keys = path.split(".")
    cur = obj
    for key in keys[:-1]:
        nxt = cur.get(key)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[key] = nxt
        cur = nxt
    cur[keys[-1]] = value
    return obj


def login(base_url, login_path, cred, *, body_template=None,
          token_json_path="data.accessToken", timeout=10):
    """테스트 계정으로 로그인해 토큰 문자열을 반환. 실패 시 RuntimeError."""
    import requests
    url = base_url.rstrip("/") + login_path
    if body_template:
        # JSON 중괄호와 충돌하지 않도록 str.format 대신 {id}/{pw} 단순 치환
        raw = body_template.replace("{id}", cred["id"]).replace("{pw}", cred["pw"])
        try:
            body = json.loads(raw)
        except (ValueError, TypeError):
            raise RuntimeError("로그인 body-template JSON 파싱 실패 — 형식을 확인하세요")
    else:
        body = {"lgnId": cred["id"], "password": cred["pw"]}  # sef-2026 프리셋
    try:
        resp = requests.post(url, json=body, timeout=timeout, allow_redirects=False)
    except Exception as e:
        raise RuntimeError(f"로그인 요청 실패: {url} — {type(e).__name__}")
    if not (200 <= resp.status_code < 300):
        raise RuntimeError(f"로그인 실패(HTTP {resp.status_code}): {url} — "
                           f"2xx 아님(3xx 리다이렉트·4xx 거부 포함). 자격/요청형식 확인")
    try:
        data = resp.json()
    except ValueError:
        raise RuntimeError(f"로그인 응답이 JSON 아님: {url}")
    token = extract_by_path(data, token_json_path)
    if not token:
        raise RuntimeError(f"토큰 추출 실패: 경로 '{token_json_path}' (응답 형식 확인)")
    token = str(token)  # 토큰이 문자열 아닌 값(정수 등)이면 다운스트림 "Bearer "+token 결합 크래시 방어 (login_response와 동일 정책, PR 리뷰 반영)
    return token


def login_response(base_url, login_path, cred, *, body_template=None,
                   token_json_path="data.accessToken", timeout=10):
    """로그인 후 토큰과 응답 Set-Cookie를 함께 반환.

    반환: {"token": <str>, "set_cookie": <str>} — attack_auth.py:200-203 계약.
    실패(2xx 아님/토큰 추출 실패) 시 RuntimeError (login()과 동일 정책).
    login()을 위임하지 않고 로직을 복제한다(login 시그니처 불변 유지, 회귀 방지).
    """
    import requests
    url = base_url.rstrip("/") + login_path
    if body_template:
        # JSON 중괄호와 충돌하지 않도록 str.format 대신 {id}/{pw} 단순 치환
        raw = body_template.replace("{id}", cred["id"]).replace("{pw}", cred["pw"])
        try:
            body = json.loads(raw)
        except (ValueError, TypeError):
            raise RuntimeError("로그인 body-template JSON 파싱 실패 — 형식을 확인하세요")
    else:
        body = {"lgnId": cred["id"], "password": cred["pw"]}  # sef-2026 프리셋
    try:
        resp = requests.post(url, json=body, timeout=timeout, allow_redirects=False)
    except Exception as e:
        raise RuntimeError(f"로그인 요청 실패: {url} — {type(e).__name__}")
    if not (200 <= resp.status_code < 300):
        raise RuntimeError(f"로그인 실패(HTTP {resp.status_code}): {url} — "
                           f"2xx 아님(3xx 리다이렉트·4xx 거부 포함). 자격/요청형식 확인")
    try:
        data = resp.json()
    except ValueError:
        raise RuntimeError(f"로그인 응답이 JSON 아님: {url}")
    token = extract_by_path(data, token_json_path)
    if not token:
        raise RuntimeError(f"토큰 추출 실패: 경로 '{token_json_path}' (응답 형식 확인)")
    token = str(token)  # 토큰이 문자열 아닌 값(정수 등)이면 다운스트림 split/결합 크래시 방어 (PR 리뷰 반영)
    set_cookie = resp.headers.get("Set-Cookie", "")
    return {"token": token, "set_cookie": set_cookie}


def new_session():
    """requests.Session 팩토리(테스트 seam 단일화)."""
    import requests
    return requests.Session()


def _location_matches(location, success_path):
    """응답 Location의 path가 success_path(전체 URL 또는 경로)와 일치하는지(후행슬래시 정규화)."""
    if not location or not success_path:
        return False
    from urllib.parse import urlparse
    loc = urlparse(location).path.rstrip("/") or "/"
    want = urlparse(success_path).path.rstrip("/") or "/"
    return loc == want


def _safe_location(location):
    """실패 메시지용 Location 정제 — 세션ID/토큰이 담길 수 있는 쿼리·매트릭스 파라미터를
    제거하고 path만 노출한다(레거시 URL rewriting의 ;jsessionid= 등이 로그·리포트에 유출되는 것 방지)."""
    if not location:
        return ""
    from urllib.parse import urlparse
    path = urlparse(location).path        # 쿼리·프래그먼트 제거
    return path.split(";", 1)[0] or "/"    # ;jsessionid 등 매트릭스 파라미터 제거


def form_login(base_url, login_path, cred, *, id_field=None, pw_field=None,
               success_path=None, timeout=10, session=None):
    """form-urlencoded 로그인 + 세션쿠키 확보. 성공 시 {"session","set_cookie","status","location"}.

    실패 시 원인(자격/형식/필드)을 구분한 RuntimeError. success_path는 필수(Location 일치 판정).
    session 미전달 시 new_session()으로 생성. data=(form)로 form-urlencoded 전송.
    """
    if not success_path:   # 발사 전 검증 — 대상 서버에 불필요한 로그인 요청을 보내지 않는다
        raise RuntimeError("form 로그인은 --success-path 필요")
    session = session or new_session()
    url = base_url.rstrip("/") + login_path
    form = {(id_field or "username"): cred["id"], (pw_field or "password"): cred["pw"]}
    try:
        resp = session.post(url, data=form, timeout=timeout, allow_redirects=False)
    except Exception as e:
        raise RuntimeError(f"로그인 요청 실패: {url} — {type(e).__name__}")
    status = resp.status_code
    location = resp.headers.get("Location", "")
    if 300 <= status < 400:
        if _location_matches(location, success_path):
            return {"session": session,
                    "set_cookie": resp.headers.get("Set-Cookie", ""),
                    "status": status, "location": location}
        if location:
            raise RuntimeError(
                f"로그인 실패(자격 추정): 성공 경로 '{success_path}' 아닌 "
                f"'{_safe_location(location)}'로 이동")
        raise RuntimeError("로그인 실패(형식): 3xx이나 Location 없음")
    if 200 <= status < 300:
        raise RuntimeError(
            f"로그인 실패(형식/필드): 리다이렉트 없이 {status} — "
            f"폼 재표시 추정, 필드명 확인")
    raise RuntimeError(f"로그인 실패(형식): 요청 거부 HTTP {status}")


def request(method, url, *, token=None, json_body=None, files=None, data=None,
            timeout=10, session=None):
    """인증 헤더를 자동 부착해 요청. {status, body, headers, elapsed} 반환.

    headers는 응답 헤더 dict(Location 등 오픈리다이렉트 판정에 필수).
    files/data는 multipart 업로드(파일업로드 동적 검사)용 — 기본 None이면 requests가
    바디에 싣지 않으므로 기존 5종 호출과 바이트 동일(하위호환).
    session 유무로 발사 경로 결정: 있으면 세션 쿠키 jar 자동 사용, 없으면 requests
    (미전달 시 requests.request 적중 → 기존 5종 호출 바이트 불변).
    attack_auth/access는 status/body만 참조하므로 하위호환(키 추가만).
    """
    import requests
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    # token 과 session 은 직교(독립) 전송 수단이다:
    #   · token  → Authorization: Bearer 헤더(스테이트리스 인증)
    #   · session → requests.Session 쿠키 jar(세션쿠키 인증) + 발사 caller
    # 현재 attack 배선은 둘을 상호배타로 쓴다(bearer=token만 / cookie=session만).
    # 둘 다 전달돼도 오류는 아니며(헤더+쿠키 동시 부착) 단지 현재 미사용 조합일 뿐이다.
    caller = session if session is not None else requests
    t0 = time.monotonic()
    resp = caller.request(
        method.upper(), url, headers=headers, json=json_body,
        files=files, data=data,
        timeout=timeout, allow_redirects=False)
    return {"status": resp.status_code, "body": resp.text,
            "headers": dict(resp.headers),
            "elapsed": round(time.monotonic() - t0, 3)}


def emit(result, as_json):
    """표준 결과 출력. as_json이면 JSON, 아니면 사람용 요약."""
    if as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    print(f"\n{'=' * 60}")
    print(f"  동적 점검 결과: {result.get('skill', 'dyn')}")
    print(f"{'=' * 60}")
    print(f"  대상: {result.get('target')}")
    for f in result.get("findings", []):
        if f.get("skipped"):
            verdict = f"[미발사: {f['skipped']}]"
        elif f.get("error"):
            verdict = f"[발사실패: {f['error']}]"
        elif f.get("vulnerable"):
            verdict = "[취약 후보]"
        else:
            verdict = "[방어/정상]"
        print(f"  {verdict} {f.get('kind')} {f.get('method')} {f.get('path')} "
              f"→ HTTP {f.get('status')}")
    print(f"{'=' * 60}\n")


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
