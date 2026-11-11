#!/usr/bin/env python3
"""
tools/dyn_session.py — 동적 침투 스킬 공용 엔진.
로그인 자동화·토큰 보관·인증 HTTP·표준 출력·scope 위임을 제공한다.
모든 exploiting-* 스킬이 공유하며, 클래스별 공격 로직은 포함하지 않는다.
Specialist requests use approved numeric IPs and shared absolute budgets.
Release checks also require gxsec.transport's separate trusted readiness contract.
"""
import sys
import os
import json
import time
import ipaddress
import hashlib
from collections import OrderedDict
from contextlib import contextmanager
from contextvars import ContextVar
from urllib.parse import urlsplit

_HERE = os.path.dirname(os.path.abspath(__file__))
_PLUGIN_ROOT = os.path.normpath(os.path.join(_HERE, ".."))
if _PLUGIN_ROOT not in sys.path:
    sys.path.insert(0, _PLUGIN_ROOT)

from tools.scope_guard import assert_in_scope, ScopeError  # noqa: F401  (재노출)
from tools import io_utf8  # noqa: F401  (emit()의 JSON 출력 계약 — Task 1)
from tools.redaction import redact
from tools.specialist_transport import BoundedAdapter, OperationContext, PolicyError, canonical_origin

io_utf8.configure()

_burp_warned = False
ERROR_TYPES = frozenset({"timeout", "connection_error", "request_failed", "invalid_response",
                         "scope_blocked", "login_failed", "response_limit", "budget_exhausted"})
_ACTIVE_SCOPE = ContextVar("gxsec_specialist_diagnostic_scope", default=None)


class _DiagnosticState:
    def __init__(self, operation):
        self.operation = operation
        self.credential_origins = {}


def _transport_settings():
    proxies = _burp_proxies()
    proxy = proxies["http"] if proxies else None
    ca = (os.environ.get("SECURITY_PLUGIN_BURP_CA", "").strip() or None) if proxy else None
    return proxy, ca


@contextmanager
def diagnostic_scope(target_urls, *, authorized_flag=False, target_ips=None, limits=None):
    """Bind one approved origin/IP snapshot and budgets across all diagnostic requests."""
    urls = [target_urls] if isinstance(target_urls, str) else list(target_urls)
    proxy, ca = _transport_settings()
    operation = OperationContext(urls, authorized_flag=authorized_flag, target_ips=target_ips,
                                 limits=limits, proxy_url=proxy, ca_file=ca)
    token = _ACTIVE_SCOPE.set(_DiagnosticState(operation))
    try:
        yield operation
    finally:
        _ACTIVE_SCOPE.reset(token)


def request_error_type(error):
    """Return a fixed diagnostic code without retaining exception text or URLs."""
    code = getattr(error, "code", None)
    if isinstance(code, str) and code in ERROR_TYPES:
        return code
    if isinstance(error, ScopeError):
        return "scope_blocked"
    timeout_types = (TimeoutError,)
    connection_types = (ConnectionError,)
    try:
        from requests import exceptions
        timeout_types += (exceptions.Timeout,)
        connection_types += (exceptions.ConnectionError,)
    except ImportError:
        pass
    if isinstance(error, timeout_types):
        return "timeout"
    if isinstance(error, connection_types):
        return "connection_error"
    if isinstance(error, (KeyError, TypeError, ValueError)):
        return "invalid_response"
    return "request_failed"


class RequestFailure(RuntimeError):
    """Carry a fixed cause through legacy RuntimeError and CLI boundaries."""
    def __init__(self, error, message="요청 실패"):
        self.code = request_error_type(error)
        super().__init__(f"{message}: {self.code}")


def login_error_type(error):
    code = getattr(error, "code", None)
    return code if isinstance(code, str) and code in ERROR_TYPES else "login_failed"


def validate_burp_proxy_url(val):
    """Normalize local proxy syntax; the transport additionally requires HTTP CONNECT."""
    try:
        if not isinstance(val, str) or not val:
            raise ValueError
        parsed = urlsplit(val)
        if (val != val.strip() or any(c.isspace() for c in val)
                or any(c in val for c in ("%", "?", "#", "\\"))
                or parsed.scheme not in {"http", "https"}
                or parsed.username is not None or parsed.password is not None
                or parsed.path or parsed.query or parsed.fragment
                or parsed.netloc.endswith(":")):
            raise ValueError
        address = ipaddress.ip_address(parsed.hostname)
        port = parsed.port
        if (not address.is_loopback or (port is not None and port == 0)
                or (isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None)):
            raise ValueError
    except (ValueError, TypeError):
        raise ScopeError("Burp proxy supports only loopback IP literal HTTP(S) endpoints; remote proxies are unsupported") from None
    host = "[" + address.compressed + "]" if address.version == 6 else address.compressed
    port = port if port is not None else 443 if parsed.scheme == "https" else 80
    return f"{parsed.scheme}://{host}:{port}"


def _burp_proxies():
    """An absent/blank environment value means direct, environment-isolated requests."""
    val = os.environ.get("SECURITY_PLUGIN_BURP_PROXY", "")
    if not val.strip():
        return None
    val = validate_burp_proxy_url(val)
    return {"http": val, "https": val}


def _proxy_kwargs():
    """Keep TLS verification enabled; explicitly trust a local Burp CA if supplied."""
    proxies = _burp_proxies()
    if not proxies:
        return {}
    ca = os.environ.get("SECURITY_PLUGIN_BURP_CA", "").strip()
    return {"proxies": proxies, "verify": ca or True}


def _client(method, url, *, session=None, **kwargs):
    """Use the active pinned, bounded operation and keep credentials on one origin."""
    if "proxies" in kwargs or "verify" in kwargs:
        raise ValueError("Per-request proxy/TLS overrides are unsupported; use the validated loopback Burp configuration")
    if kwargs.get("stream", False) is not False or kwargs.get("allow_redirects", False) is not False:
        raise PolicyError()
    state = _ACTIVE_SCOPE.get()
    if state is None:
        host = urlsplit(canonical_origin(url)).hostname
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if host != "localhost":
                raise PolicyError() from None
        with diagnostic_scope([url]):
            return _client(method, url, session=session, **kwargs)
    operation = state.operation
    origin = operation.ensure_origin(url)
    if _transport_settings() != (operation.proxy_url, operation.ca_file):
        raise PolicyError()
    fingerprints = []
    for key, value in (kwargs.get("headers") or {}).items():
        if str(key).lower() in {"authorization", "cookie", "proxy-authorization"}:
            if not isinstance(value, str):
                raise PolicyError()
            fingerprint = hashlib.sha256((str(key).lower() + "\0" + value).encode()).hexdigest()
            previous = state.credential_origins.get(fingerprint)
            if previous is not None and previous != origin:
                raise PolicyError()
            fingerprints.append(fingerprint)
    caller = session if session is not None else new_session()
    previous = vars(caller).get("_gxsec_bound_origin")
    if previous is not None and previous != origin:
        if session is None:
            caller.close()
        raise PolicyError()
    caller._gxsec_bound_origin = origin
    caller.trust_env = False
    caller.proxies = {}
    caller.verify = True
    # Replace the entire prefix table: mount() alone leaves longer custom prefixes.
    caller.adapters = OrderedDict((scheme, BoundedAdapter(operation)) for scheme in ("https://", "http://"))
    state.credential_origins.update((fingerprint, origin) for fingerprint in fingerprints)
    kwargs["stream"] = False
    kwargs["allow_redirects"] = False
    proxy_kwargs = {"proxies": {"http": operation.proxy_url, "https": operation.proxy_url}} if operation.proxy_url else {}
    proxy_kwargs["verify"] = operation.ca_file or True
    try:
        return caller.request(method.upper(), url, **kwargs, **proxy_kwargs)
    finally:
        if session is None:
            caller.close()


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
        resp = _client("POST", url, json=body, timeout=timeout, allow_redirects=False)
    except Exception as e:
        hint = " (Burp 프록시 경유 중 — Burp 가동·Intercept OFF 확인)" if os.environ.get("SECURITY_PLUGIN_BURP_PROXY", "").strip() else ""
        raise RequestFailure(e, f"로그인 요청 실패{hint}") from None
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
        resp = _client("POST", url, json=body, timeout=timeout, allow_redirects=False)
    except Exception as e:
        hint = " (Burp 프록시 경유 중 — Burp 가동·Intercept OFF 확인)" if os.environ.get("SECURITY_PLUGIN_BURP_PROXY", "").strip() else ""
        raise RequestFailure(e, f"로그인 요청 실패{hint}") from None
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
    """Create a cookie-capable session without ambient transport/auth policy."""
    import requests
    session = requests.Session()
    session.trust_env = False
    return session


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
    owns_session = session is None
    session = session if session is not None else new_session()

    def fail_login(message, error=None):
        if owns_session:
            session.close()
        if error is not None:
            raise RequestFailure(error, message) from None
        raise RuntimeError(message) from None

    url = base_url.rstrip("/") + login_path
    form = {(id_field or "username"): cred["id"], (pw_field or "password"): cred["pw"]}
    try:
        resp = _client("POST", url, session=session, data=form, timeout=timeout, allow_redirects=False)
    except Exception as e:
        fail_login("로그인 요청 실패", e)
    status = resp.status_code
    location = resp.headers.get("Location", "")
    if 300 <= status < 400:
        if _location_matches(location, success_path):
            return {"session": session,
                    "set_cookie": resp.headers.get("Set-Cookie", ""),
                    "status": status, "location": location}
        if location:
            fail_login(
                f"로그인 실패(자격 추정): 성공 경로 '{success_path}' 아닌 "
                f"'{_safe_location(location)}'로 이동")
        fail_login("로그인 실패(형식): 3xx이나 Location 없음")
    if 200 <= status < 300:
        fail_login(
            f"로그인 실패(형식/필드): 리다이렉트 없이 {status} — "
            f"폼 재표시 추정, 필드명 확인")
    fail_login(f"로그인 실패(형식): 요청 거부 HTTP {status}")


def request(method, url, *, token=None, json_body=None, files=None, data=None,
            timeout=10, session=None):
    """인증 헤더를 자동 부착해 요청. {status, body, headers, elapsed} 반환.

    headers는 응답 헤더 dict(Location 등 오픈리다이렉트 판정에 필수).
    files/data는 multipart 업로드(파일업로드 동적 검사)용 — 기본 None이면 requests가
    바디에 싣지 않으므로 기존 5종 호출과 바이트 동일(하위호환).
    세션이 있으면 쿠키 jar를 재사용한다. 모든 경로는 환경 proxy/netrc/CA를 무시하는
    _client를 사용하며 명시한 검증된 loopback Burp proxy만 지원한다.
    attack_auth/access는 status/body만 참조하므로 하위호환(키 추가만).
    """
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    # token 과 session 은 직교(독립) 전송 수단이다:
    #   · token  → Authorization: Bearer 헤더(스테이트리스 인증)
    #   · session → requests.Session 쿠키 jar(세션쿠키 인증) + 발사 caller
    # 현재 attack 배선은 둘을 상호배타로 쓴다(bearer=token만 / cookie=session만).
    # 둘 다 전달돼도 오류는 아니며(헤더+쿠키 동시 부착) 단지 현재 미사용 조합일 뿐이다.
    t0 = time.monotonic()
    resp = _client(
        method.upper(), url, session=session, headers=headers, json=json_body,
        files=files, data=data,
        timeout=timeout, allow_redirects=False)
    return {"status": resp.status_code, "body": resp.text,
            "headers": dict(resp.headers),
            "elapsed": round(time.monotonic() - t0, 3)}


def emit(result, as_json):
    """표준 결과 출력. as_json이면 JSON, 아니면 사람용 요약."""
    result = redact(result)
    if as_json:
        io_utf8.emit_json(result)
        return
    print(f"\n{'=' * 60}")
    print(f"  동적 점검 결과: {result.get('skill', 'dyn')}")
    print(f"{'=' * 60}")
    print(f"  대상: {result.get('target')}")
    for f in result.get("findings", []):
        if f.get("skipped"):
            verdict = f"[미발사: {f['skipped']}]"
        elif f.get("error"):
            error_type = f.get("error_type")
            safe_error_type = error_type if isinstance(error_type, str) and error_type in ERROR_TYPES else "request_failed"
            verdict = f"[발사실패: {safe_error_type}]"
        elif f.get("vulnerable"):
            verdict = "[취약 후보]"
        elif f.get("undetermined") or f.get("validation") == "undetermined":
            verdict = "[미확정]"
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
