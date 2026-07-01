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


def request(method, url, *, token=None, json_body=None, timeout=10):
    """인증 헤더를 자동 부착해 요청. {status, body, elapsed} 반환."""
    import requests
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    t0 = time.monotonic()
    resp = requests.request(
        method.upper(), url, headers=headers, json=json_body,
        timeout=timeout, allow_redirects=False)
    return {"status": resp.status_code, "body": resp.text,
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
