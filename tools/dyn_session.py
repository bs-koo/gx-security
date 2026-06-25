#!/usr/bin/env python3
"""
tools/dyn_session.py — 동적 침투 스킬 공용 엔진.
로그인 자동화·토큰 보관·인증 HTTP·표준 출력·scope 위임을 제공한다.
모든 exploiting-* 스킬이 공유하며, 클래스별 공격 로직은 포함하지 않는다.
"""
import sys
import os

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
