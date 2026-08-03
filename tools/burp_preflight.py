#!/usr/bin/env python3
"""
tools/burp_preflight.py — Burp Suite 가동 프리플라이트 + 설치 온보딩.

Burp 프록시(기본 127.0.0.1:8080)와 MCP 서버(기본 127.0.0.1:9876)의 포트 개방을
TCP 연결로 프로브한다. 미가동이면 설치·설정 온보딩 텍스트를 제공한다.
Burp 경로(audit --burp-proxy / exploiting-with-burp)는 발사 전 이 게이트를 통과해야 한다.
"""
import argparse
import os
import socket
import sys
from urllib.parse import urlparse

_HERE = os.path.dirname(os.path.abspath(__file__))
_PLUGIN_ROOT = os.path.normpath(os.path.join(_HERE, ".."))
if _PLUGIN_ROOT not in sys.path:
    sys.path.insert(0, _PLUGIN_ROOT)

from tools import io_utf8  # noqa: E402
io_utf8.configure()

DEFAULT_PROXY_HOST = "127.0.0.1"
DEFAULT_PROXY_PORT = 8080
DEFAULT_MCP_HOST = "127.0.0.1"
DEFAULT_MCP_PORT = 9876


def probe_port(host, port, timeout=1.0):
    """host:port에 TCP 연결을 시도해 열려 있으면 True. 거부·타임아웃·오류면 False."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except (OSError, ValueError, OverflowError):
        return False


def split_hostport(proxy_url):
    """'http://127.0.0.1:8080' 또는 '127.0.0.1:8080' → ('127.0.0.1', 8080).
    포트 없으면 프록시 기본(8080)으로 폴백."""
    raw = proxy_url if "://" in proxy_url else "http://" + proxy_url
    u = urlparse(raw)
    return (u.hostname or DEFAULT_PROXY_HOST), int(u.port or DEFAULT_PROXY_PORT)


def check(proxy_host=DEFAULT_PROXY_HOST, proxy_port=DEFAULT_PROXY_PORT,
          mcp_host=DEFAULT_MCP_HOST, mcp_port=DEFAULT_MCP_PORT, timeout=1.0):
    """프록시/MCP 포트 개방 상태를 dict로 반환."""
    return {
        "proxy_up": probe_port(proxy_host, proxy_port, timeout),
        "mcp_up": probe_port(mcp_host, mcp_port, timeout),
        "proxy": f"{proxy_host}:{proxy_port}",
        "mcp": f"{mcp_host}:{mcp_port}",
    }


def onboarding_text(proxy="127.0.0.1:8080", mcp="127.0.0.1:9876"):
    """Burp 미가동 시 설치·설정 온보딩 안내(1회 셋업)."""
    return (
        "\n[Burp 미가동] Burp Suite MCP 연동이 설정되지 않았습니다. 1회 셋업:\n"
        "  1) Java(JDK) 설치 — PATH에 java\n"
        "  2) Burp Suite 실행 (Community 가능. Collaborator·Scanner는 Pro 전용)\n"
        "  3) MCP Server 확장 로드 — BApp Store 또는 ./gradlew embedProxyJar 후\n"
        "     Burp > Extensions > Add > Java > burp-mcp-all.jar\n"
        f"  4) Burp MCP 탭에서 서버 Enable ({mcp}) + 프록시 리스너 확인 ({proxy})\n"
        "  5) Claude Code에 MCP 등록 (SSE 직결 — stdio proxy jar 불필요):\n"
        "     claude mcp add --transport sse burp http://127.0.0.1:9876   (엔드포인트는 루트, /sse 아님)\n"
        "  ⚠ Burp Proxy > Intercept 는 OFF로 두세요 — ON이면 프록시 경유 발사가 전부 멈춥니다.\n"
        "  설정 후 다시 실행하세요. (Burp 없이 진행하려면 --burp-proxy 없이 기존 스크립트 경로 사용)\n"
    )


def main():
    p = argparse.ArgumentParser(description="Burp 가동 프리플라이트 프로브")
    p.add_argument("--proxy-host", default=DEFAULT_PROXY_HOST)
    p.add_argument("--proxy-port", type=int, default=DEFAULT_PROXY_PORT)
    p.add_argument("--mcp-host", default=DEFAULT_MCP_HOST)
    p.add_argument("--mcp-port", type=int, default=DEFAULT_MCP_PORT)
    p.add_argument("--require", choices=["proxy", "mcp", "both"], default="proxy",
                   help="통과 조건(기본 proxy — 프록시 경유만 필요)")
    args = p.parse_args()
    st = check(args.proxy_host, args.proxy_port, args.mcp_host, args.mcp_port)
    need_proxy = args.require in ("proxy", "both")
    need_mcp = args.require in ("mcp", "both")
    ok = (st["proxy_up"] or not need_proxy) and (st["mcp_up"] or not need_mcp)
    print(f"[프리플라이트] 프록시({st['proxy']}): {'OK' if st['proxy_up'] else '미가동'}  /  "
          f"MCP({st['mcp']}): {'OK' if st['mcp_up'] else '미가동'}")
    if not ok:
        print(onboarding_text(st["proxy"], st["mcp"]))
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
