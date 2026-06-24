#!/usr/bin/env python3
"""
공격형(exploiting-*) 스킬 공용 안전 게이트.

실제 공격 페이로드를 발사하기 전에 대상이 '권한 있는 테스트 범위'인지 강제 검증한다.
모든 attack_*.py 는 페이로드 발사 전에 반드시 assert_in_scope() 를 호출해야 한다.

정책
- 로컬/사설/스테이징 대상: 자동 허용
- 그 외(공인 도메인·공인 IP): 차단. 단 사용자가 소유를 명시한 경우에만
  --authorized 플래그 + SECURITY_PLUGIN_AUTHORIZED=1 환경변수 동시 충족 시 허용.
- 운영으로 보이는 호스트(prod/www 등) 또는 명시적 차단 목록: 항상 거부.
- 기본은 '비파괴 모드'. 파괴적 작업(데이터 변조/삭제)은 별도 --allow-destructive 필요.
"""
import ipaddress
import os
import re
import sys
from urllib.parse import urlparse

try:  # Windows 콘솔(cp949)에서도 안전하게 출력
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

# 자동 허용: 로컬/사설 대역 + 스테이징/개발 호스트 패턴
_PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]
_ALLOW_HOST_PATTERNS = [
    re.compile(r"^localhost$", re.I),
    re.compile(r"\.local$", re.I),
    re.compile(r"\.test$", re.I),
    re.compile(r"(^|[.\-])stag(e|ing)([.\-]|$)", re.I),
    re.compile(r"(^|[.\-])dev([.\-]|$)", re.I),
    re.compile(r"(^|[.\-])qa([.\-]|$)", re.I),
]
# 항상 거부(운영으로 강하게 의심되는 호스트)
_DENY_HOST_PATTERNS = [
    re.compile(r"(^|[.\-])prod([.\-]|$)", re.I),
    re.compile(r"(^|[.\-])production([.\-]|$)", re.I),
    re.compile(r"^www\.", re.I),
]


class ScopeError(Exception):
    pass


def _host_from(target: str) -> str:
    if "://" not in target:
        target = "http://" + target
    return (urlparse(target).hostname or "").strip()


def classify(target: str) -> tuple[str, str]:
    """returns (decision, reason). decision in {allow, deny, needs-authorization}."""
    host = _host_from(target)
    if not host:
        return "deny", f"호스트를 해석할 수 없음: {target!r}"

    for rx in _DENY_HOST_PATTERNS:
        if rx.search(host):
            return "deny", f"운영 의심 호스트 차단 패턴 매치: {host}"

    # IP 대역 검사
    try:
        ip = ipaddress.ip_address(host)
        for net in _PRIVATE_NETS:
            if ip in net:
                return "allow", f"사설/로컬 IP: {host}"
        return "needs-authorization", f"공인 IP: {host}"
    except ValueError:
        pass  # 도메인

    for rx in _ALLOW_HOST_PATTERNS:
        if rx.search(host):
            return "allow", f"스테이징/로컬 호스트 패턴: {host}"

    return "needs-authorization", f"공인 도메인(소유 확인 필요): {host}"


def assert_in_scope(target: str, authorized_flag: bool = False) -> str:
    """범위를 벗어나면 ScopeError 발생. 통과하면 사유 문자열 반환."""
    decision, reason = classify(target)
    if decision == "allow":
        return reason
    if decision == "deny":
        raise ScopeError(f"[차단] {reason} — 운영 대상으로 보입니다. 공격 중단.")
    # needs-authorization
    env_ok = os.environ.get("SECURITY_PLUGIN_AUTHORIZED") == "1"
    if authorized_flag and env_ok:
        return f"{reason} — --authorized + SECURITY_PLUGIN_AUTHORIZED=1 확인됨(소유자 책임)"
    raise ScopeError(
        f"[권한 필요] {reason}\n"
        f"  공인 대상은 자동 허용되지 않습니다. 본인 소유/승인된 자산임이 확실하면:\n"
        f"    1) 환경변수  SECURITY_PLUGIN_AUTHORIZED=1  설정\n"
        f"    2) 스크립트에 --authorized 플래그 전달\n"
        f"  운영 환경에는 절대 사용하지 마세요."
    )


if __name__ == "__main__":
    # CLI 셀프테스트:  python scope_guard.py <target> [--authorized]
    if len(sys.argv) < 2:
        print("usage: scope_guard.py <target_url> [--authorized]")
        sys.exit(2)
    tgt = sys.argv[1]
    auth = "--authorized" in sys.argv
    try:
        print("ALLOW:", assert_in_scope(tgt, auth))
    except ScopeError as e:
        print(e)
        sys.exit(1)
