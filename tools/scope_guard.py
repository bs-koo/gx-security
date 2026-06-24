#!/usr/bin/env python3
"""
공격형(exploiting-*) 스킬 공용 안전 게이트.

실제 공격 페이로드를 발사하기 전에 대상이 '권한 있는 테스트 범위'인지 강제 검증한다.
모든 attack_*.py 는 발사 전에 반드시 assert_in_scope() 를 호출하며, 이 함수는
모든 비허용 입력을 ScopeError 로 정규화한다(파싱 실패 포함 → fail-closed).

정책 (코드 리뷰 반영 강화판)
- loopback(127.0.0.0/8, ::1): 항상 허용
- 사설 IP(10/172.16/192.168/fc00::): 기본 '권한 필요'(사내 운영이 사설망일 수 있음).
  SECURITY_PLUGIN_ALLOW_PRIVATE=1 일 때만 허용.
- 링크로컬/메타데이터(169.254.0.0/16, 0.0.0.0/8): 항상 차단.
- 정수형 IP 표기(십진/16진/8진)도 IP로 해석(127.0.0.1 → 2130706433 등 위장 차단).
- 자동 허용 도메인: localhost 및 RFC 예약 TLD(.localhost/.local/.test/.example/.invalid)만.
  공개 TLD(.dev/.qa 등)와 'staging'/'dev' 부분일치는 자동 허용하지 않는다.
- 사내 스테이징은 SECURITY_PLUGIN_ALLOW_HOSTS(쉼표구분, 정확매칭 또는 suffix)로 명시 등록.
- 운영 의심(prod/production/www) 및 SECURITY_PLUGIN_DENY_HOSTS: 항상 차단(우선).
- 그 외 공인 도메인/IP: '권한 필요'(--authorized + SECURITY_PLUGIN_AUTHORIZED=1 동시 충족 시만).
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

# 자동 허용 TLD — RFC 6761/2606 예약(라우팅 불가). 공개 TLD(.dev/.qa 등)는 제외.
_ALLOW_TLDS = (".localhost", ".local", ".test", ".example", ".invalid")

# 항상 차단(운영 의심 호스트)
_DENY_HOST_PATTERNS = [
    re.compile(r"(^|[.\-])prod([.\-]|$)", re.I),
    re.compile(r"(^|[.\-])production([.\-]|$)", re.I),
    re.compile(r"^www\.", re.I),
]

# loopback은 항상 허용
_LOOPBACK_NETS = [ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128")]
# 사설 — 기본 '권한 필요'(사내 운영 가능). SECURITY_PLUGIN_ALLOW_PRIVATE=1 일 때만 허용.
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
]
# 항상 차단 — 링크로컬/클라우드 메타데이터/와일드카드
_DENY_NETS = [
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
]


class ScopeError(Exception):
    pass


def _host_from(target: str) -> str:
    """호스트를 소문자·후행점 제거로 정규화. 파싱 실패 시 '' 반환(→ deny 수렴)."""
    try:
        if "://" not in target:
            target = "http://" + target
        host = urlparse(target).hostname or ""
    except (ValueError, TypeError):
        return ""
    return host.strip().rstrip(".").lower()


def _as_ip(host: str):
    """일반 IP + 정수 표기(십진/16진/8진)까지 IP로 해석. 아니면 None."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    try:
        if re.fullmatch(r"\d+", host):
            return ipaddress.ip_address(int(host))
        if re.fullmatch(r"0[xX][0-9a-fA-F]+", host):
            return ipaddress.ip_address(int(host, 16))
        if re.fullmatch(r"0[oO][0-7]+", host):
            return ipaddress.ip_address(int(host, 8))
    except (ValueError, ipaddress.AddressValueError):
        pass
    return None


def _env_list(name: str):
    return [x.strip().lower() for x in os.environ.get(name, "").split(",") if x.strip()]


def classify(target: str) -> tuple[str, str]:
    """returns (decision, reason). decision in {allow, deny, needs-authorization}.
    우선순위: ① 명시 deny → ② IP 판정 → ③ 명시/예약 allow → ④ 기본 needs-authorization."""
    host = _host_from(target)
    if not host:
        return "deny", f"호스트 해석 실패(파싱 오류): {target!r}"

    # ① 명시 deny (운영) — 항상 우선
    for rx in _DENY_HOST_PATTERNS:
        if rx.search(host):
            return "deny", f"운영 의심 호스트 차단 패턴 매치: {host}"
    if host in _env_list("SECURITY_PLUGIN_DENY_HOSTS"):
        return "deny", f"차단 목록(SECURITY_PLUGIN_DENY_HOSTS) 매치: {host}"

    # ② IP 판정 (정수 표기 위장 포함)
    ip = _as_ip(host)
    if ip is not None:
        for net in _DENY_NETS:
            if ip in net:
                return "deny", f"링크로컬/메타데이터 대역 차단: {host}"
        for net in _LOOPBACK_NETS:
            if ip in net:
                return "allow", f"loopback: {host}"
        for net in _PRIVATE_NETS:
            if ip in net:
                if os.environ.get("SECURITY_PLUGIN_ALLOW_PRIVATE") == "1":
                    return "allow", f"사설 IP(ALLOW_PRIVATE=1): {host}"
                return "needs-authorization", f"사설 IP(사내 운영 가능 — 기본 차단): {host}"
        return "needs-authorization", f"공인 IP: {host}"

    # ③ 명시 허용 호스트(환경변수) — 정확매칭 또는 suffix(.example.com)
    for entry in _env_list("SECURITY_PLUGIN_ALLOW_HOSTS"):
        if host == entry or host.endswith("." + entry):
            return "allow", f"허용 목록(SECURITY_PLUGIN_ALLOW_HOSTS): {host}"

    # ③ localhost 및 RFC 예약 TLD만 자동 허용
    if host == "localhost" or host.endswith(_ALLOW_TLDS):
        return "allow", f"예약 TLD/localhost: {host}"

    # ④ 그 외 공인 도메인 — 자동 허용 안 함
    return "needs-authorization", f"공인 도메인(소유 확인 필요): {host}"


def assert_in_scope(target: str, authorized_flag: bool = False) -> str:
    """범위를 벗어나면 ScopeError 발생. 통과하면 사유 문자열 반환.
    모든 비허용(파싱 실패 포함)은 ScopeError 로 수렴한다(fail-closed)."""
    decision, reason = classify(target)
    if decision == "allow":
        return reason
    if decision == "deny":
        raise ScopeError(f"[차단] {reason} — 운영/위험 대상으로 보입니다. 공격 중단.")
    # needs-authorization
    env_ok = os.environ.get("SECURITY_PLUGIN_AUTHORIZED") == "1"
    if authorized_flag and env_ok:
        return f"{reason} — --authorized + SECURITY_PLUGIN_AUTHORIZED=1 확인됨(소유자 책임)"
    raise ScopeError(
        f"[권한 필요] {reason}\n"
        f"  공인/사설 대상은 자동 허용되지 않습니다. 본인 소유/승인된 자산이면:\n"
        f"    1) 환경변수  SECURITY_PLUGIN_AUTHORIZED=1  설정\n"
        f"    2) 스크립트에 --authorized 플래그 전달\n"
        f"  (사내 스테이징은 SECURITY_PLUGIN_ALLOW_HOSTS=<도메인> 또는 ALLOW_PRIVATE=1 로 사전 등록)\n"
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
