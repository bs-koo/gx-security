#!/usr/bin/env python3
"""
exploiting-broken-access-control / attack_access.py
SQIsoft 사내 권한 있는 펜테스트 전용 — BFLA/IDOR을 실제 발사해 악용을 확정한다.
운영 대상 금지. 발사 전 scope_guard 강제. 비파괴 기본.

판정 규칙: BFLA=일반토큰 2xx AND 무토큰(anon) non-2xx (anon도 2xx면 공개 엔드포인트로 제외).
  IDOR=B(타인)토큰 2xx=취약 후보, 401/403=방어. IDOR에서 B가 403이면 즉시 오탐 확정.
"""
import sys
import os
import re
import argparse
import json
from urllib.parse import quote

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

_HERE = os.path.dirname(os.path.abspath(__file__))
_PLUGIN_ROOT = os.path.normpath(os.path.join(_HERE, "..", "..", ".."))
if _PLUGIN_ROOT not in sys.path:
    sys.path.insert(0, _PLUGIN_ROOT)

from tools import dyn_session

_MAPPING_RX = re.compile(
    r'@(?:Get|Post|Put|Patch|Delete|Request)Mapping\(\s*(?:value\s*=\s*|path\s*=\s*)?"([^"]+)"')
_PLACEHOLDER_RX = re.compile(r"\{[^}]+\}")


def build_targets(scan_json, base_url):
    """scan_access --json 결과를 BFLA/IDOR 표적 초안으로 변환."""
    targets = []
    for c in scan_json.get("candidates", []):
        rid = c.get("rule_id", "")
        if "admin-no-preauthorize" in rid or "anyrequestpermitall" in rid:
            kind = "bfla"
        elif "pathvariable-id" in rid:
            kind = "idor"
        else:
            continue
        m = _MAPPING_RX.search(c.get("snippet", ""))
        path = m.group(1) if m else "<UNKNOWN>"
        needs_review = path == "<UNKNOWN>"
        # IDOR는 placeholder가 정확히 1개여야 안전 치환 가능.
        # 0개면 치환 대상이 없어 B가 '자기 리소스'를 조회해 2xx 오탐, 2개 이상이면 단일 id로 불가 → 검토 대상
        if kind == "idor" and len(_PLACEHOLDER_RX.findall(path)) != 1:
            needs_review = True
        targets.append({
            "kind": kind,
            "method": "GET",
            "path": path,
            "source": f"{c.get('file')}:{c.get('line')}",
            "needs_review": needs_review,
        })
    return targets


def run_bfla(base_url, target, normal_token):
    """무토큰(anon)과 일반토큰을 대조: anon 거부(non-2xx)인데 일반토큰 2xx여야 역할우회 취약.
    anon도 2xx면 공개 엔드포인트이므로 역할우회가 아니다(거짓양성 방지)."""
    url = base_url.rstrip("/") + target["path"]
    anon = dyn_session.request("GET", url, token=None)
    r = dyn_session.request("GET", url, token=normal_token)
    anon_2xx = anon["status"] // 100 == 2
    user_2xx = r["status"] // 100 == 2
    return {
        "kind": "bfla", "method": "GET", "path": target["path"],
        "status": r["status"], "anon_status": anon["status"],
        "vulnerable": user_2xx and not anon_2xx,
        "note": ("공개 엔드포인트(anon도 2xx) — 역할우회 아님" if anon_2xx else None),
        "evidence": {"requester": "일반 사용자 토큰", "url": url,
                     "http_status": r["status"], "anon_http_status": anon["status"]},
    }


def run_idor(base_url, target, other_token, resource_id):
    """타인(B) 토큰으로 A 소유 리소스 조회 → 2xx면 IDOR, 403이면 방어(오탐 확정)."""
    # resource_id를 URL-인코딩해 경로 구조 깨짐(슬래시 등)·re.sub 백슬래시 해석을 방지
    path = _PLACEHOLDER_RX.sub(quote(resource_id, safe=""), target["path"], count=1)  # 단일 placeholder
    url = base_url.rstrip("/") + path
    r = dyn_session.request("GET", url, token=other_token)
    return {
        "kind": "idor",
        "method": "GET",
        "path": path,
        "status": r["status"],
        "vulnerable": r["status"] // 100 == 2,
        "evidence": {"requester": "타인(B) 토큰", "resource_owner": "A",
                     "url": url, "http_status": r["status"]},
    }


def _resolve_token(inject, user_id, user_pw, base_url, args):
    """주입 토큰 우선, 없으면 login 자동화."""
    if inject:
        return inject
    if user_id and user_pw:
        return dyn_session.login(
            base_url, args.login_path, {"id": user_id, "pw": user_pw},
            body_template=args.body_template, token_json_path=args.token_path)
    if user_id or user_pw:
        raise RuntimeError("계정 id/pw는 함께 지정해야 합니다 (한쪽만 전달됨)")
    return None


def run(args):
    base_url = args.base_url
    # 0. 안전 게이트
    try:
        scope_reason = dyn_session.assert_in_scope(base_url, authorized_flag=args.authorized)
    except dyn_session.ScopeError as e:
        if args.json:
            print(json.dumps({"error": "scope_blocked", "detail": str(e)}, ensure_ascii=False))
        else:
            print(f"[차단] {e}")
        sys.exit(1)

    if not args.json:
        print(f"[+] scope 통과: {scope_reason}")

    # 1. 토큰 확보 (A=일반, B=타인/비교군) — 로그인 실패는 명확히 보고(spec 9절)
    try:
        token_a = _resolve_token(args.token_a, args.user_a_id, args.user_a_pw, base_url, args)
        token_b = _resolve_token(args.token_b, args.user_b_id, args.user_b_pw, base_url, args)
    except RuntimeError as e:
        if args.json:
            print(json.dumps({"error": "login_failed", "detail": str(e)}, ensure_ascii=False))
        else:
            print(f"[로그인 실패] {e}")
        sys.exit(2)

    if not args.json:   # 토큰은 마스킹해 발급 여부만 노출
        print(f"[+] A 토큰: {dyn_session.mask_token(token_a)}  /  B 토큰: {dyn_session.mask_token(token_b)}")

    # 2. 표적 생성
    targets = []
    if args.scan:
        try:
            with open(args.scan, encoding="utf-8") as f:
                targets = build_targets(json.load(f), base_url)
        except (OSError, ValueError) as e:
            if args.json:
                print(json.dumps({"error": "scan_file_error", "detail": str(e)}, ensure_ascii=False))
            else:
                print(f"[오류] 스캔 결과를 읽을 수 없습니다: {e}")
            sys.exit(3)
    elif not args.json:
        print("[!] --scan 미지정 — 발사할 표적이 없습니다. scan_access.py --json 결과를 지정하세요.")

    # 3. 발사 (GET 비파괴만). 발사 불가 표적은 skipped, 연결 실패는 error로 기록하고 계속한다.
    bfla_ready = bool(token_a)
    idor_ready = bool(token_b and args.resource_id)
    if not args.json:
        if any(t["kind"] == "bfla" and not t.get("needs_review") for t in targets) and not bfla_ready:
            print("[!] BFLA 표적이 있으나 A(일반) 토큰이 없습니다 — --token-a 또는 --user-a-id/pw 필요")
        if any(t["kind"] == "idor" and not t.get("needs_review") for t in targets) and not idor_ready:
            print("[!] IDOR 표적이 있으나 B(타인) 토큰 또는 --resource-id가 없어 발사하지 못합니다")
    findings = []
    for t in targets:
        if t.get("needs_review"):
            continue
        try:
            if t["kind"] == "bfla":
                if bfla_ready:
                    findings.append(run_bfla(base_url, t, token_a))
                else:
                    findings.append({"kind": "bfla", "method": "GET", "path": t.get("path"),
                                     "status": None, "vulnerable": False, "skipped": "A 토큰 없음"})
            elif t["kind"] == "idor":
                if idor_ready:
                    findings.append(run_idor(base_url, t, token_b, args.resource_id))
                else:
                    findings.append({"kind": "idor", "method": "GET", "path": t.get("path"),
                                     "status": None, "vulnerable": False,
                                     "skipped": "B 토큰 또는 resource-id 없음"})
        except Exception as e:
            findings.append({"kind": t["kind"], "method": "GET", "path": t.get("path"),
                             "status": None, "vulnerable": False,
                             "error": f"발사 실패: {type(e).__name__}"})

    if args.allow_destructive and not args.json:
        print("[!] --allow-destructive: 쓰기(PUT/DELETE) 확정은 수동 승인 후 별도 발사 필요")

    # 4. 출력
    dyn_session.emit({"skill": "exploiting-broken-access-control",
                      "target": base_url, "findings": findings}, args.json)


def _build_parser():
    p = argparse.ArgumentParser(
        description="BFLA/IDOR 동적 침투 (SQIsoft 사내 펜테스트 전용). scope_guard 강제.")
    p.add_argument("base_url", help="대상 베이스 URL (예: http://localhost:7171)")
    p.add_argument("--scan", help="scan_access.py --json 결과 파일 경로")
    p.add_argument("--user-a-id")
    p.add_argument("--user-a-pw")
    p.add_argument("--user-b-id")
    p.add_argument("--user-b-pw")
    p.add_argument("--token-a", help="A(일반) 토큰 직접 주입 (로그인 생략)")
    p.add_argument("--token-b", help="B(타인) 토큰 직접 주입")
    p.add_argument("--login-path", default="/api/v1/auth/login")
    p.add_argument("--body-template", default=None,
                   help='예: \'{"lgnId":"{id}","password":"{pw}"}\'')
    p.add_argument("--token-path", default="data.accessToken")
    p.add_argument("--resource-id", help="IDOR: A가 소유/생성한 리소스 ID")
    p.add_argument("--allow-destructive", action="store_true")
    p.add_argument("--authorized", action="store_true")
    p.add_argument("--json", action="store_true")
    return p


if __name__ == "__main__":
    run(_build_parser().parse_args())
