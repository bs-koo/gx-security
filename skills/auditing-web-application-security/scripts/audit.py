#!/usr/bin/env python3
"""
SQIsoft 보안 통합 점검 오케스트레이터 (정적 + 동적 한 번에).

한 명령으로:
  1) 정적 — scan_all.py 로 9종 취약점 후보를 일괄 도출(소스만 있으면 됨)
  2) 동적 — --target(실행 중 URL) 이 주어지면 exploiting-* 로 실제 페이로드 발사
  3) 통합 결과(JSON/요약) 출력

⚠️ 이 스크립트는 '엔진'이다. 오탐 제거·컨텍스트 판단·4요소 리포트 작성은
   Claude Code에서 auditing-web-application-security 스킬(AI 단계)이 수행한다.

사용:
  python audit.py <소스경로>                          # 정적만
  python audit.py <소스경로> --target http://localhost:8080 --params id,q   # 정적 + 동적
"""
import argparse
import json
import os
import subprocess
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    # [L3] stderr도 UTF-8로 고정 (scope_guard 등 다른 스크립트와 일관성)
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

# audit.py 위치: skills/auditing-web-application-security/scripts/audit.py → 3단계 상위가 플러그인 루트
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))

# 동적 공격 스크립트 (현재 구현된 exploiting-*)
DYNAMIC = {
    "sql-injection": os.path.join(ROOT, "skills", "exploiting-sql-injection", "scripts", "attack_sqli.py"),
    "xss": os.path.join(ROOT, "skills", "exploiting-xss-vulnerabilities", "scripts", "attack_xss.py"),
}


def run_static(source):
    """scan_all.py를 호출해 정적 스캔 결과를 반환.

    [L2] 자식 returncode != 0 이고 stdout이 비면 stderr를 error로 노출.
    """
    cmd = [sys.executable, os.path.join(ROOT, "scan_all.py"), source, "--json"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=900)
        if out.stdout and out.stdout.strip():
            try:
                data = json.loads(out.stdout)
                if out.returncode != 0:
                    data.setdefault("error", f"rc={out.returncode}: {out.stderr[:200].strip()}")
                return data, None
            except json.JSONDecodeError:
                pass
        stderr_head = out.stderr[:300].strip() if out.stderr else ""
        return None, f"rc={out.returncode}: {stderr_head or '(출력 없음)'}"
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except OSError as e:
        return None, str(e)[:150]


def run_dynamic(target, params, authorized):
    results = []
    for vuln, script in DYNAMIC.items():
        if not os.path.exists(script):
            continue
        for param in (params or [None]):
            cmd = [sys.executable, script, target, "--json"]
            if param:
                cmd += ["--param", param]
            if authorized:
                cmd += ["--authorized"]
            try:
                out = subprocess.run(cmd, capture_output=True, text=True,
                                     encoding="utf-8", errors="replace", timeout=600)
                # 안전게이트 차단 시 비-JSON(차단 메시지)일 수 있음 → 안전 파싱
                try:
                    data = json.loads(out.stdout or "{}")
                except json.JSONDecodeError:
                    data = {"raw": (out.stdout or out.stderr or "").strip()[:200],
                            "blocked_or_no_json": True}
                d = {"vuln": vuln, "param": param, "result": data,
                     "returncode": out.returncode}
                if param is None:
                    d["param_missing"] = True
                    d["reason"] = (
                        f"파라미터 미지정 — attack 스크립트가 --param 누락으로 "
                        f"미발사(rc={out.returncode}). --params id,q 등 지정 필요")
                results.append(d)
            except (subprocess.TimeoutExpired, OSError) as e:
                results.append({"vuln": vuln, "param": param, "error": str(e)[:120]})
    return results


_ACCESS_SCRIPT = os.path.join(
    ROOT, "skills", "exploiting-broken-access-control", "scripts", "attack_access.py")

_AUTH_SCRIPT = os.path.join(
    ROOT, "skills", "exploiting-auth-session", "scripts", "attack_auth.py")


def _extract_access_candidates(static_result):
    """정적 통합 결과(by_skill)에서 접근통제(BFLA/IDOR) 후보만 추출."""
    for s in (static_result or {}).get("by_skill", []):
        if "broken-access-control" in s.get("skill", ""):
            return s.get("candidates", [])
    return []


def run_access_dynamic(target, static_result, creds, authorized):
    """정적 access-control 후보를 attack_access로 동적 확정한다(개선 D).

    계정/토큰 미제공 시 발사하지 않고 'static-only'(정적 추정·동적 미확정)로 표기한다(개선 E).
    IDOR/BFLA는 본질적으로 동적 확정이 필요하므로, 동적을 못 돌리면 High로 단정하지 않는다.
    """
    if not os.path.exists(_ACCESS_SCRIPT):
        return {"skipped": "attack_access.py 없음"}
    # N1: 정적 스캔이 부분 실패(error 동반)면 불완전한 후보로 동적 확정하지 않는다
    if isinstance(static_result, dict) and static_result.get("error"):
        return {"skipped": "정적 스캔 부분 실패 — 동적 연계 보류",
                "static_error": str(static_result["error"])[:200]}
    candidates = _extract_access_candidates(static_result)
    if not candidates:
        return {"skipped": "정적 access-control 후보 없음"}
    has_creds = creds.get("token_a") or (creds.get("user_a_id") and creds.get("user_a_pw"))
    if not has_creds:
        return {
            "confidence": "static-only",
            "candidate_count": len(candidates),
            "note": ("access-control 후보가 있으나 테스트 계정 미제공 → 동적 미확정(정적 추정). "
                     "--user-a-id/pw(+--user-b-id/pw·--resource-id) 또는 --token-a 제공 시 동적 확정."),
        }
    import tempfile
    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    try:
        json.dump({"candidates": candidates}, tmp, ensure_ascii=False)
        tmp.close()
        cmd = [sys.executable, _ACCESS_SCRIPT, target, "--scan", tmp.name, "--json"]
        for flag, key in [("--token-a", "token_a"), ("--token-b", "token_b"),
                          ("--resource-id", "resource_id")]:
            if creds.get(key):
                cmd += [flag, creds[key]]
        if creds.get("user_a_id") and creds.get("user_a_pw"):
            cmd += ["--user-a-id", creds["user_a_id"], "--user-a-pw", creds["user_a_pw"]]
        if creds.get("user_b_id") and creds.get("user_b_pw"):
            cmd += ["--user-b-id", creds["user_b_id"], "--user-b-pw", creds["user_b_pw"]]
        if authorized:
            cmd += ["--authorized"]
        out = subprocess.run(cmd, capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=600)
        try:
            data = json.loads(out.stdout or "{}")
            if not isinstance(data, dict):  # dict 아닌 JSON(list 등) 반환 시 data.get() 크래시 방어 (PR 리뷰 반영)
                data = {"raw": str(data)[:200], "blocked_or_no_json": True}
        except json.JSONDecodeError:
            data = {"raw": (out.stdout or out.stderr or "").strip()[:200],
                    "blocked_or_no_json": True}
        # 발사했더라도 모든 표적이 skipped(예: IDOR인데 token_b/resource_id 없음)면
        # 동적으로 확정한 게 없으므로 'dynamic'으로 과대표기하지 않는다(정적 추정 유지).
        fired = [f for f in (data.get("findings") or [])
                 if isinstance(f, dict) and not f.get("skipped")]
        if isinstance(data, dict) and data.get("findings") and not fired:
            return {"confidence": "static-only", "result": data, "returncode": out.returncode,
                    "note": "동적 발사했으나 모든 표적이 skipped(토큰/리소스 부족) — 정적 추정 유지"}
        return {"confidence": "dynamic", "result": data, "returncode": out.returncode}
    except (subprocess.TimeoutExpired, OSError) as e:
        return {"error": str(e)[:120]}
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def run_auth_dynamic(target, creds, probe, authorized):
    """정적 추정된 인증/세션/JWT를 attack_auth로 동적 확정한다(FR-2/3).

    계정/토큰 미제공 시 발사하지 않고 'static-only'(정적 추정·동적 미확정)로 표기한다(AC-2).
    발사하더라도 모든 검사가 skip(probe 미지정+쿠키 없음 등)이면 과대표기하지 않고
    static-only로 유지한다(run_access_dynamic L158-162 방어 패턴 준용).
    """
    if not os.path.exists(_AUTH_SCRIPT):
        return {"skipped": "attack_auth.py 없음"}
    has_creds = creds.get("token_a") or (creds.get("user_a_id") and creds.get("user_a_pw"))
    if not has_creds:
        return {
            "confidence": "static-only",
            "note": ("로그인 계정/토큰 미제공 → 인증 동적 미확정(정적 추정). "
                     "--user-a-id/pw 또는 --token-a 제공 시 발사"),
        }
    cmd = [sys.executable, _AUTH_SCRIPT, target, "--json"]
    if probe:
        cmd += ["--probe", probe]
    if creds.get("token_a"):
        cmd += ["--token-a", creds["token_a"]]
    elif creds.get("user_a_id") and creds.get("user_a_pw"):
        cmd += ["--user-a-id", creds["user_a_id"], "--user-a-pw", creds["user_a_pw"]]
    if authorized:
        cmd += ["--authorized"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=600)
        try:
            data = json.loads(out.stdout or "{}")
            if not isinstance(data, dict):  # dict 아닌 JSON(list 등) 반환 시 data.get() 크래시 방어 (PR 리뷰 반영)
                data = {"raw": str(data)[:200], "blocked_or_no_json": True}
        except json.JSONDecodeError:
            data = {"raw": (out.stdout or out.stderr or "").strip()[:200],
                    "blocked_or_no_json": True}
        if data.get("error") == "scope_blocked":
            return {"blocked": "scope_guard", "detail": data.get("detail"), "returncode": 1}
        # 로그인 실패는 자식이 {"error":"login_failed"} JSON 출력 후 exit(2)하므로 error 키로 판정.
        # (argparse 인자오류 등 stdout 없는 rc=2는 아래 rc 게이트가 error로 정직 표기 — 코드리뷰 #11)
        if data.get("error") == "login_failed":
            return {"confidence": "login-failed", "detail": data.get("detail"),
                    "returncode": 2}
        # rc 게이트(크래시 은폐 방지, ZT CRITICAL): 발사(계정 있음) 후 stdout이 빈 채
        # (data=={}) 비정상 종료(rc≠0)면 자식이 uncaught 예외로 죽은 것 — static-only로
        # 오분류하지 말고 error로 정직 표기한다. fired 판정보다 반드시 먼저 평가한다.
        if data == {} and out.returncode not in (0, None):
            return {"error": f"인증 발사 중 오류(rc={out.returncode}) — 자식 프로세스 비정상 종료",
                    "returncode": out.returncode}
        findings = data.get("findings", [])
        fired = [f for f in findings if isinstance(f, dict) and not f.get("skipped")]
        if not fired:
            return {"confidence": "static-only", "result": data,
                    "note": ("발사 시도했으나 모든 검사 skip(probe 미지정+쿠키 없음 등) "
                             "→ 정적 추정")}
        if not probe:
            return {"confidence": "partial", "result": data,
                    "note": ("쿠키 속성만 발사, JWT 변조·재사용은 정적 추정(probe 미지정). "
                             "--probe 지정 시 전체 발사")}
        return {"confidence": "dynamic", "result": data, "returncode": out.returncode}
    except (subprocess.TimeoutExpired, OSError) as e:
        return {"error": str(e)[:120]}


def render_dynamic_line(d):
    """동적 공격 결과 항목 1건을 사람이 읽는 한 줄 문자열로 렌더링한다.

    분기 순서(위→아래, 먼저 매치되는 것 채택)가 §9-C 안전 불변식이다:
    scope_blocked(3)·blocked_or_no_json(4)이 rc≠0(5)보다 먼저 평가돼야
    scope 차단/차단 raw가 '발사 실패 rc'로 뭉개지지 않는다.
    """
    prefix = f"  - {d['vuln']}({d.get('param')}) : "
    res = d.get("result")
    if not isinstance(res, dict):  # 자식이 dict 아닌 JSON(list 등) 반환 시 방어 (PR 리뷰 반영)
        res = {}
    if d.get("error"):
        return f"{prefix}⚠ 오류: {d['error']}"
    if d.get("param_missing"):
        return f"{prefix}⏭ 미발사 (파라미터 미지정) — {d.get('reason')}"
    if res.get("error") == "scope_blocked":
        return f"{prefix}⏭ 차단됨 (scope_guard) — {res.get('detail') or 'scope 범위 밖'}"
    if res.get("blocked_or_no_json"):
        return f"{prefix}{res.get('raw','')[:80]}"
    if d.get("returncode") not in (0, None):
        return f"{prefix}⚠ 발사 실패 rc={d.get('returncode')}"
    return f"{prefix}{'🔴 악용 확정' if res.get('exploited') else '— 미확인'}"


def main():
    ap = argparse.ArgumentParser(description="SQIsoft 보안 통합 점검 오케스트레이터")
    ap.add_argument("source", help="검사 대상 소스 디렉토리")
    ap.add_argument("--target", help="실행 중인 대상 URL(스테이징/로컬). 주면 동적 공격 수행")
    ap.add_argument("--params", help="동적 공격 대상 파라미터(쉼표구분, 예: id,q,search)")
    ap.add_argument("--authorized", action="store_true", help="공인 대상 명시 승인(소유자 책임)")
    # 접근통제(BFLA/IDOR) 동적 연계용 테스트 계정/토큰 (개선 D)
    ap.add_argument("--user-a-id"); ap.add_argument("--user-a-pw")
    ap.add_argument("--user-b-id"); ap.add_argument("--user-b-pw")
    ap.add_argument("--token-a"); ap.add_argument("--token-b")
    ap.add_argument("--resource-id", help="IDOR: A가 소유한 리소스 ID")
    ap.add_argument("--probe", help="인증 동적: 보호 엔드포인트 직접 지정(예: /api/v1/users/me). "
                                    "미지정 시 JWT·재사용 정적 추정")
    ap.add_argument("--json", action="store_true", help="통합 JSON 출력")
    args = ap.parse_args()

    if not os.path.isdir(args.source):
        print(f"오류: 소스 디렉토리가 아닙니다 — {args.source}", file=sys.stderr)
        sys.exit(2)

    report = {"source": args.source, "target": args.target, "phases": {}}

    # 1) 정적
    static, err = run_static(args.source)
    report["phases"]["static"] = {"error": err} if err else static

    # 2) 동적 (대상 URL 있을 때만)
    if args.target:
        # [H3] 빈/공백 토큰 제거: "id,,q, " → ["id", "q"]
        # 모두 비면 None으로 처리해 빈 파라미터 공격 유발 방지
        params = (
            [p.strip() for p in args.params.split(",") if p.strip()] or None
            if args.params else None
        )
        report["phases"]["dynamic"] = run_dynamic(args.target, params, args.authorized)
        creds = {"user_a_id": args.user_a_id, "user_a_pw": args.user_a_pw,
                 "user_b_id": args.user_b_id, "user_b_pw": args.user_b_pw,
                 "token_a": args.token_a, "token_b": args.token_b,
                 "resource_id": args.resource_id}
        # N2: 한쪽만 지정된 계정(id 또는 pw) 경고 — audit 레이어가 조용히 drop하지 않도록
        for _who in ("a", "b"):
            _uid = getattr(args, f"user_{_who}_id")
            _upw = getattr(args, f"user_{_who}_pw")
            if bool(_uid) != bool(_upw) and not args.json:
                print(f"[!] --user-{_who}-id/--user-{_who}-pw는 함께 지정해야 합니다 (한쪽만 전달 — 무시됨)")
        report["phases"]["access_dynamic"] = run_access_dynamic(
            args.target, report["phases"]["static"], creds, args.authorized)
        report["phases"]["auth_dynamic"] = run_auth_dynamic(
            args.target,
            {"user_a_id": args.user_a_id, "user_a_pw": args.user_a_pw,
             "token_a": args.token_a},
            args.probe, args.authorized)
    else:
        report["phases"]["dynamic"] = {"skipped": "대상 URL(--target) 미지정 — 정적만 수행"}
        report["phases"]["access_dynamic"] = {"skipped": "대상 URL 미지정"}
        report["phases"]["auth_dynamic"] = {"skipped": "대상 URL 미지정"}

    report["next"] = ("Claude Code에서 auditing-web-application-security 스킬로 "
                      "오탐 제거·컨텍스트 검증·4요소 통합 리포트를 완성하세요.")

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return

    # 사람이 읽는 요약
    print(f"━━━ SQIsoft 통합 보안 점검 ━━━")
    print(f"소스: {args.source}")
    print(f"대상 URL: {args.target or '(없음 — 정적만)'}\n")

    st = report["phases"]["static"]
    if isinstance(st, dict) and st.get("by_skill"):
        print(f"[정적] 감지 스택: {', '.join(st.get('detected_stacks', [])) or '?'}")
        print(f"{'취약점 클래스':<24}{'후보':>6}")
        print("─" * 32)
        for r in st["by_skill"]:
            cnt = "ERR" if r.get("candidate_count") is None else r["candidate_count"]
            print(f"{r['label']:<24}{str(cnt):>6}")
        print("─" * 32)
        print(f"{'합계':<24}{st.get('total_candidates', 0):>6}\n")
        if isinstance(st, dict) and st.get("warnings"):
            print("[!] 정적 폴백 경고")
            for w in st["warnings"]:
                print(f"  - {w}")
            print()
    else:
        print(f"[정적] 실패: {st}\n")

    dyn = report["phases"]["dynamic"]
    if isinstance(dyn, list):
        print("[동적] 실제 공격 발사 결과")
        for d in dyn:
            print(render_dynamic_line(d))
    else:
        print(f"[동적] {dyn.get('skipped','')}")

    acc = report["phases"].get("access_dynamic", {})
    if acc.get("confidence") == "static-only":
        print(f"[접근통제] 정적 추정(동적 미확정) — 후보 {acc.get('candidate_count')}건. "
              f"테스트 계정 제공 시 동적 확정")
    elif acc.get("confidence") == "dynamic":
        res = acc.get("result", {})
        fcount = len(res.get("findings", [])) if isinstance(res, dict) else 0
        print(f"[접근통제] 동적 확정 발사 완료 — findings {fcount}건")
    elif acc.get("error"):
        print(f"[접근통제] 오류: {acc['error']}")
    elif acc.get("skipped"):
        print(f"[접근통제] {acc['skipped']}")

    au = report["phases"].get("auth_dynamic", {})
    if au.get("blocked") == "scope_guard":  # rc로 안 뭉개지게 최상단(AC-5)
        print(f"[인증] 차단됨(scope_guard) — {au.get('detail') or 'scope 범위 밖'}")
    elif au.get("confidence") == "login-failed":  # '미발견'과 구분(AC-4)
        print(f"[인증] 동적 미확정(로그인 실패) — {au.get('detail')}")
    elif au.get("confidence") == "static-only":  # 과대표기 방지(AC-2)
        print(f"[인증] 정적 추정(동적 미확정) — {au.get('note')}")
    elif au.get("confidence") in ("partial", "dynamic"):
        label = "부분 발사(쿠키만)" if au["confidence"] == "partial" else "동적 확정 발사"
        print(f"[인증] {label}")
        for f in au.get("result", {}).get("findings", []):  # finding별 취약/방어(FR-4)
            # 우선순위 skipped > error > vulnerable. error finding(발사 예외 격리)을
            # '방어'로 오표기하면 크래시 은폐의 finding판(P0 조용한 실패)이 되므로 정직 표기한다.
            if f.get("skipped"):
                print(f"    - [{f.get('kind')}] 미발사({f.get('skipped')})")
            elif f.get("error"):
                print(f"    - [{f.get('kind')}] ⚠ 오류: {f.get('error')}")
            else:
                print(f"    - [{f.get('kind')}] {'🔴 취약' if f.get('vulnerable') else '방어'}")
                # jwt-tamper 4변형(alg_none/sig_strip/payload_role/exp_past) variant별 세분 노출(FR-4)
                if f.get("kind") == "jwt-tamper" and isinstance(f.get("findings"), list):
                    for v in f["findings"]:
                        if not isinstance(v, dict):
                            continue
                        if v.get("error"):  # variant 발사 예외도 '방어'로 은폐 금지
                            print(f"        · {v.get('variant')}: ⚠ 오류: {v.get('error')}")
                            continue
                        mark = "🔴 취약" if v.get("vulnerable") else "방어"
                        print(f"        · {v.get('variant')}(HTTP {v.get('status')}): {mark}")
    elif au.get("error"):
        print(f"[인증] 오류: {au['error']}")
    elif au.get("skipped"):
        print(f"[인증] {au['skipped']}")

    print(f"\n※ {report['next']}")


if __name__ == "__main__":
    main()
