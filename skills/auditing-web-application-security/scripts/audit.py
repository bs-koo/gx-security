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
    cmd = [sys.executable, os.path.join(ROOT, "scan_all.py"), source, "--json"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=900)
        return json.loads(out.stdout or "{}"), None
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as e:
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
                results.append({"vuln": vuln, "param": param, "result": data,
                                "returncode": out.returncode})
            except (subprocess.TimeoutExpired, OSError) as e:
                results.append({"vuln": vuln, "param": param, "error": str(e)[:120]})
    return results


def main():
    ap = argparse.ArgumentParser(description="SQIsoft 보안 통합 점검 오케스트레이터")
    ap.add_argument("source", help="검사 대상 소스 디렉토리")
    ap.add_argument("--target", help="실행 중인 대상 URL(스테이징/로컬). 주면 동적 공격 수행")
    ap.add_argument("--params", help="동적 공격 대상 파라미터(쉼표구분, 예: id,q,search)")
    ap.add_argument("--authorized", action="store_true", help="공인 대상 명시 승인(소유자 책임)")
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
        params = [p.strip() for p in args.params.split(",")] if args.params else None
        report["phases"]["dynamic"] = run_dynamic(args.target, params, args.authorized)
    else:
        report["phases"]["dynamic"] = {"skipped": "대상 URL(--target) 미지정 — 정적만 수행"}

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
    else:
        print(f"[정적] 실패: {st}\n")

    dyn = report["phases"]["dynamic"]
    if isinstance(dyn, list):
        print("[동적] 실제 공격 발사 결과")
        for d in dyn:
            if "error" in d:
                print(f"  - {d['vuln']}({d.get('param')}) : 오류 {d['error']}")
                continue
            res = d.get("result", {})
            if res.get("blocked_or_no_json"):
                print(f"  - {d['vuln']}({d.get('param')}) : {res.get('raw','')[:80]}")
            else:
                exploited = res.get("exploited")
                mark = "🔴 악용 확정" if exploited else "— 미확인"
                print(f"  - {d['vuln']}({d.get('param')}) : {mark}")
    else:
        print(f"[동적] {dyn.get('skipped','')}")

    print(f"\n※ {report['next']}")


if __name__ == "__main__":
    main()
