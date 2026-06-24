#!/usr/bin/env python3
"""
SQIsoft 보안 플러그인 통합 스캐너 런처.

플러그인의 모든 취약점 스킬(skills/*/scripts/scan_*.py)을 대상 프로젝트에
한 번에 돌려 1차 후보를 요약한다. 스택은 각 스킬이 자동 감지한다.

⚠️ 이것은 '1단계(스캐너) 일괄 실행'일 뿐이다. 오탐이 포함되며,
   최종 취약/오탐 판정과 4요소 리포트는 Claude Code에서 각 스킬의
   2단계(AI 컨텍스트 검증)를 수행해야 완성된다.

사용:
  python scan_all.py <target_path>            # 요약 표
  python scan_all.py <target_path> --json     # 통합 JSON
  python scan_all.py <target_path> --only csrf,sqli   # 일부 스킬만
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

ROOT = os.path.dirname(os.path.abspath(__file__))
SKILLS_DIR = os.path.join(ROOT, "skills")

# 스킬 디렉토리명 → 사람이 읽는 라벨
LABELS = {
    "detecting-csrf-vulnerabilities": "CSRF",
    "detecting-xss-vulnerabilities": "XSS",
    "detecting-sql-injection": "SQL Injection",
    "detecting-file-upload-vulnerabilities": "File Upload/웹쉘",
    "detecting-path-traversal": "Path Traversal",
    "detecting-broken-access-control": "Access Control/IDOR",
    "detecting-auth-session-weaknesses": "Auth/Session/JWT",
    "detecting-sensitive-data-exposure": "Sensitive Data/Secret",
    "detecting-ssrf-and-open-redirect": "SSRF/Open Redirect",
}


def find_scanners():
    """각 스킬의 scripts/scan_*.py 경로를 찾는다."""
    found = []
    if not os.path.isdir(SKILLS_DIR):
        return found
    for skill in sorted(os.listdir(SKILLS_DIR)):
        sdir = os.path.join(SKILLS_DIR, skill, "scripts")
        if not os.path.isdir(sdir):
            continue
        for f in sorted(os.listdir(sdir)):
            if f.startswith("scan_") and f.endswith(".py"):
                found.append((skill, os.path.join(sdir, f)))
                break
    return found


def run_one(script, target):
    try:
        out = subprocess.run(
            [sys.executable, script, target, "--json"],
            capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=600,
        )
        data = json.loads(out.stdout or "{}")
        return data, None
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except (json.JSONDecodeError, OSError) as e:
        return None, str(e)[:120]


def main():
    ap = argparse.ArgumentParser(description="SQIsoft 통합 보안 스캐너")
    ap.add_argument("target", help="검사 대상 디렉토리")
    ap.add_argument("--json", action="store_true", help="통합 JSON 출력")
    ap.add_argument("--only", help="쉼표구분 키워드로 일부 스킬만 (예: csrf,sqli,xss)")
    args = ap.parse_args()

    if not os.path.isdir(args.target):
        print(f"오류: 디렉토리가 아닙니다 — {args.target}", file=sys.stderr)
        sys.exit(2)

    scanners = find_scanners()
    if args.only:
        keys = [k.strip().lower() for k in args.only.split(",") if k.strip()]
        scanners = [s for s in scanners if any(k in s[0].lower() for k in keys)]

    results = []
    stacks = set()
    engine = None
    for skill, script in scanners:
        data, err = run_one(script, args.target)
        if err:
            results.append({"skill": skill, "label": LABELS.get(skill, skill),
                            "error": err, "candidate_count": None})
            continue
        for s in data.get("detected_stacks", []):
            stacks.add(s)
        engine = engine or data.get("engine")
        results.append({
            "skill": skill,
            "label": LABELS.get(skill, skill),
            "candidate_count": data.get("candidate_count", 0),
            "candidates": data.get("candidates", []),
        })

    summary = {
        "target": args.target,
        "detected_stacks": sorted(stacks),
        "engine": engine,
        "total_candidates": sum(r.get("candidate_count") or 0 for r in results),
        "by_skill": results,
        "note": "1차 후보입니다. 최종 판정/4요소 리포트는 Claude Code에서 각 스킬 2단계(AI 검증) 수행.",
    }

    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return

    print(f"대상: {args.target}")
    print(f"감지 스택: {', '.join(summary['detected_stacks']) or '?'}   엔진: {engine}")
    print(f"{'─'*48}")
    print(f"{'취약점 클래스':<24}{'후보 수':>8}")
    print(f"{'─'*48}")
    for r in results:
        cnt = "ERR" if r.get("candidate_count") is None else r["candidate_count"]
        print(f"{r['label']:<24}{str(cnt):>8}")
    print(f"{'─'*48}")
    print(f"{'합계':<24}{summary['total_candidates']:>8}")
    print(f"\n※ 1차 후보(오탐 포함)입니다. 정확한 취약/오탐 판정과")
    print(f"  4요소 리포트는 Claude Code에서 각 스킬을 호출해 완성하세요.")


if __name__ == "__main__":
    main()
