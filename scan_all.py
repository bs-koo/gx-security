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

# [L1] --only 사용자 친화 별칭 → 디렉토리명 키워드 매핑
# 예: "sqli" → "sql-injection" 으로 정규화해 detecting-sql-injection 디렉토리를 매칭
ALIAS_MAP = {
    "sqli": "sql-injection",
    "sql": "sql-injection",
    "secrets": "sensitive-data",
    "secret": "sensitive-data",
    "auth": "auth-session",
    "session": "auth-session",
    "access": "broken-access",
    "idor": "broken-access",
    "upload": "file-upload",
    "webshell": "file-upload",
    "traversal": "path-traversal",
    "lfi": "path-traversal",
    "redirect": "ssrf-and-open-redirect",
    "ssrf": "ssrf-and-open-redirect",
    "openredirect": "ssrf-and-open-redirect",
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
    """스캐너 스크립트 1개를 실행해 (data, error) 튜플로 반환.

    [L2] 자식 프로세스가 returncode != 0 이고 stdout이 비어 있으면
    stderr 앞부분을 error 필드에 담아 실패를 숨기지 않는다.
    """
    try:
        out = subprocess.run(
            [sys.executable, script, target, "--json"],
            capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=600,
        )
        # 정상 JSON이 있으면 그것을 우선 반환
        if out.stdout and out.stdout.strip():
            try:
                data = json.loads(out.stdout)
                # 자식이 실패했지만 JSON을 내보낸 경우 error 필드 추가
                if out.returncode != 0:
                    data.setdefault("error", f"rc={out.returncode}: {out.stderr[:200].strip()}")
                return data, None
            except json.JSONDecodeError:
                pass
        # stdout 없거나 JSON 파싱 실패 → stderr를 error로 반환
        stderr_head = out.stderr[:300].strip() if out.stderr else ""
        msg = f"rc={out.returncode}: {stderr_head}" if stderr_head else f"rc={out.returncode}: (출력 없음)"
        return None, msg
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except OSError as e:
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
        # [L1] 사용자 키워드를 별칭맵으로 정규화한 뒤 디렉토리명에 부분문자열 매칭
        raw_keys = [k.strip().lower() for k in args.only.split(",") if k.strip()]
        keys = [ALIAS_MAP.get(k, k) for k in raw_keys]
        scanners = [s for s in scanners if any(k in s[0].lower() for k in keys)]

    results = []
    stacks = set()
    # [M4] 여러 스킬이 서로 다른 engine을 보고할 수 있으므로 set으로 수집
    engines: set = set()
    for skill, script in scanners:
        data, err = run_one(script, args.target)
        if err:
            results.append({"skill": skill, "label": LABELS.get(skill, skill),
                            "error": err, "candidate_count": None})
            continue
        for s in data.get("detected_stacks", []):
            stacks.add(s)
        # [M4] data에 error 필드가 있으면(자식 rc != 0) 결과에 포함
        eng = data.get("engine")
        if eng:
            engines.add(eng)
        row = {
            "skill": skill,
            "label": LABELS.get(skill, skill),
            "candidate_count": data.get("candidate_count", 0),
            "candidates": data.get("candidates", []),
        }
        if data.get("error"):
            row["error"] = data["error"]
        results.append(row)

    # [M4] engines 집합을 정렬 목록으로 보고 (불일치 가시화)
    engines_sorted = sorted(engines)

    summary = {
        "target": args.target,
        "detected_stacks": sorted(stacks),
        "engines": engines_sorted,                          # [M4] 복수 엔진 목록
        "engine": engines_sorted[0] if len(engines_sorted) == 1 else engines_sorted,
        "total_candidates": sum(r.get("candidate_count") or 0 for r in results),
        "by_skill": results,
        "note": "1차 후보입니다. 최종 판정/4요소 리포트는 Claude Code에서 각 스킬 2단계(AI 검증) 수행.",
    }

    # [폴백 경고] grep-fallback 엔진이 하나라도 쓰였으면 recall 저하 경고를 실어 보낸다
    if "grep-fallback" in engines:
        summary["warnings"] = [
            "grep-fallback 엔진 사용 — recall(탐지율)이 낮습니다",
            "semgrep 설치 권장: pip install semgrep",
            "후보 0건이 안전을 의미하지 않습니다",
        ]

    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return

    engine_label = ", ".join(engines_sorted) if engines_sorted else "?"
    print(f"대상: {args.target}")
    print(f"감지 스택: {', '.join(summary['detected_stacks']) or '?'}   엔진: {engine_label}")
    print(f"{'─'*56}")
    print(f"{'취약점 클래스':<24}{'후보 수':>8}  {'비고'}")
    print(f"{'─'*56}")
    for r in results:
        cnt = "ERR" if r.get("candidate_count") is None else r["candidate_count"]
        note = f"  [오류] {r['error'][:40]}" if r.get("error") else ""
        print(f"{r['label']:<24}{str(cnt):>8}{note}")
    print(f"{'─'*56}")
    print(f"{'합계':<24}{summary['total_candidates']:>8}")
    if summary.get("warnings"):
        print(f"\n[!] 폴백 경고")
        for w in summary["warnings"]:
            print(f"  - {w}")
    print(f"\n※ 1차 후보(오탐 포함)입니다. 정확한 취약/오탐 판정과")
    print(f"  4요소 리포트는 Claude Code에서 각 스킬을 호출해 완성하세요.")


if __name__ == "__main__":
    main()
