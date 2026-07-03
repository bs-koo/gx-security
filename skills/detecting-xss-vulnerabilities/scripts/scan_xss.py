#!/usr/bin/env python3
"""
SQIsoft XSS 1차 스캐너 (하이브리드 검사의 1단계).

동작:
  1) 대상 경로의 스택을 감지 (spring-modern / jsp-legacy / mixed)
  2) semgrep 이 있으면 rules/xss.yml 로 후보 탐지
  3) semgrep 이 없으면 정규식 grep 폴백으로 후보 탐지
  4) {file,line,rule_id,stack,snippet} 목록을 텍스트/JSON 으로 출력

이 스크립트는 "후보를 넓게" 잡는다. 최종 취약/오탐 판정은 SKILL.md 2단계의
AI 컨텍스트 검증이 수행한다 (특히 fn:escapeXml / c:out / th:text 오탐 제거).

사용:
  python scan_xss.py <target_path> [--json]
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys

# Windows 콘솔(cp949)에서도 한글이 깨지지 않도록 UTF-8 고정
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
RULES = os.path.join(os.path.dirname(HERE), "rules", "xss.yml")

# ── 스택 감지 신호 ────────────────────────────────────────────────
def detect_stacks(target):
    """리포에 섞일 수 있으므로 발견된 스택들의 집합을 반환."""
    stacks = set()
    for root, dirs, files in os.walk(target):
        # 잡음 디렉토리 제외
        dirs[:] = [d for d in dirs if d not in
                   (".git", "node_modules", "build", "target", "dist", ".gradle",
                    ".dev", ".omc", ".humanize", ".idea", ".vscode")]
        base = os.path.basename(root)
        for f in files:
            if f in ("build.gradle.kts", "settings.gradle.kts", "build.gradle"):
                stacks.add("spring-modern")
            if f == "web.xml" and "WEB-INF" in root.replace("\\", "/"):
                stacks.add("jsp-legacy")
            if f.endswith(".jsp"):
                stacks.add("jsp-legacy")
        if base == "webapp":
            stacks.add("jsp-legacy")
    if not stacks:
        stacks.add("unknown")
    return sorted(stacks)


# ── semgrep 경로 ─────────────────────────────────────────────────
def run_semgrep(target):
    cmd = ["semgrep", "--config", RULES, "--json", "--quiet",
           "--exclude", ".dev", "--exclude", ".omc", "--exclude", ".humanize", target]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=600,
                             encoding="utf-8", errors="replace")
    except (subprocess.TimeoutExpired, OSError) as e:
        return None, f"semgrep 실행 실패: {e}"
    if out.returncode not in (0, 1):  # 1 = findings 있음
        return None, f"semgrep 오류(rc={out.returncode}): {out.stderr[:300]}"
    try:
        data = json.loads(out.stdout or "{}")
    except json.JSONDecodeError:
        return None, "semgrep JSON 파싱 실패"
    findings = []
    for r in data.get("results", []):
        findings.append({
            "file": r.get("path"),
            "line": r.get("start", {}).get("line"),
            "rule_id": r.get("check_id", "").split(".")[-1],
            "stack": r.get("extra", {}).get("metadata", {}).get("stack", "?"),
            "snippet": (r.get("extra", {}).get("lines", "") or "").strip()[:200],
        })
    return findings, None


# ── grep 폴백 경로 ───────────────────────────────────────────────
# semgrep 미설치 환경에서 최소한의 후보를 잡는다(정밀도 낮음 → AI 검증 강화).
FALLBACK_PATTERNS = [
    # (rule_id, stack, 파일확장자들, 정규식)

    # jsp-legacy — scriptlet 직접 출력
    ("jsp-scriptlet-direct-output", "jsp-legacy", (".jsp",),
     re.compile(r'<%=\s*request\.(getParameter|getAttribute)\s*\(', re.I)),

    # jsp-legacy — EL param 미이스케이프 (fn:escapeXml 래핑 없는 것만)
    # 단순 grep이라 fn:escapeXml 안에 있는 것도 잡힘 → AI 검증 필수
    ("jsp-el-unescaped-param", "jsp-legacy", (".jsp",),
     re.compile(r'\$\{param\.[^}]+\}|\$\{requestScope\.[^}]+\}', re.I)),

    # jsp-legacy — escapeXml=false
    ("jsp-c-out-escapexml-false", "jsp-legacy", (".jsp",),
     re.compile(r'escapeXml\s*=\s*["\']false["\']', re.I)),

    # jsp-legacy — JS 블록 안 EL 삽입
    ("jsp-el-in-javascript", "jsp-legacy", (".jsp",),
     re.compile(r'var\s+\w+\s*=\s*["\'][^"\']*\$\{[^}]+\}[^"\']*["\']|var\s+\w+\s*=\s*\$\{[^}]+\}')),

    # spring-modern — innerHTML 할당
    ("js-innerhtml-assignment", "spring-modern", (".js", ".ts", ".jsx", ".tsx", ".vue"),
     re.compile(r'\.innerHTML\s*=')),

    # spring-modern — dangerouslySetInnerHTML
    ("react-dangerous-innerhtml", "spring-modern", (".jsx", ".tsx", ".js", ".ts"),
     re.compile(r'dangerouslySetInnerHTML')),

    # spring-modern — Thymeleaf th:utext
    ("thymeleaf-utext", "spring-modern", (".html", ".htm"),
     re.compile(r'th:utext')),

    # spring-modern — document.write
    ("js-document-write", "spring-modern", (".js", ".ts", ".jsx", ".tsx", ".jsp", ".html"),
     re.compile(r'document\.write\s*\(')),
]


# 서드파티 라이브러리 경로 — 오탐 방지를 위해 스캔 제외
_EXCLUDE_DIRS = {
    ".git", "node_modules", "build", "target", "dist", ".gradle",
    ".dev", ".omc", ".humanize", ".idea", ".vscode",
    "fullcalendar", "jquery", "bootstrap", "datatables", "tinymce",
    "ckeditor", "codemirror", "ace", "lib", "vendor", "assets",
    "pubRes",  # Gseed_Web_Renew 정적 리소스(서드파티 JS 포함)
}
_EXCLUDE_FILE_PATTERNS = re.compile(
    r'(\.min\.js|\.min\.css|highcharts.*\.js|jquery.*\.js|bootstrap.*\.js|'
    r'datatables.*\.js|tinymce.*\.js|codemirror.*\.js)$', re.I)


def run_fallback(target):
    findings = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in _EXCLUDE_DIRS]
        for f in files:
            if _EXCLUDE_FILE_PATTERNS.search(f):
                continue
            ext = os.path.splitext(f)[1].lower()
            rules = [r for r in FALLBACK_PATTERNS if ext in r[2]]
            if not rules:
                continue
            path = os.path.join(root, f)
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    for i, line in enumerate(fh, 1):
                        for rule_id, stack, _exts, rx in rules:
                            if rx.search(line):
                                findings.append({
                                    "file": path, "line": i, "rule_id": rule_id,
                                    "stack": stack, "snippet": line.strip()[:200],
                                })
            except OSError:
                continue
    return findings


# ── main ─────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="SQIsoft XSS 1차 스캐너")
    ap.add_argument("target", help="검사 대상 디렉토리")
    ap.add_argument("--json", action="store_true", help="JSON 출력")
    args = ap.parse_args()

    if not os.path.isdir(args.target):
        print(f"오류: 디렉토리가 아닙니다 — {args.target}", file=sys.stderr)
        sys.exit(2)

    stacks = detect_stacks(args.target)
    engine = "semgrep" if shutil.which("semgrep") else "grep-fallback"

    if engine == "semgrep":
        findings, err = run_semgrep(args.target)
        if err:  # semgrep 있으나 실패 → 폴백
            print(f"[경고] {err} → grep 폴백 사용", file=sys.stderr)
            engine, findings = "grep-fallback", run_fallback(args.target)
    else:
        findings = run_fallback(args.target)

    result = {
        "target": args.target,
        "detected_stacks": stacks,
        "engine": engine,
        "candidate_count": len(findings),
        "candidates": findings,
        "note": "후보 목록입니다. 최종 취약/오탐 판정은 SKILL.md 2단계 AI 검증으로 수행하세요. "
                "특히 fn:escapeXml() / <c:out> / th:text 래핑 여부를 반드시 확인하세요.",
    }

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"대상: {args.target}")
        print(f"감지 스택: {', '.join(stacks)}   엔진: {engine}")
        print(f"후보: {len(findings)}건\n")
        for c in findings:
            print(f"  [{c['stack']}] {c['rule_id']}  {c['file']}:{c['line']}")
            print(f"      {c['snippet']}")
        print("\n※ 후보일 뿐입니다. 2단계 AI 컨텍스트 검증 필요")
        print("  (fn:escapeXml / <c:out> 래핑 → 오탐, escapeXml=false / innerHTML → 요주의).")


if __name__ == "__main__":
    main()
