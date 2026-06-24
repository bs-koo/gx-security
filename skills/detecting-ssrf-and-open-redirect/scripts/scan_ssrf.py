#!/usr/bin/env python3
"""
SQIsoft SSRF / 오픈 리다이렉트 1차 스캐너 (하이브리드 검사의 1단계).

동작:
  1) 대상 경로의 스택을 감지 (spring-modern / jsp-legacy / mixed)
  2) semgrep 이 있으면 rules/ssrf-redirect.yml 로 후보 탐지
  3) semgrep 이 없으면 정규식 폴백으로 후보 탐지
     - RestTemplate/WebClient/URL.openStream 사용 위치
     - response.sendRedirect 사용 위치
     - "redirect:" + 변수 패턴
     - returnUrl/next/redirectUrl 파라미터 수신
  4) {file,line,rule_id,stack,snippet} 목록을 텍스트/JSON 으로 출력

이 스크립트는 "후보를 넓게" 잡는다. 최종 취약/오탐 판정은 SKILL.md 2단계의
AI 컨텍스트 검증이 수행한다 (특히 하드코딩 경로 리다이렉트 오탐 제외).

사용:
  python scan_ssrf.py <target_path> [--json]
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
RULES = os.path.join(os.path.dirname(HERE), "rules", "ssrf-redirect.yml")

# 스캔 제외 디렉토리
SKIP_DIRS = {".git", "node_modules", "build", "target", "dist", ".gradle",
             "__pycache__", ".svn", ".idea", ".vscode"}


# ── 스택 감지 ────────────────────────────────────────────────────
def detect_stacks(target):
    """리포에 섞일 수 있으므로 발견된 스택들의 집합을 반환."""
    stacks = set()
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if f in ("build.gradle.kts", "settings.gradle.kts", "build.gradle"):
                stacks.add("spring-modern")
            if f == "web.xml" and "WEB-INF" in root.replace("\\", "/"):
                stacks.add("jsp-legacy")
            if f.endswith(".jsp"):
                stacks.add("jsp-legacy")
            if f == "globals.properties":
                stacks.add("jsp-legacy")
        if os.path.basename(root) == "webapp":
            stacks.add("jsp-legacy")
    if not stacks:
        stacks.add("unknown")
    return sorted(stacks)


# ── semgrep 경로 ─────────────────────────────────────────────────
def run_semgrep(target):
    cmd = ["semgrep", "--config", RULES, "--json", "--quiet", target]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=600,
                             encoding="utf-8", errors="replace")
    except (subprocess.TimeoutExpired, OSError) as e:
        return None, f"semgrep 실행 실패: {e}"
    if out.returncode not in (0, 1):
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


# ── 폴백 정규식 패턴 정의 ─────────────────────────────────────────
# (rule_id, stack, 대상 확장자 튜플, 컴파일된 정규식)
FALLBACK_PATTERNS = [
    # ── SSRF: RestTemplate ──
    (
        "ssrf-resttemplate",
        "spring-modern",
        (".java", ".kt"),
        re.compile(
            r'restTemplate\s*\.\s*(?:getForEntity|getForObject|postForEntity|'
            r'postForObject|exchange|execute)\s*\(',
        ),
    ),
    # ── SSRF: WebClient ──
    (
        "ssrf-webclient",
        "spring-modern",
        (".java", ".kt"),
        re.compile(
            r'(?:webClient|WebClient)\s*(?:\.\s*(?:get|post|put|delete|patch)\s*\(\s*\)'
            r'\s*\.\s*uri|\.create)\s*\(',
        ),
    ),
    # ── SSRF: HttpURLConnection ──
    (
        "ssrf-httpurlconnection",
        "jsp-legacy",
        (".java",),
        re.compile(
            r'(?:HttpURLConnection|URL)\s+\w+\s*=\s*new\s+URL\s*\(',
        ),
    ),
    # ── SSRF: URL.openStream / openConnection ──
    (
        "ssrf-url-openstream",
        "jsp-legacy",
        (".java",),
        re.compile(r'\.openStream\s*\(\s*\)|\.openConnection\s*\(\s*\)'),
    ),

    # ── 오픈 리다이렉트: sendRedirect ──
    # 하드코딩 패턴(/memberLoginForm.do 등 상수만 있는 경우)은 후처리로 낮은 신뢰도 표기
    (
        "open-redirect-sendredirect",
        "jsp-legacy",
        (".java",),
        re.compile(r'(?:response|resp)\s*\.\s*sendRedirect\s*\('),
    ),

    # ── 오픈 리다이렉트: "redirect:" + 변수 (Spring MVC) ──
    (
        "open-redirect-spring-return",
        "spring-modern",
        (".java", ".kt"),
        re.compile(r'return\s+"redirect:\s*"\s*\+'),
    ),

    # ── 오픈 리다이렉트: returnUrl/next 파라미터 수신 ──
    (
        "return-url-param",
        "spring-modern",
        (".java", ".kt"),
        re.compile(
            r'(?i)(?:@RequestParam\s+(?:String\s+)?|getParameter\s*\(\s*")'
            r'(?:returnUrl|return_url|redirectUrl|redirect_url|nextUrl|next|callbackUrl|callback)',
        ),
    ),
    # JSP 파라미터에서도 동일 패턴
    (
        "return-url-param",
        "jsp-legacy",
        (".java", ".jsp"),
        re.compile(
            r'(?i)getParameter\s*\(\s*"(?:returnUrl|return_url|redirectUrl|'
            r'redirect_url|nextUrl|next|callbackUrl|callback)"',
        ),
    ),
]

# 오탐 제외 패턴: 하드코딩 경로 sendRedirect (사용자 입력 없음)
# 아래 패턴에 해당하는 라인은 low-confidence 태그를 붙임
HARDCODED_REDIRECT_RE = re.compile(
    r'sendRedirect\s*\(\s*(?:request\.getContextPath\s*\(\s*\)\s*\+\s*)?'
    r'"[^"]*(?:\.do|\.jsp|\.html|/)[^"]*"\s*\)',
)
HARDCODED_SPRING_REDIRECT_RE = re.compile(
    r'return\s+"redirect:[^"]*(?:\.do|\.jsp|\.html|/)[^"]*"\s*;',
)


# ── 폴백 실행 ────────────────────────────────────────────────────
def run_fallback(target):
    findings = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            applicable = [p for p in FALLBACK_PATTERNS if ext in p[2]]
            if not applicable:
                continue
            path = os.path.join(root, f)
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    for i, line in enumerate(fh, 1):
                        for rule_id, stack, _exts, rx in applicable:
                            if not rx.search(line):
                                continue
                            snippet = line.strip()[:200]
                            # 하드코딩 경로 리다이렉트는 낮은 신뢰도로 표기
                            confidence = "needs-context"
                            if rule_id == "open-redirect-sendredirect":
                                if HARDCODED_REDIRECT_RE.search(line):
                                    confidence = "likely-fp"
                            if rule_id == "open-redirect-spring-return":
                                if HARDCODED_SPRING_REDIRECT_RE.search(line):
                                    confidence = "likely-fp"
                            findings.append({
                                "file": path,
                                "line": i,
                                "rule_id": rule_id,
                                "stack": stack,
                                "confidence": confidence,
                                "snippet": snippet,
                            })
            except OSError:
                continue
    return findings


# ── 요약 통계 ────────────────────────────────────────────────────
def summarize(findings):
    counts = {}
    for f in findings:
        counts[f["rule_id"]] = counts.get(f["rule_id"], 0) + 1
    return counts


# ── main ─────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="SQIsoft SSRF / 오픈 리다이렉트 1차 스캐너")
    ap.add_argument("target", help="검사 대상 디렉토리")
    ap.add_argument("--json", action="store_true", help="JSON 출력")
    ap.add_argument("--skip-fp", action="store_true",
                    help="likely-fp(오탐 가능성 높음) 항목 출력 제외")
    args = ap.parse_args()

    if not os.path.isdir(args.target):
        print(f"오류: 디렉토리가 아닙니다 — {args.target}", file=sys.stderr)
        sys.exit(2)

    stacks = detect_stacks(args.target)
    engine = "semgrep" if shutil.which("semgrep") else "grep-fallback"

    if engine == "semgrep":
        findings, err = run_semgrep(args.target)
        if err:
            print(f"[경고] {err} → grep 폴백 사용", file=sys.stderr)
            engine, findings = "grep-fallback", run_fallback(args.target)
    else:
        findings = run_fallback(args.target)

    if args.skip_fp:
        findings = [f for f in findings if f.get("confidence") != "likely-fp"]

    result = {
        "target": args.target,
        "detected_stacks": stacks,
        "engine": engine,
        "candidate_count": len(findings),
        "rule_summary": summarize(findings),
        "candidates": findings,
        "note": (
            "후보 목록입니다. confidence=likely-fp 항목은 하드코딩 경로 리다이렉트로 오탐 가능성이 높습니다. "
            "최종 취약/오탐 판정은 SKILL.md 2단계 AI 검증으로 수행하세요."
        ),
    }

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"대상     : {args.target}")
        print(f"감지 스택: {', '.join(stacks)}")
        print(f"엔진     : {engine}")
        print(f"후보     : {len(findings)}건")
        if result["rule_summary"]:
            print("\n[룰별 집계]")
            for rule_id, cnt in sorted(result["rule_summary"].items(),
                                        key=lambda x: -x[1]):
                print(f"  {rule_id}: {cnt}건")
        print()
        for c in findings:
            conf_tag = f" [{c.get('confidence','?')}]" if "confidence" in c else ""
            print(f"  [{c['stack']}]{conf_tag} {c['rule_id']}  {c['file']}:{c['line']}")
            print(f"      {c['snippet']}")
        print(
            "\n※ 후보일 뿐입니다. likely-fp=하드코딩 경로(오탐 가능성 높음). "
            "2단계 AI 컨텍스트 검증 필요."
        )


if __name__ == "__main__":
    main()
