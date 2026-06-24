#!/usr/bin/env python3
"""
SQIsoft 민감정보 노출 1차 스캐너 (하이브리드 검사의 1단계).

동작:
  1) 대상 경로의 스택을 감지 (spring-modern / jsp-legacy / mixed)
  2) semgrep 이 있으면 rules/sensitive-data.yml 로 후보 탐지
  3) semgrep 이 없으면 정규식 폴백으로 후보 탐지
     - properties/yml/xml 평문 시크릿
     - Java 소스 문자열 리터럴 자격증명
     - Base64 인코딩 API 키 하드코딩
     - 로그·System.out 개인정보 출력
  4) {file,line,rule_id,stack,snippet} 목록을 텍스트/JSON 으로 출력

이 스크립트는 "후보를 넓게" 잡는다. 최종 취약/오탐 판정은 SKILL.md 2단계의
AI 컨텍스트 검증이 수행한다 (특히 ${...} placeholder 오탐 제외).

사용:
  python scan_secrets.py <target_path> [--json]
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
RULES = os.path.join(os.path.dirname(HERE), "rules", "sensitive-data.yml")

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


# ── 폴백 정규식 패턴 정의 ─────────────────────────────────────────
# (rule_id, stack, 대상 확장자 튜플, 컴파일된 정규식)
FALLBACK_PATTERNS = [
    # --- properties/yml: 평문 시크릿 ---
    # password=실제값 (${...} 참조 제외, 주석 라인 제외)
    (
        "hardcoded-password-properties",
        "jsp-legacy",
        (".properties",),
        re.compile(
            r'(?i)^[^#]*(?:password|passwd|pwd|secret|apikey|api_key|'
            r'secretkey|initpassword|initpwd)\s*=\s*(?!\$\{)(?!\s*$).{4,}',
            re.MULTILINE,
        ),
    ),
    # yaml: password: 실제값
    (
        "hardcoded-password-yaml",
        "spring-modern",
        (".yml", ".yaml"),
        re.compile(
            r'(?i)^\s*(?:password|passwd|pwd|secret|secret-key|secretKey)\s*:\s*'
            r'(?!\$\{)(?!["\']?\s*$)["\']?[^\s$\{][^\n]{3,}',
            re.MULTILINE,
        ),
    ),
    # xml: <property name="password" value="실제값"/>
    (
        "hardcoded-password-xml",
        "jsp-legacy",
        (".xml",),
        re.compile(
            r'(?i)<property\s+name\s*=\s*["\'](?:password|passwd|pwd|secret)["\']'
            r'\s+value\s*=\s*["\'](?!\$\{)[^"\']{4,}["\']',
        ),
    ),

    # --- Java 소스: 문자열 리터럴 자격증명 ---
    # String password = "실제값";
    (
        "hardcoded-credential-java-string",
        "spring-modern",
        (".java", ".kt"),
        re.compile(
            r'(?i)(?:private\s+)?(?:static\s+)?(?:final\s+)?String\s+'
            r'(?:password|passwd|pwd|secret|secretKey|apiKey|api_key|authKey|'
            r'confmKey|gbcsApiKey|serviceKey)\s*=\s*"(?!\$\{)[^"]{6,}"',
        ),
    ),
    # Base64처럼 보이는 긴 리터럴 할당
    (
        "base64-encoded-secret",
        "jsp-legacy",
        (".java", ".kt"),
        re.compile(
            r'String\s+\w+\s*=\s*"([A-Za-z0-9+/]{24,}={0,2})"',
        ),
    ),

    # --- 로그·System.out 개인정보 ---
    # log.xxx에 password/개인정보 변수 포함 (값이 직접 출력되는 형태)
    (
        "log-sensitive-value",
        "spring-modern",
        (".java", ".kt"),
        re.compile(
            r'(?i)(?:log\.\w+|System\.out\.print(?:ln)?)\s*\('
            r'[^)]*(?:password|passwd|pwd|주민|jumin|ssn|주민번호)[^)]*\)',
        ),
    ),
    # System.out.println 전체 (운영 코드에 남아있으면 경고)
    (
        "system-out-println",
        "spring-modern",
        (".java", ".kt"),
        re.compile(r'System\.out\.print(?:ln)?\s*\('),
    ),

    # --- JSP 패턴 ---
    # JSP 주석 내 비밀번호/계정 언급
    (
        "jsp-comment-credential",
        "jsp-legacy",
        (".jsp",),
        re.compile(
            r'(?i)<!--.*?(?:password|passwd|pwd|id/pw|계정|비밀번호|아이디).*?-->',
            re.DOTALL,
        ),
    ),

    # --- @Value 기본값 시크릿 ---
    (
        "value-annotation-default-secret",
        "spring-modern",
        (".java", ".kt"),
        re.compile(
            r'@Value\s*\(\s*"\$\{[^}]+:[^$\{"]{6,}\}"\s*\)',
        ),
    ),
]


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
                    content = fh.read()
                # 라인별로 매칭
                for i, line in enumerate(content.splitlines(), 1):
                    for rule_id, stack, _exts, rx in applicable:
                        if rx.search(line):
                            snippet = line.strip()[:200]
                            # 명백한 오탐 제외: placeholder 형태
                            if re.search(r'\$\{[A-Z_]+\}', snippet):
                                continue
                            findings.append({
                                "file": path,
                                "line": i,
                                "rule_id": rule_id,
                                "stack": stack,
                                "snippet": snippet,
                            })
            except OSError:
                continue
    return findings


# ── 요약 통계 ────────────────────────────────────────────────────
def summarize(findings):
    """rule_id 별 집계를 반환."""
    counts = {}
    for f in findings:
        counts[f["rule_id"]] = counts.get(f["rule_id"], 0) + 1
    return counts


# ── main ─────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="SQIsoft 민감정보 노출 1차 스캐너")
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
        if err:
            print(f"[경고] {err} → grep 폴백 사용", file=sys.stderr)
            engine, findings = "grep-fallback", run_fallback(args.target)
    else:
        findings = run_fallback(args.target)

    result = {
        "target": args.target,
        "detected_stacks": stacks,
        "engine": engine,
        "candidate_count": len(findings),
        "rule_summary": summarize(findings),
        "candidates": findings,
        "note": (
            "후보 목록입니다. ${...} placeholder·reCAPTCHA siteKey 등은 오탐입니다. "
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
            print(f"  [{c['stack']}] {c['rule_id']}  {c['file']}:{c['line']}")
            print(f"      {c['snippet']}")
        print(
            "\n※ 후보일 뿐입니다. ${{...}} placeholder·공개키는 오탐, "
            "2단계 AI 컨텍스트 검증 필요."
        )


if __name__ == "__main__":
    main()
