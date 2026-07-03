#!/usr/bin/env python3
"""
SQIsoft 인증·세션·JWT 취약점 1차 스캐너 (하이브리드 검사의 1단계).

동작:
  1) 대상 경로의 스택을 감지 (spring-modern / jsp-legacy / mixed)
  2) semgrep 이 있으면 rules/auth-session.yml 로 후보 탐지
  3) semgrep 이 없으면 정규식 grep 폴백으로 후보 탐지
  4) {file,line,rule_id,stack,snippet} 목록을 텍스트/JSON 으로 출력

이 스크립트는 "후보를 넓게" 잡는다. 최종 취약/오탐 판정은 SKILL.md 2단계의
AI 컨텍스트 검증이 수행한다 (특히 JWT 서명 검증 방식, 세션 재생성 유무,
BCrypt 실제 사용 여부).

사용:
  python scan_auth.py <target_path> [--json]
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
RULES = os.path.join(os.path.dirname(HERE), "rules", "auth-session.yml")


# ── 스택 감지 신호 ────────────────────────────────────────────────
def detect_stacks(target):
    """리포에 섞일 수 있으므로 발견된 스택들의 집합을 반환."""
    stacks = set()
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in
                   (".git", "node_modules", "build", "target", "dist", ".gradle",
                    ".dev", ".omc", ".humanize", ".idea", ".vscode")]
        for f in files:
            if f in ("build.gradle.kts", "settings.gradle.kts", "build.gradle"):
                stacks.add("spring-modern")
            if f == "web.xml" and "WEB-INF" in root.replace("\\", "/"):
                stacks.add("jsp-legacy")
            if f.endswith(".jsp"):
                stacks.add("jsp-legacy")
        if os.path.basename(root) == "webapp":
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


# ── grep 폴백 경로 ───────────────────────────────────────────────
# semgrep 미설치 환경에서 최소한의 후보를 잡는다(정밀도 낮음 → AI 검증 강화).
FALLBACK_PATTERNS = [
    # (rule_id, stack, 파일확장자들, 정규식)

    # spring-modern: JWT 시크릿 하드코딩 의심 (String 리터럴에 secret 계열 필드)
    ("spring-jwt-secret-literal", "spring-modern", (".java", ".kt"),
     re.compile(
         r'(?i)(secretKey|jwtSecret|tokenSecret|signingKey|SECRET_KEY)\s*='
         r'\s*"[A-Za-z0-9+/=_\-]{8,}"'
     )),

    # spring-modern: 서명 없는 JWT 파싱 (구 jjwt API)
    ("spring-jwt-parse-no-verify", "spring-modern", (".java", ".kt"),
     re.compile(r'\.parseClaimsJwt\s*\(|\.parseClaimsJws\s*\(|Jwts\.parser\(\)\.parse\s*\(')),

    # spring-modern: Cookie Secure 미설정 (setSecure 호출 없이 addCookie)
    ("spring-cookie-no-secure", "spring-modern", (".java", ".kt"),
     re.compile(r'new\s+Cookie\s*\(')),

    # spring-modern: MD5/SHA1 비밀번호 해시
    ("spring-weak-password-hash", "spring-modern", (".java", ".kt"),
     re.compile(r'MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-?1)"\s*\)', re.I)),

    # spring-modern: 쿠키 Secure 기본값 false (application.yml)
    ("spring-cookie-secure-false-default", "spring-modern", (".yml", ".yaml", ".properties"),
     re.compile(r'secure\s*:\s*\$\{[^:}]+:\s*false\s*\}|cookie\.secure\s*=\s*false')),

    # spring-modern: STATELESS 아닌 세션 정책
    ("spring-session-not-stateless", "spring-modern", (".java", ".kt"),
     re.compile(r'SessionCreationPolicy\.(IF_REQUIRED|ALWAYS|NEVER)')),

    # jsp-legacy: plaintext 해시 설정
    ("jsp-password-plaintext", "jsp-legacy", (".xml",),
     re.compile(r'hash\s*=\s*"plaintext"', re.I)),

    # jsp-legacy: SHA-256 해시 사용 (context-security 또는 유틸 코드)
    ("jsp-sha256-hash", "jsp-legacy", (".java", ".xml"),
     re.compile(r'MessageDigest\.getInstance\s*\(\s*"SHA-256"\s*\)|hash\s*=\s*"sha-256"', re.I)),

    # jsp-legacy: deprecated 단일 인자 encryptPassword
    ("jsp-deprecated-encrypt-password", "jsp-legacy", (".java",),
     re.compile(r'EgovFileScrty\.encryptPassword\s*\(\s*\w+\s*\)')),

    # jsp-legacy: 로그인 후 세션 재생성 없이 setAttribute (세션 고정 후보)
    ("jsp-session-no-invalidate", "jsp-legacy", (".java",),
     re.compile(r'getSession\(\)\.setAttribute\s*\(\s*"(?i:LoginVo|loginVO|userInfo)"')),

    # jsp-legacy: 로그아웃 시 null 설정만 (invalidate 미호출)
    ("jsp-logout-null-only", "jsp-legacy", (".java",),
     re.compile(r'getSession\(\)\.setAttribute\s*\(\s*"(?i:LoginVo|loginVO)"\s*,\s*null\s*\)')),

    # jsp-legacy: web.xml cookie-config 없음 (web.xml에서 확인)
    ("jsp-webxml-no-cookie-config", "jsp-legacy", (".xml",),
     re.compile(r'<session-config>')),

    # 공통: 자동로그인 쿠키 / remember-me (추가 점검 후보)
    ("common-remember-me-cookie", "jsp-legacy", (".java", ".xml"),
     re.compile(r'remember-me|rememberMe|autoLogin|auto_login', re.I)),
]


def run_fallback(target):
    findings = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in
                   (".git", "node_modules", "build", "target", "dist", ".gradle",
                    ".dev", ".omc", ".humanize", ".idea", ".vscode")]
        for f in files:
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


# ── 추가 분석: web.xml cookie-config 누락 탐지 ────────────────────
def check_webxml_cookie_config(target):
    """
    web.xml에 <session-config>는 있으나 <cookie-config>가 없는 경우를 탐지.
    grep 폴백의 단순 정규식으로는 부재를 감지할 수 없으므로 파일 레벨로 보완.
    """
    findings = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in
                   (".git", "node_modules", "build", "target", "dist", ".gradle",
                    ".dev", ".omc", ".humanize", ".idea", ".vscode")]
        for f in files:
            if f != "web.xml":
                continue
            path = os.path.join(root, f)
            try:
                content = open(path, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            has_session_config = "<session-config>" in content
            has_cookie_config = "<cookie-config>" in content
            if has_session_config and not has_cookie_config:
                for i, line in enumerate(content.splitlines(), 1):
                    if "<session-config>" in line:
                        findings.append({
                            "file": path,
                            "line": i,
                            "rule_id": "jsp-webxml-no-cookie-config",
                            "stack": "jsp-legacy",
                            "snippet": line.strip()[:200] + " [cookie-config 없음]",
                        })
                        break
    return findings


# ── 추가 분석: JwtTokenProvider 환경변수 주입 확인 ───────────────
def check_jwt_secret_injection(target):
    """
    JwtTokenProvider 계열 파일에서 secretKey 필드가 @Value 없이
    리터럴로 선언됐는지 파일 레벨로 확인.
    """
    findings = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in
                   (".git", "node_modules", "build", "target", "dist", ".gradle",
                    ".dev", ".omc", ".humanize", ".idea", ".vscode")]
        for f in files:
            if not (f.endswith(".java") or f.endswith(".kt")):
                continue
            if "JwtTokenProvider" not in f and "JwtProvider" not in f:
                continue
            path = os.path.join(root, f)
            try:
                content = open(path, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            # @Value 없이 secretKey 리터럴 선언 탐지
            literal_pattern = re.compile(
                r'(?<!@Value\s)\bsecretKey\s*=\s*"[^$][^"]{7,}"'
            )
            for i, line in enumerate(content.splitlines(), 1):
                if literal_pattern.search(line):
                    findings.append({
                        "file": path,
                        "line": i,
                        "rule_id": "spring-jwt-secret-hardcoded",
                        "stack": "spring-modern",
                        "snippet": line.strip()[:200],
                    })
    return findings


# ── main ─────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="SQIsoft 인증·세션·JWT 1차 스캐너")
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
            engine = "grep-fallback"
            findings = run_fallback(args.target)
    else:
        findings = run_fallback(args.target)

    # grep 폴백일 때 추가 분석 실행
    if engine == "grep-fallback":
        existing_keys = {(c["file"], c["line"]) for c in findings}

        if "jsp-legacy" in stacks:
            for e in check_webxml_cookie_config(args.target):
                if (e["file"], e["line"]) not in existing_keys:
                    findings.append(e)
                    existing_keys.add((e["file"], e["line"]))

        if "spring-modern" in stacks:
            for e in check_jwt_secret_injection(args.target):
                if (e["file"], e["line"]) not in existing_keys:
                    findings.append(e)
                    existing_keys.add((e["file"], e["line"]))

    result = {
        "target": args.target,
        "detected_stacks": stacks,
        "engine": engine,
        "candidate_count": len(findings),
        "candidates": findings,
        "note": (
            "후보 목록입니다. 최종 취약/오탐 판정은 SKILL.md 2단계 AI 검증으로 수행하세요. "
            "특히 JWT verifyWith(key) 사용 여부, 세션 invalidate() 호출 여부, "
            "context-security.xml hash= 값, COOKIE_SECURE 환경변수 설정을 코드로 확인하세요."
        ),
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
        print(
            "\n※ 후보일 뿐입니다. 2단계 AI 컨텍스트 검증 필요"
            " (JWT 서명 검증, 세션 재생성, 비밀번호 해시, 쿠키 보안속성)."
        )


if __name__ == "__main__":
    main()
