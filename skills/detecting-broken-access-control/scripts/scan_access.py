#!/usr/bin/env python3
"""
SQIsoft 접근통제(IDOR/BFLA/강제브라우징) 1차 스캐너 (하이브리드 검사의 1단계).

동작:
  1) 대상 경로의 스택을 감지 (spring-modern / jsp-legacy / mixed)
  2) semgrep 이 있으면 rules/access-control.yml 로 후보 탐지
  3) semgrep 이 없으면 정규식 grep 폴백으로 후보 탐지
  4) {file,line,rule_id,stack,snippet} 목록을 텍스트/JSON 으로 출력

이 스크립트는 "후보를 넓게" 잡는다. 최종 취약/오탐 판정은 SKILL.md 2단계의
AI 컨텍스트 검증이 수행한다 (특히 서비스 레이어 소유권 검증, 세션 기반 ID 추출).

사용:
  python scan_access.py <target_path> [--json]
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
RULES = os.path.join(os.path.dirname(HERE), "rules", "access-control.yml")


# ── 스택 감지 신호 ────────────────────────────────────────────────
def detect_stacks(target):
    """리포에 섞일 수 있으므로 발견된 스택들의 집합을 반환."""
    stacks = set()
    for root, dirs, files in os.walk(target):
        # 잡음 디렉토리 제외
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

    # spring-modern: /adm/** 매핑인데 @PreAuthorize 없는 클래스 감지 (파일 단위 휴리스틱)
    ("spring-admin-no-preauthorize", "spring-modern", (".java",),
     re.compile(r'@RequestMapping\s*\(\s*"(?:/adm|/admin)[^"]*"')),

    # spring-modern: @PathVariable로 id/seq 계열 파라미터를 받는 엔드포인트
    ("spring-pathvariable-id", "spring-modern", (".java", ".kt"),
     re.compile(r'@PathVariable\s+(?:\w+\s+)?(\w*[Ii][Dd]\w*|\w*[Ss]eq\w*|\w*[Nn]o\b)')),

    # spring-modern: anyRequest().permitAll() — 사각지대 위험
    ("spring-anyrequestpermitall", "spring-modern", (".java", ".kt"),
     re.compile(r'anyRequest\s*\(\s*\)\s*\.\s*permitAll\s*\(\s*\)')),

    # spring-modern: CORS wildcard
    ("spring-cors-wildcard", "spring-modern", (".java", ".kt"),
     re.compile(r'allowedOrigins\s*\(\s*"\*"\s*\)|@CrossOrigin\s*\(\s*origins\s*=\s*"\*"')),

    # jsp-legacy: AuthInterceptor mode=off/audit (properties/xml)
    ("jsp-auth-gate-mode-off", "jsp-legacy", (".properties", ".xml"),
     re.compile(r'authGate\.mode\s*=\s*(off|audit)', re.I)),

    # jsp-legacy: getParameter로 ID 계열 파라미터 직접 수신
    ("jsp-getparameter-id", "jsp-legacy", (".java",),
     re.compile(r'getParameter\s*\(\s*"(?:seq|id|certiNo|userId|boardSeq|fileSeq|no)"\s*\)', re.I)),

    # jsp-legacy: AuthUtil.isAdmin 호출 (null 체크 선행 여부는 AI 검증)
    ("jsp-isadmin-check", "jsp-legacy", (".java",),
     re.compile(r'AuthUtil\.isAdmin\s*\(')),

    # jsp-legacy: GET 링크로 상태변경 동작 노출
    ("jsp-state-changing-get-link", "jsp-legacy", (".jsp", ".html"),
     re.compile(r'<a[^>]+href="[^"]*(delete|withdraw|remove|update|approve|reject)', re.I)),

    # 공통: 관리자 JSP 경로 직접 링크 (강제 브라우징 후보)
    ("jsp-admin-url-exposure", "jsp-legacy", (".jsp", ".html", ".java"),
     re.compile(r'(?:adminCerti|admin[A-Z]\w*|/admin/)\w*\.(?:do|jsp)', re.I)),
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


# ── 추가 분석: @PreAuthorize 없는 Admin 컨트롤러 파일 탐지 ──────
def check_admin_controllers_without_preauthorize(target):
    """
    /adm/ 매핑이 있는 Java 파일에서 @PreAuthorize가 전혀 없는 경우를 탐지.
    semgrep 없이도 파일 레벨 BFLA 후보를 보완한다.
    """
    findings = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in
                   (".git", "node_modules", "build", "target", "dist", ".gradle",
                    ".dev", ".omc", ".humanize", ".idea", ".vscode")]
        for f in files:
            if not f.endswith(".java"):
                continue
            path = os.path.join(root, f)
            try:
                content = open(path, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            # 관리자 매핑 패턴이 있고 @PreAuthorize가 없는 파일
            has_adm_mapping = bool(re.search(
                r'@RequestMapping\s*\(\s*"(?:/adm|/admin)[^"]*"', content))
            has_preauthorize = "@PreAuthorize" in content or "@Secured" in content
            if has_adm_mapping and not has_preauthorize:
                # 첫 번째 매핑 라인 번호 찾기
                for i, line in enumerate(content.splitlines(), 1):
                    if re.search(r'@RequestMapping\s*\(', line):
                        findings.append({
                            "file": path,
                            "line": i,
                            "rule_id": "spring-admin-controller-no-preauthorize",
                            "stack": "spring-modern",
                            "snippet": line.strip()[:200],
                        })
                        break
    return findings


# ── main ─────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="SQIsoft 접근통제 1차 스캐너")
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

    # grep 폴백일 때 관리자 컨트롤러 추가 분석 실행
    if engine == "grep-fallback" and "spring-modern" in stacks:
        extra = check_admin_controllers_without_preauthorize(args.target)
        # 중복 제거 (같은 파일:라인)
        existing_keys = {(c["file"], c["line"]) for c in findings}
        for e in extra:
            if (e["file"], e["line"]) not in existing_keys:
                findings.append(e)

    result = {
        "target": args.target,
        "detected_stacks": stacks,
        "engine": engine,
        "candidate_count": len(findings),
        "candidates": findings,
        "note": (
            "후보 목록입니다. 최종 취약/오탐 판정은 SKILL.md 2단계 AI 검증으로 수행하세요. "
            "특히 서비스 레이어의 소유권 검증, 세션 기반 ID 추출, "
            "AuthInterceptor mode 설정을 코드로 직접 확인하세요."
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
            " (소유권 검증, AuthInterceptor mode, DB 룰 테이블 유무)."
        )


if __name__ == "__main__":
    main()
