#!/usr/bin/env python3
"""
SQIsoft SQL Injection 1차 스캐너 (하이브리드 검사의 1단계).

동작:
  1) 대상 경로의 스택을 감지 (spring-modern / jsp-legacy / mixed)
  2) semgrep 이 있으면 rules/sqli.yml 로 후보 탐지
  3) semgrep 이 없으면 정규식 grep 폴백으로 후보 탐지
  4) {file,line,rule_id,stack,snippet} 목록을 텍스트/JSON 으로 출력

이 스크립트는 "후보를 넓게" 잡는다. 최종 취약/오탐 판정은 SKILL.md 2단계의
AI 컨텍스트 검증이 수행한다 (특히 #{} vs ${} 구분, 입력 출처 추적, allowlist 확인).

사용:
  python scan_sqli.py <target_path> [--json]
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
RULES = os.path.join(os.path.dirname(HERE), "rules", "sqli.yml")

# ── 스택 감지 신호 ────────────────────────────────────────────────
def detect_stacks(target):
    """리포에 섞일 수 있으므로 발견된 스택들의 집합을 반환."""
    stacks = set()
    for root, dirs, files in os.walk(target):
        # 잡음 디렉토리 제외
        dirs[:] = [d for d in dirs if d not in
                   (".git", "node_modules", "build", "target", "dist", ".gradle")]
        base = os.path.basename(root)
        for f in files:
            if f in ("build.gradle.kts", "settings.gradle.kts", "build.gradle"):
                stacks.add("spring-modern")
            if f == "web.xml" and "WEB-INF" in root.replace("\\", "/"):
                stacks.add("jsp-legacy")
            if f.endswith(".jsp"):
                stacks.add("jsp-legacy")
            # MyBatis XML 위치로 추가 판별
            if f.endswith(".xml") and "sqlmap" in root.replace("\\", "/"):
                stacks.add("jsp-legacy")
            if f.endswith(".xml") and "mybatis" in root.replace("\\", "/"):
                stacks.add("spring-modern")
        if base == "webapp":
            stacks.add("jsp-legacy")
    if not stacks:
        stacks.add("unknown")
    return sorted(stacks)


# ── semgrep 경로 ─────────────────────────────────────────────────
def run_semgrep(target):
    cmd = ["semgrep", "--config", RULES, "--json", "--quiet", target]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
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
#
# MyBatis ${} 폴백 패턴 설명:
#   - #{} 는 안전(PreparedStatement 바인딩) → 매칭 제외
#   - ${pageContext}, ${contextPath}, ${sessionScope.LoginVo} 등 JSP 내부 EL은
#     SQL 컨텍스트가 아니므로 XML 파일에서만 잡는다
#   - 폴백은 단순 정규식이라 오탐 가능성 높음 → AI 검증 필수

# MyBatis XML ${} — #{} 가 아닌 것만 (느슨한 판별)
_MYBATIS_DOLLAR = re.compile(r'\$\{(?!#)[^}]+\}')

# JDBC Statement + SQL 문자열 연결 의심
_STMT_CONCAT = re.compile(
    r'(executeQuery|executeUpdate|execute)\s*\(\s*\S+\s*\+', re.I)

# JdbcTemplate 문자열 연결 의심
_JDBC_TMPL_CONCAT = re.compile(
    r'\.(query|queryForObject|queryForList|update)\s*\(\s*\S+\s*\+', re.I)

# JPA createQuery 문자열 연결 의심
_JPA_CREATE_CONCAT = re.compile(
    r'\.(createQuery|createNativeQuery)\s*\(\s*\S+\s*\+', re.I)

FALLBACK_PATTERNS = [
    # (rule_id, stack, 파일확장자들, 정규식)

    # jsp-legacy — Statement 문자열 연결
    ("jdbc-statement-string-concat", "jsp-legacy", (".java",),
     _STMT_CONCAT),

    # 공통 — MyBatis XML ${} (jsp-legacy sqlmap XML)
    ("mybatis-xml-dollar-interpolation", "jsp-legacy", (".xml",),
     _MYBATIS_DOLLAR),

    # spring-modern — JdbcTemplate 문자열 연결
    ("spring-jdbctemplate-string-concat", "spring-modern", (".java", ".kt"),
     _JDBC_TMPL_CONCAT),

    # spring-modern — JPA createQuery 문자열 연결
    ("spring-jpa-createquery-string-concat", "spring-modern", (".java", ".kt"),
     _JPA_CREATE_CONCAT),

    # spring-modern — MyBatis XML ${} (mybatis mapper XML)
    ("mybatis-xml-dollar-spring", "spring-modern", (".xml",),
     _MYBATIS_DOLLAR),
]

# XML 파일을 MyBatis 맥락에서만 검사하기 위한 경로 필터
# sqlmap/ 또는 mybatis/ 경로 하위 XML만 대상
def _is_mybatis_xml(path: str) -> bool:
    """MyBatis SQL 매퍼 XML 경로 판별.
    Spring/Maven 설정 XML(context-*.xml, pom.xml 등)과 구분한다.
    """
    norm = path.replace("\\", "/").lower()
    filename = os.path.basename(norm)
    # 설정 XML 제외 — context-*.xml, web.xml, pom.xml, log4j2.xml 등
    if filename.startswith("context-") or filename in (
        "web.xml", "pom.xml", "log4j2.xml", "log4j.xml",
        "sql-map-config.xml", "mybatis-config.xml",
    ):
        return False
    # mapper / sqlmap 하위에 있고 설정 파일이 아닌 것만 허용
    return ("sqlmap" in norm or "mybatis" in norm or "mapper" in norm) and \
           not norm.endswith("config.xml")


def run_fallback(target):
    findings = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in
                   (".git", "node_modules", "build", "target", "dist", ".gradle")]
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            path = os.path.join(root, f)

            # XML 파일은 MyBatis 맥락 경로만 검사 (Spring/Maven 설정 XML 오탐 방지)
            if ext == ".xml" and not _is_mybatis_xml(path):
                continue

            rules = [r for r in FALLBACK_PATTERNS if ext in r[2]]
            if not rules:
                continue

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
    ap = argparse.ArgumentParser(description="SQIsoft SQL Injection 1차 스캐너")
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
                "MyBatis #{} 는 안전(오탐), ${}는 입력 출처·allowlist 확인 필수.",
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
        print("  (#{} → 오탐, ${} → 입력 출처·ORDER BY allowlist 확인).")


if __name__ == "__main__":
    main()
