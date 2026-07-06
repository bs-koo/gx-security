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

# 초대형 단일 라인(minified 등)에 폴백 정규식을 적용하면 O(n²) 백트래킹으로
# 사실상 멈출 수 있다(ReDoS). 이 길이를 넘는 라인은 매칭을 조용히 스킵한다.
_MAX_LINE_LEN = 5000

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
            if f in ("build.gradle.kts", "settings.gradle.kts", "build.gradle", "pom.xml"):
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
            "confidence": r.get("extra", {}).get("metadata", {}).get("confidence") or "needs-context",
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

# MyBatis XML ${}: 파라미터 문자열 보간(취약). #{}(바인딩)는 $로 시작 안 해 자연히 제외됨.
_MYBATIS_DOLLAR = re.compile(r'\$\{[^}]+\}')

# JDBC Statement + SQL 문자열 연결 의심
# [^;]+ — 문장 종결자(;) 전까지: 다중 인자·공백 포함 문자열 리터럴("SELECT " + x)·
#   변수(sql + x)·복잡한 인자(f("a","b") + x) 연결까지 매치 (PR 리뷰 반영, 미탐 감소)
_STMT_CONCAT = re.compile(
    r'(executeQuery|executeUpdate|execute)\s*\(\s*[^;]+\s*\+', re.I)

# JdbcTemplate 문자열 연결 의심
_JDBC_TMPL_CONCAT = re.compile(
    r'\.(query|queryForObject|queryForList|update)\s*\(\s*[^;]+\s*\+', re.I)

# JPA createQuery 문자열 연결 의심
_JPA_CREATE_CONCAT = re.compile(
    r'\.(createQuery|createNativeQuery)\s*\(\s*[^;]+\s*\+', re.I)

# FR-1 — 2줄 인접 조립+실행(변수 상관). 직전줄에서 변수에 "리터럴"+식별자를 대입하고,
# 현재줄에서 같은 변수를 executeQuery/executeUpdate로 실행하는 형태만 후보화한다.
# group(1) = 조립/실행 변수명. 두 group(1)이 문자열 동일할 때만 매칭(Runnable/스레드풀 오탐 차단).
_SQL_CONCAT_ASSIGN = re.compile(
    r'([A-Za-z_]\w*)\s*(?:=|\+=)\s*[^;]*"[^"]*"\s*\+\s*[A-Za-z_]\w*', re.I)
_SQL_EXECUTE_VAR = re.compile(
    r'(?:executeQuery|executeUpdate)\s*\(\s*([A-Za-z_]\w*)\s*\)', re.I)

# FR-2 — prepareStatement("리터럴" + ...) 인라인 concat. ?+setString(안전)은 미매치.
_PREPARE_CONCAT = re.compile(
    r'prepareStatement\s*\(\s*[^;)]*"[^"]*"\s*\+', re.I)

FALLBACK_PATTERNS = [
    # (rule_id, stack, 파일확장자들, 정규식)

    # jsp-legacy — Statement 문자열 연결
    ("jdbc-statement-string-concat", "jsp-legacy", (".java",),
     _STMT_CONCAT),

    # jsp-legacy — prepareStatement 인라인 문자열 연결 (FR-2)
    ("jdbc-preparestatement-concat", "jsp-legacy", (".java",),
     _PREPARE_CONCAT),

    # 공통 — MyBatis XML ${} (jsp-legacy sqlmap XML)
    ("mybatis-xml-dollar-interpolation", "jsp-legacy", (".xml",),
     _MYBATIS_DOLLAR),

    # spring-modern — JdbcTemplate 문자열 연결
    ("spring-jdbctemplate-string-concat", "spring-modern", (".java", ".kt"),
     _JDBC_TMPL_CONCAT),

    # spring-modern — JPA createQuery 문자열 연결
    ("spring-jpa-createquery-string-concat", "spring-modern", (".java", ".kt"),
     _JPA_CREATE_CONCAT),

    # MyBatis XML ${}는 단일 룰(mybatis-xml-dollar-interpolation)로 통합한다.
    # 과거 jsp/spring 두 룰이 동일 _MYBATIS_DOLLAR 정규식으로 같은 라인을 이중 카운트했다
    # (코드리뷰 M6). 스택 라벨은 run_fallback에서 경로(mybatis/ vs 그 외)로 판별한다.
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
                   (".git", "node_modules", "build", "target", "dist", ".gradle",
                    ".dev", ".omc", ".humanize", ".idea", ".vscode")]
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
                    # FR-1 — 직전줄 버퍼. 2줄 인접 조립+실행(변수 상관) 판정에 사용.
                    prev = ""
                    for i, line in enumerate(fh, 1):
                        # 초대형 minified 단일 라인은 정규식 백트래킹 방어를 위해
                        # 매칭을 조용히 스킵한다(성능 가드).
                        if len(line) > _MAX_LINE_LEN:
                            # 초과 라인은 prev를 비워 2줄 전 라인과의 오결합을 차단한다.
                            prev = ""
                            continue
                        for rule_id, stack, _exts, rx in rules:
                            if rx.search(line):
                                eff_stack = stack
                                # MyBatis ${}는 단일 룰이므로 스택을 경로로 판별(mybatis/=spring, 그 외=jsp)
                                if rule_id == "mybatis-xml-dollar-interpolation":
                                    norm = path.replace("\\", "/").lower()
                                    eff_stack = "spring-modern" if "mybatis" in norm else "jsp-legacy"
                                findings.append({
                                    "file": path, "line": i, "rule_id": rule_id,
                                    "stack": eff_stack, "confidence": "needs-context",
                                    "snippet": line.strip()[:200],
                                })
                        # FR-1 — 직전줄 "리터럴"+식별자 대입 + 현재줄 executeQuery/executeUpdate,
                        # 두 변수명이 동일할 때만 후보화(변수 상관). java 파일 전용.
                        if ext == ".java":
                            m_exec = _SQL_EXECUTE_VAR.search(line)
                            if m_exec:
                                m_assign = _SQL_CONCAT_ASSIGN.search(prev)
                                if m_assign and m_assign.group(1) == m_exec.group(1):
                                    findings.append({
                                        "file": path, "line": i,
                                        "rule_id": "jdbc-two-line-sql-concat",
                                        "stack": "jsp-legacy",
                                        "confidence": "needs-context",
                                        "snippet": line.strip()[:200],
                                    })
                        # 정상 라인은 다음 반복의 직전줄로 보관(모든 반복 종료 시 갱신).
                        prev = line
            except OSError:
                continue
    return findings


# ── main ─────────────────────────────────────────────────────────
def summarize(findings):
    """rule_id 별 집계를 반환."""
    counts = {}
    for f in findings:
        counts[f["rule_id"]] = counts.get(f["rule_id"], 0) + 1
    return counts


def build_warnings(detected_stacks, engine, candidate_count):
    # 두 경고 모두 "0건" 맥락이므로 candidate_count==0 일 때만 노출한다.
    # (후보가 1건 이상인데 unknown 스택이라는 이유로 "0건이..." 를 띄우면 결과와 모순 — Gemini 리뷰 반영)
    w = []
    if candidate_count == 0:
        if detected_stacks == ["unknown"]:
            w.append("프로젝트 구조를 인식하지 못했습니다. 0건이 스캔 대상 인식 실패 때문일 수 있습니다.")
        if engine == "grep-fallback":
            w.append("정규식 폴백 엔진은 재현율이 낮습니다. 0건이 안전을 보장하지 않습니다.")
    return w


def main():
    ap = argparse.ArgumentParser(description="SQIsoft SQL Injection 1차 스캐너")
    ap.add_argument("target", help="검사 대상 디렉토리")
    ap.add_argument("--json", action="store_true", help="JSON 출력")
    args = ap.parse_args()

    if not os.path.isdir(args.target):
        print(f"오류: 디렉토리가 아닙니다 — {args.target}", file=sys.stderr)
        sys.exit(2)

    stacks = detect_stacks(args.target)
    engine = "semgrep" if (shutil.which("semgrep") and not os.environ.get("GXSEC_NO_SEMGREP")) else "grep-fallback"

    if engine == "semgrep":
        findings, err = run_semgrep(args.target)
        if err:  # semgrep 있으나 실패 → 폴백
            print(f"[경고] {err} → grep 폴백 사용", file=sys.stderr)
            engine, findings = "grep-fallback", run_fallback(args.target)
    else:
        findings = run_fallback(args.target)

    warnings = build_warnings(stacks, engine, len(findings))

    result = {
        "target": args.target,
        "detected_stacks": stacks,
        "engine": engine,
        "candidate_count": len(findings),
        "rule_summary": summarize(findings),
        "candidates": findings,
        "note": "후보 목록입니다. 최종 취약/오탐 판정은 SKILL.md 2단계 AI 검증으로 수행하세요. "
                "MyBatis #{} 는 안전(오탐), ${}는 입력 출처·allowlist 확인 필수.",
    }
    if warnings:
        result["warnings"] = warnings

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"대상: {args.target}")
        print(f"감지 스택: {', '.join(stacks)}   엔진: {engine}")
        print(f"후보: {len(findings)}건\n")
        for c in findings:
            print(f"  [{c['stack']}] {c['rule_id']}  {c['file']}:{c['line']}")
            print(f"      {c['snippet']}")
        if warnings:
            print("\n[!] 미탐 경고:")
            for wmsg in warnings:
                print(f"  - {wmsg}")
        print("\n※ 후보일 뿐입니다. 2단계 AI 컨텍스트 검증 필요")
        print("  (#{} → 오탐, ${} → 입력 출처·ORDER BY allowlist 확인).")


if __name__ == "__main__":
    main()
