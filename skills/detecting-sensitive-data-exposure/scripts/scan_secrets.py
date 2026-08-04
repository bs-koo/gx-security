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

HERE = os.path.dirname(os.path.abspath(__file__))
_PLUGIN_ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
if _PLUGIN_ROOT not in sys.path:
    sys.path.insert(0, _PLUGIN_ROOT)
from tools import io_utf8  # noqa: E402  (UTF-8 콘솔 강제 — Windows cp949 크래시 방지, Task 1)
io_utf8.configure()

RULES = os.path.join(os.path.dirname(HERE), "rules", "sensitive-data.yml")

# 초대형 단일 라인(minified 등)에 폴백 정규식을 적용하면 O(n²) 백트래킹으로
# 사실상 멈출 수 있다(ReDoS). 이 길이를 넘는 라인은 매칭을 조용히 스킵한다.
_MAX_LINE_LEN = 5000

# 스캔 제외 디렉토리
SKIP_DIRS = {".git", "node_modules", "build", "target", "dist", ".gradle",
             "__pycache__", ".svn", ".idea", ".vscode",
             ".dev", ".omc", ".humanize"}


# ── 스택 감지 ────────────────────────────────────────────────────
def detect_stacks(target):
    """리포에 섞일 수 있으므로 발견된 스택들의 집합을 반환."""
    stacks = set()
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if f in ("build.gradle.kts", "settings.gradle.kts", "build.gradle", "pom.xml"):
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


# ── 폴백 정규식 패턴 정의 ─────────────────────────────────────────
# (rule_id, stack, 대상 확장자 튜플, 컴파일된 정규식)

# [FR-9] 포맷 기반 시크릿 대상 확장자 (코드+설정 중심, 문서 .md 제외)
_SECRET_FMT_EXTS = (".java", ".kt", ".properties", ".yml", ".yaml",
                    ".xml", ".json", ".env", ".conf", ".config")

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
    # [M-3] System.out.println 전체는 노이즈가 크므로 별도 카테고리 "debug-output-residue"로
    # 분리하고 severity=info 수준으로 처리. 실제 민감정보 규칙과 출력에서 구분됨.
    (
        "debug-output-residue",
        "spring-modern",
        (".java", ".kt"),
        re.compile(r'System\.out\.print(?:ln)?\s*\('),
    ),

    # --- JSP 패턴 ---
    # [M-4] jsp-comment-credential 은 re.DOTALL 멀티라인 규칙이므로
    # 라인단위 루프에서 제외하고 별도 멀티라인 집합에 등록 (아래 MULTILINE_PATTERNS 참조)
    # 여기서는 단일 라인에서도 매칭되는 단순화 버전만 남긴다.
    (
        "jsp-comment-credential",
        "jsp-legacy",
        (".jsp",),
        re.compile(
            # 키워드[:=]값 형태만 — UI 섹션 주석(<!-- BEGIN: 비밀번호 영역 -->) 오탐 제거
            r'(?i)<!--[^>]*(?:password|passwd|pwd|id/pw|계정|비밀번호|아이디)\s*[:=]\s*[^\s<>]{3,}[^>]*-->',
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

    # --- [FR-9] 포맷 기반 시크릿 5종 ---
    # AWS Access Key ID (AKIA + 16자 = 총 20자)
    (
        "aws-access-key-id",
        "spring-modern",
        _SECRET_FMT_EXTS,
        re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    ),
    # GitHub Personal Access Token (ghp_ + 20자 이상, 자리표시자 _ 는 자연 회피)
    (
        "github-token",
        "spring-modern",
        _SECRET_FMT_EXTS,
        re.compile(r'\bghp_[0-9A-Za-z]{20,}\b'),
    ),
    # PEM 개인키 마커 — .pem/.key 파일 내용까지 스캔(공개 인증서 BEGIN CERTIFICATE 는 미탐)
    (
        "pem-private-key",
        "spring-modern",
        _SECRET_FMT_EXTS + (".pem", ".key", ".txt"),
        re.compile(r'-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE KEY-----'),
    ),
    # JDBC URL 내 평문 password — (?!\$\{) 로 카멜케이스 플레이스홀더 ${dbPassword} 차단
    (
        "jdbc-url-password",
        "spring-modern",
        _SECRET_FMT_EXTS,
        re.compile(r'(?i)jdbc:\w+:[^\s"\']*[?&;]password=(?!\$\{)[^&\s"\';]+'),
    ),
]

# [M-4] 멀티라인 전용 패턴: (rule_id, stack, 대상 확장자 튜플, 컴파일된 정규식)
# run_fallback에서 content 전체에 finditer 적용 후 오프셋→라인번호 변환
MULTILINE_PATTERNS = [
    (
        "jsp-comment-credential-multiline",
        "jsp-legacy",
        (".jsp",),
        re.compile(
            # 키워드[:=]값 형태만 — UI 섹션 주석 오탐 제거(멀티라인)
            r'(?i)<!--.*?(?:password|passwd|pwd|id/pw|계정|비밀번호|아이디)\s*[:=]\s*[^\s<>]{3,}.*?-->',
            re.DOTALL,
        ),
    ),
]


# [M-3] debug-output-residue 는 severity=info 로 간주하는 rule_id 집합
INFO_RULES = {"debug-output-residue"}


# ── 폴백 실행 ────────────────────────────────────────────────────
def run_fallback(target):
    """라인단위 FALLBACK_PATTERNS + 멀티라인 MULTILINE_PATTERNS 를 분리 처리.

    [M-4] re.DOTALL 멀티라인 규칙은 content 전체에 finditer 적용 후
    매치 시작 오프셋을 라인번호로 환산해 정확한 위치를 기록한다.
    라인단위 루프와 섞으면 여러 줄 주석이 미탐되므로 완전히 분리.

    [M-3] debug-output-residue(System.out.println 전체) 는 severity=info 필드를
    추가해 실제 민감정보 규칙과 출력에서 구분될 수 있도록 한다.
    """
    findings = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            line_patterns = [p for p in FALLBACK_PATTERNS if ext in p[2]]
            ml_patterns   = [p for p in MULTILINE_PATTERNS if ext in p[2]]
            if not line_patterns and not ml_patterns:
                continue
            path = os.path.join(root, f)
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except OSError:
                continue

            # ── 라인단위 매칭 ──────────────────────────────────────
            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                # 초대형 minified 단일 라인은 정규식 백트래킹 방어를 위해 스킵
                if len(line) > _MAX_LINE_LEN:
                    continue
                for rule_id, stack, _exts, rx in line_patterns:
                    if rx.search(line):
                        snippet = line.strip()[:200]
                        if re.search(r'\$\{[A-Z_]+\}', snippet):
                            continue
                        entry = {
                            "file": path,
                            "line": i,
                            "rule_id": rule_id,
                            "stack": stack,
                            "confidence": "needs-context",
                            "snippet": snippet,
                        }
                        # [M-3] 디버그 잔류 출력은 info 등급 표기
                        if rule_id in INFO_RULES:
                            entry["severity"] = "info"
                        findings.append(entry)

            # ── 멀티라인 매칭 ──────────────────────────────────────
            # [M-4] content 전체에 finditer → 매치 시작 위치로 라인번호 계산
            for rule_id, stack, _exts, rx in ml_patterns:
                for m in rx.finditer(content):
                    # [재리뷰] 단일 줄 매치는 라인단위 규칙과 중복(이중 카운트)되므로
                    # 여러 줄에 걸친 매치만 채택한다.
                    if "\n" not in m.group(0):
                        continue
                    # 매치 시작 오프셋 앞의 줄바꿈 수 + 1 = 라인번호
                    line_no = content[:m.start()].count("\n") + 1
                    snippet = m.group(0).replace("\n", " ").strip()[:200]
                    if re.search(r'\$\{[A-Z_]+\}', snippet):
                        continue
                    findings.append({
                        "file": path,
                        "line": line_no,
                        "rule_id": rule_id,
                        "stack": stack,
                        "confidence": "needs-context",
                        "snippet": snippet,
                    })

    return findings


# ── 요약 통계 ────────────────────────────────────────────────────
def summarize(findings):
    """rule_id 별 집계를 반환."""
    counts = {}
    for f in findings:
        counts[f["rule_id"]] = counts.get(f["rule_id"], 0) + 1
    return counts


# ── main ─────────────────────────────────────────────────────────
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
    ap = argparse.ArgumentParser(description="SQIsoft 민감정보 노출 1차 스캐너")
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
        if err:
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
        "note": (
            "후보 목록입니다. ${...} placeholder·reCAPTCHA siteKey 등은 오탐입니다. "
            "최종 취약/오탐 판정은 SKILL.md 2단계 AI 검증으로 수행하세요."
        ),
    }
    if warnings:
        result["warnings"] = warnings

    if args.json:
        io_utf8.emit_json(result)
    else:
        # [M-3] info 등급(debug-output-residue)과 실제 민감정보 후보를 구분
        info_findings = [c for c in findings if c.get("severity") == "info"]
        real_findings = [c for c in findings if c.get("severity") != "info"]

        print(f"대상     : {args.target}")
        print(f"감지 스택: {', '.join(stacks)}")
        print(f"엔진     : {engine}")
        print(f"후보     : {len(real_findings)}건 (민감정보)  /  {len(info_findings)}건 (info: 디버그 잔류)")
        if result["rule_summary"]:
            print("\n[룰별 집계]")
            for rule_id, cnt in sorted(result["rule_summary"].items(),
                                        key=lambda x: -x[1]):
                tag = "  [info]" if rule_id in INFO_RULES else ""
                print(f"  {rule_id}: {cnt}건{tag}")
        if real_findings:
            print("\n[민감정보 후보]")
            for c in real_findings:
                print(f"  [{c['stack']}] {c['rule_id']}  {c['file']}:{c['line']}")
                print(f"      {c['snippet']}")
        if info_findings:
            print("\n[디버그 잔류 출력 (info — 낮은 우선순위)]")
            for c in info_findings:
                print(f"  [{c['stack']}] {c['rule_id']}  {c['file']}:{c['line']}")
                print(f"      {c['snippet']}")
        if warnings:
            print("\n[!] 미탐 경고:")
            for wmsg in warnings:
                print(f"  - {wmsg}")
        print(
            "\n※ 후보일 뿐입니다. ${{...}} placeholder·공개키는 오탐, "
            "2단계 AI 컨텍스트 검증 필요."
        )


if __name__ == "__main__":
    main()
