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

HERE = os.path.dirname(os.path.abspath(__file__))
_PLUGIN_ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
if _PLUGIN_ROOT not in sys.path:
    sys.path.insert(0, _PLUGIN_ROOT)
from tools import io_utf8  # noqa: E402  (UTF-8 콘솔 강제 — Windows cp949 크래시 방지, Task 1)
io_utf8.configure()

RULES = os.path.join(os.path.dirname(HERE), "rules", "access-control.yml")

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
        for f in files:
            if f in ("build.gradle.kts", "settings.gradle.kts", "build.gradle", "pom.xml"):
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
            "confidence": r.get("extra", {}).get("metadata", {}).get("confidence") or "needs-context",
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
    # FR-7: camelCase 접미(Id/Seq/No, 대소문자 구분) 또는 whole-word id/seq/no만 매칭 →
    # avoid("id" 부분포함) 과탐 배제. all-lowercase 접미(boardid)는 미탐 손실 허용(D1, Java 관례).
    # 케이싱: 폴백 whole-word는 첫글자만 case-무관([Ss]eq), semgrep(access-control.yml)은 전체 case-무관(^(?i:...)$).
    ("spring-pathvariable-id", "spring-modern", (".java", ".kt"),
     re.compile(r'@PathVariable\s+(?:\w+\s+)?([A-Za-z_]\w*(?:Id|Seq|No)\b|\b(?:[Ii][Dd]|[Ss]eq|[Nn]o)\b)')),

    # spring-modern: @PathVariable("id")/@PathVariable(name="userId") 어노테이션 값 지정형
    # value= 및 name= 별칭 모두 처리. 값 전체가 camelCase 접미(userId/boardSeq/certiNo)이거나
    # whole-word id/seq/no 일 때만 후보화(bare 룰과 동일 D1 스타일). avoid/boardid 과탐 배제.
    ("spring-pathvariable-annotated-id", "spring-modern", (".java", ".kt"),
     re.compile(r'@PathVariable\s*\(\s*(?:(?:value|name)\s*=\s*)?"(?:[A-Za-z_]\w*(?:Id|Seq|No)|(?i:id|seq|no))"')),

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


# ── 접근통제 전용: 소유권/권한 "집행" 신호 (P4 결정 2 — 이 스킬에만 추가) ──
# 후보 라인의 '같은 메서드' 창 안에 아래 강한 집행 신호가 있으면 IDOR/BFLA 후보에서 제외한다.
# 보수적 원칙(FN 회피): 소유권을 실제로 '강제'하는 패턴만 신호로 본다 —
#   · @Pre/@PostAuthorize 에 소유권 표현(#id·owns·hasPermission·returnObject·커스텀 빈 @auth.*)
#   · 소유자 스코핑 조회(findByOwner/findByIdAndUser…·existsBy…Owner…)
#   · 명시적 소유권 검사 호출(check/assert/verify/validate/ensure …Owner/Access/Permission, .owns())
# @AuthenticationPrincipal·SecurityContextHolder 등 '보유'만으로는 집행이 아니므로(스코핑에
# 안 쓸 수 있음) 억제 신호로 쓰지 않는다 — context.annotations 로만 노출해 AI 2단계가 판단한다.
_OWNERSHIP_RULES = {
    "spring-pathvariable-id", "spring-pathvariable-annotated-id", "jsp-getparameter-id",
}
_OWNERSHIP_ENFORCE = re.compile(
    r'@(?:Pre|Post)Authorize\s*\(\s*"[^"]*(?:#\w+|\bowns\b|hasPermission|returnObject|@\w+\.\w+)'
    r'|findBy\w*(?:Owner|User|Member|Writer|Creator|Author)\w*'
    r'|existsBy\w*(?:Owner|User|Member)\w*'
    r'|\b(?:check|assert|verify|validate|ensure)\w*(?:Owner|Ownership|Access|Permission)\s*\('
    r'|\.owns\s*\(',
    re.I,
)
_METHOD_DECL = re.compile(r'\b(?:public|private|protected)\b[\w<>\[\],.\s]*\s+\w+\s*\(')
_DELEGATE = re.compile(r'\b(\w+(?:Service|Repository|Mapper|Dao|DAO|Manager|Store))\.(\w+)\s*\(')
_ANNOTATION = re.compile(r'^\s*@\w+')


def _enclosing_method(lines, i):
    """후보(1-based i)를 감싸는 메서드 창 (start, end) 1-based inclusive 반환.

    ① 후보 위(≤40줄)에서 메서드 시그니처(_METHOD_DECL)를 찾아 body_start로 삼고,
    ② 그 위 연속 어노테이션 라인을 start에 포함(@Pre/PostAuthorize 포착),
    ③ body_start부터 중괄호 깊이로 메서드 끝을 찾는다(cap +80). 시그니처를 못 찾으면
    후보 자신을 기준으로 한다. 창을 넘겨 다른 메서드 신호를 오억제하지 않도록 보수적.
    """
    n = len(lines)
    sig = None
    for j in range(i, max(0, i - 40), -1):
        if _METHOD_DECL.search(lines[j - 1]):
            sig = j
            break
    body_start = sig or i
    start = body_start
    for j in range(body_start - 1, max(0, body_start - 12), -1):
        if _ANNOTATION.match(lines[j - 1]):
            start = j
        else:
            break
    depth = 0
    seen_open = False
    end = body_start
    for j in range(body_start, min(n, body_start + 80) + 1):
        ln = lines[j - 1]
        depth += ln.count("{") - ln.count("}")
        if "{" in ln:
            seen_open = True
        end = j
        if seen_open and depth <= 0:
            break
    return start, max(end, i)


def _has_enforcement(lines, start, end):
    return any(_OWNERSHIP_ENFORCE.search(lines[j - 1]) for j in range(start, end + 1))


def _build_context(lines, i, start, end):
    """AI 2단계 소유권 판정 사다리를 돕는 선택 필드(schema 선택)."""
    method = None
    for j in range(i, start - 1, -1):
        if _METHOD_DECL.search(lines[j - 1]):
            method = lines[j - 1].strip()[:160]
            break
    annotations = [lines[j - 1].strip()[:80]
                   for j in range(start, end + 1) if _ANNOTATION.match(lines[j - 1])]
    delegates = []
    for j in range(start, end + 1):
        for m in _DELEGATE.finditer(lines[j - 1]):
            tag = f"{m.group(1)}.{m.group(2)}"
            if tag not in delegates:
                delegates.append(tag)
    return {"method": method, "annotations": annotations[:6], "delegates_to": delegates[:8]}


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
                    lines = fh.readlines()
            except OSError:
                continue
            for i, line in enumerate(lines, 1):
                # 초대형 minified 단일 라인은 정규식 백트래킹 방어를 위해 스킵
                if len(line) > _MAX_LINE_LEN:
                    continue
                for rule_id, stack, _exts, rx in rules:
                    if not rx.search(line):
                        continue
                    cand = {
                        "file": path, "line": i, "rule_id": rule_id,
                        "stack": stack, "confidence": "needs-context",
                        "snippet": line.strip()[:200],
                    }
                    # 접근통제 전용(P4 결정 2): 소유권/권한 후보는 같은 메서드 창에 강한
                    # 집행 신호가 있으면 제외(오탐↓), 아니면 context를 달아 AI 판정에 넘긴다.
                    # 그 외 규칙(admin 매핑·CORS·anyRequest 등)은 기존과 바이트 동일하게 방출.
                    if rule_id in _OWNERSHIP_RULES:
                        m_start, m_end = _enclosing_method(lines, i)
                        if _has_enforcement(lines, m_start, m_end):
                            continue
                        cand["context"] = _build_context(lines, i, m_start, m_end)
                    findings.append(cand)
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
                            "confidence": "needs-context",
                            "snippet": line.strip()[:200],
                        })
                        break
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
    ap = argparse.ArgumentParser(description="SQIsoft 접근통제 1차 스캐너")
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

    warnings = build_warnings(stacks, engine, len(findings))

    result = {
        "target": args.target,
        "detected_stacks": stacks,
        "engine": engine,
        "candidate_count": len(findings),
        "rule_summary": summarize(findings),
        "candidates": findings,
        "note": (
            "후보 목록입니다. 최종 취약/오탐 판정은 SKILL.md 2단계 AI 검증으로 수행하세요. "
            "특히 서비스 레이어의 소유권 검증, 세션 기반 ID 추출, "
            "AuthInterceptor mode 설정을 코드로 직접 확인하세요."
        ),
    }
    if warnings:
        result["warnings"] = warnings

    if args.json:
        io_utf8.emit_json(result)
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
        print(
            "\n※ 후보일 뿐입니다. 2단계 AI 컨텍스트 검증 필요"
            " (소유권 검증, AuthInterceptor mode, DB 룰 테이블 유무)."
        )


if __name__ == "__main__":
    main()
