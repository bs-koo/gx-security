#!/usr/bin/env python3
"""
SQIsoft 경로 탐색(Path Traversal) 1차 스캐너 (CWE-22 / 하이브리드 검사의 1단계).

동작:
  1) 대상 경로의 스택을 감지 (spring-modern / jsp-legacy / mixed)
  2) semgrep 이 있으면 rules/path-traversal.yml 로 후보 탐지
  3) semgrep 이 없으면 정규식 grep 폴백으로 후보 탐지
  4) {file, line, rule_id, stack, snippet} 목록을 텍스트/JSON 으로 출력

이 스크립트는 "후보를 넓게" 잡는다. 최종 취약/오탐 판정은 SKILL.md 2단계의
AI 컨텍스트 검증이 수행한다.
  - getCanonicalPath()+startsWith(base) 패턴이 있으면 안전(오탐).
  - 블랙리스트만 사용하면 Medium으로 기록하고 getCanonicalPath 교체를 권고.

사용:
  python scan_pathtraversal.py <target_path> [--json]
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
RULES = os.path.join(os.path.dirname(HERE), "rules", "path-traversal.yml")

# 탐지 대상에서 제외할 디렉토리
SKIP_DIRS = {".git", "node_modules", "build", "target", "dist", ".gradle", ".idea", "__pycache__",
             ".dev", ".omc", ".humanize", ".vscode"}


# ── 스택 감지 신호 ────────────────────────────────────────────────
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
# 각 항목: (rule_id, stack, 파일확장자 튜플, 컴파일된_정규식)
#
# 안전 패턴(getCanonicalPath+startsWith) 제외는 단일 라인에서 판단 불가.
# → AI 검증 단계에서 전후 문맥 확인 필수.
FALLBACK_PATTERNS = [
    # Spring: Paths.get(base).resolve(param) — 가장 흔한 Path Traversal 진입점
    # "LocaleTextResolver.resolve" 같은 비파일 메서드와 구분: Path/Paths 클래스와 함께 쓰일 때
    ("spring-paths-resolve", "spring-modern", (".java", ".kt"),
     re.compile(r"(?:Paths\.get|path|filePath|uploadDir|baseDir|destDir)[^;]*\.resolve\s*\(")),

    # Spring: new File(base, param) 또는 new File(base + param) — 파일 관련 변수명 필터
    ("spring-new-file-with-param", "spring-modern", (".java", ".kt"),
     re.compile(r"new\s+File\s*\(\s*(?:filePath|uploadPath|savePath|destPath|baseDir|base|strgFilePath|[a-zA-Z]+[Pp]ath|[a-zA-Z]+[Dd]ir)")),

    # Spring: FileSystemResource / UrlResource 직접 생성
    ("spring-filesystemresource", "spring-modern", (".java", ".kt"),
     re.compile(r"new\s+(?:FileSystemResource|UrlResource)\s*\(")),

    # Spring: normalize() 호출 — Path 관련 변수에서만
    ("spring-normalize-only", "spring-modern", (".java", ".kt"),
     re.compile(r"(?:path|resolved|filePath|uploadPath)[^;]*\.normalize\s*\(\s*\)")),

    # 공통: ZipEntry.getName() — ZipSlip 의심 지점 (ZipEntry 컨텍스트 있는 파일에서만)
    ("zipslip-entry-getname", "spring-modern", (".java", ".kt"),
     re.compile(r"\.getName\s*\(\s*\)")),

    # JSP: ../를 indexOf/contains로만 블랙리스트 필터 — ".." 문자열 리터럴 있는 경우만
    ("jsp-blacklist-dotdot", "jsp-legacy", (".java",),
     re.compile(r'indexOf\s*\(\s*"\.\."\s*\)|contains\s*\(\s*"\.\."\s*\)')),

    # JSP: request.getParameter를 new File에 직접 전달 — 같은 줄에 new File이 있는 경우
    ("jsp-getparam-to-file", "jsp-legacy", (".java",),
     re.compile(r"new\s+File\s*\([^)]*getParameter\s*\(")),

    # JSP: filePath/fileName 파라미터에 startsWith 비교 (canonical 없이)
    # — 경로 관련 변수명 + startsWith 조합만
    ("jsp-startswith-no-canonical", "jsp-legacy", (".java",),
     re.compile(r'(?:filePath|fileName|savePath|uploadPath|baseDir)[^;]*\.startsWith\s*\(')),
]

# ZipSlip 탐지: 파일에 ZipEntry 또는 ZipInputStream 사용이 있어야 의미 있음
ZIPSLIP_CONTEXT = re.compile(r"ZipEntry|ZipInputStream|ZipFile")

# getCanonicalPath 안전 패턴: 이 키워드가 같은 파일에 있으면 오탐 가능성 높음
# (정확한 판단은 AI가 전후 문맥으로 수행)
CANONICAL_KEYWORD = re.compile(r"getCanonicalPath\s*\(\s*\)")


def run_fallback(target):
    findings = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            applicable = [r for r in FALLBACK_PATTERNS if ext in r[2]]
            if not applicable:
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, encoding="utf-8", errors="replace") as fh:
                    lines = fh.readlines()
                file_content = "".join(lines)
                has_canonical = bool(CANONICAL_KEYWORD.search(file_content))

                for i, line in enumerate(lines, 1):
                    for rule_id, stack, _exts, rx in applicable:
                        if not rx.search(line):
                            continue

                        # ZipSlip: 파일 내 ZipEntry 사용이 없으면 무의미
                        if rule_id == "zipslip-entry-getname":
                            if not ZIPSLIP_CONTEXT.search(file_content):
                                continue

                        # getCanonicalPath가 있는 파일은 주석에 [safe?] 표기
                        # — AI가 실제 위치 관계를 확인해야 최종 판정 가능
                        note = " [파일 내 getCanonicalPath 있음 — 오탐 가능, AI 위치 확인]" if has_canonical else ""

                        findings.append({
                            "file": fpath,
                            "line": i,
                            "rule_id": rule_id,
                            "stack": stack,
                            "snippet": line.strip()[:200] + note,
                        })
            except OSError:
                continue
    return findings


# ── main ─────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="SQIsoft 경로 탐색(Path Traversal) 1차 스캐너 (CWE-22)")
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
        "candidates": findings,
        "note": (
            "후보 목록입니다. 최종 취약/오탐 판정은 SKILL.md 2단계 AI 검증으로 수행하세요. "
            "getCanonicalPath()+startsWith(base) 패턴이 선행되면 오탐. "
            "블랙리스트(indexOf/contains '..') 방식만 있으면 Medium으로 기록 후 교체 권고."
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
            "\n※ 후보일 뿐입니다. 2단계 AI 컨텍스트 검증 필요.\n"
            "  getCanonicalPath()+startsWith(base) 검증 완비 패턴은 오탐 처리하세요.\n"
            "  블랙리스트 방식(indexOf '..') 단독 사용은 Medium — getCanonicalPath 교체 권고."
        )


if __name__ == "__main__":
    main()
