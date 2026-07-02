#!/usr/bin/env python3
"""
SQIsoft 파일 업로드 취약점 1차 스캐너 (CWE-434 / 하이브리드 검사의 1단계).

동작:
  1) 대상 경로의 스택을 감지 (spring-modern / jsp-legacy / mixed)
  2) semgrep 이 있으면 rules/file-upload.yml 로 후보 탐지
  3) semgrep 이 없으면 정규식 grep 폴백으로 후보 탐지
  4) {file, line, rule_id, stack, snippet} 목록을 텍스트/JSON 으로 출력

이 스크립트는 "후보를 넓게" 잡는다. 최종 취약/오탐 판정은 SKILL.md 2단계의
AI 컨텍스트 검증이 수행한다.
  - 안전 패턴(FileUtils.validateFile 또는 FileValidator.validate 선행 후 transferTo) 오탐 주의.
  - 저장 경로가 웹루트 밖인지는 설정 파일까지 추적해야 최종 판정 가능.

사용:
  python scan_upload.py <target_path> [--json]
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
RULES = os.path.join(os.path.dirname(HERE), "rules", "file-upload.yml")

# 탐지 대상에서 제외할 디렉토리 (빌드 산출물, 의존성 등)
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


# ── grep 폴백 경로 ───────────────────────────────────────────────
# semgrep 미설치 환경에서 최소한의 후보를 잡는다(정밀도 낮음 → AI 검증 강화).
#
# 각 항목: (rule_id, stack, 파일확장자 튜플, 컴파일된_정규식)
#
# 중요: transferTo 패턴은 검증 메서드 선행 여부를 한 줄에서 판단할 수 없으므로
#        "가능성 있는 위치"를 모아 AI가 전후 문맥으로 최종 판정한다.
FALLBACK_PATTERNS = [
    # Spring: transferTo() 호출 — 검증 없는 경우 포함 가능 (AI가 전후 확인)
    ("spring-transferto", "spring-modern", (".java", ".kt"),
     re.compile(r"\.transferTo\s*\(")),

    # Spring: getRealPath → 웹루트 내 저장 의심
    ("spring-getrealpath-upload", "spring-modern", (".java", ".kt"),
     re.compile(r"getRealPath\s*\(")),

    # Spring: getOriginalFilename() 반환값을 File 생성자에 직접 사용
    ("spring-originalfilename-direct", "spring-modern", (".java", ".kt"),
     re.compile(r"getOriginalFilename\s*\(\s*\)")),

    # Spring: getContentType()만 사용 후 저장 의심 흐름
    ("spring-contenttype-only", "spring-modern", (".java", ".kt"),
     re.compile(r"getContentType\s*\(\s*\)")),

    # JSP: transferTo() — FileValidator 선행 여부 AI 확인 필요
    ("jsp-transferto-without-validator", "jsp-legacy", (".java",),
     re.compile(r"\.transferTo\s*\(new\s+File\s*\(")),

    # JSP: 업로드 폼 enctype 감지
    ("jsp-multipart-form", "jsp-legacy", (".jsp", ".html"),
     re.compile(r'enctype\s*=\s*["\']multipart/form-data["\']', re.I)),

    # 공통: ZipEntry.getName()을 경로에 직접 사용 (ZipSlip 의심)
    ("zipslip-zipentry-name", "spring-modern", (".java", ".kt"),
     re.compile(r"\.getName\s*\(\s*\)")),
]

# ZipSlip 탐지를 위해 ZipEntry 처리 파일만 대상으로 추가 필터링할 키워드
ZIPSLIP_CONTEXT_KEYWORD = re.compile(r"ZipEntry|ZipInputStream|ZipFile")


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

                for i, line in enumerate(lines, 1):
                    for rule_id, stack, _exts, rx in applicable:
                        if not rx.search(line):
                            continue

                        # ZipSlip 룰은 파일 내에 ZipEntry 사용이 있는 경우만 보고
                        if rule_id == "zipslip-zipentry-name":
                            if not ZIPSLIP_CONTEXT_KEYWORD.search(file_content):
                                continue

                        findings.append({
                            "file": fpath,
                            "line": i,
                            "rule_id": rule_id,
                            "stack": stack,
                            "snippet": line.strip()[:200],
                        })
            except OSError:
                continue
    return findings


# ── main ─────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="SQIsoft 파일 업로드 취약점 1차 스캐너 (CWE-434)")
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
            "특히 FileUtils.validateFile() / FileValidator.validate() 선행 여부, "
            "저장 경로가 웹루트 밖인지를 코드+설정 파일로 추적해야 합니다."
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
            "  안전 패턴(validateFile/FileValidator 선행 + 웹루트 밖 저장)은 오탐 처리하세요."
        )


if __name__ == "__main__":
    main()
