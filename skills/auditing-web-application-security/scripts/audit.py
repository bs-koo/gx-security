#!/usr/bin/env python3
"""
SQIsoft 보안 통합 점검 오케스트레이터 (정적 + 동적 한 번에).

한 명령으로:
  1) 정적 — scan_all.py 로 9종 취약점 후보를 일괄 도출(소스만 있으면 됨)
  2) 동적 — --target(실행 중 URL) 이 주어지면 exploiting-* 로 실제 페이로드 발사
  3) 통합 결과(JSON/요약) 출력

⚠️ 이 스크립트는 '엔진'이다. 오탐 제거·컨텍스트 판단·4요소 리포트 작성은
   Claude Code에서 auditing-web-application-security 스킬(AI 단계)이 수행한다.

사용:
  python audit.py <소스경로>                          # 정적만
  python audit.py <소스경로> --target http://localhost:8080 --params id,q   # 정적 + 동적
"""
import argparse
import json
import os
import subprocess
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    # [L3] stderr도 UTF-8로 고정 (scope_guard 등 다른 스크립트와 일관성)
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

# audit.py 위치: skills/auditing-web-application-security/scripts/audit.py → 3단계 상위가 플러그인 루트
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))

# 동적 공격 스크립트 (현재 구현된 exploiting-*)
DYNAMIC = {
    "sql-injection": os.path.join(ROOT, "skills", "exploiting-sql-injection", "scripts", "attack_sqli.py"),
    "xss": os.path.join(ROOT, "skills", "exploiting-xss-vulnerabilities", "scripts", "attack_xss.py"),
}


def run_static(source):
    """scan_all.py를 호출해 정적 스캔 결과를 반환.

    [L2] 자식 returncode != 0 이고 stdout이 비면 stderr를 error로 노출.
    """
    cmd = [sys.executable, os.path.join(ROOT, "scan_all.py"), source, "--json"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=900)
        if out.stdout and out.stdout.strip():
            try:
                data = json.loads(out.stdout)
                if out.returncode != 0:
                    data.setdefault("error", f"rc={out.returncode}: {out.stderr[:200].strip()}")
                return data, None
            except json.JSONDecodeError:
                pass
        stderr_head = out.stderr[:300].strip() if out.stderr else ""
        return None, f"rc={out.returncode}: {stderr_head or '(출력 없음)'}"
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except OSError as e:
        return None, str(e)[:150]


def run_dynamic(target, params, authorized):
    results = []
    for vuln, script in DYNAMIC.items():
        if not os.path.exists(script):
            continue
        for param in (params or [None]):
            cmd = [sys.executable, script, target, "--json"]
            if param:
                cmd += ["--param", param]
            if authorized:
                cmd += ["--authorized"]
            try:
                out = subprocess.run(cmd, capture_output=True, text=True,
                                     encoding="utf-8", errors="replace", timeout=600)
                # 안전게이트 차단 시 비-JSON(차단 메시지)일 수 있음 → 안전 파싱
                try:
                    data = json.loads(out.stdout or "{}")
                except json.JSONDecodeError:
                    data = {"raw": (out.stdout or out.stderr or "").strip()[:200],
                            "blocked_or_no_json": True}
                d = {"vuln": vuln, "param": param, "result": data,
                     "returncode": out.returncode}
                if param is None:
                    d["param_missing"] = True
                    d["reason"] = (
                        f"파라미터 미지정 — attack 스크립트가 --param 누락으로 "
                        f"미발사(rc={out.returncode}). --params id,q 등 지정 필요")
                results.append(d)
            except (subprocess.TimeoutExpired, OSError) as e:
                results.append({"vuln": vuln, "param": param, "error": str(e)[:120]})
    return results


_ACCESS_SCRIPT = os.path.join(
    ROOT, "skills", "exploiting-broken-access-control", "scripts", "attack_access.py")

_AUTH_SCRIPT = os.path.join(
    ROOT, "skills", "exploiting-auth-session", "scripts", "attack_auth.py")

_SSRF_SCRIPT = os.path.join(
    ROOT, "skills", "exploiting-ssrf-and-open-redirect", "scripts", "attack_ssrf.py")

_PATHUP_SCRIPT = os.path.join(
    ROOT, "skills", "exploiting-path-traversal-upload", "scripts", "attack_pathupload.py")


def _extract_access_candidates(static_result):
    """정적 통합 결과(by_skill)에서 접근통제(BFLA/IDOR) 후보만 추출."""
    for s in (static_result or {}).get("by_skill", []):
        if "broken-access-control" in s.get("skill", ""):
            return s.get("candidates", [])
    return []


def run_access_dynamic(target, static_result, creds, authorized):
    """정적 access-control 후보를 attack_access로 동적 확정한다(개선 D).

    계정/토큰 미제공 시 발사하지 않고 'static-only'(정적 추정·동적 미확정)로 표기한다(개선 E).
    IDOR/BFLA는 본질적으로 동적 확정이 필요하므로, 동적을 못 돌리면 High로 단정하지 않는다.
    """
    if not os.path.exists(_ACCESS_SCRIPT):
        return {"skipped": "attack_access.py 없음"}
    # N1: 정적 스캔이 부분 실패(error 동반)면 불완전한 후보로 동적 확정하지 않는다
    if isinstance(static_result, dict) and static_result.get("error"):
        return {"skipped": "정적 스캔 부분 실패 — 동적 연계 보류",
                "static_error": str(static_result["error"])[:200]}
    candidates = _extract_access_candidates(static_result)
    if not candidates:
        return {"skipped": "정적 access-control 후보 없음"}
    has_creds = creds.get("token_a") or (creds.get("user_a_id") and creds.get("user_a_pw"))
    if not has_creds:
        return {
            "confidence": "static-only",
            "candidate_count": len(candidates),
            "note": ("access-control 후보가 있으나 테스트 계정 미제공 → 동적 미확정(정적 추정). "
                     "--user-a-id/pw(+--user-b-id/pw·--resource-id) 또는 --token-a 제공 시 동적 확정."),
        }
    import tempfile
    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    try:
        json.dump({"candidates": candidates}, tmp, ensure_ascii=False)
        tmp.close()
        cmd = [sys.executable, _ACCESS_SCRIPT, target, "--scan", tmp.name, "--json"]
        for flag, key in [("--token-a", "token_a"), ("--token-b", "token_b"),
                          ("--resource-id", "resource_id")]:
            if creds.get(key):
                cmd += [flag, creds[key]]
        if creds.get("user_a_id") and creds.get("user_a_pw"):
            cmd += ["--user-a-id", creds["user_a_id"], "--user-a-pw", creds["user_a_pw"]]
        if creds.get("user_b_id") and creds.get("user_b_pw"):
            cmd += ["--user-b-id", creds["user_b_id"], "--user-b-pw", creds["user_b_pw"]]
        if authorized:
            cmd += ["--authorized"]
        out = subprocess.run(cmd, capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=600)
        try:
            data = json.loads(out.stdout or "{}")
            if not isinstance(data, dict):  # dict 아닌 JSON(list 등) 반환 시 data.get() 크래시 방어 (PR 리뷰 반영)
                data = {"raw": str(data)[:200], "blocked_or_no_json": True}
        except json.JSONDecodeError:
            data = {"raw": (out.stdout or out.stderr or "").strip()[:200],
                    "blocked_or_no_json": True}
        # scope 차단/로그인 실패/발사 오류를 fired 판정보다 먼저 평가한다(auth·ssrf 분기 순서 일치).
        # scope_blocked(error만·findings 없음)를 'dynamic'으로 오표기하던 잠복결함 수정(사용자2).
        if data.get("error") == "scope_blocked":
            return {"blocked": "scope_guard", "detail": data.get("detail"), "returncode": 1}
        # 로그인 실패는 자식이 {"error":"login_failed"} JSON 출력 후 exit(2)하므로 error 키로 판정.
        # (argparse 인자오류 등 stdout 없는 rc=2는 아래 rc 게이트가 error로 정직 표기 — 코드리뷰 #11)
        if data.get("error") == "login_failed":
            return {"confidence": "login-failed", "detail": data.get("detail"),
                    "returncode": 2}
        # rc 게이트: 발사(계정 있음) 후 stdout이 빈 채(data=={}) 비정상 종료(rc≠0)면
        # 자식이 uncaught 예외로 죽은 것 — static-only로 오분류 말고 error로 정직 표기한다.
        if data == {} and out.returncode not in (0, None):
            return {"error": f"접근통제 발사 중 오류(rc={out.returncode}) — 자식 프로세스 비정상 종료",
                    "returncode": out.returncode}
        # 발사했더라도 모든 표적이 skipped(예: IDOR인데 token_b/resource_id 없음)면
        # 동적으로 확정한 게 없으므로 'dynamic'으로 과대표기하지 않는다(정적 추정 유지).
        fired = [f for f in (data.get("findings") or [])
                 if isinstance(f, dict) and not f.get("skipped")]
        # fired(비-skipped finding)가 하나도 없으면 동적으로 확정한 게 없다.
        # run_auth/ssrf_dynamic과 동일하게 `if not fired`로 통일한다. 빈 findings(rc0)나
        # 전부 skipped 모두 static-only로 유지해 'dynamic 발사 완료 findings 0건' 과대표기를 막는다.
        if not fired:
            return {"confidence": "static-only", "result": data, "returncode": out.returncode,
                    "note": "동적 발사했으나 확정된 finding 없음(모든 표적 skip 또는 findings 0건) — 정적 추정 유지"}
        return {"confidence": "dynamic", "result": data, "returncode": out.returncode}
    except (subprocess.TimeoutExpired, OSError) as e:
        return {"error": str(e)[:120]}
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def run_auth_dynamic(target, creds, probe, authorized):
    """정적 추정된 인증/세션/JWT를 attack_auth로 동적 확정한다(FR-2/3).

    계정/토큰 미제공 시 발사하지 않고 'static-only'(정적 추정·동적 미확정)로 표기한다(AC-2).
    발사하더라도 모든 검사가 skip(probe 미지정+쿠키 없음 등)이면 과대표기하지 않고
    static-only로 유지한다(run_access_dynamic L158-162 방어 패턴 준용).
    """
    if not os.path.exists(_AUTH_SCRIPT):
        return {"skipped": "attack_auth.py 없음"}
    has_creds = creds.get("token_a") or (creds.get("user_a_id") and creds.get("user_a_pw"))
    if not has_creds:
        return {
            "confidence": "static-only",
            "note": ("로그인 계정/토큰 미제공 → 인증 동적 미확정(정적 추정). "
                     "--user-a-id/pw 또는 --token-a 제공 시 발사"),
        }
    cmd = [sys.executable, _AUTH_SCRIPT, target, "--json"]
    if probe:
        cmd += ["--probe", probe]
    if creds.get("token_a"):
        cmd += ["--token-a", creds["token_a"]]
    elif creds.get("user_a_id") and creds.get("user_a_pw"):
        cmd += ["--user-a-id", creds["user_a_id"], "--user-a-pw", creds["user_a_pw"]]
    if authorized:
        cmd += ["--authorized"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=600)
        try:
            data = json.loads(out.stdout or "{}")
            if not isinstance(data, dict):  # dict 아닌 JSON(list 등) 반환 시 data.get() 크래시 방어 (PR 리뷰 반영)
                data = {"raw": str(data)[:200], "blocked_or_no_json": True}
        except json.JSONDecodeError:
            data = {"raw": (out.stdout or out.stderr or "").strip()[:200],
                    "blocked_or_no_json": True}
        if data.get("error") == "scope_blocked":
            return {"blocked": "scope_guard", "detail": data.get("detail"), "returncode": 1}
        # 로그인 실패는 자식이 {"error":"login_failed"} JSON 출력 후 exit(2)하므로 error 키로 판정.
        # (argparse 인자오류 등 stdout 없는 rc=2는 아래 rc 게이트가 error로 정직 표기 — 코드리뷰 #11)
        if data.get("error") == "login_failed":
            return {"confidence": "login-failed", "detail": data.get("detail"),
                    "returncode": 2}
        # rc 게이트(크래시 은폐 방지, ZT CRITICAL): 발사(계정 있음) 후 stdout이 빈 채
        # (data=={}) 비정상 종료(rc≠0)면 자식이 uncaught 예외로 죽은 것 — static-only로
        # 오분류하지 말고 error로 정직 표기한다. fired 판정보다 반드시 먼저 평가한다.
        if data == {} and out.returncode not in (0, None):
            return {"error": f"인증 발사 중 오류(rc={out.returncode}) — 자식 프로세스 비정상 종료",
                    "returncode": out.returncode}
        findings = data.get("findings", [])
        fired = [f for f in findings if isinstance(f, dict) and not f.get("skipped")]
        if not fired:
            return {"confidence": "static-only", "result": data,
                    "note": ("발사 시도했으나 모든 검사 skip(probe 미지정+쿠키 없음 등) "
                             "→ 정적 추정")}
        if not probe:
            return {"confidence": "partial", "result": data,
                    "note": ("쿠키 속성만 발사, JWT 변조·재사용은 정적 추정(probe 미지정). "
                             "--probe 지정 시 전체 발사")}
        return {"confidence": "dynamic", "result": data, "returncode": out.returncode}
    except (subprocess.TimeoutExpired, OSError) as e:
        return {"error": str(e)[:120]}


def run_ssrf_dynamic(target, creds, redirect_target, ssrf_target, authorized):
    """정적 추정된 SSRF/오픈리다이렉트를 attack_ssrf로 동적 확정한다(FR-2/3).

    표적(--redirect-target/--ssrf-target)과 계정/토큰이 '모두' 있어야 발사한다(PRD1).
    표적 우선 판정: 표적이 없으면 계정 유무와 무관하게 '표적 미지정' static-only(AC-2).
    canary 옵션(--canary-host/port/timeout)은 audit에 미노출 — attack_ssrf 기본값
    (127.0.0.1/0/5.0)을 유지해 원격 콜백을 차단한다(AC-9/PRD3).
    """
    if not os.path.exists(_SSRF_SCRIPT):
        return {"skipped": "attack_ssrf.py 없음"}
    has_target = bool(redirect_target or ssrf_target)
    has_creds = creds.get("token_a") or (creds.get("user_a_id") and creds.get("user_a_pw"))
    # 표적 우선(PRD1): 표적이 없으면 계정 유무와 무관하게 '표적 미지정'으로 표기한다.
    if not has_target:
        return {
            "confidence": "static-only",
            "note": ("SSRF/오픈리다이렉트 표적 미지정(--redirect-target/--ssrf-target) → "
                     "정적 추정. 주입점 지정 시 동적 확정."),
        }
    if not has_creds:
        return {
            "confidence": "static-only",
            "note": ("표적은 있으나 계정/토큰 미지정 → 정적 추정. "
                     "--user-a-id/pw 또는 --token-a 제공 시 발사."),
        }
    cmd = [sys.executable, _SSRF_SCRIPT, target, "--json"]
    if redirect_target:
        cmd += ["--redirect-target", redirect_target]
    if ssrf_target:
        cmd += ["--ssrf-target", ssrf_target]
    if creds.get("token_a"):
        cmd += ["--token-a", creds["token_a"]]
    elif creds.get("user_a_id") and creds.get("user_a_pw"):
        cmd += ["--user-a-id", creds["user_a_id"], "--user-a-pw", creds["user_a_pw"]]
    if authorized:
        cmd += ["--authorized"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=600)
        try:
            data = json.loads(out.stdout or "{}")
            if not isinstance(data, dict):  # dict 아닌 JSON(list 등) 반환 시 data.get() 크래시 방어
                data = {"raw": str(data)[:200], "blocked_or_no_json": True}
        except json.JSONDecodeError:
            data = {"raw": (out.stdout or out.stderr or "").strip()[:200],
                    "blocked_or_no_json": True}
        # 판정 우선순위(auth 계약 동일): scope_blocked > login_failed/rc2 > rc게이트 > fired없음
        if data.get("error") == "scope_blocked":
            return {"blocked": "scope_guard", "detail": data.get("detail"), "returncode": 1}
        # 로그인 실패는 자식이 {"error":"login_failed"} JSON 출력 후 exit(2)하므로 error 키로 판정.
        # (argparse 인자오류 등 stdout 없는 rc=2는 아래 rc 게이트가 error로 정직 표기 — 코드리뷰 #11)
        if data.get("error") == "login_failed":
            return {"confidence": "login-failed", "detail": data.get("detail"),
                    "returncode": 2}
        # rc 게이트: 발사(계정 있음) 후 stdout이 빈 채(data=={}) 비정상 종료(rc≠0)면
        # 자식이 uncaught 예외로 죽은 것 — static-only로 오분류 말고 error로 정직 표기한다.
        if data == {} and out.returncode not in (0, None):
            return {"error": f"SSRF 발사 중 오류(rc={out.returncode}) — 자식 프로세스 비정상 종료",
                    "returncode": out.returncode}
        findings = data.get("findings", [])
        fired = [f for f in findings if isinstance(f, dict) and not f.get("skipped")]
        if not fired:
            return {"confidence": "static-only", "result": data,
                    "note": "발사 시도했으나 모든 표적이 skip — 정적 추정"}
        # targets: 렌더의 종류별 표적 미지정 표기용(CONSIDER 부분표적)
        return {"confidence": "dynamic", "result": data, "returncode": out.returncode,
                "targets": {"redirect": bool(redirect_target), "ssrf": bool(ssrf_target)}}
    except (subprocess.TimeoutExpired, OSError) as e:
        return {"error": str(e)[:120]}


def run_pathupload_dynamic(target, creds, traversal_target, upload_target, upload_field,
                           retrieve_base, allow_destructive, authorized):
    """정적 추정된 경로조작·파일업로드를 attack_pathupload로 동적 확정한다(FR-1~5).

    표적(--traversal-target/--upload-target)과 계정/토큰이 '모두' 있어야 발사한다(PRD1).
    표적 우선 판정: 표적이 없으면 계정 유무와 무관하게 '표적 미지정' static-only(AC-6).
    업로드는 파괴적(서버에 파일 기록)이라 audit 레이어에서도 --allow-destructive 없이는
    발사하지 않는다(이중 게이트/BR-3). audit이 --allow-destructive 없이는 --upload-target
    자체를 자식에 넘기지 않아 attack_pathupload 게이트와 독립적으로 이중 방어한다.
    run_ssrf_dynamic 미러링(판정 순서·비-dict 방어·반환 형식 동형).
    """
    if not os.path.exists(_PATHUP_SCRIPT):
        return {"skipped": "attack_pathupload.py 없음"}
    has_target = bool(traversal_target or upload_target)
    has_creds = creds.get("token_a") or (creds.get("user_a_id") and creds.get("user_a_pw"))
    # 표적 우선(PRD1): 표적이 없으면 계정 유무와 무관하게 '표적 미지정'으로 표기한다.
    if not has_target:
        return {
            "confidence": "static-only",
            "note": ("경로조작/파일업로드 표적 미지정(--traversal-target/--upload-target) → "
                     "정적 추정. 주입점 지정 시 동적 확정."),
        }
    if not has_creds:
        return {
            "confidence": "static-only",
            "note": ("표적은 있으나 계정/토큰 미지정 → 정적 추정. "
                     "--user-a-id/pw 또는 --token-a 제공 시 발사."),
        }
    # 이중 파괴적 게이트: 업로드 표적만 있고 --allow-destructive가 없으면(경로조작 미지정)
    # 발사할 게 없으므로 subprocess를 아예 호출하지 않고 static-only로 표기한다(방어심층/AC-8).
    fireable = bool(traversal_target) or (bool(upload_target) and allow_destructive)
    if not fireable:
        return {
            "confidence": "static-only",
            "note": ("업로드 표적은 있으나 --allow-destructive 미지정 → 미발사(정적 추정). "
                     "서버에 파일을 기록하는 파괴적 검사라 명시적 옵트인이 필요하다."),
        }
    cmd = [sys.executable, _PATHUP_SCRIPT, target, "--json"]
    if traversal_target:
        cmd += ["--traversal-target", traversal_target]
    # audit이 --allow-destructive 없이는 --upload-target 자체를 넘기지 않는다(자식 게이트와 독립 이중방어).
    if upload_target and allow_destructive:
        cmd += ["--upload-target", upload_target, "--allow-destructive"]
    if upload_field:
        cmd += ["--upload-field", upload_field]
    if retrieve_base:
        cmd += ["--retrieve-base", retrieve_base]
    if creds.get("token_a"):
        cmd += ["--token-a", creds["token_a"]]
    elif creds.get("user_a_id") and creds.get("user_a_pw"):
        cmd += ["--user-a-id", creds["user_a_id"], "--user-a-pw", creds["user_a_pw"]]
    if authorized:
        cmd += ["--authorized"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=600)
        try:
            data = json.loads(out.stdout or "{}")
            if not isinstance(data, dict):  # dict 아닌 JSON(list 등) 반환 시 data.get() 크래시 방어
                data = {"raw": str(data)[:200], "blocked_or_no_json": True}
        except json.JSONDecodeError:
            data = {"raw": (out.stdout or out.stderr or "").strip()[:200],
                    "blocked_or_no_json": True}
        # 판정 우선순위(ssrf 계약 동일): scope_blocked > login_failed/rc2 > rc게이트 > fired없음
        if data.get("error") == "scope_blocked":
            return {"blocked": "scope_guard", "detail": data.get("detail"), "returncode": 1}
        # 로그인 실패는 자식이 {"error":"login_failed"} JSON 출력 후 exit(2)하므로 error 키로 판정.
        # (argparse 인자오류 등 stdout 없는 rc=2는 아래 rc 게이트가 error로 정직 표기 — 코드리뷰 #11)
        if data.get("error") == "login_failed":
            return {"confidence": "login-failed", "detail": data.get("detail"),
                    "returncode": 2}
        # rc 게이트: 발사(계정 있음) 후 stdout이 빈 채(data=={}) 비정상 종료(rc≠0)면 자식이
        # uncaught 예외로 죽은 것(경로조작 미도달 크래시 포함) — static-only로 오분류 말고
        # error로 정직 표기한다. 업로드 표적이 있었으면 회수 중 크래시로 leftover가 소실됐을 수
        # 있어, 렌더가 '마커 잔존 확인' 안내를 붙이도록 upload_target 플래그를 함께 싣는다(QE-2).
        if data == {} and out.returncode not in (0, None):
            return {"error": f"경로조작/업로드 발사 중 오류(rc={out.returncode}) — 자식 프로세스 비정상 종료",
                    "returncode": out.returncode, "upload_target": bool(upload_target)}
        findings = data.get("findings", [])
        fired = [f for f in findings if isinstance(f, dict) and not f.get("skipped")]
        if not fired:
            return {"confidence": "static-only", "result": data,
                    "note": "발사 시도했으나 모든 표적이 skip — 정적 추정"}
        # targets: 렌더의 종류별 표적 미지정 표기용. upload_gated: 업로드 표적은 있으나
        # --allow-destructive 미지정으로 audit이 업로드 인자를 배제한 채 경로조작만 발사한 경우.
        return {"confidence": "dynamic", "result": data, "returncode": out.returncode,
                "upload_gated": bool(upload_target and not allow_destructive),
                "targets": {"traversal": bool(traversal_target), "upload": bool(upload_target)}}
    except (subprocess.TimeoutExpired, OSError) as e:
        return {"error": str(e)[:120], "upload_target": bool(upload_target)}


def _ssrf_unreached(f):
    """SSRF/오픈리다이렉트 finding이 '프로브 미도달'(전변형 오류/status None)인지 판정한다.

    미도달을 '방어'로 오표기하지 않기 위한 MUST 헬퍼(design-critic).
    vulnerable=True는 항상 취약 우선이므로 미도달로 보지 않는다.
    """
    if not isinstance(f, dict):
        return False
    kind = f.get("kind")
    if kind == "open-redirect":
        if f.get("vulnerable"):  # 취약이면 미도달 아님(취약 우선 불변식 명시, 방어심층)
            return False
        variants = f.get("findings", [])
        if not isinstance(variants, list) or not variants:
            return False
        # 하위 변형이 비어있지 않고 전부 오류/status None이면 전변형 미도달
        return all(isinstance(v, dict) and (v.get("error") or v.get("status") is None)
                   for v in variants)
    if kind == "ssrf":
        return f.get("status") is None and not f.get("vulnerable")
    return False


def _ssrf_finding_line(f):
    """SSRF/오픈리다이렉트 finding 1건을 요약 한 줄 문자열로 렌더한다(테스트 가능 헬퍼).

    우선순위: skipped > error > (ssrf 콜백판정) > 미도달 > vulnerable/방어.
    SSRF는 OOB 콜백 수신만이 취약 확정이다 — 콜백 미수신은 '방어'가 아니라 '미확정'으로 렌더한다.
    원격/비동기 대상은 loopback canary에 콜백할 수 없어 status 2xx여도 취약을 확정하지 못하며,
    이를 '방어'로 찍으면 원격 스테이징 SSRF를 안전으로 오도한다(코드리뷰 #12).
    """
    if not isinstance(f, dict):
        return None
    kind = f.get("kind")
    if f.get("skipped"):
        return f"    - [{kind}] 미발사({f.get('skipped')})"
    if f.get("error"):
        return f"    - [{kind}] ⚠ 오류: {f.get('error')}"
    if kind == "ssrf":
        if f.get("vulnerable"):
            return f"    - [{kind}] 🔴 취약(OOB 콜백 수신)"
        return f"    - [{kind}] ⚠ 미확정 — 콜백 미수신(원격/비동기 대상이면 취약 가능·안전 단정 금지)"
    if _ssrf_unreached(f):
        return f"    - [{kind}] ⚠ 미확정 — 프로브 미도달(대상 무응답/전변형 오류)"
    return f"    - [{kind}] {'🔴 취약' if f.get('vulnerable') else '방어'}"


def render_dynamic_line(d):
    """동적 공격 결과 항목 1건을 사람이 읽는 한 줄 문자열로 렌더링한다.

    분기 순서(위→아래, 먼저 매치되는 것 채택)가 §9-C 안전 불변식이다:
    scope_blocked(3)·blocked_or_no_json(4)이 rc≠0(5)보다 먼저 평가돼야
    scope 차단/차단 raw가 '발사 실패 rc'로 뭉개지지 않는다.
    """
    prefix = f"  - {d['vuln']}({d.get('param')}) : "
    res = d.get("result")
    if not isinstance(res, dict):  # 자식이 dict 아닌 JSON(list 등) 반환 시 방어 (PR 리뷰 반영)
        res = {}
    if d.get("error"):
        return f"{prefix}⚠ 오류: {d['error']}"
    if d.get("param_missing"):
        return f"{prefix}⏭ 미발사 (파라미터 미지정) — {d.get('reason')}"
    if res.get("error") == "scope_blocked":
        return f"{prefix}⏭ 차단됨 (scope_guard) — {res.get('detail') or 'scope 범위 밖'}"
    if res.get("blocked_or_no_json"):
        return f"{prefix}{res.get('raw','')[:80]}"
    if d.get("returncode") not in (0, None):
        return f"{prefix}⚠ 발사 실패 rc={d.get('returncode')}"
    return f"{prefix}{'🔴 악용 확정' if res.get('exploited') else '— 미확인'}"


def render_pathupload(res):
    """경로조작/파일업로드 동적 결과를 사람이 읽는 요약 줄들(list[str])로 렌더링한다(FR-6/7).

    SSRF 렌더 블록 미러링 — 판정 우선순위: scope_blocked > login-failed > static-only >
    dynamic > error > skipped. render_dynamic_line 재사용 안 함(그건 sql/xss param 전용).
    MUST 해소 3건: ①경로조작 미검출은 2xx면 방어, 그 외(non-2xx/None)는 '방어' 아닌
    '미확정'(미도달/차단) — 404 전량을 방어로 뭉개지 않는다, ②leftover 정리 안내는
    accepted(2xx 수용)된 업로드만, ③미지정 표적은 '미검사'로 명시(targets 소비).
    res 비-dict 방어.
    """
    if not isinstance(res, dict):
        res = {}
    lines = []
    if res.get("blocked") == "scope_guard":  # rc로 안 뭉개지게 최상단
        lines.append(f"[경로조작/파일업로드] 차단됨(scope_guard) — {res.get('detail') or 'scope 범위 밖'}")
    elif res.get("confidence") == "login-failed":  # '미발견'과 구분
        lines.append(f"[경로조작/파일업로드] 동적 미확정(로그인 실패) — {res.get('detail')}")
    elif res.get("confidence") == "static-only":  # 과대표기 방지(표적/계정/게이트 사유)
        lines.append(f"[경로조작/파일업로드] 정적 추정(동적 미확정) — {res.get('note')}")
    elif res.get("confidence") == "dynamic":
        lines.append("[경로조작/파일업로드] 동적 확정 발사")
        result = res.get("result", {})
        if not isinstance(result, dict):  # 자식이 dict 아닌 JSON 반환 시 방어
            result = {}
        findings = result.get("findings", [])
        for f in findings:
            # 우선순위 skipped > error > kind별 판정. error finding(발사 예외 격리)을
            # '방어'로 오표기하면 크래시 은폐가 되므로 정직 표기한다.
            if not isinstance(f, dict):
                continue
            kind = f.get("kind")
            if f.get("skipped"):
                lines.append(f"    - [{kind}] 미발사({f.get('skipped')})")
            elif f.get("error"):
                lines.append(f"    - [{kind}] ⚠ 오류: {f.get('error')}")
            elif kind == "path-traversal":
                # MUST#1: 미검출을 무조건 '방어'로 뭉개지 않는다. 정상 2xx 응답에서 시그니처가
                # 없어야 진짜 방어이고, non-2xx(404/403/5xx)·status None은 미도달/차단 '미확정'.
                status = f.get("status")
                if f.get("vulnerable"):
                    lines.append(f"    - [{kind}] 🔴 취약(파일내용 시그니처 검출)")
                elif isinstance(status, int) and 200 <= status < 300:
                    lines.append(f"    - [{kind}] 방어(정상 응답·시그니처 없음)")
                else:
                    lines.append(f"    - [{kind}] ⚠ 미확정 — 미도달/차단 추정(엔드포인트·주입점 확인)")
            elif kind == "file-upload":
                if f.get("retrievable"):
                    lines.append(f"    - [{kind}] 🔴 취약(High·웹루트 저장 확인)")
                elif f.get("vulnerable"):
                    lines.append(f"    - [{kind}] 🔴 취약(Medium·위험확장자 2xx 수용)")
                else:
                    lines.append(f"    - [{kind}] 방어(거부)")
            else:
                lines.append(f"    - [{kind}] {'🔴 취약' if f.get('vulnerable') else '방어'}")
        # MUST#3: 종류별 표적 미지정 개별 표기(targets 소비, SSRF 동형). 미지정 표적을
        # '검사됨·방어'로 오추론하지 않게 '미검사'로 명시한다.
        tg = res.get("targets", {})
        if not tg.get("traversal"):
            lines.append("    - [경로조작] 표적 미지정(--traversal-target) — 미검사")
        if res.get("upload_gated"):  # 업로드 표적은 있으나 게이트로 미발사
            lines.append("    - [파일업로드] 미발사(--allow-destructive 필요)")
        elif not tg.get("upload"):
            lines.append("    - [파일업로드] 표적 미지정(--upload-target) — 미검사")
        # MUST#2: leftover 정리 안내는 accepted(2xx 수용)된 업로드만 — 거부(403·미기록)엔
        # 서버에 파일이 남지 않으므로 안내하지 않는다(FR-7/QE-2).
        leftover = [f.get("leftover") for f in findings
                    if isinstance(f, dict) and f.get("leftover") and f.get("accepted")]
        if leftover:
            lines.append(f"    [정리 필요] 업로드된 마커 파일: {', '.join(leftover)} — "
                         f"서버에서 수동 삭제 권장")
    elif res.get("error"):
        line = f"[경로조작/파일업로드] 오류: {res['error']}"
        # 업로드 표적이 지정됐던 경우 회수 중 크래시로 leftover가 소실됐을 수 있어 잔존 확인 권장(QE-2)
        if res.get("upload_target"):
            line += " — 업로드가 수용됐을 수 있으니 서버에 마커 파일 잔존 여부 확인 권장"
        lines.append(line)
    elif res.get("skipped"):
        lines.append(f"[경로조작/파일업로드] {res['skipped']}")
    return lines


def main():
    ap = argparse.ArgumentParser(description="SQIsoft 보안 통합 점검 오케스트레이터")
    ap.add_argument("source", help="검사 대상 소스 디렉토리")
    ap.add_argument("--target", help="실행 중인 대상 URL(스테이징/로컬). 주면 동적 공격 수행")
    ap.add_argument("--params", help="동적 공격 대상 파라미터(쉼표구분, 예: id,q,search)")
    ap.add_argument("--authorized", action="store_true", help="공인 대상 명시 승인(소유자 책임)")
    # 접근통제(BFLA/IDOR) 동적 연계용 테스트 계정/토큰 (개선 D)
    ap.add_argument("--user-a-id"); ap.add_argument("--user-a-pw")
    ap.add_argument("--user-b-id"); ap.add_argument("--user-b-pw")
    ap.add_argument("--token-a"); ap.add_argument("--token-b")
    ap.add_argument("--resource-id", help="IDOR: A가 소유한 리소스 ID")
    ap.add_argument("--probe", help="인증 동적: 보호 엔드포인트 직접 지정(예: /api/v1/users/me). "
                                    "미지정 시 JWT·재사용 정적 추정")
    # SSRF/오픈리다이렉트 동적 연계용 주입점 (계정/토큰 플래그 재사용)
    ap.add_argument("--redirect-target", help="오픈리다이렉트 주입점(예: /login?returnUrl=). "
                                              "지정+계정(--user-a-id/pw 또는 --token-a) 시 동적 확정")
    ap.add_argument("--ssrf-target", help="SSRF 주입점(예: /api/fetch?url=). "
                                          "동적 확정에는 계정(--user-a-id/pw 또는 --token-a)도 필요")
    # 경로조작/파일업로드 동적 연계용 주입점 (계정/토큰 플래그 재사용)
    ap.add_argument("--traversal-target", help="경로조작 주입점(예: /download?filePath=). "
                                              "지정+계정(--user-a-id/pw 또는 --token-a) 시 동적 확정")
    ap.add_argument("--upload-target", help="파일업로드 엔드포인트(예: /api/v1/files). "
                                           "발사에는 계정과 --allow-destructive(파괴적 옵트인)도 필요")
    ap.add_argument("--upload-field", default="file", help="업로드 multipart 필드명(기본 file)")
    ap.add_argument("--retrieve-base", help="업로드 파일 회수 URL 베이스(웹루트 저장 가중 판정용)")
    ap.add_argument("--allow-destructive", action="store_true",
                    help="파일업로드(서버에 파일 기록) 허용 — 명시해야 업로드 검사 발사")
    ap.add_argument("--json", action="store_true", help="통합 JSON 출력")
    args = ap.parse_args()

    if not os.path.isdir(args.source):
        print(f"오류: 소스 디렉토리가 아닙니다 — {args.source}", file=sys.stderr)
        sys.exit(2)

    report = {"source": args.source, "target": args.target, "phases": {}}

    # 1) 정적
    static, err = run_static(args.source)
    report["phases"]["static"] = {"error": err} if err else static

    # 2) 동적 (대상 URL 있을 때만)
    if args.target:
        # [H3] 빈/공백 토큰 제거: "id,,q, " → ["id", "q"]
        # 모두 비면 None으로 처리해 빈 파라미터 공격 유발 방지
        params = (
            [p.strip() for p in args.params.split(",") if p.strip()] or None
            if args.params else None
        )
        report["phases"]["dynamic"] = run_dynamic(args.target, params, args.authorized)
        creds = {"user_a_id": args.user_a_id, "user_a_pw": args.user_a_pw,
                 "user_b_id": args.user_b_id, "user_b_pw": args.user_b_pw,
                 "token_a": args.token_a, "token_b": args.token_b,
                 "resource_id": args.resource_id}
        # N2: 한쪽만 지정된 계정(id 또는 pw) 경고 — audit 레이어가 조용히 drop하지 않도록
        for _who in ("a", "b"):
            _uid = getattr(args, f"user_{_who}_id")
            _upw = getattr(args, f"user_{_who}_pw")
            if bool(_uid) != bool(_upw) and not args.json:
                print(f"[!] --user-{_who}-id/--user-{_who}-pw는 함께 지정해야 합니다 (한쪽만 전달 — 무시됨)")
        report["phases"]["access_dynamic"] = run_access_dynamic(
            args.target, report["phases"]["static"], creds, args.authorized)
        report["phases"]["auth_dynamic"] = run_auth_dynamic(
            args.target,
            {"user_a_id": args.user_a_id, "user_a_pw": args.user_a_pw,
             "token_a": args.token_a},
            args.probe, args.authorized)
        report["phases"]["ssrf_dynamic"] = run_ssrf_dynamic(
            args.target,
            {"user_a_id": args.user_a_id, "user_a_pw": args.user_a_pw,
             "token_a": args.token_a},
            args.redirect_target, args.ssrf_target, args.authorized)
        report["phases"]["pathupload_dynamic"] = run_pathupload_dynamic(
            args.target,
            {"user_a_id": args.user_a_id, "user_a_pw": args.user_a_pw,
             "token_a": args.token_a},
            args.traversal_target, args.upload_target, args.upload_field,
            args.retrieve_base, args.allow_destructive, args.authorized)
    else:
        report["phases"]["dynamic"] = {"skipped": "대상 URL(--target) 미지정 — 정적만 수행"}
        report["phases"]["access_dynamic"] = {"skipped": "대상 URL 미지정"}
        report["phases"]["auth_dynamic"] = {"skipped": "대상 URL 미지정"}
        report["phases"]["ssrf_dynamic"] = {"skipped": "대상 URL 미지정"}
        report["phases"]["pathupload_dynamic"] = {"skipped": "대상 URL 미지정"}

    report["next"] = ("Claude Code에서 auditing-web-application-security 스킬로 "
                      "오탐 제거·컨텍스트 검증·4요소 통합 리포트를 완성하세요.")

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return

    # 사람이 읽는 요약
    print(f"━━━ SQIsoft 통합 보안 점검 ━━━")
    print(f"소스: {args.source}")
    print(f"대상 URL: {args.target or '(없음 — 정적만)'}\n")

    st = report["phases"]["static"]
    if isinstance(st, dict) and st.get("by_skill"):
        print(f"[정적] 감지 스택: {', '.join(st.get('detected_stacks', [])) or '?'}")
        print(f"{'취약점 클래스':<24}{'후보':>6}")
        print("─" * 32)
        for r in st["by_skill"]:
            cnt = "ERR" if r.get("candidate_count") is None else r["candidate_count"]
            print(f"{r['label']:<24}{str(cnt):>6}")
        print("─" * 32)
        print(f"{'합계':<24}{st.get('total_candidates', 0):>6}\n")
        if isinstance(st, dict) and st.get("warnings"):
            print("[!] 정적 폴백 경고")
            for w in st["warnings"]:
                print(f"  - {w}")
            print()
    else:
        print(f"[정적] 실패: {st}\n")

    dyn = report["phases"]["dynamic"]
    if isinstance(dyn, list):
        print("[동적] 실제 공격 발사 결과")
        for d in dyn:
            print(render_dynamic_line(d))
    else:
        print(f"[동적] {dyn.get('skipped','')}")

    acc = report["phases"].get("access_dynamic", {})
    if acc.get("blocked") == "scope_guard":  # rc로 안 뭉개지게 최상단(AC-4)
        print(f"[접근통제] 차단됨(scope_guard) — {acc.get('detail') or 'scope 범위 밖'}")
    elif acc.get("confidence") == "login-failed":  # '미발견'과 구분
        print(f"[접근통제] 동적 미확정(로그인 실패) — {acc.get('detail')}")
    elif acc.get("confidence") == "static-only":
        print(f"[접근통제] 정적 추정(동적 미확정) — 후보 {acc.get('candidate_count')}건. "
              f"테스트 계정 제공 시 동적 확정")
    elif acc.get("confidence") == "dynamic":
        res = acc.get("result", {})
        fcount = len(res.get("findings", [])) if isinstance(res, dict) else 0
        print(f"[접근통제] 동적 확정 발사 완료 — findings {fcount}건")
    elif acc.get("error"):
        print(f"[접근통제] 오류: {acc['error']}")
    elif acc.get("skipped"):
        print(f"[접근통제] {acc['skipped']}")

    au = report["phases"].get("auth_dynamic", {})
    if au.get("blocked") == "scope_guard":  # rc로 안 뭉개지게 최상단(AC-5)
        print(f"[인증] 차단됨(scope_guard) — {au.get('detail') or 'scope 범위 밖'}")
    elif au.get("confidence") == "login-failed":  # '미발견'과 구분(AC-4)
        print(f"[인증] 동적 미확정(로그인 실패) — {au.get('detail')}")
    elif au.get("confidence") == "static-only":  # 과대표기 방지(AC-2)
        print(f"[인증] 정적 추정(동적 미확정) — {au.get('note')}")
    elif au.get("confidence") in ("partial", "dynamic"):
        label = "부분 발사(쿠키만)" if au["confidence"] == "partial" else "동적 확정 발사"
        print(f"[인증] {label}")
        for f in au.get("result", {}).get("findings", []):  # finding별 취약/방어(FR-4)
            # 우선순위 skipped > error > vulnerable. error finding(발사 예외 격리)을
            # '방어'로 오표기하면 크래시 은폐의 finding판(P0 조용한 실패)이 되므로 정직 표기한다.
            if f.get("skipped"):
                print(f"    - [{f.get('kind')}] 미발사({f.get('skipped')})")
            elif f.get("error"):
                print(f"    - [{f.get('kind')}] ⚠ 오류: {f.get('error')}")
            else:
                print(f"    - [{f.get('kind')}] {'🔴 취약' if f.get('vulnerable') else '방어'}")
                # jwt-tamper 4변형(alg_none/sig_strip/payload_role/exp_past) variant별 세분 노출(FR-4)
                if f.get("kind") == "jwt-tamper" and isinstance(f.get("findings"), list):
                    for v in f["findings"]:
                        if not isinstance(v, dict):
                            continue
                        if v.get("error"):  # variant 발사 예외도 '방어'로 은폐 금지
                            print(f"        · {v.get('variant')}: ⚠ 오류: {v.get('error')}")
                            continue
                        mark = "🔴 취약" if v.get("vulnerable") else "방어"
                        print(f"        · {v.get('variant')}(HTTP {v.get('status')}): {mark}")
    elif au.get("error"):
        print(f"[인증] 오류: {au['error']}")
    elif au.get("skipped"):
        print(f"[인증] {au['skipped']}")

    ss = report["phases"].get("ssrf_dynamic", {})
    if ss.get("blocked") == "scope_guard":  # rc로 안 뭉개지게 최상단(AC-4)
        print(f"[SSRF/오픈리다이렉트] 차단됨(scope_guard) — {ss.get('detail') or 'scope 범위 밖'}")
    elif ss.get("confidence") == "login-failed":  # '미발견'과 구분
        print(f"[SSRF/오픈리다이렉트] 동적 미확정(로그인 실패) — {ss.get('detail')}")
    elif ss.get("confidence") == "static-only":  # 과대표기 방지(AC-2/11)
        print(f"[SSRF/오픈리다이렉트] 정적 추정(동적 미확정) — {ss.get('note')}")
    elif ss.get("confidence") == "dynamic":
        print(f"[SSRF/오픈리다이렉트] 동적 확정 발사")
        res = ss.get("result", {})
        if not isinstance(res, dict):  # 자식이 dict 아닌 JSON 반환 시 방어
            res = {}
        tg = ss.get("targets", {})
        kinds_seen = set()
        for f in res.get("findings", []):
            # 우선순위 skipped > error > (ssrf 콜백판정) > 미도달 > vulnerable/방어.
            # 렌더 판정은 _ssrf_finding_line 헬퍼로 위임(유닛 테스트 가능·조용한 실패 금지).
            if not isinstance(f, dict):
                continue
            kinds_seen.add(f.get("kind"))
            print(_ssrf_finding_line(f))
        # 종류별 표적 미지정 개별 표기(CONSIDER 부분표적)
        if tg.get("redirect") is False and "open-redirect" not in kinds_seen:
            print("    - [open-redirect] 표적 미지정(--redirect-target)")
        if tg.get("ssrf") is False and "ssrf" not in kinds_seen:
            print("    - [ssrf] 표적 미지정(--ssrf-target)")
    elif ss.get("error"):
        print(f"[SSRF/오픈리다이렉트] 오류: {ss['error']}")
    elif ss.get("skipped"):
        print(f"[SSRF/오픈리다이렉트] {ss['skipped']}")

    pu = report["phases"].get("pathupload_dynamic", {})
    for line in render_pathupload(pu):
        print(line)

    print(f"\n※ {report['next']}")


if __name__ == "__main__":
    main()
