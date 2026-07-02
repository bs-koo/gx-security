import importlib.util
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_MOD = os.path.join(_ROOT, "skills", "auditing-web-application-security",
                    "scripts", "audit.py")
_spec = importlib.util.spec_from_file_location("audit", _MOD)
audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(audit)


class TestAccessDynamic(unittest.TestCase):
    def test_extract_access_candidates(self):
        static = {"by_skill": [
            {"skill": "detecting-csrf-vulnerabilities", "candidates": [1]},
            {"skill": "detecting-broken-access-control", "candidates": [{"rule_id": "x"}]},
        ]}
        self.assertEqual(audit._extract_access_candidates(static), [{"rule_id": "x"}])

    def test_no_creds_is_static_only(self):
        # 계정/토큰 미제공 → 동적 미확정(정적 추정)으로 표기, 발사하지 않음 (D/E)
        static = {"by_skill": [
            {"skill": "detecting-broken-access-control",
             "candidates": [{"rule_id": "spring-admin-no-preauthorize"}]}]}
        out = audit.run_access_dynamic("http://localhost:7171", static, {}, False)
        self.assertEqual(out["confidence"], "static-only")
        self.assertEqual(out["candidate_count"], 1)

    def test_no_candidates_skipped(self):
        static = {"by_skill": [{"skill": "detecting-csrf-vulnerabilities", "candidates": []}]}
        out = audit.run_access_dynamic("http://localhost:7171", static, {"token_a": "X"}, False)
        self.assertIn("skipped", out)

    def test_partial_static_error_short_circuits(self):
        # N1: 정적 부분 실패(error 동반)면 동적 연계 보류
        static = {"error": "rc=1: scan failed", "by_skill": [
            {"skill": "detecting-broken-access-control", "candidates": [{"rule_id": "x"}]}]}
        out = audit.run_access_dynamic("http://localhost:7171", static, {"token_a": "X"}, False)
        self.assertIn("skipped", out)
        self.assertIn("static_error", out)

    def test_access_scope_blocked(self):
        # §4 잠복결함 회귀: 계정+후보가 있어 발사 경로로 진입하되, 자식이 scope_guard
        # 차단(error=scope_blocked, findings 없음, rc=1)으로 종료하면 이를 'dynamic'으로
        # 오표기하지 말고 blocked=="scope_guard"로 정직 표기해야 한다(사용자2 수정). mock 재현.
        static = {"by_skill": [
            {"skill": "detecting-broken-access-control",
             "candidates": [{"rule_id": "x"}]}]}

        class _Proc:
            stdout = '{"error":"scope_blocked","detail":"운영 차단"}'
            stderr = ""
            returncode = 1
        with patch.object(audit.subprocess, "run", return_value=_Proc()):
            out = audit.run_access_dynamic(
                "http://127.0.0.1:1", static, {"token_a": "X"}, True)
        self.assertEqual(out.get("blocked"), "scope_guard")
        self.assertNotEqual(out.get("confidence"), "dynamic")  # dynamic 오표기 방지(핵심)

    def test_access_empty_findings_not_dynamic(self):
        # HIGH 회귀: 발사 경로(계정+후보)에서 자식이 findings 빈 배열(rc0)을 반환하면
        # fired가 하나도 없으므로 static-only로 유지해야 한다(dynamic 과대표기 금지).
        # 빈 findings(falsy)를 'dynamic'으로 오표기하던 §4 fired 판정 미통일 결함 재발 방지.
        static = {"by_skill": [
            {"skill": "detecting-broken-access-control",
             "candidates": [{"rule_id": "x"}]}]}

        class _Proc:
            stdout = '{"findings":[]}'
            stderr = ""
            returncode = 0
        with patch.object(audit.subprocess, "run", return_value=_Proc()):
            out = audit.run_access_dynamic(
                "http://127.0.0.1:1", static, {"token_a": "X"}, True)
        self.assertEqual(out["confidence"], "static-only")
        self.assertNotEqual(out.get("confidence"), "dynamic")  # 과대표기 방지(핵심)


class TestAuthDynamic(unittest.TestCase):
    """FR-5/AC-2·4·10 — run_auth_dynamic의 조기반환·과대표기 방지 경로만 유닛 검증.

    TestAccessDynamic 구조 준용: 실제 발사 경로는 네트워크 미접속(계정 없음 →
    발사 안 함 / token-a·probe 없음 → findings 전부 skip / 127.0.0.1:1 로그인
    접속 거부)으로 빠르게 종료되는 케이스만 다룬다. creds dict 키는 audit.py
    run_auth_dynamic 실제 코드(user_a_id/user_a_pw/token_a)와 일치.
    """

    def test_no_creds_static_only(self):
        # 계정/토큰 전무 → probe가 있어도 발사하지 않고 static-only 표기(AC-2). 네트워크 미접속.
        out = audit.run_auth_dynamic("http://localhost:7171", {}, "/api/x", False)
        self.assertEqual(out["confidence"], "static-only")

    def test_token_no_probe_no_fire_static_only(self):
        # token-a라 쿠키 검사 skip(set_cookie="") + probe 없어 JWT/재사용 skip →
        # 실제 발사 0건 → static-only로 과대표기 방지(design-critic MUST 2, AC-10).
        # attack_auth를 subprocess로 실행하되 findings 전부 skip이라 실제 네트워크 요청 없음.
        out = audit.run_auth_dynamic(
            "http://127.0.0.1:1", {"token_a": "a.b.c"}, None, True)
        self.assertEqual(out["confidence"], "static-only")

    def test_login_failed_distinguished(self):
        # 계정 제공 → 로그인 시도하나 127.0.0.1:1 접속 거부 → login-failed로 종료.
        # '취약점 미발견(static-only)'과 구분됨(AC-4).
        out = audit.run_auth_dynamic(
            "http://127.0.0.1:1", {"user_a_id": "x", "user_a_pw": "y"}, "/api/x", True)
        self.assertEqual(out["confidence"], "login-failed")

    def test_missing_script_skipped(self):
        # _AUTH_SCRIPT 부재 재현 → 발사 전 조기반환으로 "skipped" 표기
        with patch.object(audit.os.path, "exists", return_value=False):
            out = audit.run_auth_dynamic(
                "http://127.0.0.1:1", {"token_a": "a.b.c"}, "/api/x", True)
        self.assertIn("skipped", out)

    def test_rc_gate_error_not_static_only(self):
        # 크래시 은폐 방지(ZT CRITICAL): 계정 있는 경로(token_a)로 발사했으나 자식이
        # stdout 빈 채 rc=1로 비정상 종료하면 static-only로 오분류하지 말고 error로
        # 정직 표기해야 한다(P0 조용한 실패 금지). subprocess.run을 mock해 재현.
        class _Proc:
            stdout, stderr, returncode = "", "", 1
        with patch.object(audit.subprocess, "run", return_value=_Proc()):
            out = audit.run_auth_dynamic(
                "http://127.0.0.1:1", {"token_a": "a.b.c"}, "/api/x", True)
        self.assertIn("error", out)
        self.assertNotEqual(out.get("confidence"), "static-only")
        self.assertEqual(out.get("returncode"), 1)


class TestDynamicParamMissing(unittest.TestCase):
    """FR2-4/AC-10 — --param 미지정 시 미발사 사유 표기 + attack 스크립트 rc=2 회귀.

    params=None이면 attack 스크립트가 argparse 단계(--param required=True)에서 rc=2로
    즉시 종료 → 대상 URL(127.0.0.1:1)에 접속하기 전에 끝나므로 네트워크 미접속·고속.
    """

    def test_run_dynamic_param_missing_reason(self):
        # A: run_dynamic이 DYNAMIC의 각 스크립트를 실제 호출 → param None 항목에
        #    param_missing 플래그와 "파라미터 미지정" 사유가 실린다
        results = audit.run_dynamic("http://127.0.0.1:1", None, False)
        self.assertTrue(results)  # DYNAMIC 스크립트가 최소 1건 실행됨
        for d in results:
            self.assertIs(d.get("param_missing"), True)
            self.assertIn("파라미터 미지정", d.get("reason", ""))

    def test_attack_sqli_rc2_without_param(self):
        # B: --param 누락 시 argparse가 rc=2로 종료됨을 직접 재현(AC-10)
        out = subprocess.run(
            [sys.executable, audit.DYNAMIC["sql-injection"], "http://127.0.0.1:1"],
            capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertEqual(out.returncode, 2)

    def test_attack_xss_rc2_without_param(self):
        # B: attack_xss.py 동일 재현
        out = subprocess.run(
            [sys.executable, audit.DYNAMIC["xss"], "http://127.0.0.1:1"],
            capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertEqual(out.returncode, 2)


class TestRenderDynamicLine(unittest.TestCase):
    """§9-C 분기순서 회귀 — render_dynamic_line의 위→아래 우선순위 고정.

    핵심 불변식: scope_blocked(3)·blocked_or_no_json(4)이 rc≠0(5)보다 먼저
    평가돼야 scope 차단/차단 raw가 '발사 실패 rc'로 뭉개지지 않는다.
    """

    def test_scope_blocked_precedes_rc(self):
        # scope 차단은 rc=1을 동반하지만 branch3이 branch5보다 먼저 매치돼야 한다
        d = {"vuln": "sql-injection", "param": "id",
             "result": {"error": "scope_blocked", "detail": "운영 차단"},
             "returncode": 1}
        line = audit.render_dynamic_line(d)
        self.assertIn("차단됨", line)
        self.assertIn("운영 차단", line)
        self.assertNotIn("발사 실패 rc", line)  # rc 분기로 뭉개지지 않음(핵심)

    def test_scope_blocked_detail_fallback(self):
        # detail 없으면 기본 사유 문구
        d = {"vuln": "xss", "param": "q",
             "result": {"error": "scope_blocked"}, "returncode": 1}
        line = audit.render_dynamic_line(d)
        self.assertIn("차단됨", line)
        self.assertIn("scope 범위 밖", line)

    def test_blocked_or_no_json_precedes_rc(self):
        # 차단/비-JSON raw는 rc≠0이어도 발사 실패로 표기하지 않고 raw를 노출
        d = {"vuln": "sql-injection", "param": "id",
             "result": {"blocked_or_no_json": True, "raw": "안전게이트 차단"},
             "returncode": 1}
        line = audit.render_dynamic_line(d)
        self.assertIn("안전게이트 차단", line)
        self.assertNotIn("발사 실패 rc", line)

    def test_rc_nonzero_non_scope(self):
        # scope도 blocked도 아닌 순수 rc≠0 → 발사 실패 rc 표기
        d = {"vuln": "sql-injection", "param": "id", "result": {}, "returncode": 2}
        line = audit.render_dynamic_line(d)
        self.assertIn("발사 실패 rc=2", line)

    def test_param_missing(self):
        d = {"vuln": "xss", "param": None, "param_missing": True,
             "reason": "파라미터 미지정 — 미발사", "result": {}, "returncode": 2}
        line = audit.render_dynamic_line(d)
        self.assertIn("미발사", line)

    def test_exploited(self):
        d = {"vuln": "sql-injection", "param": "id",
             "result": {"exploited": True}, "returncode": 0}
        line = audit.render_dynamic_line(d)
        self.assertIn("악용 확정", line)

    def test_not_exploited(self):
        d = {"vuln": "sql-injection", "param": "id",
             "result": {"exploited": False}, "returncode": 0}
        line = audit.render_dynamic_line(d)
        self.assertIn("미확인", line)

    def test_error_precedes_all(self):
        d = {"vuln": "sql-injection", "param": "id", "error": "timeout"}
        line = audit.render_dynamic_line(d)
        self.assertIn("오류", line)
        self.assertIn("timeout", line)

    def test_result_none_no_crash(self):
        # 자식이 result=None(JSON null 등) 반환해도 예외 없이 문자열 반환(비-dict result 방어, PR 리뷰)
        line = audit.render_dynamic_line({"vuln": "x", "result": None})
        self.assertIsInstance(line, str)

    def test_result_list_no_crash(self):
        # 자식이 result=[1,2](JSON list) 반환해도 예외 없이 문자열 반환(비-dict result 방어, PR 리뷰)
        line = audit.render_dynamic_line({"vuln": "x", "result": [1, 2]})
        self.assertIsInstance(line, str)


class TestSsrfDynamic(unittest.TestCase):
    """§5/AC-2·4·11 — run_ssrf_dynamic의 게이트·조기반환·과대표기 방지 경로 유닛 검증.

    TestAuthDynamic 구조 준용: 표적/계정 게이트는 네트워크 미접속으로 즉시 종료되고,
    발사 경로(login-failed)는 127.0.0.1:1 접속 거부로 빠르게 끝난다. scope_blocked·
    rc게이트는 subprocess.run을 mock해 재현한다. creds dict 키는 audit.py 실제 코드
    (user_a_id/user_a_pw/token_a)와 일치.
    """

    def test_no_target_static_only(self):
        # 표적 미지정(계정은 있음) → 발사하지 않고 static-only '표적 미지정'(AC-2). 네트워크 미접속.
        out = audit.run_ssrf_dynamic(
            "http://localhost:7171", {"token_a": "t"}, None, None, True)
        self.assertEqual(out["confidence"], "static-only")
        self.assertIn("표적 미지정", out["note"])

    def test_no_creds_static_only(self):
        # 표적은 있으나 계정/토큰 미지정 → static-only(AC-11). note에 '계정' 사유.
        out = audit.run_ssrf_dynamic(
            "http://localhost:7171", {}, "/go?u=", None, True)
        self.assertEqual(out["confidence"], "static-only")
        self.assertIn("계정", out["note"])

    def test_no_target_no_creds_target_first(self):
        # 표적·계정 둘 다 없음 → '표적 우선' 판정으로 '표적 미지정' 사유가 나와야 한다(PRD1).
        out = audit.run_ssrf_dynamic(
            "http://localhost:7171", {}, None, None, True)
        self.assertEqual(out["confidence"], "static-only")
        self.assertIn("표적 미지정", out["note"])  # 계정 아닌 표적 사유 우선

    def test_login_failed_distinguished(self):
        # 표적+계정 제공 → 발사하나 127.0.0.1:1 로그인 접속 거부 → login-failed로 종료.
        # '취약점 미발견(static-only)'과 구분된다.
        out = audit.run_ssrf_dynamic(
            "http://127.0.0.1:1", {"user_a_id": "x", "user_a_pw": "y"},
            "/go?u=", None, True)
        self.assertEqual(out["confidence"], "login-failed")

    def test_scope_blocked(self):
        # scope_guard 차단(error=scope_blocked, rc=1)은 rc게이트로 뭉개지 말고
        # 최상단에서 blocked=="scope_guard"로 표기해야 한다(AC-4). mock 재현.
        class _Proc:
            stdout = '{"error":"scope_blocked","detail":"운영 차단"}'
            stderr = ""
            returncode = 1
        with patch.object(audit.subprocess, "run", return_value=_Proc()):
            out = audit.run_ssrf_dynamic(
                "http://127.0.0.1:1", {"token_a": "a.b.c"}, "/go?u=", None, True)
        self.assertEqual(out.get("blocked"), "scope_guard")
        self.assertEqual(out.get("detail"), "운영 차단")

    def test_rc_gate_error_not_static_only(self):
        # 크래시 은폐 방지: 계정+표적으로 발사했으나 자식이 stdout 빈 채 rc=1로 비정상
        # 종료하면 static-only로 오분류 말고 error로 정직 표기(P0 조용한 실패 금지). mock 재현.
        class _Proc:
            stdout, stderr, returncode = "", "", 1
        with patch.object(audit.subprocess, "run", return_value=_Proc()):
            out = audit.run_ssrf_dynamic(
                "http://127.0.0.1:1", {"token_a": "a.b.c"}, "/go?u=", None, True)
        self.assertIn("error", out)
        self.assertNotEqual(out.get("confidence"), "static-only")
        self.assertEqual(out.get("returncode"), 1)

    def test_missing_script_skipped(self):
        # _SSRF_SCRIPT 부재 재현 → 발사 전 조기반환으로 "skipped" 표기
        with patch.object(audit.os.path, "exists", return_value=False):
            out = audit.run_ssrf_dynamic(
                "http://127.0.0.1:1", {"token_a": "a.b.c"}, "/go?u=", None, True)
        self.assertIn("skipped", out)

    def test_no_canary_options_in_cmd(self):
        # AC-9 회귀: 발사 경로(계정+표적)에서 audit이 attack_ssrf로 넘기는 cmd에
        # --canary-host/--canary-port가 절대 없어야 한다. audit이 canary 옵션을 노출하면
        # attack_ssrf 기본값(127.0.0.1/0)이 덮여 원격 콜백 차단(AC-9/PRD3)이 깨지므로,
        # 향후 실수로 canary 옵션을 subprocess cmd에 실어보내지 않게 고정한다.
        class _Proc:
            stdout = '{"findings":[]}'
            stderr = ""
            returncode = 0
        with patch.object(audit.subprocess, "run", return_value=_Proc()) as mock_run:
            audit.run_ssrf_dynamic(
                "http://127.0.0.1:1", {"token_a": "a.b.c"},
                "/go?u=", "/api/fetch?url=", True)
        mock_run.assert_called_once()  # 발사 경로 진입 확인(게이트 통과)
        cmd = mock_run.call_args[0][0]
        self.assertNotIn("--canary-host", cmd)
        self.assertNotIn("--canary-port", cmd)


class TestSsrfUnreached(unittest.TestCase):
    """§3 MUST 회귀 — _ssrf_unreached가 '프로브 미도달'을 '방어'로 오표기하지 않는다.

    미도달(ssrf status None·미취약 / open-redirect 전변형 오류·status None)은 True(미확정),
    정상 응답이 하나라도 있으면 False(진짜 방어/취약 정상 판정)를 반환해야 한다(design-critic).
    """

    def test_unreached_ssrf_not_defense(self):
        # 요청이 대상에 닿지 못함(status None) + 미취약 → '방어' 아닌 '미도달'(True)
        self.assertTrue(audit._ssrf_unreached(
            {"kind": "ssrf", "status": None, "vulnerable": False}))
        # 정상 응답(status 200) → '프로브 도달'이므로 _ssrf_unreached=False.
        # (SSRF 최종판정은 _ssrf_finding_line이 콜백으로 결정 — status 200+콜백미수신은 '미확정'이지 '방어' 아님. 코드리뷰 #12)
        self.assertFalse(audit._ssrf_unreached(
            {"kind": "ssrf", "status": 200, "vulnerable": False}))

    def test_unreached_open_redirect_all_error(self):
        # 전 변형이 오류/status None → 미도달(True)
        self.assertTrue(audit._ssrf_unreached({
            "kind": "open-redirect",
            "findings": [{"variant": "a", "error": "conn"},
                         {"variant": "b", "status": None}]}))
        # 한 변형이라도 정상 응답(status 302) → 미도달 아님(False)
        self.assertFalse(audit._ssrf_unreached({
            "kind": "open-redirect",
            "findings": [{"variant": "a", "error": "conn"},
                         {"variant": "b", "status": 302}]}))


class TestPathuploadDynamic(unittest.TestCase):
    """AC-5~9 — run_pathupload_dynamic의 게이트·조기반환·과대표기 방지 경로 유닛 검증.

    TestSsrfDynamic 구조 준용: 표적/계정/파괴적 게이트는 네트워크 미접속으로 즉시 종료,
    발사 경로(login-failed)는 127.0.0.1:1 접속 거부로 빠르게 끝난다. scope_blocked·
    rc게이트는 subprocess.run을 mock해 재현한다. creds dict 키는 audit.py 실제 코드
    (user_a_id/user_a_pw/token_a)와 일치.
    """

    def test_no_target_static_only(self):
        # 표적 미지정(계정은 있음) → 발사하지 않고 static-only '표적 미지정'(AC-6). 네트워크 미접속.
        out = audit.run_pathupload_dynamic(
            "http://localhost:7171", {"token_a": "t"}, None, None, "file", None, False, True)
        self.assertEqual(out["confidence"], "static-only")
        self.assertIn("표적 미지정", out["note"])

    def test_no_creds_static_only(self):
        # 표적은 있으나 계정/토큰 미지정 → static-only(AC-7). note에 '계정' 사유.
        out = audit.run_pathupload_dynamic(
            "http://localhost:7171", {}, "/download?filePath=", None, "file", None, False, True)
        self.assertEqual(out["confidence"], "static-only")
        self.assertIn("계정", out["note"])

    def test_no_target_no_creds_target_first(self):
        # 표적·계정 둘 다 없음 → '표적 우선' 판정으로 '표적 미지정' 사유가 나와야 한다(AC-6).
        out = audit.run_pathupload_dynamic(
            "http://localhost:7171", {}, None, None, "file", None, False, True)
        self.assertEqual(out["confidence"], "static-only")
        self.assertIn("표적 미지정", out["note"])  # 계정 아닌 표적 사유 우선

    def test_upload_only_no_destructive_skipped(self):
        # AC-8/BR-3: upload 표적만 + --allow-destructive 미지정 → subprocess 미호출, static-only.
        with patch.object(audit.subprocess, "run") as mock_run:
            out = audit.run_pathupload_dynamic(
                "http://localhost:7171", {"token_a": "t"}, None, "/api/upload",
                "file", None, False, True)
        mock_run.assert_not_called()  # 파괴적 게이트로 발사 자체를 안 함(방어심층)
        self.assertEqual(out["confidence"], "static-only")

    def test_upload_gated_cmd_excludes_flag(self):
        # AC-8: 경로조작+업로드 표적이나 --allow-destructive 미지정이면 cmd에서 업로드 인자를
        # 배제하고 경로조작만 발사한다(자식 게이트와 독립 이중방어).
        class _Proc:
            stdout = ('{"findings":[{"kind":"path-traversal","vulnerable":false,'
                      '"status":200}]}')
            stderr = ""
            returncode = 0
        with patch.object(audit.subprocess, "run", return_value=_Proc()) as mock_run:
            audit.run_pathupload_dynamic(
                "http://127.0.0.1:1", {"token_a": "t"}, "/download?filePath=",
                "/api/upload", "file", None, False, True)  # allow_destructive=False
        cmd = mock_run.call_args[0][0]
        self.assertIn("--traversal-target", cmd)
        self.assertNotIn("--upload-target", cmd)
        self.assertNotIn("--allow-destructive", cmd)

    def test_dynamic_fires(self):
        # AC-5: 표적+계정 → attack_pathupload를 subprocess로 호출해 confidence=dynamic 반환.
        class _Proc:
            stdout = ('{"findings":[{"kind":"path-traversal","vulnerable":true,'
                      '"status":200,"findings":[{"variant":"plain_d3","leaked":true}]}]}')
            stderr = ""
            returncode = 0
        with patch.object(audit.subprocess, "run", return_value=_Proc()) as mock_run:
            out = audit.run_pathupload_dynamic(
                "http://127.0.0.1:1", {"token_a": "t"}, "/download?filePath=",
                None, "file", None, False, True)
        self.assertEqual(out["confidence"], "dynamic")
        cmd = mock_run.call_args[0][0]
        self.assertIn("--traversal-target", cmd)

    def test_scope_blocked(self):
        # AC-9: scope_guard 차단(error=scope_blocked, rc=1)은 rc게이트로 뭉개지 말고
        # 최상단에서 blocked=="scope_guard"로 표기해야 한다. mock 재현.
        class _Proc:
            stdout = '{"error":"scope_blocked","detail":"운영 차단"}'
            stderr = ""
            returncode = 1
        with patch.object(audit.subprocess, "run", return_value=_Proc()):
            out = audit.run_pathupload_dynamic(
                "http://127.0.0.1:1", {"token_a": "t"}, "/download?filePath=",
                None, "file", None, False, True)
        self.assertEqual(out.get("blocked"), "scope_guard")
        self.assertEqual(out.get("detail"), "운영 차단")

    def test_login_failed_distinguished(self):
        # AC-9: 표적+계정 제공 → 발사하나 127.0.0.1:1 로그인 접속 거부 → login-failed로 종료.
        # '취약점 미발견(static-only)'과 구분된다.
        out = audit.run_pathupload_dynamic(
            "http://127.0.0.1:1", {"user_a_id": "x", "user_a_pw": "y"},
            "/download?filePath=", None, "file", None, False, True)
        self.assertEqual(out["confidence"], "login-failed")

    def test_rc_gate_error_not_static_only(self):
        # AC-9: 계정+표적으로 발사했으나 자식이 stdout 빈 채 rc=1로 비정상 종료하면
        # static-only로 오분류 말고 error로 정직 표기(P0 조용한 실패 금지). mock 재현.
        class _Proc:
            stdout, stderr, returncode = "", "", 1
        with patch.object(audit.subprocess, "run", return_value=_Proc()):
            out = audit.run_pathupload_dynamic(
                "http://127.0.0.1:1", {"token_a": "t"}, "/download?filePath=",
                None, "file", None, False, True)
        self.assertIn("error", out)
        self.assertNotEqual(out.get("confidence"), "static-only")
        self.assertEqual(out.get("returncode"), 1)

    def test_missing_script_skipped(self):
        # _PATHUP_SCRIPT 부재 재현 → 발사 전 조기반환으로 "skipped" 표기
        with patch.object(audit.os.path, "exists", return_value=False):
            out = audit.run_pathupload_dynamic(
                "http://127.0.0.1:1", {"token_a": "t"}, "/download?filePath=",
                None, "file", None, False, True)
        self.assertIn("skipped", out)

    def test_upload_destructive_cmd_includes_flag(self):
        # BR-3 이중 게이트 positive: 업로드 표적+계정+--allow-destructive면 자식 cmd에
        # --upload-target과 --allow-destructive가 '모두' 실려 실제 발사된다(게이트 개방 방향;
        # test_upload_gated_cmd_excludes_flag의 대칭 검증).
        class _Proc:
            stdout = ('{"findings":[{"kind":"file-upload","vulnerable":true,'
                      '"status":200,"accepted":true}]}')
            stderr = ""
            returncode = 0
        with patch.object(audit.subprocess, "run", return_value=_Proc()) as mock_run:
            audit.run_pathupload_dynamic(
                "http://127.0.0.1:1", {"token_a": "t"}, None,
                "/api/files", "file", None, True, True)  # allow_destructive=True
        cmd = mock_run.call_args[0][0]
        self.assertIn("--upload-target", cmd)
        self.assertIn("--allow-destructive", cmd)


class TestPathuploadRender(unittest.TestCase):
    """AC-10~12 + MUST-ADDRESS 3건 — render_pathupload가 미도달≠방어, leftover accepted
    게이팅, 미지정 표적 '미검사' 명시를 지켜 '방어' 오표기를 내지 않는다(design-critic).
    """

    def _dynamic(self, findings, targets=None, upload_gated=False):
        return {"confidence": "dynamic", "result": {"findings": findings},
                "targets": targets if targets is not None else {"traversal": True, "upload": True},
                "upload_gated": upload_gated}

    def test_render_traversal_vulnerable(self):
        # AC-10: 시그니처 검출 → 🔴 취약
        text = "\n".join(audit.render_pathupload(
            self._dynamic([{"kind": "path-traversal", "vulnerable": True, "status": 200}])))
        self.assertIn("🔴", text)
        self.assertIn("path-traversal", text)

    def test_render_traversal_404_unreached_not_defended(self):
        # MUST#1: status=404·미취약은 '방어'가 아니라 '미확정/미도달'이어야 한다.
        # 엔드포인트 오지정으로 전량 404가 와도 '방어'로 뭉개지 않는다(QE-1).
        text = "\n".join(audit.render_pathupload(
            self._dynamic([{"kind": "path-traversal", "vulnerable": False, "status": 404}])))
        self.assertIn("미확정", text)
        self.assertNotIn("방어", text)

    def test_render_traversal_200_defended(self):
        # MUST#1: status=200·미취약은 진짜 방어(정상 응답·시그니처 없음).
        text = "\n".join(audit.render_pathupload(
            self._dynamic([{"kind": "path-traversal", "vulnerable": False, "status": 200}])))
        self.assertIn("방어", text)
        self.assertNotIn("🔴", text)

    def test_render_upload_high_retrievable(self):
        # AC-11: 회수 성공 → 웹루트 저장 가중(High)
        text = "\n".join(audit.render_pathupload(self._dynamic(
            [{"kind": "file-upload", "vulnerable": True, "accepted": True,
              "retrievable": True, "leftover": "gxmarker_x.jsp", "status": 200}])))
        self.assertIn("🔴", text)
        self.assertIn("High", text)

    def test_render_upload_medium_accepted(self):
        # AC-11: 2xx 수용·회수 실패 → 위험확장자 수용(Medium)
        text = "\n".join(audit.render_pathupload(self._dynamic(
            [{"kind": "file-upload", "vulnerable": True, "accepted": True,
              "retrievable": False, "leftover": "gxmarker_x.jsp", "status": 200}])))
        self.assertIn("Medium", text)
        self.assertNotIn("High", text)

    def test_leftover_notice_only_when_accepted(self):
        # AC-12: accepted된 업로드 leftover → '정리 필요' 안내 노출
        text = "\n".join(audit.render_pathupload(self._dynamic(
            [{"kind": "file-upload", "vulnerable": True, "accepted": True,
              "retrievable": False, "leftover": "gxmarker_x.jsp", "status": 200}])))
        self.assertIn("정리 필요", text)
        self.assertIn("gxmarker_x.jsp", text)

    def test_no_leftover_notice_when_rejected(self):
        # MUST#2: accepted=False인데 leftover 필드가 남아있어도(거부) 정리 안내는 노출 안 함.
        text = "\n".join(audit.render_pathupload(self._dynamic(
            [{"kind": "file-upload", "vulnerable": False, "accepted": False,
              "retrievable": False, "leftover": "gxmarker_x.jsp", "status": 403}])))
        self.assertNotIn("정리 필요", text)

    def test_render_upload_only_marks_traversal_unchecked(self):
        # MUST#3: --upload-target만 지정(targets traversal=False) → 경로조작은 '미검사'로
        # 명시돼 '검사됨·방어' 오추론을 차단한다. 경로조작 finding·방어 표기는 없어야 한다.
        text = "\n".join(audit.render_pathupload(self._dynamic(
            [{"kind": "file-upload", "vulnerable": False, "accepted": False,
              "retrievable": False, "leftover": "gxmarker_x.jsp", "status": 403}],
            targets={"traversal": False, "upload": True})))
        self.assertIn("[경로조작] 표적 미지정", text)
        self.assertNotIn("[path-traversal]", text)  # 경로조작은 발사조차 안 됨(방어 아님)

    def test_render_upload_gated_marks_not_fired(self):
        # MUST#3 변형: 경로조작만 발사되고 업로드는 게이트로 미발사 → '미발사(--allow-destructive 필요)'
        text = "\n".join(audit.render_pathupload(self._dynamic(
            [{"kind": "path-traversal", "vulnerable": False, "status": 200}],
            targets={"traversal": True, "upload": True}, upload_gated=True)))
        self.assertIn("미발사(--allow-destructive 필요)", text)

    def test_render_scope_blocked(self):
        # AC-9 렌더: scope 차단은 최상단에서 '차단됨(scope_guard)'
        text = "\n".join(audit.render_pathupload(
            {"blocked": "scope_guard", "detail": "운영 차단"}))
        self.assertIn("차단됨", text)
        self.assertIn("운영 차단", text)

    def test_render_login_failed(self):
        text = "\n".join(audit.render_pathupload(
            {"confidence": "login-failed", "detail": "conn refused"}))
        self.assertIn("로그인 실패", text)

    def test_render_error_upload_hint_when_upload_target(self):
        # QE-2: rc게이트 error + 업로드 표적 지정 → 마커 잔존 확인 권장 부기
        text = "\n".join(audit.render_pathupload(
            {"error": "경로조작/업로드 발사 중 오류(rc=1)", "returncode": 1,
             "upload_target": True}))
        self.assertIn("오류", text)
        self.assertIn("마커", text)

    def test_render_non_dict_no_crash(self):
        # res가 dict 아님(None/list)이어도 예외 없이 list 반환(비-dict 방어)
        self.assertIsInstance(audit.render_pathupload(None), list)
        self.assertIsInstance(audit.render_pathupload([1, 2]), list)


class TestSsrfFindingLine(unittest.TestCase):
    """코드리뷰 #12 회귀 — SSRF 콜백 미수신을 '방어'로 오표기하지 않는다.

    SSRF는 OOB 콜백 수신만이 취약 확정. status 2xx라도 콜백 미수신이면 '미확정'(원격/비동기면 취약 가능)이며
    절대 '방어'로 찍지 않는다. open-redirect는 인밴드 Location 판정이라 방어/취약을 정상 표기한다.
    """

    def test_ssrf_callback_received_is_vulnerable(self):
        line = audit._ssrf_finding_line({"kind": "ssrf", "status": 200, "vulnerable": True})
        self.assertIn("🔴 취약", line)

    def test_ssrf_status200_no_callback_is_unconfirmed_not_defended(self):
        # 핵심 회귀: 원격 대상은 status 200이라도 loopback canary 콜백 불가 → '미확정'이지 '방어' 아님
        line = audit._ssrf_finding_line({"kind": "ssrf", "status": 200, "vulnerable": False})
        self.assertIn("미확정", line)
        self.assertNotIn("방어", line)

    def test_ssrf_status_none_no_callback_is_unconfirmed(self):
        line = audit._ssrf_finding_line({"kind": "ssrf", "status": None, "vulnerable": False})
        self.assertIn("미확정", line)
        self.assertNotIn("방어", line)

    def test_open_redirect_reached_not_vulnerable_is_defended(self):
        # 오픈리다이렉트는 인밴드 판정 — 정상 응답(302)+미취약이면 '방어'로 확정 가능(SSRF와 대비)
        line = audit._ssrf_finding_line({
            "kind": "open-redirect", "vulnerable": False,
            "findings": [{"variant": "a", "status": 302}]})
        self.assertIn("방어", line)

    def test_open_redirect_all_unreached_is_unconfirmed(self):
        line = audit._ssrf_finding_line({
            "kind": "open-redirect", "vulnerable": False,
            "findings": [{"variant": "a", "error": "conn"}]})
        self.assertIn("미확정", line)

    def test_error_and_skipped_priority(self):
        self.assertIn("오류", audit._ssrf_finding_line({"kind": "ssrf", "error": "boom"}))
        self.assertIn("미발사", audit._ssrf_finding_line({"kind": "ssrf", "skipped": "표적 없음"}))


if __name__ == "__main__":
    unittest.main()
