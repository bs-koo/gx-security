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


if __name__ == "__main__":
    unittest.main()
