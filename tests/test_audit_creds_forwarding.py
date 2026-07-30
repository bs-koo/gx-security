"""audit → 자식 subprocess 자격증명 env 포워딩 회귀 (Task 4).

audit.py가 --creds-stdin/--*-env/--login-profile로 받은 자격증명(user_a_pw/token_a/
user_b_pw/token_b)을 자식 cmd 리스트에 평문으로 싣지 않고 env로 전달하는지 검증한다
(자식 프로세스 목록 노출 제거가 이 task의 핵심 — `ps`/`/proc/pid/cmdline`으로 비밀이
보이면 안 된다). subprocess.run을 mock해 cmd/env 구성만 캡처하고 실발사는 하지 않는다
(기존 test_audit_login_forwarding.py 패턴).

두 층위로 검증한다:
  - TestSecretForwardingDirect: run_*_dynamic 함수를 직접 호출해 secret_env_names
    유무에 따른 cmd/env 구성 자체를 검증(빠르고 결정적).
  - TestMainCredsWiring: audit.py CLI(--creds-stdin/--login-profile/direct)가
    argparse→해석→run_auth_dynamic까지 실제로 배선되는지 종단 검증.
"""
import argparse
import contextlib
import importlib.util
import io
import os
import sys
import unittest
from unittest import mock

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_MOD = os.path.join(_ROOT, "skills", "auditing-web-application-security",
                    "scripts", "audit.py")
_spec = importlib.util.spec_from_file_location("audit_credfwd", _MOD)
audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(audit)


class _Proc:
    stdout = '{"findings":[]}'
    stderr = ""
    returncode = 0


class TestSecretForwardingDirect(unittest.TestCase):
    """run_*_dynamic 자식 cmd/env 구성 — secret_env_names 유무에 따른 평문/env 분기."""

    def test_token_a_env_routed_when_marked(self):
        with mock.patch.object(audit.subprocess, "run", return_value=_Proc()) as mock_run:
            audit.run_auth_dynamic(
                "http://127.0.0.1:1", {"token_a": "SECRET"}, "/api/x", True,
                secret_env_names={"token_a": "GXSEC_TOKEN_A"})
        cmd = mock_run.call_args[0][0]
        env = mock_run.call_args.kwargs.get("env", {})
        self.assertNotIn("SECRET", cmd)
        self.assertIn("--token-a-env", cmd)
        self.assertIn("GXSEC_TOKEN_A", cmd)
        self.assertEqual(env.get("GXSEC_TOKEN_A"), "SECRET")

    def test_token_a_plaintext_when_not_marked(self):
        # secret_env_names 미전달(기본값) → 기존과 바이트 동일하게 평문 cmd(하위호환)
        with mock.patch.object(audit.subprocess, "run", return_value=_Proc()) as mock_run:
            audit.run_auth_dynamic(
                "http://127.0.0.1:1", {"token_a": "SECRET"}, "/api/x", True)
        cmd = mock_run.call_args[0][0]
        self.assertIn("--token-a", cmd)
        self.assertIn("SECRET", cmd)
        self.assertNotIn("--token-a-env", cmd)

    def test_user_a_pw_env_routed_id_stays_plaintext(self):
        # id는 비밀이 아니므로 평문 유지, pw만 env 경유(브리프 결정사항)
        with mock.patch.object(audit.subprocess, "run", return_value=_Proc()) as mock_run:
            audit.run_auth_dynamic(
                "http://127.0.0.1:1",
                {"user_a_id": "alice", "user_a_pw": "SECRETPW"}, "/api/x", True,
                secret_env_names={"user_a_pw": "GXSEC_USER_A_PW"})
        cmd = mock_run.call_args[0][0]
        env = mock_run.call_args.kwargs.get("env", {})
        self.assertIn("--user-a-id", cmd)
        self.assertIn("alice", cmd)
        self.assertNotIn("SECRETPW", cmd)
        self.assertIn("--user-a-pw-env", cmd)
        self.assertEqual(env.get("GXSEC_USER_A_PW"), "SECRETPW")

    def test_access_partial_marking_only_token_b_routed(self):
        # access는 A/B 양쪽 비밀을 다룬다 — token_a는 미마킹(평문 유지), token_b만 env 경유되는
        # 부분 마킹이 가능해야 한다(각 비밀 독립 판정).
        static = {"by_skill": [{"skill": "detecting-broken-access-control",
                                "candidates": [{"rule_id": "x"}]}]}
        with mock.patch.object(audit.subprocess, "run", return_value=_Proc()) as mock_run:
            audit.run_access_dynamic(
                "http://127.0.0.1:1", static, {"token_a": "A", "token_b": "BSECRET"}, True,
                secret_env_names={"token_b": "GXSEC_TOKEN_B"})
        cmd = mock_run.call_args[0][0]
        env = mock_run.call_args.kwargs.get("env", {})
        self.assertIn("--token-a", cmd)
        self.assertIn("A", cmd)
        self.assertNotIn("BSECRET", cmd)
        self.assertIn("--token-b-env", cmd)
        self.assertEqual(env.get("GXSEC_TOKEN_B"), "BSECRET")

    def test_ssrf_and_pathupload_also_support_env_routing(self):
        # auth와 동일 패턴을 공유하는 ssrf/pathupload도 회귀 없이 env 경유해야 한다.
        with mock.patch.object(audit.subprocess, "run", return_value=_Proc()) as mock_run:
            audit.run_ssrf_dynamic(
                "http://127.0.0.1:1", {"token_a": "SECRET"}, "/go?u=", None, True,
                secret_env_names={"token_a": "GXSEC_TOKEN_A"})
        cmd = mock_run.call_args[0][0]
        self.assertNotIn("SECRET", cmd)
        self.assertIn("--token-a-env", cmd)

        with mock.patch.object(audit.subprocess, "run", return_value=_Proc()) as mock_run2:
            audit.run_pathupload_dynamic(
                "http://127.0.0.1:1", {"token_a": "SECRET"}, "/download?filePath=",
                None, "file", None, False, True,
                secret_env_names={"token_a": "GXSEC_TOKEN_A"})
        cmd2 = mock_run2.call_args[0][0]
        self.assertNotIn("SECRET", cmd2)
        self.assertIn("--token-a-env", cmd2)


class TestApplyLoginProfile(unittest.TestCase):
    """_apply_login_profile — 프로파일 값이 args에 채워지는지(개별 인자 우선), 특히
    token_path 매핑(self-review 대상)을 sef-2026 기본값과 겹치지 않는 커스텀 값으로 검증."""

    def _args(self, **overrides):
        base = dict(login_path=None, body_template=None, token_path=None,
                    id_field=None, pw_field=None, auth_mode=None)
        base.update(overrides)
        return argparse.Namespace(**base)

    def test_token_path_filled_from_profile(self):
        a = self._args()
        audit._apply_login_profile(a, {"token_path": "result.jwt", "auth_mode": "cookie"})
        self.assertEqual(a.token_path, "result.jwt")
        self.assertEqual(a.auth_mode, "cookie")

    def test_explicit_token_path_overrides_profile(self):
        a = self._args(token_path="custom.path")
        audit._apply_login_profile(a, {"token_path": "result.jwt"})
        self.assertEqual(a.token_path, "custom.path")

    def test_defaults_when_no_profile(self):
        # login_path/token_path는 강제 기본값으로 채우지 않고 None으로 남겨 자식(attack_*.py)이
        # 자체 기본값을 적용하도록 위임해야 한다(byte-identity 리뷰 수정 — 여기서 강제하면 신규
        # 인자를 안 쓴 direct 경로에서도 자식 cmd에 --login-path/--token-path가 추가돼 P2 이전
        # baseline과 달라진다). auth_mode만 byte-neutral하게 "bearer"로 폴백된다.
        a = self._args()
        audit._apply_login_profile(a, {})
        self.assertIsNone(a.login_path)
        self.assertIsNone(a.token_path)
        self.assertEqual(a.auth_mode, "bearer")


class TestResolveAllSecrets(unittest.TestCase):
    """_resolve_all_secrets — 4개 비밀 각각 독립적으로 env/stdin 출처를 판정하는지."""

    def _args(self, **overrides):
        base = dict(user_a_pw=None, user_a_pw_env=None, token_a=None, token_a_env=None,
                    user_b_pw=None, user_b_pw_env=None, token_b=None, token_b_env=None)
        base.update(overrides)
        return argparse.Namespace(**base)

    def test_stdin_secret_marked_for_env_routing(self):
        a = self._args()
        names = audit._resolve_all_secrets(a, {"token_a": "SECRET"})
        self.assertEqual(a.token_a, "SECRET")
        self.assertEqual(names.get("token_a"), "GXSEC_TOKEN_A")

    def test_env_secret_marked_for_env_routing(self):
        a = self._args(user_a_pw_env="GXSEC_TEST_PW")
        with mock.patch.dict(os.environ, {"GXSEC_TEST_PW": "envpw"}):
            names = audit._resolve_all_secrets(a, None)
        self.assertEqual(a.user_a_pw, "envpw")
        self.assertEqual(names.get("user_a_pw"), "GXSEC_USER_A_PW")

    def test_direct_secret_not_marked(self):
        a = self._args(token_a="DIRECT")
        names = audit._resolve_all_secrets(a, None)
        self.assertEqual(a.token_a, "DIRECT")
        self.assertNotIn("token_a", names)

    def test_no_source_leaves_none_and_unmarked(self):
        a = self._args()
        names = audit._resolve_all_secrets(a, None)
        self.assertIsNone(a.token_a)
        self.assertEqual(names, {})


class TestMainCredsWiring(unittest.TestCase):
    """audit.py CLI(--creds-stdin/--login-profile/direct)가 run_auth_dynamic까지
    실제로 배선되는지 종단 검증(subprocess.run만 mock, 실발사 없음)."""

    def _auth_cmd_env(self, mock_run):
        for call in mock_run.call_args_list:
            cmd = call.args[0]
            if audit._AUTH_SCRIPT in cmd:
                return cmd, call.kwargs.get("env", {})
        raise AssertionError("attack_auth.py 호출을 찾지 못함(발사 게이트 확인 필요)")

    def test_creds_stdin_token_a_not_in_cmd_and_in_env(self):
        argv = ["audit.py", _ROOT, "--target", "http://127.0.0.1:1",
                "--creds-stdin", "--authorized", "--json"]
        with mock.patch.object(sys, "argv", argv), \
             mock.patch.object(audit, "run_static", return_value=({"by_skill": []}, None)), \
             mock.patch.object(sys, "stdin", io.StringIO('{"token_a":"SECRET"}')), \
             mock.patch.object(sys.stdin, "isatty", return_value=False, create=True), \
             mock.patch.object(audit.subprocess, "run", return_value=_Proc()) as mock_run, \
             contextlib.redirect_stdout(io.StringIO()):
            audit.main()
        cmd, env = self._auth_cmd_env(mock_run)
        self.assertNotIn("SECRET", cmd)
        self.assertIn("--token-a-env", cmd)
        self.assertEqual(env.get("GXSEC_TOKEN_A"), "SECRET")

    def test_login_profile_jsp_form_fills_child_cmd(self):
        argv = ["audit.py", _ROOT, "--target", "http://127.0.0.1:1",
                "--login-profile", "jsp-form", "--token-a", "T",
                "--authorized", "--json"]
        with mock.patch.object(sys, "argv", argv), \
             mock.patch.object(audit, "run_static", return_value=({"by_skill": []}, None)), \
             mock.patch.object(audit.subprocess, "run", return_value=_Proc()) as mock_run, \
             contextlib.redirect_stdout(io.StringIO()):
            audit.main()
        cmd, _ = self._auth_cmd_env(mock_run)
        self.assertIn("--auth-mode", cmd)
        self.assertIn("cookie", cmd)
        self.assertIn("--id-field", cmd)
        self.assertIn("j_username", cmd)

    def test_no_new_args_direct_token_stays_plaintext(self):
        # 신규 인자(--creds-stdin/--*-env/--login-profile) 미사용 → 기존 direct 경로
        # (--token-a 평문이 자식 cmd에 실림)와 바이트 동일해야 한다(하위호환 필수).
        argv = ["audit.py", _ROOT, "--target", "http://127.0.0.1:1",
                "--token-a", "SECRET", "--authorized", "--json"]
        with mock.patch.object(sys, "argv", argv), \
             mock.patch.object(audit, "run_static", return_value=({"by_skill": []}, None)), \
             mock.patch.object(audit.subprocess, "run", return_value=_Proc()) as mock_run, \
             contextlib.redirect_stdout(io.StringIO()):
            audit.main()
        cmd, _ = self._auth_cmd_env(mock_run)
        self.assertIn("--token-a", cmd)
        self.assertIn("SECRET", cmd)
        self.assertNotIn("--token-a-env", cmd)
        # byte-identity: --login-profile 미사용 direct 경로는 --login-path/--token-path도
        # 자식 cmd에 실리면 안 된다(P2 이전 baseline과 동일해야 함 — 리뷰 수정).
        self.assertNotIn("--login-path", cmd)
        self.assertNotIn("--token-path", cmd)

    def test_bad_creds_stdin_json_is_friendly_error_not_traceback(self):
        # Task 3 attack들은 이 지점에서 raw traceback을 냈다(RuntimeError 미포착) — audit은
        # 이를 반복하지 않고 friendly JSON 에러 + sys.exit로 종료해야 한다.
        argv = ["audit.py", _ROOT, "--target", "http://127.0.0.1:1",
                "--creds-stdin", "--authorized", "--json"]
        buf = io.StringIO()
        with mock.patch.object(sys, "argv", argv), \
             mock.patch.object(audit, "run_static", return_value=({"by_skill": []}, None)), \
             mock.patch.object(sys, "stdin", io.StringIO("not json")), \
             mock.patch.object(sys.stdin, "isatty", return_value=False, create=True), \
             contextlib.redirect_stdout(buf):
            with self.assertRaises(SystemExit) as ctx:
                audit.main()
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("creds_stdin_failed", buf.getvalue())

    def test_bad_login_profile_is_friendly_error_not_traceback(self):
        argv = ["audit.py", _ROOT, "--target", "http://127.0.0.1:1",
                "--login-profile", "nonexistent-xyz", "--authorized", "--json"]
        buf = io.StringIO()
        with mock.patch.object(sys, "argv", argv), \
             mock.patch.object(audit, "run_static", return_value=({"by_skill": []}, None)), \
             contextlib.redirect_stdout(buf):
            with self.assertRaises(SystemExit) as ctx:
                audit.main()
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("login_profile_failed", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
