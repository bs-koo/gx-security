"""attack 4종 자격증명 env/stdin·로그인 프로파일 배선(D1·D2, Task 3) 테스트.

brief 명시대로 실제 네트워크 없이 _build_parser() + _apply_creds_and_profile()만 검증한다.
4개 스크립트가 동일 해석 로직(헬퍼)을 공유하므로 스크립트별로 파라미터화한다.
"""
import importlib.util
import io
import os
import sys
import unittest
from unittest import mock

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def _load(rel, name):
    mod_path = os.path.join(_ROOT, *rel.split("/"))
    spec = importlib.util.spec_from_file_location(name, mod_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


attack_auth = _load("skills/exploiting-auth-session/scripts/attack_auth.py", "credwire_auth")
attack_access = _load("skills/exploiting-broken-access-control/scripts/attack_access.py", "credwire_access")
attack_ssrf = _load("skills/exploiting-ssrf-and-open-redirect/scripts/attack_ssrf.py", "credwire_ssrf")
attack_pathupload = _load("skills/exploiting-path-traversal-upload/scripts/attack_pathupload.py",
                          "credwire_pathupload")

# 4개 스크립트 모두 base_url 포지셔널 + 공용 인자(user-a-pw-env/token-a-env/creds-stdin/login-profile)를 갖는다.
ALL_MODULES = [attack_auth, attack_access, attack_ssrf, attack_pathupload]

_BASE_URL = "http://localhost:7171"


class TestCredsStdinWiring(unittest.TestCase):
    """--creds-stdin으로 전달한 비밀이 argv에 노출되지 않고 args에 반영되는지(4종 파라미터화)."""

    def test_token_a_from_stdin_not_in_argv(self):
        for mod in ALL_MODULES:
            with self.subTest(module=mod.__name__):
                argv = [_BASE_URL, "--creds-stdin"]
                self.assertNotIn("T", argv)  # 비밀이 argv 리스트 자체에 없어야 함(설계 의도)
                args = mod._build_parser().parse_args(argv)
                with mock.patch.object(sys, "stdin", io.StringIO('{"token_a":"T"}')):
                    with mock.patch.object(sys.stdin, "isatty", return_value=False, create=True):
                        stdin_creds = mod.dyn_session.read_stdin_creds() if args.creds_stdin else None
                mod._apply_creds_and_profile(args, stdin_creds)
                self.assertEqual(args.token_a, "T")


class TestLoginProfileWiring(unittest.TestCase):
    """--login-profile 적용 + 개별 CLI 인자 우선순위(4종 파라미터화)."""

    def test_profile_fills_auth_mode_and_id_field(self):
        for mod in ALL_MODULES:
            with self.subTest(module=mod.__name__):
                args = mod._build_parser().parse_args(
                    [_BASE_URL, "--login-profile", "jsp-form"])
                mod._apply_creds_and_profile(args, None)
                self.assertEqual(args.auth_mode, "cookie")
                self.assertEqual(args.id_field, "j_username")

    def test_explicit_auth_mode_overrides_profile(self):
        for mod in ALL_MODULES:
            with self.subTest(module=mod.__name__):
                args = mod._build_parser().parse_args(
                    [_BASE_URL, "--login-profile", "jsp-form", "--auth-mode", "bearer"])
                mod._apply_creds_and_profile(args, None)
                self.assertEqual(args.auth_mode, "bearer")

    def test_explicit_login_path_overrides_profile(self):
        for mod in ALL_MODULES:
            with self.subTest(module=mod.__name__):
                args = mod._build_parser().parse_args(
                    [_BASE_URL, "--login-profile", "jsp-form", "--login-path", "/custom/login"])
                mod._apply_creds_and_profile(args, None)
                self.assertEqual(args.login_path, "/custom/login")

    def test_sef2026_profile_fills_body_template_and_token_path(self):
        for mod in ALL_MODULES:
            with self.subTest(module=mod.__name__):
                args = mod._build_parser().parse_args(
                    [_BASE_URL, "--login-profile", "sef-2026"])
                mod._apply_creds_and_profile(args, None)
                self.assertEqual(args.token_path, "data.accessToken")
                self.assertIn("{id}", args.body_template)
                self.assertEqual(args.auth_mode, "bearer")


class TestEnvCredWiring(unittest.TestCase):
    """--user-a-pw-env/--token-a-env 로 전달한 환경변수가 args에 반영되는지(4종 파라미터화)."""

    def test_user_a_pw_env(self):
        for mod in ALL_MODULES:
            with self.subTest(module=mod.__name__):
                args = mod._build_parser().parse_args(
                    [_BASE_URL, "--user-a-pw-env", "GXSEC_TEST_USER_A_PW"])
                with mock.patch.dict(os.environ, {"GXSEC_TEST_USER_A_PW": "x"}):
                    mod._apply_creds_and_profile(args, None)
                self.assertEqual(args.user_a_pw, "x")

    def test_token_a_env(self):
        for mod in ALL_MODULES:
            with self.subTest(module=mod.__name__):
                args = mod._build_parser().parse_args(
                    [_BASE_URL, "--token-a-env", "GXSEC_TEST_TOKEN_A"])
                with mock.patch.dict(os.environ, {"GXSEC_TEST_TOKEN_A": "tok123"}):
                    mod._apply_creds_and_profile(args, None)
                self.assertEqual(args.token_a, "tok123")


class TestAccessUserBWiring(unittest.TestCase):
    """attack_access.py 전용 — user_b/token_b도 동일 env/stdin 패턴을 지원해야 함(brief: access만)."""

    def test_user_b_pw_env_and_token_b_env(self):
        args = attack_access._build_parser().parse_args([
            _BASE_URL, "--user-b-pw-env", "GXSEC_TEST_USER_B_PW",
            "--token-b-env", "GXSEC_TEST_TOKEN_B"])
        with mock.patch.dict(os.environ, {"GXSEC_TEST_USER_B_PW": "bpw",
                                          "GXSEC_TEST_TOKEN_B": "btok"}):
            attack_access._apply_creds_and_profile(args, None)
        self.assertEqual(args.user_b_pw, "bpw")
        self.assertEqual(args.token_b, "btok")

    def test_token_b_and_user_b_pw_from_stdin(self):
        args = attack_access._build_parser().parse_args([_BASE_URL, "--creds-stdin"])
        stdin_creds = {"token_b": "TB", "user_b_pw": "PB"}
        attack_access._apply_creds_and_profile(args, stdin_creds)
        self.assertEqual(args.token_b, "TB")
        self.assertEqual(args.user_b_pw, "PB")


class TestBackwardCompatibleDefaults(unittest.TestCase):
    """신규 인자를 전혀 안 쓰면 login_path/token_path/auth_mode 최종값이 기존과 동일해야 한다."""

    def test_defaults_unchanged_when_no_new_flags(self):
        for mod in ALL_MODULES:
            with self.subTest(module=mod.__name__):
                args = mod._build_parser().parse_args([_BASE_URL])
                mod._apply_creds_and_profile(args, None)
                self.assertEqual(args.login_path, "/api/v1/auth/login")
                self.assertEqual(args.token_path, "data.accessToken")
                self.assertEqual(args.auth_mode, "bearer")

    def test_no_profile_no_stdin_leaves_creds_as_direct(self):
        # --login-profile/--creds-stdin 미지정 시 user_a_pw/token_a는 직접 인자값 그대로(회귀 방지)
        for mod in ALL_MODULES:
            with self.subTest(module=mod.__name__):
                args = mod._build_parser().parse_args(
                    [_BASE_URL, "--user-a-pw", "direct-pw", "--token-a", "direct-tok"])
                mod._apply_creds_and_profile(args, None)
                self.assertEqual(args.user_a_pw, "direct-pw")
                self.assertEqual(args.token_a, "direct-tok")


if __name__ == "__main__":
    unittest.main()
