"""자격증명 env/stdin 해석 헬퍼(D1) 단위 검증."""
import io
import os
import sys
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools import dyn_session


class TestResolveSecret(unittest.TestCase):
    def test_direct_only(self):
        self.assertEqual(dyn_session.resolve_secret(direct="pw1"), "pw1")

    def test_env_over_direct(self):
        with mock.patch.dict(os.environ, {"MY_PW": "envpw"}):
            self.assertEqual(
                dyn_session.resolve_secret(direct="pw1", env_var="MY_PW"), "envpw")

    def test_stdin_over_env(self):
        with mock.patch.dict(os.environ, {"MY_PW": "envpw"}):
            self.assertEqual(
                dyn_session.resolve_secret(
                    direct="pw1", env_var="MY_PW",
                    stdin_creds={"user_a_pw": "spw"}, stdin_key="user_a_pw"),
                "spw")

    def test_env_name_missing_falls_through(self):
        # env_var 이름이 환경에 없으면 direct로 폴백
        self.assertEqual(
            dyn_session.resolve_secret(direct="pw1", env_var="NOPE_XYZ"), "pw1")

    def test_none_when_no_source(self):
        self.assertIsNone(dyn_session.resolve_secret())


class TestReadStdinCreds(unittest.TestCase):
    def test_parses_json(self):
        with mock.patch.object(sys, "stdin", io.StringIO('{"token_a":"T"}')):
            with mock.patch.object(sys.stdin, "isatty", return_value=False, create=True):
                self.assertEqual(dyn_session.read_stdin_creds(), {"token_a": "T"})

    def test_raises_on_bad_json(self):
        with mock.patch.object(sys, "stdin", io.StringIO("not json")):
            with mock.patch.object(sys.stdin, "isatty", return_value=False, create=True):
                with self.assertRaises(RuntimeError):
                    dyn_session.read_stdin_creds()


if __name__ == "__main__":
    unittest.main()
