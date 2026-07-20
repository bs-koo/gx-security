"""로그인 프로파일 로더(D2) 단위 검증."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools import dyn_session

ROOT = Path(__file__).resolve().parent.parent


class TestLoadLoginProfile(unittest.TestCase):
    def test_builtin_sef_2026(self):
        prof = dyn_session.load_login_profile("sef-2026")
        self.assertEqual(prof["login_path"], "/api/v1/auth/login")
        self.assertEqual(prof["token_path"], "data.accessToken")

    def test_builtin_jsp_form(self):
        prof = dyn_session.load_login_profile("jsp-form")
        self.assertEqual(prof["auth_mode"], "cookie")

    def test_path_form(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "custom.json"
            p.write_text(json.dumps({"login_path": "/x"}), encoding="utf-8")
            self.assertEqual(dyn_session.load_login_profile(str(p))["login_path"], "/x")

    def test_unknown_key_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.json"
            p.write_text(json.dumps({"evil": 1}), encoding="utf-8")
            with self.assertRaises(RuntimeError):
                dyn_session.load_login_profile(str(p))

    def test_missing_name_raises(self):
        with self.assertRaises(RuntimeError):
            dyn_session.load_login_profile("nonexistent-xyz")


if __name__ == "__main__":
    unittest.main()
