import base64
import importlib.util
import json
import os
import unittest
from unittest.mock import patch

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_MOD = os.path.join(_ROOT, "skills", "exploiting-auth-session",
                    "scripts", "attack_auth.py")
_spec = importlib.util.spec_from_file_location("attack_auth", _MOD)
attack_auth = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(attack_auth)


def _make_jwt(header, payload, sig="SIG"):
    def enc(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
    return f"{enc(header)}.{enc(payload)}.{sig}"


class TestTamperJwt(unittest.TestCase):
    def test_variants_generated(self):
        tok = _make_jwt({"alg": "HS256"}, {"sub": "u", "roles": ["USER"], "exp": 9999999999})
        out = attack_auth.tamper_jwt(tok)
        self.assertEqual(set(out), {"alg_none", "sig_strip", "payload_role", "exp_past"})

    def test_alg_none_header_changed(self):
        tok = _make_jwt({"alg": "HS256"}, {"sub": "u"})
        out = attack_auth.tamper_jwt(tok)
        h = json.loads(attack_auth._b64url_decode(out["alg_none"].split(".")[0]))
        self.assertEqual(h["alg"], "none")

    def test_payload_role_escalated(self):
        tok = _make_jwt({"alg": "HS256"}, {"sub": "u", "roles": ["USER"]})
        out = attack_auth.tamper_jwt(tok)
        p = json.loads(attack_auth._b64url_decode(out["payload_role"].split(".")[1]))
        self.assertIn("ADMIN", p["roles"])

    def test_malformed_returns_empty(self):
        self.assertEqual(attack_auth.tamper_jwt("not-a-jwt"), {})


class TestRunJwtTamper(unittest.TestCase):
    @patch("tools.dyn_session.request")
    def test_2xx_variant_is_vulnerable(self, mock_req):
        mock_req.return_value = {"status": 200, "body": "{}", "elapsed": 0.0, "headers": {}}
        tok = _make_jwt({"alg": "HS256"}, {"sub": "u", "roles": ["USER"]})
        out = attack_auth.run_jwt_tamper("http://h", "/api/v1/users/me", tok)
        self.assertTrue(out["vulnerable"])

    @patch("tools.dyn_session.request")
    def test_403_all_is_defended(self, mock_req):
        mock_req.return_value = {"status": 403, "body": "", "elapsed": 0.0, "headers": {}}
        tok = _make_jwt({"alg": "HS256"}, {"sub": "u"})
        out = attack_auth.run_jwt_tamper("http://h", "/api/v1/users/me", tok)
        self.assertFalse(out["vulnerable"])


class TestTokenReuse(unittest.TestCase):
    @patch("tools.dyn_session.request")
    def test_reuse_after_logout_vulnerable(self, mock_req):
        mock_req.side_effect = [
            {"status": 200, "body": "", "elapsed": 0.0, "headers": {}},  # before
            {"status": 200, "body": "", "elapsed": 0.0, "headers": {}},  # logout
            {"status": 200, "body": "", "elapsed": 0.0, "headers": {}},  # after
        ]
        out = attack_auth.run_token_reuse("http://h", "/api/v1/users/me", "T", "/api/v1/auth/logout")
        self.assertTrue(out["vulnerable"])

    @patch("tools.dyn_session.request")
    def test_reuse_after_logout_revoked(self, mock_req):
        mock_req.side_effect = [
            {"status": 200, "body": "", "elapsed": 0.0, "headers": {}},  # before
            {"status": 200, "body": "", "elapsed": 0.0, "headers": {}},  # logout
            {"status": 401, "body": "", "elapsed": 0.0, "headers": {}},  # after
        ]
        out = attack_auth.run_token_reuse("http://h", "/api/v1/users/me", "T", "/api/v1/auth/logout")
        self.assertFalse(out["vulnerable"])


class TestCookieFlags(unittest.TestCase):
    def test_missing_flags_vulnerable(self):
        out = attack_auth.check_cookie_flags("refresh-token=abc; Path=/")
        self.assertTrue(out["vulnerable"])
        self.assertIn("Secure", out["missing"])
        self.assertIn("HttpOnly", out["missing"])

    def test_all_flags_safe(self):
        out = attack_auth.check_cookie_flags("refresh-token=abc; Secure; HttpOnly; SameSite=Strict")
        self.assertFalse(out["vulnerable"])

    def test_no_cookie_skipped(self):
        self.assertIn("skipped", attack_auth.check_cookie_flags(""))


class TestRunScopeGate(unittest.TestCase):
    @patch("tools.dyn_session.assert_in_scope")
    def test_run_blocks_on_scope_error(self, mock_scope):
        mock_scope.side_effect = attack_auth.dyn_session.ScopeError("운영 차단")
        parser = attack_auth._build_parser()
        args = parser.parse_args(["http://prod.example.com", "--token-a", "X"])
        with self.assertRaises(SystemExit) as cm:
            attack_auth.run(args)
        self.assertEqual(cm.exception.code, 1)


class TestPickProbe(unittest.TestCase):
    @patch("tools.dyn_session.request")
    def test_picks_first_200_get(self, mock_req):
        mock_req.side_effect = [
            {"status": 404, "body": "", "elapsed": 0.0, "headers": {}},
            {"status": 200, "body": "", "elapsed": 0.0, "headers": {}},
        ]
        probe = attack_auth.pick_probe("http://h", ["/a", "/b"], "T")
        self.assertEqual(probe, "/b")

    @patch("tools.dyn_session.request")
    def test_skips_placeholder_paths(self, mock_req):
        mock_req.return_value = {"status": 200, "body": "", "elapsed": 0.0, "headers": {}}
        probe = attack_auth.pick_probe("http://h", ["/users/{id}", "/me"], "T")
        self.assertEqual(probe, "/me")


if __name__ == "__main__":
    unittest.main()
