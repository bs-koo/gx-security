import importlib.util
import io
import json
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from tools import dyn_session, scope_guard

ROOT = Path(__file__).resolve().parents[1]


def load(skill, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "skills" / skill / "scripts" / (name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ReleaseDynamicRegressions(unittest.TestCase):
    def test_non_http_scheme_and_allowlist_suffix_are_blocked(self):
        for scheme in ("ftp", "file", "gopher"):
            self.assertEqual(scope_guard.classify(scheme + "://localhost/path")[0], "deny")
        with patch.dict(os.environ, {"SECURITY_PLUGIN_ALLOW_HOSTS": "example.com"}, clear=True):
            self.assertNotEqual(scope_guard.classify("https://child.example.com")[0], "allow")

    def test_undetermined_common_output_is_not_rendered_as_defended(self):
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            dyn_session.emit({"findings": [{"kind": "bfla", "vulnerable": False, "undetermined": True}]}, False)
        self.assertIn("미확정", output.getvalue())
        self.assertNotIn("방어/정상", output.getvalue())

    @patch("tools.dyn_session.request")
    def test_access_soft200_and_anonymous200_are_undetermined(self, request):
        access = load("exploiting-broken-access-control", "attack_access")
        for anonymous in (401, 200):
            request.side_effect = [{"status": anonymous, "body": "login page"},
                                   {"status": 200, "body": "access denied"}]
            out = access.run_bfla("http://localhost:9", {"path": "/admin"}, "fixture")
            self.assertFalse(out["vulnerable"])
            self.assertEqual(out["validation"], "undetermined")
            self.assertNotIn("공개 엔드포인트", out.get("note") or "")

    def test_sqlmap_automatic_execution_is_unavailable_without_confinement(self):
        sqli = load("exploiting-sql-injection", "attack_sqli")
        with patch.object(sqli.shutil, "which", return_value="sqlmap"), patch.object(sqli.subprocess, "run") as run:
            out = sqli._run_sqlmap("http://localhost:9/api", "q", "post", None, False, False)
        run.assert_not_called()
        self.assertFalse(out["exploited"])
        self.assertEqual(out["execution_status"], "unsupported")

    @patch("tools.dyn_session.request")
    def test_authentication_jwt_soft200_is_never_runtime_confirmation(self, request):
        auth = load("exploiting-auth-session", "attack_auth")
        request.side_effect = [{"status": 200, "body": '{"id":"A"}'},
                               {"status": 401, "body": ""},
                               {"status": 200, "body": "login required"}]
        with patch.object(auth, "tamper_jwt", return_value={"unsigned": "fixture"}):
            out = auth.run_jwt_tamper("http://localhost:9", "/me", "normal")
        self.assertFalse(out["vulnerable"])
        self.assertEqual(out["validation"], "undetermined")

    @patch("tools.dyn_session.request")
    def test_opaque_token_reuse_soft200_is_never_confirmation(self, request):
        auth = load("exploiting-auth-session", "attack_auth")
        request.side_effect = [{"status": 200, "body": "{}"}, {"status": 401, "body": ""},
                               {"status": 200, "body": "{}"}, {"status": 200, "body": "access denied"}]
        out = auth.run_token_reuse("http://localhost:9", "/me", "opaque-fixture", "/logout")
        self.assertFalse(out["vulnerable"])
        self.assertEqual(out["validation"], "undetermined")

    def test_sqli_connectivity_probe_preserves_common_auth_and_no_redirect_path(self):
        sqli = load("exploiting-sql-injection", "attack_sqli")
        args = sqli._build_parser().parse_args(["http://localhost:9/api", "--param", "q", "--token-a", "fixture", "--json"])
        with patch.object(sqli.dyn_session, "request", return_value={"status": 302, "body": "", "headers": {}, "elapsed": 0.01}) as request, \
             patch.object(sqli, "_run_sqlmap", return_value=None), \
             patch.object(sqli, "_try_error_based", return_value=(None, None)), \
             patch.object(sqli, "_try_boolean_based", return_value=(None, None)), \
             patch.object(sqli, "_try_time_based", return_value=(None, None)), \
             patch.object(sqli, "_output"):
            sqli.run_attack(args)
        request.assert_called_once()
        self.assertEqual(request.call_args.kwargs["token"], "fixture")

    @patch("tools.dyn_session.request")
    def test_xss_authenticated_json_uses_common_session(self, request):
        xss = load("exploiting-xss-vulnerabilities", "attack_xss")
        request.return_value = {"status": 200, "body": "clean", "elapsed": 0.01, "headers": {}}
        xss.check_reflection("http://localhost:9/api", "q", "post", {"keep": True}, "PAYLOAD", "MARKER",
                             token="fixture", content_type="json", inject_path="data.query")
        kwargs = request.call_args.kwargs
        self.assertEqual(kwargs["token"], "fixture")
        self.assertEqual(kwargs["json_body"], {"keep": True, "data": {"query": "PAYLOAD"}})

    def test_xss_cookie_mode_does_not_reuse_a_bearer_token(self):
        xss = load("exploiting-xss-vulnerabilities", "attack_xss")
        with patch.object(sys, "argv", ["attack_xss.py", "http://localhost:9/search", "--param", "q",
                                       "--auth-mode", "cookie", "--token-a", "fixture"]):
            args = xss.parse_args()
        self.assertEqual(xss._resolve_auth(args), (None, None))

    def test_audit_forwards_injection_auth_and_json_without_secret_argv(self):
        audit = load("auditing-web-application-security", "audit")
        process = SimpleNamespace(stdout="{}", stderr="", returncode=0)
        with patch.object(audit.subprocess, "run", return_value=process) as run:
            audit.run_dynamic("http://localhost:9/api", ["q"], False,
                              creds={"token_a": "fixture-secret"}, auth_mode="bearer",
                              content_type="json", inject_path="data.query", method="post")
        self.assertEqual(run.call_count, 2)
        for call in run.call_args_list:
            argv = call.args[0]
            self.assertNotIn("fixture-secret", argv)
            self.assertIn("--token-a-env", argv)
            self.assertIn("--content-type", argv)
            self.assertIn("data.query", argv)
            self.assertEqual(call.kwargs["env"]["GXSEC_TOKEN_A"], "fixture-secret")


if __name__ == "__main__":
    unittest.main()
