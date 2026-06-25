import importlib.util
import os
import unittest
from unittest.mock import patch

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_MOD = os.path.join(_ROOT, "skills", "exploiting-broken-access-control",
                    "scripts", "attack_access.py")
_spec = importlib.util.spec_from_file_location("attack_access", _MOD)
attack_access = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(attack_access)


class TestBuildTargets(unittest.TestCase):
    def test_classifies_bfla_and_idor(self):
        scan = {"candidates": [
            {"rule_id": "spring-admin-no-preauthorize",
             "file": "UserAdminController.java", "line": 48,
             "snippet": '@RequestMapping("/adm/v1/users")'},
            {"rule_id": "spring-pathvariable-id",
             "file": "BoardController.java", "line": 57,
             "snippet": '@GetMapping("/api/v1/boards/{id}")'},
        ]}
        targets = attack_access.build_targets(scan, "http://localhost:7171")
        kinds = {t["kind"] for t in targets}
        self.assertEqual(kinds, {"bfla", "idor"})
        bfla = next(t for t in targets if t["kind"] == "bfla")
        self.assertEqual(bfla["path"], "/adm/v1/users")

    def test_unknown_path_flags_review(self):
        scan = {"candidates": [
            {"rule_id": "spring-admin-no-preauthorize",
             "file": "X.java", "line": 1, "snippet": "// no mapping here"}]}
        targets = attack_access.build_targets(scan, "http://localhost:7171")
        self.assertEqual(targets[0]["path"], "<UNKNOWN>")
        self.assertTrue(targets[0]["needs_review"])

    def test_regex_handles_value_form(self):
        # @RequestMapping(value = "...") 형태도 추출 (M4 회귀)
        scan = {"candidates": [
            {"rule_id": "spring-admin-no-preauthorize", "file": "A.java", "line": 1,
             "snippet": '@RequestMapping(value = "/adm/v1/x")'}]}
        targets = attack_access.build_targets(scan, "http://localhost:7171")
        self.assertEqual(targets[0]["path"], "/adm/v1/x")
        self.assertFalse(targets[0]["needs_review"])

    def test_idor_multi_placeholder_needs_review(self):
        # 다중 placeholder는 단일 resource-id로 안전 치환 불가 → 검토 대상 (M5)
        scan = {"candidates": [
            {"rule_id": "spring-pathvariable-id", "file": "B.java", "line": 1,
             "snippet": '@GetMapping("/api/v1/users/{uid}/posts/{pid}")'}]}
        targets = attack_access.build_targets(scan, "http://localhost:7171")
        self.assertTrue(targets[0]["needs_review"])


class TestBfla(unittest.TestCase):
    @patch("tools.dyn_session.request")
    def test_bfla_2xx_is_vulnerable(self, mock_req):
        mock_req.return_value = {"status": 200, "body": "[]", "elapsed": 0.01}
        t = {"kind": "bfla", "method": "GET", "path": "/adm/v1/users"}
        out = attack_access.run_bfla("http://localhost:7171", t, "NORMALTOK")
        self.assertTrue(out["vulnerable"])
        self.assertEqual(out["status"], 200)

    @patch("tools.dyn_session.request")
    def test_bfla_403_is_defended(self, mock_req):
        mock_req.return_value = {"status": 403, "body": "", "elapsed": 0.01}
        t = {"kind": "bfla", "method": "GET", "path": "/adm/v1/users"}
        out = attack_access.run_bfla("http://localhost:7171", t, "NORMALTOK")
        self.assertFalse(out["vulnerable"])


class TestIdor(unittest.TestCase):
    @patch("tools.dyn_session.request")
    def test_idor_2xx_is_vulnerable(self, mock_req):
        mock_req.return_value = {"status": 200, "body": "{타인데이터}", "elapsed": 0.01}
        t = {"kind": "idor", "method": "GET", "path": "/api/v1/users/{id}"}
        out = attack_access.run_idor("http://localhost:7171", t, "BTOK", "A-USER-1")
        self.assertTrue(out["vulnerable"])
        url_arg = mock_req.call_args[0][1]  # positional ("GET", url)
        self.assertIn("/api/v1/users/A-USER-1", url_arg)

    @patch("tools.dyn_session.request")
    def test_idor_403_is_defended_falsepositive(self, mock_req):
        mock_req.return_value = {"status": 403, "body": "FORBIDDEN", "elapsed": 0.01}
        t = {"kind": "idor", "method": "GET", "path": "/api/v1/comments/{id}"}
        out = attack_access.run_idor("http://localhost:7171", t, "BTOK", "99")
        self.assertFalse(out["vulnerable"])
        self.assertEqual(out["evidence"]["http_status"], 403)


class TestResolveToken(unittest.TestCase):
    def test_inject_token_takes_precedence(self):
        from unittest.mock import MagicMock
        self.assertEqual(
            attack_access._resolve_token("TOK", None, None,
                                         "http://localhost:7171", MagicMock()),
            "TOK")

    def test_id_without_pw_raises(self):
        from unittest.mock import MagicMock
        with self.assertRaises(RuntimeError):
            attack_access._resolve_token(None, "userid", None,
                                         "http://localhost:7171", MagicMock())


class TestRunScopeGate(unittest.TestCase):
    @patch("tools.dyn_session.assert_in_scope")
    def test_run_blocks_on_scope_error(self, mock_scope):
        mock_scope.side_effect = attack_access.dyn_session.ScopeError("운영 차단")
        parser = attack_access._build_parser()
        args = parser.parse_args(["http://prod.example.com",
                                  "--token-a", "X", "--token-b", "Y"])
        with self.assertRaises(SystemExit) as cm:
            attack_access.run(args)
        self.assertEqual(cm.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
