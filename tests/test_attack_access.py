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

    def test_idor_without_placeholder_flags_review(self):
        # placeholder 0개 IDOR 경로(/api/v1/me)는 치환 대상이 없어 오탐 위험 → 검토 격리(리뷰 반영)
        scan = {"candidates": [
            {"rule_id": "spring-pathvariable-id", "file": "Me.java", "line": 9,
             "snippet": '@GetMapping("/api/v1/me")'}]}
        targets = attack_access.build_targets(scan, "http://localhost:7171")
        self.assertEqual(targets[0]["kind"], "idor")
        self.assertTrue(targets[0]["needs_review"])

    def test_idor_multi_placeholder_needs_review(self):
        # 다중 placeholder는 단일 resource-id로 안전 치환 불가 → 검토 대상 (M5)
        scan = {"candidates": [
            {"rule_id": "spring-pathvariable-id", "file": "B.java", "line": 1,
             "snippet": '@GetMapping("/api/v1/users/{uid}/posts/{pid}")'}]}
        targets = attack_access.build_targets(scan, "http://localhost:7171")
        self.assertTrue(targets[0]["needs_review"])


class TestBfla(unittest.TestCase):
    # run_bfla는 무토큰 대조 오라클 도입 후 anon→user 순으로 request를 2회 호출한다.
    @patch("tools.dyn_session.request")
    def test_bfla_2xx_is_vulnerable(self, mock_req):
        # anon(무토큰) 거부(401) + 일반 토큰 2xx → 역할우회 취약.
        mock_req.side_effect = [
            {"status": 401, "body": "", "elapsed": 0.01},    # anon
            {"status": 200, "body": "[]", "elapsed": 0.01},  # user
        ]
        t = {"kind": "bfla", "method": "GET", "path": "/adm/v1/users"}
        out = attack_access.run_bfla("http://localhost:7171", t, "NORMALTOK")
        self.assertTrue(out["vulnerable"])
        self.assertEqual(out["status"], 200)

    @patch("tools.dyn_session.request")
    def test_bfla_403_is_defended(self, mock_req):
        # anon 거부(401) + 일반 토큰도 거부(403) → 방어(정상).
        mock_req.side_effect = [
            {"status": 401, "body": "", "elapsed": 0.01},    # anon
            {"status": 403, "body": "", "elapsed": 0.01},    # user
        ]
        t = {"kind": "bfla", "method": "GET", "path": "/adm/v1/users"}
        out = attack_access.run_bfla("http://localhost:7171", t, "NORMALTOK")
        self.assertFalse(out["vulnerable"])

    @patch("tools.dyn_session.request")
    def test_bfla_anon_denied_user_2xx_is_vulnerable(self, mock_req):
        # anon 401 + user 200 → 역할우회 취약(note 없음, anon_status 노출).
        mock_req.side_effect = [
            {"status": 401, "body": "", "elapsed": 0.01},    # anon
            {"status": 200, "body": "[]", "elapsed": 0.01},  # user
        ]
        t = {"kind": "bfla", "method": "GET", "path": "/adm/v1/users"}
        out = attack_access.run_bfla("http://localhost:7171", t, "NORMALTOK")
        self.assertTrue(out["vulnerable"])
        self.assertEqual(out["anon_status"], 401)
        self.assertIsNone(out["note"])

    @patch("tools.dyn_session.request")
    def test_bfla_public_endpoint_anon_2xx_not_vulnerable(self, mock_req):
        # anon도 2xx(공개 엔드포인트) → 역할우회 아님(거짓양성 방지), note 세팅.
        mock_req.side_effect = [
            {"status": 200, "body": "[]", "elapsed": 0.01},  # anon
            {"status": 200, "body": "[]", "elapsed": 0.01},  # user
        ]
        t = {"kind": "bfla", "method": "GET", "path": "/public/v1/notices"}
        out = attack_access.run_bfla("http://localhost:7171", t, "NORMALTOK")
        self.assertFalse(out["vulnerable"])
        self.assertEqual(out["anon_status"], 200)
        self.assertIsNotNone(out["note"])


class TestIdor(unittest.TestCase):
    # run_idor는 공개리소스 대조 도입 후 anon→B 순으로 request를 2회 호출한다.
    @patch("tools.dyn_session.request")
    def test_idor_anon_denied_b_2xx_is_vulnerable(self, mock_req):
        # anon(무토큰) 401 + B(타인) 토큰 200 → IDOR 취약.
        mock_req.side_effect = [
            {"status": 401, "body": "", "elapsed": 0.01},              # anon
            {"status": 200, "body": "{타인데이터}", "elapsed": 0.01},  # B
        ]
        t = {"kind": "idor", "method": "GET", "path": "/api/v1/users/{id}"}
        out = attack_access.run_idor("http://localhost:7171", t, "BTOK", "A-USER-1")
        self.assertTrue(out["vulnerable"])
        self.assertEqual(out["anon_status"], 401)
        self.assertIsNone(out["note"])
        url_arg = mock_req.call_args[0][1]  # 마지막(B) 호출 url
        self.assertIn("/api/v1/users/A-USER-1", url_arg)

    @patch("tools.dyn_session.request")
    def test_idor_anon_leg_is_fresh_token_session_none(self, mock_req):
        # 익명 레그는 항상 token=None, session=None 강제 — 쿠키 모드 세션 미승계(오탐/미탐 방지).
        mock_req.side_effect = [
            {"status": 401, "body": "", "elapsed": 0.01},   # anon
            {"status": 200, "body": "x", "elapsed": 0.01},  # B
        ]
        t = {"kind": "idor", "method": "GET", "path": "/api/v1/users/{id}"}
        attack_access.run_idor("http://localhost:7171", t, "BTOK", "7", session="SESS_B")
        anon_call = mock_req.call_args_list[0]
        self.assertIsNone(anon_call.kwargs["token"])
        self.assertIsNone(anon_call.kwargs["session"])
        b_call = mock_req.call_args_list[1]   # B 레그는 토큰·세션 그대로 발사
        self.assertEqual(b_call.kwargs["token"], "BTOK")
        self.assertEqual(b_call.kwargs["session"], "SESS_B")

    @patch("tools.dyn_session.request")
    def test_idor_public_resource_anon_2xx_not_reported(self, mock_req):
        # anon도 2xx(공개 리소스) → IDOR 아님(거짓양성 방지), note 세팅.
        mock_req.side_effect = [
            {"status": 200, "body": "public", "elapsed": 0.01},  # anon
            {"status": 200, "body": "public", "elapsed": 0.01},  # B
        ]
        t = {"kind": "idor", "method": "GET", "path": "/api/v1/notices/{id}"}
        out = attack_access.run_idor("http://localhost:7171", t, "BTOK", "1")
        self.assertFalse(out["vulnerable"])
        self.assertEqual(out["anon_status"], 200)
        self.assertIsNotNone(out["note"])

    @patch("tools.dyn_session.request")
    def test_idor_403_is_defended_falsepositive(self, mock_req):
        # anon 401 + B 403 → 방어(오탐 확정).
        mock_req.side_effect = [
            {"status": 401, "body": "", "elapsed": 0.01},           # anon
            {"status": 403, "body": "FORBIDDEN", "elapsed": 0.01},  # B
        ]
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


class TestSoft200EvidenceCard(unittest.TestCase):
    """P4 Task 8 (④) — 상태코드상 취약 시 soft-200(200+거부본문) 구분용 사람확인 카드 방출."""

    @patch("tools.dyn_session.request")
    def test_bfla_vulnerable_has_evidence_expectation(self, mock_req):
        t = {"path": "/adm/v1/users"}
        mock_req.side_effect = [
            {"status": 401, "body": "", "elapsed": 0.0, "headers": {}},        # anon 거부
            {"status": 200, "body": "data", "elapsed": 0.0, "headers": {}},    # user 2xx
        ]
        out = attack_access.run_bfla("http://localhost:7171", t, "NORMALTOK")
        self.assertTrue(out["vulnerable"])
        self.assertIn("evidence_expectation", out)
        self.assertIn("contrast", out["evidence_expectation"])

    @patch("tools.dyn_session.request")
    def test_bfla_public_no_card(self, mock_req):
        t = {"path": "/adm/v1/users"}
        mock_req.side_effect = [
            {"status": 200, "body": "", "elapsed": 0.0, "headers": {}},        # anon 2xx(공개)
            {"status": 200, "body": "data", "elapsed": 0.0, "headers": {}},
        ]
        out = attack_access.run_bfla("http://localhost:7171", t, "NORMALTOK")
        self.assertFalse(out["vulnerable"])
        self.assertNotIn("evidence_expectation", out)


if __name__ == "__main__":
    unittest.main()
