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
        # before=200(정상토큰), anon=401(무토큰 → 인증 적용 확인), 변조 200 → 취약
        mock_req.side_effect = [
            {"status": 200, "body": "{}", "elapsed": 0.0, "headers": {}},  # before
            {"status": 401, "body": "", "elapsed": 0.0, "headers": {}},    # anon
        ] + [{"status": 200, "body": "{}", "elapsed": 0.0, "headers": {}} for _ in range(4)]
        tok = _make_jwt({"alg": "HS256"}, {"sub": "u", "roles": ["USER"]})
        out = attack_auth.run_jwt_tamper("http://h", "/api/v1/users/me", tok)
        self.assertTrue(out["vulnerable"])

    @patch("tools.dyn_session.request")
    def test_403_all_is_defended(self, mock_req):
        # before=200, anon=401(인증 적용), 변조 4변형 모두 403 → 방어
        mock_req.side_effect = [
            {"status": 200, "body": "", "elapsed": 0.0, "headers": {}},  # before
            {"status": 401, "body": "", "elapsed": 0.0, "headers": {}},  # anon
        ] + [{"status": 403, "body": "", "elapsed": 0.0, "headers": {}} for _ in range(4)]
        tok = _make_jwt({"alg": "HS256"}, {"sub": "u"})
        out = attack_auth.run_jwt_tamper("http://h", "/api/v1/users/me", tok)
        self.assertFalse(out["vulnerable"])

    @patch("tools.dyn_session.request")
    def test_skips_when_probe_inaccessible(self, mock_req):
        # 정상 토큰으로도 probe가 401 → 변조 판정 보류(오탐 방지, 리뷰 반영)
        mock_req.return_value = {"status": 401, "body": "", "elapsed": 0.0, "headers": {}}
        tok = _make_jwt({"alg": "HS256"}, {"sub": "u"})
        out = attack_auth.run_jwt_tamper("http://h", "/api/v1/users/me", tok)
        self.assertIn("skipped", out)
        self.assertNotIn("vulnerable", out)

    @patch("tools.dyn_session.request")
    def test_skips_when_probe_is_public(self, mock_req):
        # before=200, anon=200(무토큰도 통과 → 인증 미적용) → 변조 판정 무의미(오탐 방지, 리뷰 반영)
        mock_req.side_effect = [
            {"status": 200, "body": "", "elapsed": 0.0, "headers": {}},  # before
            {"status": 200, "body": "", "elapsed": 0.0, "headers": {}},  # anon
        ]
        tok = _make_jwt({"alg": "HS256"}, {"sub": "u"})
        out = attack_auth.run_jwt_tamper("http://h", "/public/info", tok)
        self.assertIn("skipped", out)
        self.assertNotIn("vulnerable", out)


class TestTokenReuse(unittest.TestCase):
    @patch("tools.dyn_session.request")
    def test_reuse_after_logout_vulnerable(self, mock_req):
        mock_req.side_effect = [
            {"status": 200, "body": "", "elapsed": 0.0, "headers": {}},  # before
            {"status": 401, "body": "", "elapsed": 0.0, "headers": {}},  # anon(무토큰 → 인증 적용 확인)
            {"status": 200, "body": "", "elapsed": 0.0, "headers": {}},  # logout
            {"status": 200, "body": "", "elapsed": 0.0, "headers": {}},  # after
        ]
        out = attack_auth.run_token_reuse("http://h", "/api/v1/users/me", "T", "/api/v1/auth/logout")
        self.assertTrue(out["vulnerable"])

    @patch("tools.dyn_session.request")
    def test_reuse_after_logout_revoked(self, mock_req):
        mock_req.side_effect = [
            {"status": 200, "body": "", "elapsed": 0.0, "headers": {}},  # before
            {"status": 401, "body": "", "elapsed": 0.0, "headers": {}},  # anon(인증 적용)
            {"status": 200, "body": "", "elapsed": 0.0, "headers": {}},  # logout
            {"status": 401, "body": "", "elapsed": 0.0, "headers": {}},  # after
        ]
        out = attack_auth.run_token_reuse("http://h", "/api/v1/users/me", "T", "/api/v1/auth/logout")
        self.assertFalse(out["vulnerable"])

    @patch("tools.dyn_session.request")
    def test_skips_when_logout_fails(self, mock_req):
        # 로그아웃이 404 → 재사용 2xx는 '미폐기'가 아니라 '로그아웃 실패' → 보류(오탐 방지)
        mock_req.side_effect = [
            {"status": 200, "body": "", "elapsed": 0.0, "headers": {}},  # before
            {"status": 401, "body": "", "elapsed": 0.0, "headers": {}},  # anon(인증 적용)
            {"status": 404, "body": "", "elapsed": 0.0, "headers": {}},  # logout 실패
        ]
        out = attack_auth.run_token_reuse("http://h", "/api/v1/users/me", "T", "/api/v1/auth/logout")
        self.assertIn("skipped", out)
        self.assertNotIn("vulnerable", out)

    @patch("tools.dyn_session.request")
    def test_skips_when_probe_is_public(self, mock_req):
        # before=200, anon=200(무토큰도 통과 → 인증 미적용) → 재사용 판정 무의미(오탐 방지, 리뷰 반영)
        # 공개 엔드포인트를 probe로 줬을 때 before=200·after=200 거짓 '취약' 판정 제거
        mock_req.side_effect = [
            {"status": 200, "body": "", "elapsed": 0.0, "headers": {}},  # before
            {"status": 200, "body": "", "elapsed": 0.0, "headers": {}},  # anon(무토큰도 통과)
        ]
        out = attack_auth.run_token_reuse("http://h", "/public/info", "T", "/api/v1/auth/logout")
        self.assertIn("skipped", out)
        self.assertNotIn("vulnerable", out)


class TestCookieFlags(unittest.TestCase):
    def test_missing_flags_vulnerable(self):
        out = attack_auth.check_cookie_flags("refresh-token=abc; Path=/")
        self.assertTrue(out["vulnerable"])
        self.assertIn("Secure", out["cookies"][0]["missing"])
        self.assertIn("HttpOnly", out["cookies"][0]["missing"])

    def test_all_flags_safe(self):
        out = attack_auth.check_cookie_flags("refresh-token=abc; Secure; HttpOnly; SameSite=Strict")
        self.assertFalse(out["vulnerable"])

    def test_multi_cookie_split_independently(self):
        # 쉼표 결합된 두 쿠키 — 한쪽만 안전해도 다른 쪽 누락을 잡아야 함(리뷰 반영)
        out = attack_auth.check_cookie_flags(
            "A=1; Secure; HttpOnly; SameSite=Strict, B=2; Path=/")
        self.assertEqual(len(out["cookies"]), 2)
        self.assertTrue(out["vulnerable"])
        b = next(c for c in out["cookies"] if c["cookie_name"] == "B")
        self.assertIn("Secure", b["missing"])

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


class TestRunCrashDefense(unittest.TestCase):
    """ZT/CRITICAL — 발사 중 연결 예외를 uncaught 종료 대신 finding-level error로 변환.

    자식이 stdout 빈 채 rc=1로 죽으면 run_auth_dynamic이 static-only로 오분류하므로,
    run()의 발사별 try/except가 정상 JSON에 error finding을 포함시켜 상위가 크래시를 인지 가능해야 한다.
    """

    @patch("tools.dyn_session.emit")
    @patch("tools.dyn_session.request")
    @patch("tools.dyn_session.assert_in_scope")
    def test_fire_exception_becomes_error_finding(self, mock_scope, mock_req, mock_emit):
        # probe 발사(run_jwt_tamper/run_token_reuse) 중 ConnectionError → sys.exit/예외 없이 emit,
        # findings에 error 항목 포함(kind 유지)
        mock_scope.return_value = "authorized"
        mock_req.side_effect = ConnectionError("connection refused")
        parser = attack_auth._build_parser()
        args = parser.parse_args(
            ["http://h", "--token-a", "a.b.c", "--probe", "/api/v1/users/me", "--json"])
        attack_auth.run(args)  # uncaught 예외/SystemExit 없이 정상 종료해야 함
        self.assertTrue(mock_emit.called)
        payload = mock_emit.call_args[0][0]
        errs = [f for f in payload["findings"] if f.get("error")]
        self.assertTrue(errs)  # jwt-tamper/token-reuse가 error finding으로 변환됨
        self.assertTrue({"jwt-tamper", "token-reuse"} <= {f.get("kind") for f in errs})

    @patch("tools.dyn_session.emit")
    @patch.object(attack_auth, "pick_probe", side_effect=ConnectionError("down"))
    @patch.object(attack_auth, "_probe_candidates_from_scan", return_value=["/x"])
    @patch("tools.dyn_session.assert_in_scope", return_value="authorized")
    def test_pick_probe_exception_becomes_error_finding(
            self, mock_scope, mock_cands, mock_pick, mock_emit):
        # probe 자동 선택 단계(pick_probe)의 연결 예외도 uncaught 종료 대신 error finding으로 격리
        parser = attack_auth._build_parser()
        args = parser.parse_args(["http://h", "--token-a", "a.b.c", "--scan", "dummy.json", "--json"])
        attack_auth.run(args)
        self.assertTrue(mock_emit.called)
        payload = mock_emit.call_args[0][0]
        errs = [f for f in payload["findings"] if f.get("error")]
        self.assertTrue(any(f.get("kind") == "probe-select" for f in errs))


if __name__ == "__main__":
    unittest.main()
