import http.server
import importlib.util
import json
import os
import tempfile
import threading
import unittest
from unittest.mock import patch

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_MOD = os.path.join(_ROOT, "skills", "exploiting-ssrf-and-open-redirect",
                    "scripts", "attack_ssrf.py")
_spec = importlib.util.spec_from_file_location("attack_ssrf", _MOD)
attack_ssrf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(attack_ssrf)


class TestPayloads(unittest.TestCase):
    def test_six_variants_with_base(self):
        ps = attack_ssrf.make_redirect_payloads("app.local")
        self.assertEqual(len(ps), 6)
        names = {p["name"] for p in ps}
        self.assertIn("userinfo", names)
        self.assertTrue(any("app.local@" in p["value"] for p in ps))
        self.assertTrue(any(p["value"].startswith("https://app.local.") for p in ps))


class TestLocationExternal(unittest.TestCase):
    def test_absolute_external(self):
        self.assertTrue(attack_ssrf.location_is_external("https://evil.test/x", "app.local"))

    def test_scheme_relative_external(self):
        self.assertTrue(attack_ssrf.location_is_external("//evil.test", "app.local"))

    def test_backslash_external(self):
        self.assertTrue(attack_ssrf.location_is_external("/\\evil.test", "app.local"))

    def test_userinfo_bypass_external(self):
        self.assertTrue(attack_ssrf.location_is_external("https://app.local@evil.test", "app.local"))

    def test_relative_internal(self):
        self.assertFalse(attack_ssrf.location_is_external("/dashboard", "app.local"))

    def test_same_host_internal(self):
        self.assertFalse(attack_ssrf.location_is_external("https://app.local/home", "app.local"))

    def test_empty_internal(self):
        self.assertFalse(attack_ssrf.location_is_external("", "app.local"))


class TestInject(unittest.TestCase):
    def test_placeholder_substitution(self):
        url = attack_ssrf._inject("http://h", "/go?u={INJ}", "//evil.test")
        self.assertIn("/go?u=", url)
        self.assertNotIn("{INJ}", url)

    def test_append_when_no_placeholder(self):
        url = attack_ssrf._inject("http://h/", "/go?u=", "x")
        self.assertEqual(url, "http://h/go?u=x")


class TestGetHeader(unittest.TestCase):
    def test_case_insensitive(self):
        self.assertEqual(attack_ssrf._get_header({"location": "/x"}, "Location"), "/x")

    def test_missing(self):
        self.assertIsNone(attack_ssrf._get_header({}, "Location"))


class TestRunOpenRedirect(unittest.TestCase):
    @patch("tools.dyn_session.request")
    def test_external_location_vulnerable(self, mock_req):
        mock_req.return_value = {"status": 302, "body": "", "elapsed": 0.0,
                                 "headers": {"Location": "https://evil.test"}}
        out = attack_ssrf.run_open_redirect("http://app.local", "/go?u=", "app.local")
        self.assertTrue(out["vulnerable"])
        self.assertEqual(out["kind"], "open-redirect")
        # emit 비-json 요약이 쓰는 키(method/path) 계약 고정
        self.assertEqual(out["method"], "GET")
        self.assertEqual(out["path"], "/go?u=")

    @patch("tools.dyn_session.request")
    def test_relative_location_defended(self, mock_req):
        mock_req.return_value = {"status": 302, "body": "", "elapsed": 0.0,
                                 "headers": {"Location": "/siteMain.do"}}
        out = attack_ssrf.run_open_redirect("http://app.local", "/go?u=", "app.local")
        self.assertFalse(out["vulnerable"])


class _FakeListener:
    def __init__(self, hit):
        self._hit = hit

    def url_for(self, nonce):
        return f"http://127.0.0.1:9/c/{nonce}"

    def received(self, nonce, timeout=5.0):
        return self._hit


class TestRunSsrf(unittest.TestCase):
    @patch("tools.dyn_session.request")
    def test_callback_received_vulnerable(self, mock_req):
        mock_req.return_value = {"status": 200, "body": "", "elapsed": 0.0, "headers": {}}
        out = attack_ssrf.run_ssrf("http://app.local", "/api/fetch?url=",
                                   _FakeListener(hit=True))
        self.assertTrue(out["callback"])
        self.assertTrue(out["vulnerable"])
        self.assertEqual(out["kind"], "ssrf")
        self.assertEqual(out["method"], "GET")
        self.assertEqual(out["path"], "/api/fetch?url=")

    @patch("tools.dyn_session.request")
    def test_no_callback_defended(self, mock_req):
        mock_req.return_value = {"status": 200, "body": "", "elapsed": 0.0, "headers": {}}
        out = attack_ssrf.run_ssrf("http://app.local", "/api/fetch?url=",
                                   _FakeListener(hit=False))
        self.assertFalse(out["callback"])
        self.assertFalse(out["vulnerable"])

    @patch.object(attack_ssrf, "_gen_nonce", return_value="NONCE123")
    @patch("tools.dyn_session.request")
    def test_reflected_only_not_vulnerable(self, mock_req, _nonce):
        # 서버가 입력 URL을 에러 페이지에 에코하면 nonce가 본문에 반영되지만(reflected),
        # 서버측 요청은 없었으므로 SSRF 확정이 아니다 — 콜백 없으면 not vulnerable(리뷰 반영)
        mock_req.return_value = {"status": 400, "body": "invalid url: ...NONCE123",
                                 "elapsed": 0.0, "headers": {}}
        out = attack_ssrf.run_ssrf("http://app.local", "/api/fetch?url=",
                                   _FakeListener(hit=False))
        self.assertTrue(out["reflected"])
        self.assertFalse(out["callback"])
        self.assertFalse(out["vulnerable"])


class TestClassifyCandidates(unittest.TestCase):
    def test_splits_redirect_and_ssrf(self):
        data = {"candidates": [
            {"file": "LoginController.java", "line": 88,
             "snippet": 'response.sendRedirect(request.getParameter("returnUrl"))'},
            {"file": "FetchController.java", "line": 55,
             "snippet": 'restTemplate.getForObject(request.getParameter("url"), String.class)'},
        ]}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                         encoding="utf-8") as f:
            json.dump(data, f)
            path = f.name
        try:
            out = attack_ssrf._classify_candidates(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(out["redirect"]), 1)
        self.assertEqual(len(out["ssrf"]), 1)
        self.assertEqual(out["redirect"][0]["param"], "returnUrl")
        self.assertEqual(out["ssrf"][0]["param"], "url")

    def test_bad_file_returns_empty(self):
        out = attack_ssrf._classify_candidates("/nonexistent/scan.json")
        self.assertEqual(out, {"redirect": [], "ssrf": []})


class TestRunScopeGate(unittest.TestCase):
    @patch("tools.dyn_session.assert_in_scope")
    def test_run_blocks_on_scope_error(self, mock_scope):
        mock_scope.side_effect = attack_ssrf.dyn_session.ScopeError("운영 차단")
        parser = attack_ssrf._build_parser()
        args = parser.parse_args(["http://prod.example.com", "--redirect-target", "/x="])
        with self.assertRaises(SystemExit) as cm:
            attack_ssrf.run(args)
        self.assertEqual(cm.exception.code, 1)


class TestNetworkErrorHandling(unittest.TestCase):
    @patch("tools.dyn_session.request", side_effect=ConnectionError("boom"))
    def test_open_redirect_survives_request_error(self, _mock):
        # 네트워크 오류가 나도 크래시하지 않고 finding을 남긴다(리뷰 반영)
        out = attack_ssrf.run_open_redirect("http://app.local", "/go?u=", "app.local")
        self.assertFalse(out["vulnerable"])
        self.assertTrue(all("error" in f for f in out["findings"]))

    @patch("tools.dyn_session.request", side_effect=TimeoutError("slow"))
    def test_ssrf_callback_detected_despite_request_error(self, _mock):
        # 요청이 타임아웃이어도 OOB 콜백 수신이면 취약 확정(블라인드 SSRF)
        out = attack_ssrf.run_ssrf("http://app.local", "/api/fetch?url=",
                                   _FakeListener(hit=True))
        self.assertIsNone(out["status"])
        self.assertTrue(out["vulnerable"])


class TestClassifyDefensive(unittest.TestCase):
    def test_malformed_candidates_do_not_crash(self):
        data = {"candidates": ["not-a-dict", {"snippet": 12345}, {"snippet": "restTemplate.exchange(x)"}]}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                         encoding="utf-8") as f:
            json.dump(data, f)
            path = f.name
        try:
            out = attack_ssrf._classify_candidates(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(out["ssrf"]), 1)


class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    """모든 GET에 302 + Location: http://evil.test 로 응답하는 취약 서버 모사."""

    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "http://evil.test")
        self.end_headers()

    def log_message(self, *args):  # 테스트 로그 소음 억제
        pass


class TestOpenRedirectIntegration(unittest.TestCase):
    """CRITICAL 재발 방지 통합 — 실제 로컬 http.server(302 Location 외부)로
    run_open_redirect가 취약 판정하는지 mock 없이 end-to-end 검증한다(test_oob_canary
    http.server 패턴 준용). dyn_session.request가 실제로 headers를 반환하지 않으면(P3
    CRITICAL) run_open_redirect의 r["headers"] 참조가 KeyError로 흡수돼 취약을 놓치므로,
    이 통합 테스트가 실 응답 헤더 계약(Location 추출)을 CI에서 즉시 노출한다."""

    def setUp(self):
        self.server = http.server.HTTPServer(("127.0.0.1", 0), _RedirectHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_external_location_vulnerable_end_to_end(self):
        # mock 아닌 실제 요청: dyn_session.request가 응답 헤더를 반환해야 Location 외부를
        # 판정할 수 있다(headers 계약 미충족 시 KeyError → vulnerable False로 실패).
        out = attack_ssrf.run_open_redirect(
            f"http://127.0.0.1:{self.port}", "/go?u=", "127.0.0.1")
        self.assertTrue(out["vulnerable"])
        self.assertEqual(out["kind"], "open-redirect")
        hit = next(f for f in out["findings"] if f["vulnerable"])
        self.assertEqual(hit["status"], 302)
        self.assertEqual(hit["location"], "http://evil.test")


if __name__ == "__main__":
    unittest.main()
