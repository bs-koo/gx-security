import importlib.util
import io
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_MOD = os.path.join(_ROOT, "skills", "exploiting-xss-vulnerabilities",
                    "scripts", "attack_xss.py")
_spec = importlib.util.spec_from_file_location("attack_xss", _MOD)
attack_xss = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(attack_xss)


class TestNoRedirectTransport(unittest.TestCase):
    """Keep response observations while replacing the ambient urllib opener."""

    @patch("tools.dyn_session._client")
    def test_302_not_followed_original_captured(self, mock_client):
        marker = "sqixssaaaaaaaa"
        body = f"<html>original 302 body {marker}</html>"
        mock_client.return_value = MagicMock(status_code=302, content=body.encode())
        _ctx, status, resp_body = attack_xss.check_reflection(
            "http://app.local/search", "q", "get", {},
            "<script>x</script>", marker)
        self.assertEqual(status, 302)          # 리다이렉트 원응답 코드 포착(추종 안 함)
        self.assertIn(marker, resp_body)       # 리다이렉트 목적지가 아닌 원응답 본문
        self.assertFalse(mock_client.call_args.kwargs["allow_redirects"])

    @patch("tools.dyn_session._client")
    def test_uses_shared_isolated_client_with_original_user_agent(self, mock_client):
        mock_client.return_value = MagicMock(status_code=200, content=b"<html>sqixssbbbbbbbb</html>")
        attack_xss.check_reflection(
            "http://app.local/search", "q", "get", {}, "<b>x</b>", "sqixssbbbbbbbb")
        mock_client.assert_called_once()
        self.assertFalse(mock_client.call_args.kwargs["allow_redirects"])
        self.assertEqual(mock_client.call_args.kwargs["headers"]["User-Agent"], "SQI-SecurityPlugin-XSS-Scanner/0.1")

    @patch("tools.dyn_session._client", side_effect=ConnectionError("person@example.invalid password=synthetic"))
    def test_transport_error_keeps_status_zero_and_fixed_safe_code(self, _client):
        result = attack_xss.check_reflection(
            "http://app.local/search", "q", "get", {}, "<b>x</b>", "marker")
        self.assertEqual(result, (None, 0, "CONNECTION_ERROR:connection_error"))


class TestVerdictContract(unittest.TestCase):
    """P4 Task 7 (감사 #7 수정) — 반사만으로 exploited=true 를 찍지 않는다.

    HTTP 응답 반사는 verdict='needs-confirmation'(후보)이며 exploited=False. evidence_expectation
    카드를 방출한다. 확정은 Playwright 실행(④ 사람확인)으로 상위가 승격한다.
    """

    def _run(self, cr_return):
        argv = ["attack_xss.py", "http://127.0.0.1:9/search", "--param", "q", "--json"]
        buf = io.StringIO()
        with patch.object(attack_xss, "check_reflection", return_value=cr_return), \
                patch.object(sys, "argv", argv), patch.object(sys, "stdout", buf):
            attack_xss.main()
        return json.loads(buf.getvalue())

    def test_reflection_is_needs_confirmation_not_exploited(self):
        out = self._run(("html-text", 200, "body with marker reflected"))
        self.assertTrue(out["reflected"])
        self.assertEqual(out["verdict"], "needs-confirmation")
        self.assertFalse(out["exploited"])          # 반사만으론 절대 exploited=true 아님
        self.assertIn("evidence_expectation", out)
        self.assertIn("contrast", out["evidence_expectation"])

    def test_no_reflection_is_safe(self):
        out = self._run((None, 200, "clean escaped body"))
        self.assertFalse(out["reflected"])
        self.assertEqual(out["verdict"], "safe")
        self.assertFalse(out["exploited"])
        self.assertNotIn("evidence_expectation", out)

    def _run_raw(self, cr_side_effect):
        argv = ["attack_xss.py", "http://127.0.0.1:9/search", "--param", "q", "--json"]
        buf = io.StringIO()
        code = None
        with patch.object(attack_xss, "check_reflection", side_effect=cr_side_effect), \
                patch.object(sys, "argv", argv), patch.object(sys, "stdout", buf):
            try:
                attack_xss.main()
            except SystemExit as e:
                code = e.code
        return json.loads(buf.getvalue()), code

    def test_unreached_exits_nonzero(self):
        # 코드리뷰 finding: 대상 미가동 → unreached, exit != 0 (audit이 '발사 실패'로 표기).
        out, code = self._run_raw([(None, 0, "CONNECTION_ERROR: refused")])
        self.assertEqual(out["verdict"], "unreached")
        self.assertNotIn(code, (0, None))

    def test_reflection_then_disconnect_stays_needs_confirmation(self):
        # 코드리뷰 finding: 페이로드1 반사 후 페이로드2 연결끊김 → 반사 우선(needs-confirmation),
        # exit 0 — 이미 확인된 반사가 unreached로 덮이지 않는다.
        out, code = self._run_raw([("html-text", 200, "reflected"),
                                   (None, 0, "CONNECTION_ERROR: refused")])
        self.assertEqual(out["verdict"], "needs-confirmation")
        self.assertTrue(out["reflected"])
        self.assertIn(code, (0, None))


class TestRenderDynamicLineReflection(unittest.TestCase):
    """audit.render_dynamic_line 이 반사(needs-confirmation)를 '후보'로 표기하고 악용 확정하지 않는다."""

    def setUp(self):
        _amod = os.path.join(_ROOT, "skills", "auditing-web-application-security",
                             "scripts", "audit.py")
        _aspec = importlib.util.spec_from_file_location("audit_p4", _amod)
        self.audit = importlib.util.module_from_spec(_aspec)
        _aspec.loader.exec_module(self.audit)

    def test_reflected_shows_candidate_not_exploited(self):
        line = self.audit.render_dynamic_line(
            {"vuln": "xss", "param": "q", "returncode": 0,
             "result": {"verdict": "needs-confirmation", "reflected": True, "exploited": False}})
        self.assertIn("반사 확인", line)
        self.assertNotIn("악용 확정", line)

    def test_legacy_exploited_still_confirmed(self):
        # sqli 등 기존 exploited 계약은 그대로 '악용 확정'
        line = self.audit.render_dynamic_line(
            {"vuln": "sqli", "param": "id", "returncode": 0,
             "result": {"exploited": True}})
        self.assertIn("악용 확정", line)


if __name__ == "__main__":
    unittest.main()
