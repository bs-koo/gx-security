"""audit → attack 자식 cmd 로그인 옵션 전달 회귀 (코드리뷰 H1).

과거 audit이 --login-path 를 access 에만 전달하고 auth/ssrf/pathupload 에는 누락해
JSP 레거시·비표준 로그인 앱의 audit 경유 동적 점검이 조용히 login-failed 됐다.
이 테스트는 4개 동적 모듈 자식 cmd에 --login-path/--body-template/--token-path 가
빠짐없이 실리는지 고정한다(subprocess.run 을 mock 해 cmd 만 캡처, 실발사 없음).
"""
import importlib.util
import os
import unittest
from unittest.mock import patch

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_spec = importlib.util.spec_from_file_location(
    "audit_fwd", os.path.join(_ROOT, "skills", "auditing-web-application-security",
                              "scripts", "audit.py"))
audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(audit)


class _Proc:
    stdout = '{"findings":[]}'
    stderr = ""
    returncode = 0


class TestAuditLoginForwarding(unittest.TestCase):
    LOGIN = {"login_path": "/legacy/login.do",
             "body_template": '{"userId":"{id}","userPw":"{pw}"}',
             "token_path": "result.jwt"}

    def _assert_forwarded(self, cmd):
        self.assertIn("--login-path", cmd)
        self.assertIn("/legacy/login.do", cmd)
        self.assertIn("--body-template", cmd)
        self.assertIn("--token-path", cmd)
        self.assertIn("result.jwt", cmd)

    def test_auth_dynamic_forwards(self):
        with patch.object(audit.subprocess, "run", return_value=_Proc()) as mock_run:
            audit.run_auth_dynamic("http://127.0.0.1:1", {"token_a": "t"},
                                   "/api/v1/users/me", True, **self.LOGIN)
        mock_run.assert_called_once()
        self._assert_forwarded(mock_run.call_args[0][0])

    def test_ssrf_dynamic_forwards(self):
        with patch.object(audit.subprocess, "run", return_value=_Proc()) as mock_run:
            audit.run_ssrf_dynamic("http://127.0.0.1:1", {"token_a": "t"},
                                   "/go?u=", "/api/fetch?url=", True, **self.LOGIN)
        mock_run.assert_called_once()
        self._assert_forwarded(mock_run.call_args[0][0])

    def test_pathupload_dynamic_forwards(self):
        with patch.object(audit.subprocess, "run", return_value=_Proc()) as mock_run:
            audit.run_pathupload_dynamic(
                "http://127.0.0.1:1", {"token_a": "t"}, "/download?filePath=",
                None, "file", None, False, True, **self.LOGIN)
        mock_run.assert_called_once()
        self._assert_forwarded(mock_run.call_args[0][0])


if __name__ == "__main__":
    unittest.main()
