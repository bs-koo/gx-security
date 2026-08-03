import os
import sys
import importlib
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..",
                                "skills", "auditing-web-application-security", "scripts"))
audit = importlib.import_module("audit")


class TestStaticOnlyClasses(unittest.TestCase):
    def test_extracts_static_only(self):
        report = {"phases": {
            "access_dynamic": {"confidence": "static-only"},
            "auth_dynamic": {"confidence": "dynamic"},
            "ssrf_dynamic": {"confidence": "static-only"},
            "pathupload_dynamic": {"skipped": "대상 URL 미지정"},
        }}
        out = audit._static_only_classes(report)
        self.assertIn("접근통제(IDOR/BFLA)", out)
        self.assertIn("SSRF/오픈리다이렉트", out)
        self.assertNotIn("인증세션(JWT·재사용)", out)   # dynamic은 제외
        self.assertEqual(len(out), 2)

    def test_empty_when_no_static_only(self):
        report = {"phases": {"access_dynamic": {"confidence": "dynamic"}}}
        self.assertEqual(audit._static_only_classes(report), [])

    def test_handles_missing_or_malformed(self):
        self.assertEqual(audit._static_only_classes({}), [])
        self.assertEqual(audit._static_only_classes({"phases": {}}), [])
        self.assertEqual(audit._static_only_classes({"phases": {"access_dynamic": "notadict"}}), [])

    def test_partial_and_login_failed_not_static_only(self):
        # partial(쿠키만)·login-failed는 static-only가 아니므로 보강 대상에서 제외
        report = {"phases": {
            "auth_dynamic": {"confidence": "partial"},
            "access_dynamic": {"confidence": "login-failed"},
        }}
        self.assertEqual(audit._static_only_classes(report), [])


if __name__ == "__main__":
    unittest.main()
