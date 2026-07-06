"""scan_upload 폴백 회귀 (F3 / FR-8 — AC-8).

commons-fileupload(ServletFileUpload/DiskFileItemFactory) 직접 사용을 라인-로컬
근사로 후보화한다. 사용이 없는 코드는 후보로 잡지 않는다(방향성 오탐 차단).
"""
import importlib.util
import os
import tempfile
import unittest

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_MOD = os.path.join(_ROOT, "skills", "detecting-file-upload-vulnerabilities",
                    "scripts", "scan_upload.py")
_spec = importlib.util.spec_from_file_location("scan_upload", _MOD)
scan_upload = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scan_upload)


class TestCommonsFileuploadFallback(unittest.TestCase):
    def _rule_ids(self, filename, body):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, filename), "w", encoding="utf-8") as fh:
                fh.write(body)
            findings = scan_upload.run_fallback(d)
        return [c["rule_id"] for c in findings]

    def test_servletfileupload_usage_flagged(self):
        # new ServletFileUpload(new DiskFileItemFactory()) → 후보 ≥1
        rules = self._rule_ids(
            "Upload.java",
            "public class Upload {\n"
            "  void a() {\n"
            "    ServletFileUpload upload = new ServletFileUpload(new DiskFileItemFactory());\n"
            "  }\n"
            "}\n")
        self.assertGreaterEqual(rules.count("jsp-commons-fileupload"), 1)

    def test_no_upload_code_not_flagged(self):
        # commons-fileupload 미사용 코드 → 후보 0
        rules = self._rule_ids(
            "NoUpload.java",
            "public class NoUpload {\n"
            "  public void noUpload() { int x = 0; }\n"
            "}\n")
        self.assertEqual(rules.count("jsp-commons-fileupload"), 0)


if __name__ == "__main__":
    unittest.main()
