import importlib.util
import json
import os
import tempfile
import unittest
from unittest.mock import patch

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_MOD = os.path.join(_ROOT, "skills", "exploiting-path-traversal-upload",
                    "scripts", "attack_pathupload.py")
_spec = importlib.util.spec_from_file_location("attack_pathupload", _MOD)
attack_pathupload = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(attack_pathupload)
A = attack_pathupload


class TestTraversalPayloads(unittest.TestCase):
    def test_variants_include_encodings(self):
        ps = A.make_traversal_payloads("etc/passwd")
        vals = [p["value"] for p in ps]
        self.assertTrue(any(v.startswith("../../../") for v in vals))
        self.assertTrue(any("%2e%2e%2f" in v for v in vals))
        self.assertTrue(all("passwd" in v for v in vals))


class TestDetectFileContent(unittest.TestCase):
    def test_unix_passwd(self):
        self.assertEqual(A.detect_file_content("root:x:0:0:root:/root:/bin/bash"), "unix")

    def test_javaweb(self):
        self.assertEqual(A.detect_file_content('<?xml version="1.0"?><web-app>'), "javaweb")

    def test_windows(self):
        self.assertEqual(A.detect_file_content("[fonts]\nfoo=bar"), "windows")

    def test_none(self):
        self.assertIsNone(A.detect_file_content("hello world normal page"))


class TestInject(unittest.TestCase):
    def test_placeholder(self):
        url = A._inject("http://h", "/d?f={INJ}", "../x")
        self.assertNotIn("{INJ}", url)

    def test_append(self):
        url = A._inject("http://h/", "/d?f=", "x")
        self.assertEqual(url, "http://h/d?f=x")


class TestRunPathTraversal(unittest.TestCase):
    @patch("tools.dyn_session.request")
    def test_signature_in_body_vulnerable(self, mock_req):
        mock_req.return_value = {"status": 200, "body": "root:x:0:0:root:/root",
                                 "elapsed": 0.0, "headers": {}}
        out = A.run_path_traversal("http://app.local", "/download?file=")
        self.assertTrue(out["vulnerable"])
        self.assertEqual(out["kind"], "path-traversal")
        self.assertEqual(out["method"], "GET")

    @patch("tools.dyn_session.request")
    def test_no_signature_defended(self, mock_req):
        mock_req.return_value = {"status": 404, "body": "not found",
                                 "elapsed": 0.0, "headers": {}}
        out = A.run_path_traversal("http://app.local", "/download?file=")
        self.assertFalse(out["vulnerable"])


class TestMarkerUpload(unittest.TestCase):
    def test_marker_is_inert_jsp(self):
        fn, content, nonce = A.make_marker_upload()
        self.assertTrue(fn.endswith(".jsp"))
        self.assertIn(nonce, content)
        self.assertNotIn("<%", content)  # 코드 없음


class TestRunUpload(unittest.TestCase):
    @patch("tools.dyn_session.request")
    def test_accepted_vulnerable(self, mock_req):
        mock_req.return_value = {"status": 200, "body": "ok", "elapsed": 0.0, "headers": {}}
        out = A.run_upload("http://app.local", "/api/upload")
        self.assertTrue(out["accepted"])
        self.assertTrue(out["vulnerable"])
        self.assertEqual(out["kind"], "file-upload")

    @patch("tools.dyn_session.request")
    def test_rejected_defended(self, mock_req):
        mock_req.return_value = {"status": 400, "body": "bad ext", "elapsed": 0.0, "headers": {}}
        out = A.run_upload("http://app.local", "/api/upload")
        self.assertFalse(out["accepted"])
        self.assertFalse(out["vulnerable"])

    @patch("tools.dyn_session.request")
    def test_retrievable_marks_webroot(self, mock_req):
        fn, content = ("gxmarker_X.jsp", "GXMARKER-X")
        mock_req.side_effect = [
            {"status": 200, "body": "ok", "elapsed": 0.0, "headers": {}},          # upload
            {"status": 200, "body": "GXMARKER-", "elapsed": 0.0, "headers": {}},   # retrieve
        ]
        with patch.object(A, "make_marker_upload", return_value=(fn, content, "")):
            out = A.run_upload("http://app.local", "/api/upload",
                               retrieve_base="http://app.local/files/")
        self.assertTrue(out["retrievable"])


if __name__ == "__main__":
    unittest.main()
