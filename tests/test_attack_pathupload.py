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

    def test_does_not_double_encode(self):
        # 이미 인코딩된 변형(%2e%2e%2f)을 추가 인코딩하지 않아야 함(Critical 리뷰 반영)
        url = A._inject("http://h", "/d?f=", "%2e%2e%2fetc%2fpasswd")
        self.assertIn("%2e%2e%2f", url)
        self.assertNotIn("%252e", url)
        # 평문 ../ 도 그대로 전달
        self.assertTrue(A._inject("http://h", "/d?f=", "../../etc/passwd").endswith("../../etc/passwd"))


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
            {"status": 200, "body": "ok", "elapsed": 0.0, "headers": {}},              # upload
            {"status": 200, "body": "...GXMARKER-X...", "elapsed": 0.0, "headers": {}},  # 회수 본문에 전체 마커
        ]
        with patch.object(A, "make_marker_upload", return_value=(fn, content, "")):
            out = A.run_upload("http://app.local", "/api/upload",
                               retrieve_base="http://app.local/files/")
        self.assertTrue(out["retrievable"])

    @patch("tools.dyn_session.request")
    def test_partial_marker_not_retrievable(self, mock_req):
        # 회수 본문에 nonce 없는 접두('GXMARKER')만 있으면 웹루트 저장으로 오인하지 않는다(리뷰 반영)
        fn, content = ("gxmarker_X.jsp", "GXMARKER-X")
        mock_req.side_effect = [
            {"status": 200, "body": "ok", "elapsed": 0.0, "headers": {}},            # upload
            {"status": 200, "body": "GXMARKER docs page", "elapsed": 0.0, "headers": {}},  # 접두만
        ]
        with patch.object(A, "make_marker_upload", return_value=(fn, content, "")):
            out = A.run_upload("http://app.local", "/api/upload",
                               retrieve_base="http://app.local/files/")
        self.assertFalse(out["retrievable"])


class TestClassifyCandidates(unittest.TestCase):
    def test_splits_traversal_and_upload(self):
        data = {"candidates": [
            {"file": "DownloadController.java", "line": 40,
             "snippet": 'new File(baseDir, request.getParameter("filePath"))'},
            {"file": "UploadController.java", "line": 87,
             "snippet": 'multipartFile.transferTo(dest)'},
        ]}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                         encoding="utf-8") as f:
            json.dump(data, f)
            path = f.name
        try:
            out = A._classify_candidates(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(out["traversal"]), 1)
        self.assertEqual(len(out["upload"]), 1)
        self.assertEqual(out["traversal"][0]["param"], "filePath")


class TestRunGates(unittest.TestCase):
    @patch("tools.dyn_session.assert_in_scope")
    def test_scope_block_exits_1(self, mock_scope):
        mock_scope.side_effect = A.dyn_session.ScopeError("운영 차단")
        args = A._build_parser().parse_args(
            ["http://prod.example.com", "--traversal-target", "/d?f="])
        with self.assertRaises(SystemExit) as cm:
            A.run(args)
        self.assertEqual(cm.exception.code, 1)

    @patch("tools.dyn_session.assert_in_scope", return_value="loopback")
    @patch.object(attack_pathupload, "run_upload")
    def test_upload_skipped_without_destructive(self, mock_up, _scope):
        args = A._build_parser().parse_args(
            ["http://localhost:7171", "--upload-target", "/api/upload", "--json"])
        A.run(args)
        mock_up.assert_not_called()


if __name__ == "__main__":
    unittest.main()
