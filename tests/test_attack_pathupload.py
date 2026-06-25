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


if __name__ == "__main__":
    unittest.main()
