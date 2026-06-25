import importlib.util
import os
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

    @patch("tools.dyn_session.request")
    def test_relative_location_defended(self, mock_req):
        mock_req.return_value = {"status": 302, "body": "", "elapsed": 0.0,
                                 "headers": {"Location": "/siteMain.do"}}
        out = attack_ssrf.run_open_redirect("http://app.local", "/go?u=", "app.local")
        self.assertFalse(out["vulnerable"])


if __name__ == "__main__":
    unittest.main()
