import importlib.util
import os
import unittest

_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_MOD = os.path.join(_ROOT, "skills", "auditing-web-application-security",
                    "scripts", "audit.py")
_spec = importlib.util.spec_from_file_location("audit", _MOD)
audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(audit)


class TestAccessDynamic(unittest.TestCase):
    def test_extract_access_candidates(self):
        static = {"by_skill": [
            {"skill": "detecting-csrf-vulnerabilities", "candidates": [1]},
            {"skill": "detecting-broken-access-control", "candidates": [{"rule_id": "x"}]},
        ]}
        self.assertEqual(audit._extract_access_candidates(static), [{"rule_id": "x"}])

    def test_no_creds_is_static_only(self):
        # 계정/토큰 미제공 → 동적 미확정(정적 추정)으로 표기, 발사하지 않음 (D/E)
        static = {"by_skill": [
            {"skill": "detecting-broken-access-control",
             "candidates": [{"rule_id": "spring-admin-no-preauthorize"}]}]}
        out = audit.run_access_dynamic("http://localhost:7171", static, {}, False)
        self.assertEqual(out["confidence"], "static-only")
        self.assertEqual(out["candidate_count"], 1)

    def test_no_candidates_skipped(self):
        static = {"by_skill": [{"skill": "detecting-csrf-vulnerabilities", "candidates": []}]}
        out = audit.run_access_dynamic("http://localhost:7171", static, {"token_a": "X"}, False)
        self.assertIn("skipped", out)


if __name__ == "__main__":
    unittest.main()
