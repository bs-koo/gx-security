# tests/test_dyn_session.py
import unittest
from tools import dyn_session


class TestHelpers(unittest.TestCase):
    def test_mask_token_short(self):
        self.assertEqual(dyn_session.mask_token("abc"), "****")

    def test_mask_token_long(self):
        self.assertEqual(dyn_session.mask_token("abcdefghijkl"), "abcd…ijkl")

    def test_mask_token_none(self):
        self.assertEqual(dyn_session.mask_token(None), "<none>")

    def test_extract_by_path_nested(self):
        obj = {"data": {"accessToken": "TKN"}}
        self.assertEqual(dyn_session.extract_by_path(obj, "data.accessToken"), "TKN")

    def test_extract_by_path_missing(self):
        self.assertIsNone(dyn_session.extract_by_path({"data": {}}, "data.accessToken"))

    def test_reexports_scope(self):
        self.assertTrue(hasattr(dyn_session, "assert_in_scope"))
        self.assertTrue(hasattr(dyn_session, "ScopeError"))


if __name__ == "__main__":
    unittest.main()
