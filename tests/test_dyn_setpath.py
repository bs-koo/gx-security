"""set_by_path(D4 JSON 주입 지점 지정) 단위 검증."""
import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools import dyn_session


class TestSetByPath(unittest.TestCase):
    def test_top_level(self):
        self.assertEqual(dyn_session.set_by_path({}, "q", "X"), {"q": "X"})

    def test_nested_creates_intermediate(self):
        self.assertEqual(dyn_session.set_by_path({}, "data.query", "X"),
                         {"data": {"query": "X"}})

    def test_preserves_siblings(self):
        base = {"data": {"keep": 1}}
        out = dyn_session.set_by_path(base, "data.query", "X")
        self.assertEqual(out, {"data": {"keep": 1, "query": "X"}})


if __name__ == "__main__":
    unittest.main()
