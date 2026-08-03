"""버전 표기가 저장소 전역에서 일치하는지 검증(P5 버전 파편화 재발 방지)."""
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPECTED = "0.8.0"


class TestVersionConsistency(unittest.TestCase):
    def test_plugin_json_version(self):
        data = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
        self.assertEqual(data["version"], EXPECTED)

    def test_marketplace_json_versions(self):
        data = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
        self.assertEqual(data["metadata"]["version"], EXPECTED)
        self.assertEqual(data["plugins"][0]["version"], EXPECTED)

    def test_readme_footer_current(self):
        txt = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(EXPECTED, txt)
        self.assertNotIn("v0.3.0", txt)

    def test_changelog_has_current_entry(self):
        txt = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn(f"[{EXPECTED}]", txt)

    def test_skill_md_versions(self):
        skill_files = sorted(ROOT.glob("skills/*/SKILL.md"))
        self.assertGreaterEqual(
            len(skill_files), 16, "skills/*/SKILL.md 파일이 16개 미만으로 발견됨(버전 정합 대상 누락 가능)"
        )
        for path in skill_files:
            txt = path.read_text(encoding="utf-8")
            self.assertIn(f'version: "{EXPECTED}"', txt, f"{path}: frontmatter version이 {EXPECTED}가 아님")
            self.assertNotIn('"0.3.0"', txt, f"{path}: 구버전 0.3.0 잔존")
