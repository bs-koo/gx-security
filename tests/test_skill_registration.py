"""Exercise registration with temporary bundles and skill roots, never the user profile."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "register-codex-skills.ps1"
POWERSHELL = shutil.which("pwsh") or shutil.which("powershell")


@unittest.skipUnless(POWERSHELL, "PowerShell is required for registration behavior tests")
class SkillRegistrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gxsec-registration-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.bundle = self.base / "trusted bundle"
        self.skills = self.base / "local skills"
        files = {
            "gxsec.py": "# fixture runner\n",
            "scripts/gxsec.ps1": "# fixture runner\n",
            "tools/dyn_session.py": "# fixture helper\n",
            ".claude-plugin/plugin.json": '{"name":"gx-security"}',
            "skills/gx-security/SKILL.md": "---\nname: gx-security\ndescription: fixture\n---\n",
            "skills/gx-security/references/runtime.md": "fixture resource\n",
            "skills/checking-release-security/SKILL.md": "---\nname: checking-release-security\ndescription: fixture\n---\n",
        }
        for relative, content in files.items():
            file = self.bundle / relative
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(content, encoding="utf-8")

    def run_registration(self, *args):
        return subprocess.run(
            [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-File", str(SCRIPT), "-BundleRoot", str(self.bundle),
             "-SkillsDirectory", str(self.skills), *args],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=40,
        )

    def unlink_registrations(self):
        # Remove only known junction/symlink entries; never recurse into the source.
        for name in ("gx-security", "checking-release-security"):
            entry = self.skills / name
            if entry.is_symlink():
                entry.unlink()
            elif os.name == "nt" and entry.exists() and entry.resolve() != entry.absolute():
                os.rmdir(entry)

    def test_links_preserve_bundle_resources_and_realpath(self):
        self.addCleanup(self.unlink_registrations)
        result = self.run_registration()
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(result.stdout)
        self.assertEqual(len(record["skills"]), 2)
        skill = self.skills / "gx-security"
        self.assertEqual(skill.resolve(), (self.bundle / "skills/gx-security").resolve())
        self.assertEqual((skill / "references/runtime.md").read_text(), "fixture resource\n")
        self.assertTrue((skill.resolve().parents[1] / "gxsec.py").is_file())

    def test_same_registration_is_idempotent(self):
        self.addCleanup(self.unlink_registrations)
        self.assertEqual(self.run_registration().returncode, 0)
        result = self.run_registration()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({x["action"] for x in json.loads(result.stdout)["skills"]}, {"already-linked"})

    def test_existing_skill_aborts_before_any_links_are_created(self):
        existing = self.skills / "gx-security"
        existing.mkdir(parents=True)
        marker = existing / "keep.txt"
        marker.write_text("user owned", encoding="utf-8")
        result = self.run_registration()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker.read_text(), "user owned")
        self.assertFalse((self.skills / "checking-release-security").exists())

    def test_conflicting_other_bundle_link_is_preserved(self):
        self.addCleanup(self.unlink_registrations)
        self.assertEqual(self.run_registration().returncode, 0)
        original = self.bundle
        other = self.base / "other bundle"
        shutil.copytree(original, other)
        self.bundle = other
        result = self.run_registration()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.skills / "gx-security").resolve(), (original / "skills/gx-security").resolve())

    def test_incomplete_bundle_does_not_create_destination(self):
        (self.bundle / "tools/dyn_session.py").unlink()
        result = self.run_registration()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.skills.exists())

    def test_whatif_does_not_write_destination(self):
        result = self.run_registration("-WhatIf")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.skills.exists())


if __name__ == "__main__":
    unittest.main()
