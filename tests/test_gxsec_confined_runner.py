"""Reference runner tests use a synthetic child seam, never a real ZAP claim."""
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
spec = importlib.util.spec_from_file_location("confined_runner", Path(__file__).resolve().parents[1] / "scripts" / "gxsec-confined-runner.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
from gxsec.models import content_hash
from gxsec.dynamic import runtime_bundle_digest


class RunnerTests(unittest.TestCase):
    def plan(self):
        executable = Path(sys.executable).resolve()
        native = tempfile.TemporaryDirectory()
        self.addCleanup(native.cleanup)
        zap_root = Path(native.name) / "zap"
        java_home = Path(native.name) / "java"
        (zap_root / "plugin").mkdir(parents=True)
        (zap_root / "templates").mkdir()
        (java_home / "bin").mkdir(parents=True)
        (java_home / "lib").mkdir()
        launcher = zap_root / "zap.exe"
        shutil.copyfile(executable, launcher)
        (zap_root / "zap-2.16.1.jar").write_bytes(b"synthetic core JAR")
        (zap_root / "plugin" / "addon.zap").write_bytes(b"synthetic add-on archive")
        (zap_root / "templates" / "report.html").write_text("synthetic template", encoding="utf-8")
        (java_home / "bin" / "java.exe").write_bytes(b"synthetic Java executable")
        (java_home / "lib" / "modules").write_bytes(b"synthetic Java modules")
        files = {str(executable): hashlib.sha256(executable.read_bytes()).hexdigest()}
        files.update({str(path.resolve()): hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in Path(native.name).rglob("*") if path.is_file()})
        for package in ("gxsec", "yaml"):
            for root in importlib.util.find_spec(package).submodule_search_locations:
                for path in Path(root).rglob("*"):
                    if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                        files[str(path.resolve())] = hashlib.sha256(path.read_bytes()).hexdigest()
        result = {"schema_version": 1, "engine": {"name": "zap", "executable": str(launcher), "version": "2.16.1",
                "digest": "sha256:" + hashlib.sha256(executable.read_bytes()).hexdigest()},
                "bundle": {"immutable": True, "runtime_evidence_ref": "protected-test-image", "files": files,
                           "zap_runtime": {"zap_root": str(zap_root), "java_home": str(java_home),
                                           "java_executable": str(java_home / "bin" / "java.exe")}, "digest": content_hash(files)},
                "run_id": "synthetic-run", "broker_lease": {"enforced": True, "all_processes": True, "run_id": "synthetic-run"},
                "deadline_epoch": time.time() + 30,
                "source_revision": "a" * 40, "scope": {"origin": "http://fixture.test", "paths": ["/ok"], "allowed_ips": ["127.0.0.1"]},
                "budgets": {"max_duration_seconds": 30, "max_requests": 10}, "auth": {},
                "automation": {"env": {"contexts": []}, "jobs": []}, "confinement_record_id": "protected-confinement"}
        result["bundle"]["digest"] = runtime_bundle_digest(result["bundle"])
        return result

    def test_zap_runtime_tree_files_cannot_be_omitted_from_approved_manifest(self):
        for filename in ("zap-2.16.1.jar", "addon.zap", "report.html", "java.exe", "modules"):
            with self.subTest(filename=filename):
                plan = self.plan()
                key = next(path for path in plan["bundle"]["files"] if Path(path).name == filename)
                plan["bundle"]["files"].pop(key)
                plan["bundle"]["digest"] = runtime_bundle_digest(plan["bundle"])
                with self.assertRaises(ValueError):
                    runner.validate_runtime_bundle(plan["bundle"], "zap")

    def test_runtime_evidence_reference_is_bound_by_the_approved_digest(self):
        plan = self.plan()
        plan["bundle"]["runtime_evidence_ref"] = "different-unapproved-runtime"
        with self.assertRaises(ValueError):
            runner.validate_runtime_bundle(plan["bundle"], "zap")

    def test_modified_native_addon_or_outside_launcher_prevents_launch(self):
        for change in ("addon", "outside-launcher"):
            with self.subTest(change=change):
                plan = self.plan()
                if change == "addon":
                    addon = Path(plan["bundle"]["zap_runtime"]["zap_root"]) / "plugin" / "addon.zap"
                    addon.write_bytes(b"changed native add-on")
                else:
                    plan["engine"]["executable"] = sys.executable
                with patch.object(runner.subprocess, "run") as run, self.assertRaises(ValueError):
                    runner.execute_plan(plan)
                run.assert_not_called()

    def test_empty_native_report_without_independent_coverage_is_not_complete(self):
        plan = self.plan()

        def child(command, **kwargs):
            self.assertEqual(kwargs["env"]["JAVA_HOME"], plan["bundle"]["zap_runtime"]["java_home"])
            self.assertEqual(kwargs["env"]["JRE_HOME"], plan["bundle"]["zap_runtime"]["java_home"])
            self.assertTrue(kwargs["env"]["PATH"].startswith(str(Path(plan["bundle"]["zap_runtime"]["java_executable"]).parent)))
            self.assertIn("-dir", command)
            if command[-1] == "-version":
                return subprocess.CompletedProcess(command, 0, stdout="ZAP 2.16.1")
            self.assertEqual(command[1:3], ["-cmd", "-autorun"])
            self.assertTrue(Path(command[3]).is_file())
            (Path(kwargs["cwd"]) / "zap-report.json").write_text('{"site":[]}', encoding="utf-8")
            return subprocess.CompletedProcess(command, 0)

        with patch.object(runner, "_verify_auth", return_value={"a": {"Authorization": "Bearer fixture"}}), \
             patch.object(runner.subprocess, "run", side_effect=child) as run:
            with self.assertRaises(ValueError):
                runner.execute_plan(plan)
        self.assertEqual(run.call_count, 2)

    def test_engine_subprocess_does_not_inherit_any_secret_reference(self):
        plan = self.plan()

        def child(command, **kwargs):
            self.assertIsInstance(kwargs.get("env"), dict)
            self.assertFalse({"ADMIN_SECRET", "TEST_GX_A", "TEST_GX_B"} & set(kwargs["env"]))
            raise ValueError("stop after inspecting version command")

        with patch.dict("os.environ", {"ADMIN_SECRET": "admin", "TEST_GX_A": "a", "TEST_GX_B": "b"}), \
             patch.object(runner.subprocess, "run", side_effect=child) as run:
            with self.assertRaises(ValueError):
                runner.execute_plan(plan)
        self.assertEqual(run.call_count, 1)

    def test_changed_executable_digest_prevents_engine_launch(self):
        plan = self.plan()
        plan["engine"]["digest"] = "sha256:" + "0" * 64
        with patch.object(runner.subprocess, "run") as run, self.assertRaises(ValueError):
            runner.execute_plan(plan)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
