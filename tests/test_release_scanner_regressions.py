"""Release reliability regressions through real scanner/launcher entry points."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCANNERS = sorted(ROOT.glob("skills/detecting-*/scripts/scan_*.py"))


def load(path):
    spec = importlib.util.spec_from_file_location(path.stem + "_release", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def scanner(name):
    return load(next(p for p in SCANNERS if p.stem == "scan_" + name))


def run_main(module, target, *args):
    buf = io.StringIO()
    with patch.object(sys, "argv", [module.__file__, str(target), "--json", *args]), contextlib.redirect_stdout(buf):
        code = module.main()
    return code, json.loads(buf.getvalue())


class TestReleaseScannerRegressions(unittest.TestCase):
    def test_unlabelled_debug_literal_is_absent_from_json_and_text(self):
        literal = "syntheticUnlabelledSecret123"
        mod = scanner("secrets")
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "Debug.java").write_text('class Debug { void log() { System.out.println("' + literal + '"); } }', encoding="utf-8")
            with patch.dict(os.environ, {"GXSEC_NO_SEMGREP": "1"}):
                _, data = run_main(mod, tmp)
                output = io.StringIO()
                with patch.object(sys, "argv", [mod.__file__, tmp]), contextlib.redirect_stdout(output):
                    mod.main()
        self.assertIn("debug-output-residue", {c["rule_id"] for c in data["candidates"]})
        self.assertNotIn(literal, json.dumps(data))
        self.assertNotIn(literal, output.getvalue())

    def test_nested_semgrep_diagnostic_source_is_never_exported(self):
        literal = "syntheticNestedDiagnosticSecret123"
        mod = scanner("xss")
        error = {"type": "PartialParsing", "code": 3, "message": literal, "spans": [{"file": "Ctrl.java", "start": {"line": 1, "col": 2}, "end": {"line": 1, "col": 8}, "source": literal}], "detail": {"spans": [{"source": literal}]}}
        payload = {"results": [], "errors": [error], "paths": {"scanned": ["Ctrl.java"]}, "version": "test"}
        with tempfile.TemporaryDirectory() as tmp, patch.object(mod.shutil, "which", return_value="semgrep"), patch.dict(os.environ, {"GXSEC_NO_SEMGREP": ""}), patch.object(mod.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(payload), "")):
            _, data = run_main(mod, tmp)
            output = io.StringIO()
            with patch.object(sys, "argv", [mod.__file__, tmp]), contextlib.redirect_stdout(output):
                mod.main()
        self.assertNotIn(literal, json.dumps(data))
        self.assertNotIn(literal, output.getvalue())
        self.assertNotIn("source", json.dumps(data["errors"]))
        self.assertEqual(data["errors"][0]["type"], "PartialParsing")
        self.assertEqual(data["errors"][0]["code"], 3)

    def test_fallback_secret_exports_keep_locations_and_mask_literals(self):
        mod = scanner("secrets")
        secret = "syntheticHardcodedSecret123"
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, ".env").write_text("DATABASE_PASSWORD=" + secret, encoding="utf-8")
            Path(tmp, "app.js").write_text('const password = "' + secret + '"; const host = "${HOST}";', encoding="utf-8")
            with patch.dict(os.environ, {"GXSEC_NO_SEMGREP": "1"}):
                _, data = run_main(mod, tmp)
                buf = io.StringIO()
                with patch.object(sys, "argv", [mod.__file__, tmp]), contextlib.redirect_stdout(buf):
                    mod.main()
            self.assertEqual({Path(c["file"]).name for c in data["candidates"]}, {".env", "app.js"})
            self.assertNotIn(secret, json.dumps(data))
            self.assertNotIn(secret, buf.getvalue())

    def test_redaction_preserves_rule_summary_and_standalone_is_safe(self):
        from tools import redaction
        payload = {"rule_summary": {"value-annotation-default-secret": 1}, "candidates": [{"file": "config.xml", "line": 2, "rule_id": "hardcoded-password-xml", "snippet": '<property name="password" value="syntheticXmlSecret"/>'}], "errors": ["password=syntheticErrorSecret"]}
        for standalone in (False, True):
            with self.subTest(standalone=standalone), patch.object(redaction, "_SHARED", None if standalone else redaction._SHARED):
                safe = redaction.redact(payload)
            self.assertEqual(safe["rule_summary"], payload["rule_summary"])
            self.assertEqual(safe["candidates"][0]["file"], "config.xml")
            self.assertNotIn("syntheticXmlSecret", json.dumps(safe))
            self.assertNotIn("syntheticErrorSecret", json.dumps(safe))

    def test_mixed_placeholder_does_not_hide_hardcoded_secret(self):
        mod = scanner("secrets")
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "app.js").write_text('const password = "syntheticHardcodedSecret"; const host = "${HOST}";', encoding="utf-8")
            self.assertIn("hardcoded-credential-frontend", {c["rule_id"] for c in mod.run_fallback(tmp)})

    def test_all_scanners_reject_malformed_coverage_paths(self):
        for scanned, skipped in (([None], []), ([""], []), ([42], []), (["Ctrl.java"], [None]), (["Ctrl.java"], [{"path": None, "reason": "ignore"}]), (["Ctrl.java"], [{"path": "a.java", "reason": None}])):
            for path in SCANNERS:
                with self.subTest(scanner=path.stem, scanned=scanned, skipped=skipped), tempfile.TemporaryDirectory() as tmp:
                    mod = load(path)
                    payload = {"results": [], "errors": [], "paths": {"scanned": scanned, "skipped": skipped}, "version": "test"}
                    with patch.object(mod.shutil, "which", return_value="semgrep"), patch.dict(os.environ, {"GXSEC_NO_SEMGREP": ""}), patch.object(mod.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(payload), "")):
                        code, data = run_main(mod, tmp)
                    self.assertEqual(code, 2)
                    self.assertEqual(data["execution_status"], "incomplete")

    def test_all_scanner_json_masks_source_and_engine_errors(self):
        secret = "syntheticLeakedSecret123"
        for path in SCANNERS:
            with self.subTest(scanner=path.stem), tempfile.TemporaryDirectory() as tmp:
                mod = load(path)
                payload = {"results": [{"path": "Ctrl.java", "check_id": "synthetic-rule", "start": {"line": 1}, "extra": {"lines": 'const password = "' + secret + '";'}}], "errors": [{"message": "password=" + secret}], "paths": {"scanned": ["Ctrl.java"]}, "version": "test"}
                with patch.object(mod.shutil, "which", return_value="semgrep"), patch.dict(os.environ, {"GXSEC_NO_SEMGREP": ""}), patch.object(mod.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(payload), "")):
                    _, data = run_main(mod, tmp)
                self.assertNotIn(secret, json.dumps(data))
                self.assertEqual(data["candidates"][0]["file"], "Ctrl.java")
                self.assertEqual(data["candidates"][0]["rule_id"], "synthetic-rule")

    def test_launcher_masks_child_stderr_and_summary(self):
        mod = load(ROOT / "scan_all.py")
        secret = "syntheticStderrSecret123"
        with patch.object(mod.subprocess, "run", return_value=subprocess.CompletedProcess([], 2, "", "password=" + secret)):
            _, error = mod.run_one("scanner.py", "source")
        self.assertNotIn(secret, error)
        child = {"candidate_count": 0, "candidates": [], "error": "password=" + secret}
        with tempfile.TemporaryDirectory() as tmp, patch.object(mod, "find_scanners", return_value=[("xss", "scanner.py")]), patch.object(mod, "run_one", return_value=(child, None)):
            _, data = run_main(mod, tmp)
        self.assertNotIn(secret, json.dumps(data))

    def test_launcher_cannot_trust_completion_without_coverage(self):
        mod = load(ROOT / "scan_all.py")
        child = {"candidate_count": 0, "candidates": [], "engine": "semgrep", "execution_status": "complete", "errors": []}
        with tempfile.TemporaryDirectory() as tmp, patch.object(mod, "find_scanners", return_value=[("xss", "xss.py")]), patch.object(mod, "run_one", return_value=(child, None)):
            code, data = run_main(mod, tmp)
        self.assertEqual(code, 2)
        self.assertEqual(data["execution_status"], "incomplete")

    def test_semgrep_missing_version_cannot_claim_complete(self):
        mod = scanner("xss")
        payload = {"results": [], "errors": [], "paths": {"scanned": ["app.js"]}}
        with tempfile.TemporaryDirectory() as tmp, patch.object(mod.shutil, "which", return_value="semgrep"), patch.dict(os.environ, {"GXSEC_NO_SEMGREP": ""}), patch.object(mod.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(payload), "")):
            code, data = run_main(mod, tmp)
        self.assertEqual(code, 2)
        self.assertEqual(data["execution_status"], "incomplete")

    def test_malformed_semgrep_findings_produce_json_incomplete(self):
        malformed = [
            {"path": "Ctrl.java", "check_id": "rule", "start": {"line": 1}, "extra": None},
            {"path": "Ctrl.java", "check_id": "rule", "start": {"line": 1}, "extra": {"metadata": []}},
            {"path": "Ctrl.java", "check_id": None, "start": {"line": 1}, "extra": {}},
            {"path": "Ctrl.java", "check_id": "rule", "start": {"line": 1}, "extra": {"lines": 123}},
        ]
        for path in SCANNERS:
            for finding in malformed:
                with self.subTest(scanner=path.stem, finding=finding), tempfile.TemporaryDirectory() as tmp:
                    Path(tmp, "Ctrl.java").write_text("class Ctrl {}", encoding="utf-8")
                    mod = load(path)
                    payload = {"results": [finding], "errors": [], "paths": {"scanned": ["Ctrl.java"]}, "version": "test"}
                    with patch.object(mod.shutil, "which", return_value="semgrep"), patch.dict(os.environ, {"GXSEC_NO_SEMGREP": ""}), patch.object(mod.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(payload), "")):
                        code, data = run_main(mod, tmp)
                    self.assertEqual(code, 2)
                    self.assertEqual(data["execution_status"], "incomplete")
                    self.assertEqual(data["engine"], "grep-fallback")

    def test_dynamic_jsp_escape_setting_is_not_proof_of_safety(self):
        mod = scanner("xss")
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "view.jsp").write_text('<c:out value="${unsafe.title}" escapeXml="${param.escape}"/>', encoding="utf-8")
            self.assertIn("jsp-el-unescaped-model", {c["rule_id"] for c in mod.run_fallback(tmp)})

    def test_jsp_rule_does_not_suppress_property_named_escape_xml(self):
        import yaml
        rules = yaml.safe_load((ROOT / "skills/detecting-xss-vulnerabilities/rules/xss.yml").read_text(encoding="utf-8"))["rules"]
        model = next(rule for rule in rules if rule["id"] == "sqisoft-jsp-el-unescaped-model-attr")
        self.assertFalse(any("escapeXml" in pattern.get("pattern-not-regex", "") for pattern in model["patterns"]))

    def test_semgrep_ownership_candidate_retains_context(self):
        mod = scanner("access")
        body = 'class Ctrl {\n @PreAuthorize("isAuthenticated()")\n @GetMapping("/{id}")\n public String get(@PathVariable Long id, @AuthenticationPrincipal User user) {\n return userService.findById(id);\n }\n}'
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "Ctrl.java")
            path.write_text(body, encoding="utf-8")
            payload = {"results": [{"path": str(path), "check_id": "sqisoft-spring-pathvariable-id-no-ownership-check", "start": {"line": 2}, "end": {"line": 6}, "extra": {}}], "errors": [], "paths": {"scanned": [str(path)]}}
            with patch.object(mod.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(payload), "")):
                findings, error = mod.run_semgrep(tmp)
        self.assertIsNone(error)
        self.assertEqual(len(findings), 1)
        self.assertIn("PreAuthorize", " ".join(findings[0]["context"]["annotations"]))
        self.assertIn("AuthenticationPrincipal", findings[0]["context"]["method"])
        self.assertEqual(findings[0]["confidence"], "needs-context")

    def test_path_rules_cannot_drop_candidate_for_unrelated_canonical_call(self):
        import yaml
        for skill in ("detecting-path-traversal", "detecting-file-upload-vulnerabilities"):
            for file in (ROOT / "skills" / skill / "rules").glob("*.yml"):
                for rule in yaml.safe_load(file.read_text(encoding="utf-8"))["rules"]:
                    for pattern in rule.get("patterns", []):
                        if any(key.startswith("pattern-not") for key in pattern):
                            self.assertNotIn("getCanonicalPath", str(pattern), rule["id"])
                            self.assertNotIn("$Y.startsWith", str(pattern), rule["id"])

    def test_all_scanners_execution_failures_remain_incomplete_after_fallback(self):
        for failure in (subprocess.TimeoutExpired("semgrep", 1), subprocess.CompletedProcess([], 2, "not JSON", "source may contain secrets")):
            for path in SCANNERS:
                with self.subTest(scanner=path.stem, failure=type(failure).__name__), tempfile.TemporaryDirectory() as tmp:
                    Path(tmp, "Ctrl.java").write_text("class Ctrl {}", encoding="utf-8")
                    mod = load(path)
                    behavior = {"side_effect": failure} if isinstance(failure, Exception) else {"return_value": failure}
                    with patch.object(mod.shutil, "which", return_value="semgrep"), patch.dict(os.environ, {"GXSEC_NO_SEMGREP": ""}), patch.object(mod.subprocess, "run", **behavior):
                        code, data = run_main(mod, tmp)
                    self.assertEqual(code, 2)
                    self.assertEqual(data["engine"], "grep-fallback")
                    self.assertEqual(data["execution_status"], "incomplete")
                    self.assertTrue(data["errors"])

    def test_launcher_rejects_malformed_child_candidate_count(self):
        mod = load(ROOT / "scan_all.py")
        malformed = {"candidate_count": "zero", "candidates": [], "detected_stacks": []}
        with patch.object(mod.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(malformed), "")):
            data, error = mod.run_one("scanner.py", "project")
        self.assertIsNone(data)
        self.assertTrue(error)

    def test_frontend_rules_are_loaded_by_actual_entry(self):
        mod = scanner("xss")
        payload = {"results": [], "errors": [], "paths": {"scanned": ["App.vue"]}, "version": "test"}
        with patch.object(mod.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(payload), "")) as run:
            mod.run_semgrep("project")
        configs = [run.call_args.args[0][i + 1] for i, arg in enumerate(run.call_args.args[0][:-1]) if arg == "--config"]
        self.assertTrue(any(Path(p).name == "xss-frontend.yml" for p in configs), configs)
        self.assertIn("--verbose", run.call_args.args[0])
        self.assertIn("--metrics=off", run.call_args.args[0])

    def test_mixed_jsp_retains_unescaped_expression(self):
        mod = scanner("xss")
        for body in ('<c:out value="${safe.title}"/> ${unsafe.title}', '<c:if test="${safe.visible}">${unsafe.title}</c:if>'):
            with self.subTest(body=body), tempfile.TemporaryDirectory() as tmp:
                Path(tmp, "view.jsp").write_text(body, encoding="utf-8")
                self.assertIn("jsp-el-unescaped-model", {c["rule_id"] for c in mod.run_fallback(tmp)})

    def test_semgrep_mixed_jsp_uses_match_span(self):
        mod = scanner("xss")
        body = '<c:if test="${safe.visible}">${unsafe.title}</c:if>'
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "view.jsp")
            path.write_text(body, encoding="utf-8")
            start = body.index("${unsafe") + 1
            payload = {"results": [{"path": str(path), "check_id": "sqisoft-jsp-el-unescaped-model-attr", "start": {"line": 1, "col": start}, "end": {"line": 1, "col": start + len("${unsafe.title}")}, "extra": {}}], "errors": [], "paths": {"scanned": [str(path)]}}
            with patch.object(mod.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(payload), "")):
                findings, error = mod.run_semgrep(tmp)
            self.assertIsNone(error)
            self.assertEqual(len(findings), 1)

    def test_secret_sources_include_dotenv_and_frontend(self):
        mod = scanner("secrets")
        sources = {".env": "DATABASE_PASSWORD=syntheticSecret123!", ".env.production": "API_KEY=syntheticSecret456!", "config.ts": 'export const apiKey = "syntheticSecret789!";', "auth.js": 'const password = "syntheticSecret987!";'}
        with tempfile.TemporaryDirectory() as tmp:
            for name, text in sources.items():
                Path(tmp, name).write_text(text, encoding="utf-8")
            names = {Path(c["file"]).name for c in mod.run_fallback(tmp)}
        self.assertEqual(names, set(sources))

    def test_semgrep_ownership_annotations_do_not_suppress_candidates(self):
        import yaml
        rules = yaml.safe_load((ROOT / "skills/detecting-broken-access-control/rules/access-control.yml").read_text(encoding="utf-8"))["rules"]
        for rule in rules:
            if "pathvariable" not in rule["id"]:
                continue
            for pattern in rule["patterns"]:
                if any(key.startswith("pattern-not") for key in pattern):
                    self.assertNotRegex(str(pattern), "AuthenticationPrincipal|PreAuthorize|PostAuthorize|Secured")

    def test_all_scanners_surface_semgrep_errors_and_fallback_coverage(self):
        payload = {"results": [], "errors": [{"type": "ParseError", "message": "synthetic parse failure"}], "paths": {"scanned": ["Ctrl.java"], "skipped": [{"path": "Skipped.java", "reason": "parse error"}]}, "version": "1.test"}
        for path in SCANNERS:
            with self.subTest(scanner=path.stem), tempfile.TemporaryDirectory() as tmp:
                Path(tmp, "Ctrl.java").write_text('class Ctrl { String password = "syntheticSecret123!"; }', encoding="utf-8")
                mod = load(path)
                with patch.object(mod.shutil, "which", return_value="semgrep"), patch.dict(os.environ, {"GXSEC_NO_SEMGREP": ""}), patch.object(mod.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(payload), "")):
                    code, data = run_main(mod, tmp)
                self.assertEqual(code, 2)
                self.assertEqual(data["execution_status"], "incomplete")
                self.assertTrue(data["errors"])
                self.assertIn("semgrep", data["engine_metadata"])
                self.assertEqual(data["engine_metadata"]["semgrep"]["version"], "1.test")
                self.assertTrue(data["engine_metadata"]["semgrep"]["coverage"]["ignored_files"])
                self.assertGreater(data["coverage"]["parsed_file_count"], 0)

    def test_all_scanners_zero_semgrep_files_are_incomplete(self):
        payload = {"results": [], "errors": [], "paths": {"scanned": [], "skipped": [{"path": "ignored.java", "reason": "ignore"}]}}
        for path in SCANNERS:
            with self.subTest(scanner=path.stem), tempfile.TemporaryDirectory() as tmp:
                mod = load(path)
                with patch.object(mod.shutil, "which", return_value="semgrep"), patch.dict(os.environ, {"GXSEC_NO_SEMGREP": ""}), patch.object(mod.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(payload), "")):
                    code, data = run_main(mod, tmp)
                self.assertEqual(code, 2)
                self.assertEqual(data["execution_status"], "incomplete")
                self.assertTrue(data["errors"])
                self.assertEqual(data["coverage"]["parsed_file_count"], 0)

    def test_fallback_is_degraded_and_reports_ignored_long_lines(self):
        mod = scanner("xss")
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "app.js").write_text("x" * 6000 + ".innerHTML = input", encoding="utf-8")
            with patch.dict(os.environ, {"GXSEC_NO_SEMGREP": "1"}):
                code, data = run_main(mod, tmp)
        self.assertEqual(code, 0)
        self.assertEqual(data["execution_status"], "degraded")
        self.assertEqual(data["coverage"]["parsed_file_count"], 1)
        self.assertTrue(any(item["reason"] == "line_too_long" for item in data["coverage"]["ignored_files"]))

    def test_launcher_empty_selection_returns_two(self):
        mod = load(ROOT / "scan_all.py")
        with tempfile.TemporaryDirectory() as tmp:
            for selection in ("", ",", "not-a-scanner"):
                with self.subTest(selection=selection):
                    code, data = run_main(mod, tmp, "--only", selection)
                    self.assertEqual(code, 2)
                    self.assertEqual(data["execution_status"], "incomplete")
                    self.assertTrue(data["errors"])

    def test_launcher_timeout_is_nonzero_and_child_metadata_survives(self):
        mod = load(ROOT / "scan_all.py")
        child = {"candidate_count": 0, "candidates": [], "engine": "semgrep", "execution_status": "incomplete", "errors": ["parse error"], "coverage": {"parsed_file_count": 0}, "engine_metadata": {"semgrep": {"version": "test"}}, "rule_summary": {}}
        with tempfile.TemporaryDirectory() as tmp, patch.object(mod, "find_scanners", return_value=[("xss", "xss.py"), ("csrf", "csrf.py")]), patch.object(mod, "run_one", side_effect=[(None, "timeout"), (child, None)]):
            code, data = run_main(mod, tmp)
        self.assertEqual(code, 2)
        self.assertEqual(data["execution_status"], "incomplete")
        self.assertEqual(data["by_skill"][1]["coverage"], child["coverage"])
        self.assertEqual(data["by_skill"][1]["engine_metadata"], child["engine_metadata"])


@unittest.skipUnless(shutil.which("semgrep") and not os.environ.get("GXSEC_NO_SEMGREP"), "real Semgrep smoke is opt-in outside deterministic fallback runs")
class TestRealReleaseScannerWiring(unittest.TestCase):
    def scan(self, name, files):
        path = next(path for path in SCANNERS if path.stem == "scan_" + name)
        with tempfile.TemporaryDirectory(prefix="gxsec_release_") as tmp:
            for filename, content in files.items():
                Path(tmp, filename).parent.mkdir(parents=True, exist_ok=True)
                Path(tmp, filename).write_text(content, encoding="utf-8")
            env = dict(os.environ, SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0", PYTHONUTF8="1")
            env.pop("GXSEC_NO_SEMGREP", None)
            proc = subprocess.run([sys.executable, str(path), tmp, "--json"], capture_output=True, text=True, encoding="utf-8", timeout=180, env=env)
            data = json.loads(proc.stdout)
        self.assertEqual(data["engine"], "semgrep", data.get("errors"))
        self.assertEqual(data["execution_status"], "complete", data.get("errors"))
        self.assertTrue(data["engine_metadata"]["semgrep"]["version"])
        self.assertEqual(proc.returncode, 0, proc.stderr[:300])
        return data

    def test_frontend_and_mixed_jsp_actual_semgrep(self):
        data = self.scan("xss", {"App.vue": '<template><div v-html="body"/></template>\n<script>eval(code); el.outerHTML = raw;</script>', "view.jsp": '<c:if test="${safe.visible}">${unsafe.title}</c:if>\n${record.escapeXml}', "node_modules/ignored.js": "eval(code);"})
        ids = {c["rule_id"] for c in data["candidates"]}
        self.assertTrue({"sqisoft-vue-v-html-unsanitized", "sqisoft-dom-insertadjacenthtml-outerhtml", "sqisoft-js-eval-dynamic-code", "sqisoft-jsp-el-unescaped-model-attr"}.issubset(ids), ids)
        self.assertTrue(data["coverage"]["ignored_files"])
        self.assertEqual({c["line"] for c in data["candidates"] if c["rule_id"] == "sqisoft-jsp-el-unescaped-model-attr"}, {1, 2})

    def test_dotenv_and_frontend_actual_semgrep(self):
        sources = {".env": "DATABASE_PASSWORD=syntheticSecret123!", ".env.production": "API_KEY=syntheticSecret456!", "config.ts": 'export const apiKey = "syntheticSecret789!";', "auth.js": 'const password = "syntheticSecret987!";'}
        data = self.scan("secrets", sources)
        self.assertEqual({Path(c["file"]).name for c in data["candidates"]}, set(sources))

    def test_annotations_preserve_actual_semgrep_ownership_candidate(self):
        data = self.scan("access", {"Ctrl.java": 'class Ctrl {\n @PreAuthorize("isAuthenticated()")\n @GetMapping("/{id}")\n public String get(@PathVariable Long id, @AuthenticationPrincipal User user) {\n return userService.findById(id);\n }\n}'})
        candidates = [c for c in data["candidates"] if c["rule_id"] == "sqisoft-spring-pathvariable-id-no-ownership-check"]
        self.assertEqual(len(candidates), 1)
        self.assertIn("PreAuthorize", " ".join(candidates[0]["context"]["annotations"]))
        self.assertEqual(candidates[0]["confidence"], "needs-context")


if __name__ == "__main__":
    unittest.main()
