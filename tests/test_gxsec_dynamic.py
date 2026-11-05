import copy
import hashlib
import hmac
import importlib.util
import json
import os
import subprocess
import sys
import shutil
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from gxsec.dynamic import discover_endpoints, generate_zap_plan, run_dynamic_checks, run_confined_engine, runtime_bundle_digest
from gxsec.models import content_hash
from gxsec.transport import BoundedTransport


class Fixture(BaseHTTPRequestHandler):
    hits = []
    mode = "denied"
    nonce = "fixture-nonce-94721"

    def do_GET(self):
        token = self.headers.get("Authorization", "").replace("Bearer ", "")
        type(self).hits.append((self.path, token))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if self.path == "/me":
            value = {"id": token} if token in {"A", "B"} else {"error": "login required"}
        elif self.path == "/objects/a":
            value = ({"nonce": self.nonce} if token == "A" or self.mode == "vulnerable"
                     and token == "B" else {"error": "access denied"})
        else:
            value = {"error": "missing"}
        self.wfile.write(json.dumps(value).encode())

    def log_message(self, *_):
        pass


class DynamicTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        Fixture.hits.clear()
        Fixture.mode = "denied"
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.source = Path(self.tmp.name)
        self.protected = tempfile.TemporaryDirectory()
        self.addCleanup(self.protected.cleanup)
        self.protected_path = Path(self.protected.name)
        git = Path(shutil.which("git")).resolve()
        runtime = self.protected_path / "runtime.json"
        runtime.write_text(json.dumps({"schema_version": 1, "tools": {
            "git": {"executable": str(git), "sha256": hashlib.sha256(git.read_bytes()).hexdigest()},
            "python": {"executable": sys.executable, "sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()}}}), encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(self.source)], check=True)
        subprocess.run(["git", "-C", str(self.source), "-c", "user.name=Fixture", "-c",
                        "user.email=fixture@example.invalid", "commit", "--allow-empty", "-qm", "fixture"], check=True)
        revision = subprocess.check_output(["git", "-C", str(self.source), "rev-parse", "HEAD"], text=True).strip()
        self.policy = {"enabled": True,
                       "target": {"origin": self.origin, "paths": ["/me", "/objects/a"],
                                  "allowed_ips": ["127.0.0.1"]},
                       "readiness": {"status": "verified", "synthetic_data": True, "isolated": True,
                                     "source_revision": revision, "deployment_revision": revision,
                                     "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                                     "evidence_ref": "protected-ci/fixture-readiness"},
                       "auth": {"verification": {"path": "/me", "identity_field": "$.id"},
                                "identities": {"a": {"secret_ref": "TEST_GX_A", "expected_id": "A"},
                                               "b": {"secret_ref": "TEST_GX_B", "expected_id": "B"}}},
                       "scenarios": [{"id": "object-a", "kind": "authorization", "path": "/objects/a",
                                      "method": "GET", "owner": "a", "subject": "b",
                                      "oracle": {"json_pointer": "/nonce", "expected": Fixture.nonce,
                                                 "denied": {"json_pointer": "/error", "expected": "access denied"}}}]}
        self.config = {"target": {"origin": self.origin}, "_trusted_policy": {"dynamic": self.policy}}
        self.env = patch.dict(os.environ, {"TEST_GX_A": json.dumps({"token": "A"}), "GXSEC_RUNTIME_MANIFEST": str(runtime),
                                          "GX_BROKER_VERIFY_KEY": "fixture-verification-key-" * 3,
                                          "TEST_GX_B": json.dumps({"token": "B"})})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_dry_run_is_default_even_with_ready_policy(self):
        checks, findings = run_dynamic_checks(self.source, self.config)
        self.assertFalse(Fixture.hits)
        self.assertFalse(findings)
        self.assertTrue(any(c["status"] != "complete" and c["required"] for c in checks))
        self.assertTrue({"readiness", "auth", "authorization", "dast"} <= {c["id"] for c in checks})
        self.assertIn("plan", next(c for c in checks if c["id"] == "dynamic:zap"))

    def test_readiness_must_cover_the_whole_planned_deadline(self):
        self.policy["readiness"]["expires_at"] = (datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat()
        checks, _ = run_dynamic_checks(self.source, self.config, execute=True)
        self.assertFalse(Fixture.hits)
        self.assertNotEqual(next(c for c in checks if c["id"] == "readiness")["status"], "complete")

    def test_unsigned_child_coverage_cannot_complete_an_engine(self):
        self.enable_runner()

        def forged_child(command, **kwargs):
            plan = json.loads(Path(command[2]).read_text(encoding="utf-8"))
            result = {"engine": plan["engine"], "execution_status": "complete", "plan_digest": content_hash(plan),
                      "source_revision": plan["source_revision"], "auth_verified": True,
                      "observed_paths": plan["scope"]["paths"], "job_tests_passed": True, "report": {"site": []}}
            Path(command[4]).write_text(json.dumps(result), encoding="utf-8")
            return subprocess.CompletedProcess(command, 0)

        with patch("gxsec.dynamic.subprocess.run", side_effect=forged_child), \
             patch("gxsec.dynamic._revision", return_value=self.policy["readiness"]["source_revision"]):
            check, _ = run_confined_engine(self.source, self.config, "zap")
        self.assertNotEqual(check["status"], "complete")

    def test_project_only_readiness_and_revision_mismatch_send_nothing(self):
        for change in ("untrusted", "wrong-revision", "expired", "missing-evidence"):
            config = copy.deepcopy(self.config)
            p = config["_trusted_policy"]["dynamic"]
            if change == "untrusted":
                config.update(p)
                config.pop("_trusted_policy")
            elif change == "wrong-revision":
                p["readiness"]["deployment_revision"] = "different"
            elif change == "expired":
                p["readiness"]["expires_at"] = "2000-01-01T00:00:00+00:00"
            else:
                p["readiness"].pop("evidence_ref")
            checks, _ = run_dynamic_checks(self.source, config, execute=True)
            self.assertTrue(any(c["errors"] for c in checks))
        self.assertFalse(Fixture.hits)

    def test_revision_check_does_not_execute_repository_fsmonitor_hook(self):
        marker = self.source / ".git" / "executed-marker"
        hook = self.source / ".git" / "fsmonitor-hook"
        hook.write_text("#!/bin/sh\nprintf unsafe > '" + marker.as_posix() + "'\nprintf '\\0'\n", encoding="utf-8")
        hook.chmod(0o755)
        subprocess.run(["git", "-C", str(self.source), "config", "core.fsmonitor", hook.as_posix()], check=True)
        run_dynamic_checks(self.source, self.config, execute=True)
        self.assertFalse(marker.exists(), "Reading source revision must not execute repository hooks")

    def test_soft_denial_200_is_not_confirmed_but_oracle_denial_completes_scenario(self):
        checks, findings = run_dynamic_checks(self.source, self.config, execute=True)
        scenario = next(c for c in checks if c["id"] == "dynamic:object-a")
        self.assertEqual(scenario["status"], "complete")
        self.assertFalse(findings)
        self.assertIn(("/objects/a", "B"), Fixture.hits)

    def test_b_token_receiving_a_fixture_nonce_is_runtime_verified(self):
        Fixture.mode = "vulnerable"
        checks, findings = run_dynamic_checks(self.source, self.config, execute=True)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["validation"], "runtime-verified")
        self.assertEqual(findings[0]["severity"], "High")
        self.assertNotIn(Fixture.nonce, json.dumps(findings))

    def test_wrong_identity_or_missing_owner_oracle_is_incomplete(self):
        self.policy["auth"]["identities"]["b"]["expected_id"] = "not-B"
        checks, findings = run_dynamic_checks(self.source, self.config, execute=True)
        self.assertFalse(findings)
        self.assertFalse(any(p == "/objects/a" for p, _ in Fixture.hits))
        self.assertTrue(any(c["errors"] for c in checks))

    def test_200_without_positive_or_negative_oracle_remains_undetermined(self):
        self.policy["scenarios"][0]["oracle"].pop("denied")
        checks, findings = run_dynamic_checks(self.source, self.config, execute=True)
        self.assertEqual(next(c for c in checks if c["id"] == "dynamic:object-a")["status"], "partial")
        self.assertEqual(findings[0]["validation"], "undetermined")

    def test_zap_is_plan_only_without_process_confinement(self):
        plan = generate_zap_plan(self.config)
        self.assertEqual(plan["execution_status"], "unsupported")
        checks, _ = run_dynamic_checks(self.source, self.config, execute=True)
        self.assertEqual(next(c for c in checks if c["id"] == "dynamic:zap")["status"], "unsupported")

    def enable_runner(self):
        runner = Path(sys.executable).resolve()
        digest = hashlib.sha256(runner.read_bytes()).hexdigest()
        record = {"id": "confinement-fixture", "source_revision": self.policy["readiness"]["source_revision"],
                  **self.policy["target"], "engine_digest": "sha256:" + "a" * 64,
                  "runner_digest": digest, "status": "verified", "expires_at": self.policy["readiness"]["expires_at"],
                  "broker_evidence_refs": ["protected-ci/broker-test"], "firewall_evidence_refs": ["protected-ci/firewall-test"]}
        files = {str(runner): digest}
        for package in ("gxsec", "yaml"):
            spec = importlib.util.find_spec(package)
            for root in spec.submodule_search_locations:
                for path in Path(root).rglob("*"):
                    if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                        files[str(path.resolve())] = hashlib.sha256(path.read_bytes()).hexdigest()
        bundle = {"immutable": True, "runtime_evidence_ref": "protected-ci/immutable-image", "files": files,
                  "digest": content_hash(files)}
        zap_root = self.protected_path / "zap"
        java_home = self.protected_path / "java"
        (zap_root / "plugin").mkdir(parents=True, exist_ok=True)
        (zap_root / "templates").mkdir(exist_ok=True)
        (java_home / "bin").mkdir(parents=True, exist_ok=True)
        (java_home / "lib").mkdir(exist_ok=True)
        launcher = zap_root / "zap.exe"
        launcher.write_bytes(b"synthetic ZAP launcher")
        (zap_root / "zap-2.16.1.jar").write_bytes(b"synthetic core JAR")
        (zap_root / "plugin" / "addon.zap").write_bytes(b"synthetic add-on archive")
        (zap_root / "templates" / "report.html").write_text("synthetic template", encoding="utf-8")
        (java_home / "bin" / "java.exe").write_bytes(b"synthetic Java executable")
        (java_home / "lib" / "modules").write_bytes(b"synthetic Java modules")
        for root in (zap_root, java_home):
            files.update({str(path.resolve()): hashlib.sha256(path.read_bytes()).hexdigest() for path in root.rglob("*") if path.is_file()})
        bundle["zap_runtime"] = {"zap_root": str(zap_root), "java_home": str(java_home),
                                 "java_executable": str(java_home / "bin" / "java.exe")}
        bundle["digest"] = runtime_bundle_digest(bundle)
        record["engine_digest"] = "sha256:" + hashlib.sha256(launcher.read_bytes()).hexdigest()
        claims = self.protected_path / "claims"
        claims.mkdir(exist_ok=True)
        broker = {"lease_path": str(self.protected_path / "lease.json"), "receipt_path": str(self.protected_path / "receipt.json"),
                  "claim_dir": str(claims), "key_ref": "GX_BROKER_VERIFY_KEY"}
        Path(broker["receipt_path"]).write_text("{}", encoding="utf-8")
        record.update(bundle_digest=bundle["digest"], broker=broker)
        self.policy["run_id"] = "synthetic-fixture-run"
        self.policy["zap"] = {"required": True, "version": "2.16.1", "digest": record["engine_digest"],
                              "bundle": bundle, "broker": broker, "executable": str(launcher),
                              "runner": {"path": str(runner), "sha256": digest}, "confinement": record}
        self.config["_trusted_policy"]["trusted_approvals"] = [
            {"record_id": record["id"], "digest": content_hash(record), "kind": "network-confinement",
             "roles": ["protected-ci", "security-owner"]}]
        self.write_signed(broker["lease_path"], {"kind": "enforcing-network-lease", "enforced": True, "all_processes": True,
            "run_id": self.policy["run_id"], "scope_digest": content_hash(self.policy["target"]),
            "source_revision": record["source_revision"], "engine_digest": record["engine_digest"], "bundle_digest": bundle["digest"],
            "expires_at": record["expires_at"], "budgets": {"max_requests": 50, "max_total_response_bytes": 8 * 1024 * 1024,
                "max_duration_seconds": 60, "requests_per_second": 2, "concurrency": 1}})

    def write_signed(self, path, payload):
        signature = hmac.new(os.environ["GX_BROKER_VERIFY_KEY"].encode(),
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(), hashlib.sha256).hexdigest()
        Path(path).write_text(json.dumps({"payload": payload, "hmac_sha256": signature}), encoding="utf-8")

    def receipt(self, plan, result, **overrides):
        tool = self.policy[plan["engine"]["name"]]
        receipt = {"kind": "network-execution-receipt", "run_id": plan["run_id"], "plan_digest": content_hash(plan),
            "result_digest": content_hash(result), "scope_digest": content_hash(plan["scope"]),
            "engine_digest": plan["engine"]["digest"], "bundle_digest": plan["bundle"]["digest"],
            "auth_verified": True, "job_tests_passed": True, "native_job_evidence_digest": "b" * 64,
            "verified_identities": {name: identity["expected_id"] for name, identity in plan["auth"]["identities"].items()},
            "observed_paths": plan["scope"]["paths"], "all_processes": True, "lease_enforced": True,
            "expires_at": self.policy["readiness"]["expires_at"],
            "measurements": {"requests": 3, "response_bytes": 1000, "duration_seconds": 0.5,
                             "peak_requests_per_second": 2, "concurrency": 1,
                             "started_at_epoch": plan["not_before_epoch"],
                             "finished_at_epoch": plan["not_before_epoch"] + 0.5}, **overrides}
        self.write_signed(tool["broker"]["receipt_path"], receipt)

    def test_attested_zap_runner_fixed_command_and_native_alert_import(self):
        self.enable_runner()

        def fake_runner(command, **kwargs):
            self.assertEqual(command[1], "--gxsec-plan")
            plan = json.loads(Path(command[2]).read_text(encoding="utf-8"))
            self.assertNotIn('"token":', json.dumps(plan))
            self.assertLessEqual(kwargs["timeout"], 60)
            self.assertIn("TEST_GX_A", kwargs["env"])
            self.assertFalse({"TEST_GX_B", "GX_BROKER_VERIFY_KEY"} & set(kwargs["env"]))
            result = {"engine": plan["engine"], "execution_status": "complete", "plan_digest": content_hash(plan),
                      "source_revision": plan["source_revision"], "auth_verified": True,
                      "observed_paths": plan["scope"]["paths"], "job_tests_passed": True,
                      "report": {"site": [{"alerts": [{"pluginid": "10021", "alert": "Missing header",
                          "riskcode": "1", "instances": [{"uri": self.origin + "/objects/a"}]}]}]}}
            Path(command[4]).write_text(json.dumps(result), encoding="utf-8")
            self.receipt(plan, result)
            return subprocess.CompletedProcess(command, 0)

        with patch("gxsec.dynamic.subprocess.run", side_effect=fake_runner) as run, \
             patch("gxsec.dynamic._revision", return_value=self.policy["readiness"]["source_revision"]):
            check, findings = run_confined_engine(self.source, self.config, "zap")
        self.assertEqual(run.call_count, 1)
        self.assertEqual(check["status"], "complete")
        self.assertEqual(findings[0]["severity"], "Low")
        self.assertEqual(findings[0]["validation"], "candidate")

    def test_forged_or_scope_changed_confinement_never_launches_runner(self):
        self.enable_runner()
        self.policy["zap"]["confinement"]["paths"] = ["/other"]
        with patch("gxsec.dynamic.subprocess.run") as run:
            check, findings = run_confined_engine(self.source, self.config, "zap")
        run.assert_not_called()
        self.assertEqual(check["status"], "unsupported")
        self.assertFalse(findings)

    def test_changed_imported_module_digest_prevents_engine_dispatch(self):
        self.enable_runner()
        tool = self.policy["zap"]
        module = next(name for name in tool["bundle"]["files"] if name.endswith("dynamic.py"))
        tool["bundle"]["files"][module] = "0" * 64
        tool["bundle"]["digest"] = runtime_bundle_digest(tool["bundle"])
        tool["confinement"]["bundle_digest"] = tool["bundle"]["digest"]
        self.config["_trusted_policy"]["trusted_approvals"][0]["digest"] = content_hash(tool["confinement"])
        with patch("gxsec.dynamic.subprocess.run") as run:
            check, _ = run_confined_engine(self.source, self.config, "zap")
        run.assert_not_called()
        self.assertEqual(check["status"], "unsupported")

    def test_signed_overbudget_receipt_exhausts_the_shared_allowance(self):
        self.enable_runner()
        client = BoundedTransport(self.origin, paths=["/me", "/objects/a"], allowed_ips=["127.0.0.1"],
                                  budgets={"max_requests": 3})
        client.request("GET", self.origin + "/me")
        remaining_allowance = {**client.allowance(), "max_duration_seconds": 17}

        def fake_runner(command, **kwargs):
            plan = json.loads(Path(command[2]).read_text(encoding="utf-8"))
            self.assertEqual(plan["budgets"]["max_requests"], 2)
            self.assertEqual(plan["budgets"]["max_duration_seconds"], remaining_allowance["max_duration_seconds"])
            self.assertEqual(plan["budgets"]["max_total_response_bytes"], remaining_allowance["max_total_response_bytes"])
            result = {"engine": plan["engine"], "execution_status": "executed", "plan_digest": content_hash(plan),
                      "source_revision": plan["source_revision"], "report": {"site": []}}
            Path(command[4]).write_text(json.dumps(result), encoding="utf-8")
            self.receipt(plan, result)  # signed receipt says 3 requests, allowance is only 2
            return subprocess.CompletedProcess(command, 0)

        with patch.object(client, "allowance", return_value=remaining_allowance), \
             patch("gxsec.dynamic.subprocess.run", side_effect=fake_runner), \
             patch("gxsec.dynamic._revision", return_value=self.policy["readiness"]["source_revision"]):
            check, _ = run_confined_engine(self.source, self.config, "zap", budget_client=client)
        self.assertEqual(check["status"], "failed")
        self.assertEqual(client.allowance()["max_requests"], 0)

    def test_expiry_after_engine_execution_prevents_acceptance(self):
        self.enable_runner()
        now = [time.time()]

        def fake_runner(command, **kwargs):
            plan = json.loads(Path(command[2]).read_text(encoding="utf-8"))
            result = {"engine": plan["engine"], "execution_status": "executed", "plan_digest": content_hash(plan),
                      "source_revision": plan["source_revision"], "report": {"site": []}}
            Path(command[4]).write_text(json.dumps(result), encoding="utf-8")
            self.receipt(plan, result)
            now[0] += 4000
            return subprocess.CompletedProcess(command, 0)

        with patch("gxsec.dynamic.subprocess.run", side_effect=fake_runner), \
             patch("gxsec.dynamic.time.time", side_effect=lambda: now[0]), \
             patch("gxsec.dynamic._revision", return_value=self.policy["readiness"]["source_revision"]):
            check, _ = run_confined_engine(self.source, self.config, "zap")
        self.assertEqual(check["status"], "failed")

    def test_browser_nonce_requires_identity_and_positive_control(self):
        self.enable_runner()
        self.policy["browser"] = self.policy.pop("zap")
        self.policy["browser"]["scenarios"] = [{"id": "reflected-xss", "path": "/objects/a", "identity": "a",
            "nonce": "browser-nonce-98231", "param": "q", "payload": "<script>window.__xss_fired='browser-nonce-98231'</script>",
            "control_text": "fixture"}]

        def fake_runner(command, **kwargs):
            plan = json.loads(Path(command[2]).read_text(encoding="utf-8"))
            result = {"engine": plan["engine"], "execution_status": "complete", "plan_digest": content_hash(plan),
                "source_revision": plan["source_revision"], "auth_verified": True, "observed_paths": plan["scope"]["paths"],
                "job_tests_passed": True, "scenarios": [{"id": "reflected-xss", "identity_verified": True,
                    "control_passed": True, "executed_nonce": "browser-nonce-98231"}]}
            Path(command[4]).write_text(json.dumps(result), encoding="utf-8")
            self.receipt(plan, result)
            return subprocess.CompletedProcess(command, 0)

        with patch("gxsec.dynamic.subprocess.run", side_effect=fake_runner), \
             patch("gxsec.dynamic.validate_runtime_bundle", return_value=self.policy["browser"]["bundle"]["digest"]), \
             patch("gxsec.dynamic._revision", return_value=self.policy["readiness"]["source_revision"]):
            check, findings = run_confined_engine(self.source, self.config, "browser")
        self.assertEqual(check["status"], "complete")
        self.assertEqual(findings[0]["category"], "xss")
        self.assertEqual(findings[0]["validation"], "runtime-verified")

    def test_openapi_discovery_is_local_and_never_executes_or_trusts_servers(self):
        (self.source / "openapi.json").write_text(json.dumps({"openapi": "3.0.0", "servers": [{"url": "https://outside.example"}],
            "paths": {"/objects/{id}": {"get": {"operationId": "getObject"}, "delete": {}},
                      "/me": {"get": {}}}}), encoding="utf-8")
        routes = discover_endpoints(self.source, {"discovery": {"openapi": "openapi.json"}})
        self.assertEqual(len(routes), 3)
        self.assertTrue(any(r["needs_fixture"] for r in routes))
        self.assertFalse(Fixture.hits)


if __name__ == "__main__":
    unittest.main()
