"""Plan dynamic coverage and execute only trusted, synthetic HTTP scenarios.

The externally supplied policy owns readiness, identities and the required
scenario denominator. Project configuration can request coverage, never approve
it. ZAP/browser/subprocess execution is deliberately unavailable until the host
can prove network confinement for those processes.
"""
from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .transport import BoundedTransport, TransportError, parse_url
from .models import content_hash
from .source import trusted_runtime_tool, runtime_environment, reject_reparse_path


def _time(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Timezone is required")
    return result.timestamp()


def runtime_bundle_digest(bundle):
    """Bind file contents and runtime evidence/closure metadata without self-reference."""
    return content_hash({key: value for key, value in bundle.items() if key != "digest"})


def validate_runtime_bundle(bundle, engine, source=None, *, executable=None):
    """Verify the approved interpreter and every loaded package implementation file."""
    if not isinstance(bundle, dict) or bundle.get("immutable") is not True or not bundle.get("runtime_evidence_ref"):
        raise ValueError("An approved immutable runtime bundle is required")
    files = bundle.get("files") or {}
    if not files or bundle.get("digest") != runtime_bundle_digest(bundle):
        raise ValueError("Runtime bundle manifest digest mismatch")
    required = {Path(__import__("sys").executable).resolve()}
    if engine == "zap":
        native = bundle.get("zap_runtime") or {}
        roots = []
        for name in ("zap_root", "java_home"):
            root = Path(native.get(name, ""))
            if not root.is_absolute():
                raise ValueError("Complete ZAP and Java installation roots are required")
            root = reject_reparse_path(root).resolve(strict=True)
            if not root.is_dir() or (source and root.is_relative_to(Path(source).resolve())):
                raise ValueError("Native installation roots must be protected directories outside source")
            roots.append(root)
            # Includes JARs, native libraries, add-on archives, templates, Java
            # module images and every other installed runtime file.
            required.update(reject_reparse_path(p).resolve(strict=True) for p in root.rglob("*") if p.is_file())
        zap_root, java_home = roots
        java = Path(native.get("java_executable", ""))
        if not java.is_absolute():
            raise ValueError("Pinned Java executable is required")
        java = reject_reparse_path(java).resolve(strict=True)
        if not java.is_file() or not java.is_relative_to(java_home) or java.name.lower() not in {"java", "java.exe"}:
            raise ValueError("Java executable must belong to the approved Java installation")
        if not any(zap_root.glob("zap*.jar")):
            raise ValueError("Complete ZAP installation must contain its core JAR")
        if executable is not None:
            launcher = reject_reparse_path(executable).resolve(strict=True)
            if not launcher.is_file() or not launcher.is_relative_to(zap_root):
                raise ValueError("ZAP launcher must belong to the approved ZAP installation")
    for name in (["gxsec", "yaml"] + (["playwright"] if engine == "browser" else [])):
        spec = importlib.util.find_spec(name)
        if spec is None:
            raise ValueError("Runtime dependency is unavailable")
        roots = list(spec.submodule_search_locations or [])
        if roots:
            for root in roots:
                # Playwright also executes its Node driver and JavaScript/data
                # bundle. Bind the whole package, not only Python entry files.
                required.update(p.resolve() for p in Path(root).rglob("*")
                                if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc")
        elif spec.origin:
            required.add(Path(spec.origin).resolve())
    if not required <= {Path(path).resolve() for path in files}:
        raise ValueError("Runtime bundle omits imported implementation files")
    for name, expected in files.items():
        if not Path(name).is_absolute():
            raise ValueError("Bundle manifest paths must be absolute")
        path = reject_reparse_path(name).resolve(strict=True)
        if source and path.is_relative_to(Path(source).resolve()):
            raise ValueError("Runtime implementation cannot come from inspected source")
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("Runtime bundle file changed")
    return bundle["digest"]


def _signed_document(path, key):
    path = reject_reparse_path(path).resolve(strict=True)
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("Broker evidence exceeds byte limit")
    envelope = json.loads(path.read_text(encoding="utf-8"))
    payload = envelope.get("payload")
    signature = hmac.new(key.encode(), json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(), hashlib.sha256).hexdigest()
    if not isinstance(payload, dict) or not hmac.compare_digest(signature, str(envelope.get("hmac_sha256", ""))):
        raise ValueError("Independent broker evidence authentication failed")
    return payload


def _broker_lease(source, tool, plan, record):
    broker = tool.get("broker") or {}
    if record.get("broker") != broker:
        raise ValueError("Broker contract is not bound by confinement approval")
    for key in ("lease_path", "receipt_path", "claim_dir"):
        value = reject_reparse_path(broker.get(key, "")).resolve(strict=True)
        if value.is_relative_to(Path(source).resolve()):
            raise ValueError("Protected broker evidence must be outside source")
    key_ref = broker.get("key_ref")
    key = os.environ.get(key_ref, "") if isinstance(key_ref, str) else ""
    if len(key) < 32:
        raise ValueError("Protected broker verification key is missing")
    lease = _signed_document(broker["lease_path"], key)
    if (lease.get("kind") != "enforcing-network-lease" or lease.get("enforced") is not True
            or not lease.get("all_processes") or not lease.get("run_id")
            or lease.get("scope_digest") != content_hash(plan["scope"])
            or lease.get("source_revision") != plan["source_revision"]
            or lease.get("engine_digest") != plan["engine"]["digest"]
            or lease.get("bundle_digest") != plan["bundle"]["digest"]
            or _time(lease.get("expires_at", "")) < plan["deadline_epoch"]):
        raise ValueError("Protected enforcing lease does not cover this complete plan")
    limits = lease.get("budgets") or {}
    for field in ("max_requests", "max_total_response_bytes", "requests_per_second", "concurrency", "max_duration_seconds"):
        if not isinstance(limits.get(field), (int, float)) or plan["budgets"][field] > limits[field]:
            raise ValueError("Execution allowance exceeds authenticated broker lease")
    if config_run_id := plan.get("run_id"):
        if lease["run_id"] != config_run_id:
            raise ValueError("Broker lease belongs to another run")
    plan["run_id"] = lease["run_id"]
    claim = Path(broker["claim_dir"]) / (content_hash({"run": lease["run_id"], "engine": plan["engine"]["name"]}) + ".claimed")
    with claim.open("x", encoding="utf-8") as handle:
        handle.write(content_hash(lease))
    plan["broker_lease"] = lease
    return broker, key


def _broker_receipt(broker, key, plan, result):
    receipt = _signed_document(broker["receipt_path"], key)
    if (receipt.get("kind") != "network-execution-receipt" or receipt.get("run_id") != plan["run_id"]
            or receipt.get("plan_digest") != content_hash(plan) or receipt.get("result_digest") != content_hash(result)
            or receipt.get("scope_digest") != content_hash(plan["scope"])
            or receipt.get("engine_digest") != plan["engine"]["digest"]
            or receipt.get("bundle_digest") != plan["bundle"]["digest"]
            or receipt.get("auth_verified") is not True or receipt.get("job_tests_passed") is not True
            or not re.fullmatch(r"[0-9a-f]{64}", receipt.get("native_job_evidence_digest", ""))
            or set(receipt.get("observed_paths") or []) != set(plan["scope"]["paths"])
            or receipt.get("all_processes") is not True or receipt.get("lease_enforced") is not True
            or time.time() > plan["deadline_epoch"] or _time(receipt.get("expires_at", "")) <= time.time()):
        raise ValueError("Independent execution receipt does not establish complete coverage")
    expected_identities = {name: identity["expected_id"] for name, identity in plan["auth"]["identities"].items()}
    if receipt.get("verified_identities") != expected_identities:
        raise ValueError("Receipt does not establish the selected authenticated identities")
    measured = receipt.get("measurements") or {}
    for field, limit in (("requests", "max_requests"), ("response_bytes", "max_total_response_bytes"),
                         ("duration_seconds", "max_duration_seconds"), ("peak_requests_per_second", "requests_per_second"),
                         ("concurrency", "concurrency")):
        actual = measured.get(field)
        if isinstance(actual, bool) or not isinstance(actual, (int, float)) or actual < 0 or actual > plan["budgets"][limit]:
            raise ValueError("Authenticated process-tree budget was exceeded or not measured")
    if measured["requests"] < len(plan["scope"]["paths"]) or measured["response_bytes"] <= 0:
        raise ValueError("Broker receipt has no established executed scope")
    if (not isinstance(measured.get("started_at_epoch"), (int, float))
            or not isinstance(measured.get("finished_at_epoch"), (int, float))
            or measured["started_at_epoch"] < plan["not_before_epoch"]
            or measured["finished_at_epoch"] > plan["deadline_epoch"]
            or measured["finished_at_epoch"] < measured["started_at_epoch"]):
        raise ValueError("Receipt falls outside the global execution/rate lease")
    return receipt


def _trusted(config):
    policy = config.get("_trusted_policy") or {}
    dynamic = policy.get("dynamic", policy) if isinstance(policy, dict) else {}
    return dynamic if isinstance(dynamic, dict) else {}


def _check(id, status="skipped", errors=None, **kwargs):
    return {"id": id, "status": status, "required": True, "findings": [],
            "errors": errors or [], "coverage": kwargs.pop("coverage", {}), **kwargs}


def discover_endpoints(source: Path, config: dict) -> list:
    """Read a local OpenAPI document; its server declarations never grant scope."""
    location = (config.get("discovery") or {}).get("openapi")
    if not location:
        return []
    source = Path(source).resolve()
    path = (source / location).resolve()
    if not path.is_relative_to(source) or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("OpenAPI input must be a bounded file inside source")
    if path.suffix.lower() == ".json":
        document = json.loads(path.read_text(encoding="utf-8-sig"))
    else:
        import yaml
        document = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
        raise ValueError("OpenAPI paths are missing")
    endpoints = []
    for path, operations in document["paths"].items():
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(operations, dict):
            continue
        for method, operation in operations.items():
            if not isinstance(method, str) or method.lower() not in {"get", "head", "post", "put", "patch", "delete", "options"}:
                continue
            endpoints.append({"path": path, "method": method.upper(),
                              "operation_id": operation.get("operationId") if isinstance(operation, dict) else None,
                              "needs_fixture": "{" in path,
                              "execution": "planned", "source": str(location)})
    return endpoints


def generate_zap_plan(config: dict) -> dict:
    policy = _trusted(config)
    target = policy.get("target") or config.get("target") or {}
    origin = target.get("origin")
    paths = target.get("paths") or []
    automation = {"env": {"contexts": []}, "jobs": []}
    if origin:
        parse_url(origin)
        automation["env"]["contexts"] = [{"name": "gxsec-approved-scope", "urls": [origin],
            "includePaths": [re.escape(origin.rstrip("/") + path) + r"(?:\?.*)?$" for path in paths]}]
        automation["jobs"].append({"type": "requestor", "requests": [
            {"url": origin.rstrip("/") + path, "method": "GET"} for path in paths]})
    automation["jobs"].extend([{"type": "passiveScan-wait"},
        {"type": "report", "parameters": {"template": "traditional-json", "reportDir": ".",
                                             "reportFile": "zap-report.json", "displayReport": False}}])
    return {"execution_status": "unsupported", "reason": "ZAP subprocess network confinement is unavailable; plan only",
            "automation": automation, "credentials_included": False,
            "required_evidence": ["trusted network confinement", "authenticated identity verification",
                                  "exact route coverage", "engine version and job tests", "deployment revision"]}


def _confinement(source, config, engine, deadline_epoch):
    """Verify protected-host attestation; the external runner enforces its broker/firewall.

    This code does not install or independently inspect the external firewall.
    Its trust root is a protected policy approval, scoped to this exact runner,
    engine digest, revision and route/IP set, with a finite expiry.
    """
    policy = _trusted(config)
    tool = policy.get(engine) or {}
    record = tool.get("confinement") or {}
    approvals = (config.get("_trusted_policy") or {}).get("trusted_approvals") or []
    if not record.get("id") or not any(
            a.get("record_id") == record["id"] and a.get("digest") == content_hash(record)
            and a.get("kind") == "network-confinement"
            and {"protected-ci", "security-owner"} <= set(a.get("roles", []))
            for a in approvals if isinstance(a, dict)):
        raise ValueError("Independent network-confinement approval is missing")
    target = policy.get("target") or {}
    if any(record.get(key) != target.get(key) for key in ("origin", "paths", "allowed_ips")):
        raise ValueError("Confinement scope differs from target")
    if record.get("status") != "verified" or not record.get("broker_evidence_refs") or not record.get("firewall_evidence_refs"):
        raise ValueError("Protected broker and firewall evidence is required")
    expires = datetime.fromisoformat(record.get("expires_at", "").replace("Z", "+00:00"))
    if expires.tzinfo is None or expires.timestamp() < deadline_epoch:
        raise ValueError("Confinement evidence expired")
    runner = tool.get("runner") or {}
    path = Path(runner.get("path", "")).resolve()
    if path.is_relative_to(Path(source).resolve()) or not path.is_file() or path.stat().st_size > 256 * 1024 * 1024:
        raise ValueError("Trusted runner must be outside inspected source")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != runner.get("sha256") or digest != record.get("runner_digest"):
        raise ValueError("Trusted runner digest mismatch")
    if not tool.get("version") or not re.fullmatch(r"sha256:[0-9a-f]{64}", tool.get("digest", "")) or tool["digest"] != record.get("engine_digest"):
        raise ValueError("Pinned engine provenance is required")
    if record.get("source_revision") != (policy.get("readiness") or {}).get("source_revision"):
        raise ValueError("Confinement source revision mismatch")
    bundle = tool.get("bundle") or {}
    if record.get("bundle_digest") != validate_runtime_bundle(bundle, engine, source, executable=tool.get("executable")):
        raise ValueError("Confinement does not bind the immutable runtime bundle")
    return tool, path


def _zap_findings(report, origin, paths):
    if not isinstance(report, dict) or not isinstance(report.get("site"), list):
        raise ValueError("ZAP traditional JSON report missing")
    findings = []
    for site in report["site"]:
        for alert in site.get("alerts", []):
            severity = {"0": "Info", "1": "Low", "2": "Medium", "3": "High"}.get(str(alert.get("riskcode")))
            if severity is None:
                raise ValueError("Unknown ZAP alert severity")
            for instance in alert.get("instances", []):
                url = instance.get("uri", "")
                parsed, url_origin, path = parse_url(url)
                if url_origin != parse_url(origin)[1] or path not in paths:
                    raise ValueError("ZAP evidence is outside approved scope")
                # Drop query payloads and all raw request/response contents.
                safe_url = origin.rstrip("/") + path
                rule = str(alert.get("pluginid") or alert.get("alertRef") or "unknown")
                fingerprint = content_hash({"engine": "zap", "rule": rule, "url": safe_url})
                findings.append({"finding_id": "gxsec-" + fingerprint[:20], "fingerprint": fingerprint,
                    "category": "dast", "rule_id": "zap." + rule, "title": "ZAP alert " + rule,
                    "severity": severity, "validation": "candidate", "lifecycle": "open",
                    "locations": [{"url": safe_url}], "observations": [{"engine": "zap", "rule": rule}],
                    "evidence_refs": []})
    return findings


def run_confined_engine(source: Path, config: dict, engine: str, *, budget_client=None,
                        run_id=None, deadline_epoch=None) -> tuple[dict, list]:
    """Invoke a digest-pinned protected runner, never a bare browser/ZAP binary.

    External runner protocol: --gxsec-plan PLAN_JSON --gxsec-result RESULT_JSON.
    It provisions/validates the approved confinement, resolves secret references
    from its bounded environment, runs the pinned engine and emits the evidence
    envelope. Unknown or missing provenance/coverage is incomplete.
    """
    policy = _trusted(config)
    tool = policy.get(engine) or {}
    check = _check("dynamic:" + engine, "unsupported", ["Trusted confined runner is unavailable"],
                   engine={"name": engine, "version": tool.get("version"), "digest": tool.get("digest")})
    check["required"] = tool.get("required") is True
    if engine not in {"zap", "browser"}:
        return check, []
    try:
        base_budget = {"max_duration_seconds": 60, "max_requests": 50, "max_response_bytes": 1024 * 1024,
                       "max_total_response_bytes": 8 * 1024 * 1024, "requests_per_second": 2, "concurrency": 1,
                       **(policy.get("budgets") or {})}
        if budget_client:
            base_budget = {**base_budget, **budget_client.allowance()}
        if min(base_budget["max_duration_seconds"], base_budget["max_requests"], base_budget["max_total_response_bytes"]) <= 0:
            raise ValueError("The shared execution allowance is exhausted")
        deadline_epoch = deadline_epoch or time.time() + base_budget["max_duration_seconds"]
        tool, runner = _confinement(source, config, engine, deadline_epoch)
        if _readiness(source, config, policy, deadline_epoch=deadline_epoch):
            raise ValueError("Environment readiness is incomplete")
        target = policy["target"]
        # Reuse strict origin/path/IP validation before external dispatch.
        BoundedTransport(target["origin"], paths=target["paths"], allowed_ips=target["allowed_ips"], budgets=policy.get("budgets"))
        plan = {"schema_version": 1, "engine": {"name": engine, "version": tool["version"], "digest": tool["digest"],
                                               "executable": tool.get("executable")},
                "source_revision": policy["readiness"]["source_revision"], "scope": target,
                "budgets": base_budget, "deadline_epoch": deadline_epoch,
                "bundle": tool["bundle"], "auth": {}, "confinement_record_id": tool["confinement"]["id"]}
        plan["not_before_epoch"] = time.time() + (max(0, budget_client._next_request - time.monotonic()) if budget_client else 0)
        if run_id:
            plan["run_id"] = run_id
        if engine == "zap":
            plan["automation"] = generate_zap_plan(config)["automation"]
        else:
            scenarios = tool.get("scenarios") or []
            if not scenarios:
                raise ValueError("Trusted browser nonce scenarios are missing")
            for scenario in scenarios:
                if scenario.get("path") not in target["paths"] or not isinstance(scenario.get("nonce"), str) or len(scenario["nonce"]) < 8:
                    raise ValueError("Browser scope and nonce oracle are required")
            plan["scenarios"] = scenarios
        auth = policy.get("auth") or {}
        identities = auth.get("identities") or {}
        selected = ({s.get("identity") for s in plan["scenarios"]} if engine == "browser"
                    else {auth.get("default_identity") or next(iter(identities), None)})
        if not selected or None in selected or not selected <= identities.keys():
            raise ValueError("The engine's required identities are missing")
        plan["auth"] = {**auth, "identities": {name: identities[name] for name in selected}}
        environment = runtime_environment()
        for identity in plan["auth"]["identities"].values():
            ref = identity.get("secret_ref")
            if not isinstance(ref, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", ref):
                raise ValueError("Invalid credential reference")
            value = (config.get("_credentials") or {}).get(ref, os.environ.get(ref))
            if value is None:
                raise ValueError("Required credential is missing")
            environment[ref] = value if isinstance(value, str) else json.dumps(value)
        broker, broker_key = _broker_lease(source, tool, plan, tool["confinement"])
        timeout = BoundedTransport._limit(plan["budgets"]["max_duration_seconds"], "max_duration_seconds", 1200)
    except (ValueError, TypeError, KeyError, OSError, TransportError):
        return check, []
    check["status"] = "failed"
    check["errors"] = ["Confined engine execution or evidence validation failed"]
    dispatched = False
    accounted = False
    try:
        with tempfile.TemporaryDirectory(prefix="gxsec-confined-") as directory:
            plan_path = Path(directory) / "plan.json"
            result_path = Path(directory) / "result.json"
            plan_path.write_text(json.dumps(plan, ensure_ascii=False), encoding="utf-8")
            dispatched = True
            process = subprocess.run([str(runner), "--gxsec-plan", str(plan_path), "--gxsec-result", str(result_path)],
                cwd=directory, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=timeout, check=False)
            if process.returncode != 0 or not result_path.is_file() or result_path.stat().st_size > 4 * 1024 * 1024:
                return check, []
            result = json.loads(result_path.read_text(encoding="utf-8"))
        if (result.get("engine") != plan["engine"] or result.get("execution_status") not in {"executed", "complete"}
                or result.get("plan_digest") != content_hash(plan) or result.get("source_revision") != plan["source_revision"]):
            return check, []
        receipt = _broker_receipt(broker, broker_key, plan, result)
        if _readiness(source, config, policy, deadline_epoch=time.time()):
            return check, []
        _confinement(source, config, engine, time.time())
        if time.time() > deadline_epoch or _time(policy["readiness"]["expires_at"]) <= time.time():
            return check, []
        if budget_client:
            budget_client.requests_sent += receipt["measurements"]["requests"]
            budget_client.bytes_received += receipt["measurements"]["response_bytes"]
            budget_client._next_request = time.monotonic() + 1 / budget_client.requests_per_second
        accounted = True
        if engine == "zap":
            findings = _zap_findings(result.get("report"), target["origin"], target["paths"])
        else:
            observations = result.get("scenarios") or []
            if len(observations) != len(plan["scenarios"]):
                return check, []
            findings = []
            by_id = {item.get("id"): item for item in observations}
            for scenario in plan["scenarios"]:
                observed = by_id.get(scenario.get("id")) or {}
                if observed.get("identity_verified") is not True or observed.get("control_passed") is not True:
                    return check, []
                if observed.get("executed_nonce") == scenario["nonce"]:
                    candidate = {"id": scenario["id"], "path": scenario["path"]}
                    finding = _finding(target["origin"], candidate, "runtime-verified", [{"browser_nonce_executed": True}])
                    finding.update({"category": "xss", "rule_id": "gxsec.browser.nonce", "title": "Browser executed the test nonce"})
                    findings.append(finding)
                elif observed.get("defense_oracle_passed") is not True:
                    return check, []
        check.update(status="complete", errors=[], findings=[f["finding_id"] for f in findings],
                     coverage={"eligible": len(target["paths"]), "scanned": len(target["paths"]), "complete": True},
                     evidence_refs=[tool["confinement"]["id"]],
                     measurements=receipt["measurements"], run_id=plan["run_id"],
                     limitations=["Independent authenticated broker receipts are required; external broker/firewall implementation is a protected-host prerequisite"])
        return check, findings
    except (ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError):
        return check, []
    finally:
        if dispatched and budget_client and not accounted:
            # Unknown subprocess traffic cannot become a fresh allowance for
            # another engine after an invalid/missing receipt or timeout.
            budget_client.requests_sent = budget_client.max_requests
            budget_client.bytes_received = budget_client.max_total_bytes


def _revision(source):
    try:
        git = trusted_runtime_tool("git", source)["executable"]
        env = runtime_environment()
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_OPTIONAL_LOCKS="0")
        command = [git, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=", "-C", str(source)]
        result = subprocess.run(command + ["rev-parse", "HEAD"],
                                capture_output=True, text=True, timeout=5, check=True, env=env)
        revision = result.stdout.strip()
        dirty = subprocess.run(command + ["status", "--porcelain", "--untracked-files=normal"],
                               capture_output=True, text=True, timeout=5, check=True, env=env).stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{40,64}", revision) or dirty:
            return None
        return revision
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _readiness(source, config, policy, *, deadline_epoch=None):
    errors = []
    target = policy.get("target") or {}
    readiness = policy.get("readiness") or {}
    if policy.get("enabled") is not True:
        errors.append("Trusted policy has not enabled dynamic execution")
    if not target.get("origin") or not target.get("paths") or not target.get("allowed_ips"):
        errors.append("Trusted exact origin, paths and IPs are required")
    project_origin = (config.get("target") or {}).get("origin")
    if project_origin and project_origin.rstrip("/") != str(target.get("origin", "")).rstrip("/"):
        errors.append("Project target differs from trusted scope")
    if readiness.get("status") != "verified" or readiness.get("synthetic_data") is not True or readiness.get("isolated") is not True:
        errors.append("Verified synthetic-data isolation readiness is required")
    if not readiness.get("evidence_ref"):
        errors.append("Protected readiness evidence reference is required")
    try:
        expires = datetime.fromisoformat(readiness.get("expires_at", "").replace("Z", "+00:00"))
        planned_seconds = min((policy.get("budgets") or {}).get("max_duration_seconds", 60),
                              (config.get("budgets") or {}).get("max_duration_seconds", 60))
        if expires.tzinfo is None or expires.timestamp() < (deadline_epoch or time.time() + planned_seconds):
            raise ValueError()
    except (TypeError, ValueError):
        errors.append("Readiness evidence has expired or has no expiry")
    revision = _revision(source)
    if not revision or readiness.get("source_revision") != revision or readiness.get("deployment_revision") != revision:
        errors.append("target_revision_unverified: clean source and trusted deployment revision must match")
    return errors


_MISSING = object()


def _pointer(value, path):
    if not isinstance(path, str):
        return _MISSING
    if path.startswith("$."):
        keys = path[2:].split(".")
    elif path.startswith("/"):
        if re.search(r"~(?![01])", path):
            return _MISSING
        keys = [key.replace("~1", "/").replace("~0", "~") for key in path[1:].split("/")]
    else:
        return _MISSING
    try:
        for key in keys:
            if isinstance(value, list):
                if not re.fullmatch(r"0|[1-9][0-9]*", key):
                    return _MISSING
                value = value[int(key)]
            elif isinstance(value, dict):
                value = value[key]
            else:
                return _MISSING
        return value
    except (KeyError, IndexError, TypeError, ValueError):
        return _MISSING


def _json_equal(value, expected):
    # Python considers True == 1, including inside lists and dictionaries.
    # JSON evidence must preserve the distinction between booleans and numbers.
    if isinstance(value, bool) or isinstance(expected, bool):
        return type(value) is type(expected) and value == expected
    if isinstance(value, dict):
        return (isinstance(expected, dict) and value.keys() == expected.keys()
                and all(_json_equal(item, expected[key]) for key, item in value.items()))
    if isinstance(value, list):
        return (isinstance(expected, list) and len(value) == len(expected)
                and all(_json_equal(item, other) for item, other in zip(value, expected)))
    return value == expected


def _matches(response, oracle):
    try:
        body = json.loads(response["body"])
    except (ValueError, TypeError):
        return False
    if not isinstance(oracle, dict) or "expected" not in oracle:
        return False
    value = _pointer(body, oracle.get("json_pointer", ""))
    return value is not _MISSING and _json_equal(value, oracle["expected"])


def _headers(identity, config):
    secret_ref = identity.get("secret_ref")
    if not isinstance(secret_ref, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", secret_ref):
        raise ValueError("Identity requires a named secret_ref")
    value = (config.get("_credentials") or {}).get(secret_ref, os.environ.get(secret_ref))
    try:
        value = json.loads(value) if isinstance(value, str) else value
        if not isinstance(value, dict):
            raise ValueError()
        if value.get("token"):
            return {"Authorization": "Bearer " + str(value["token"])}
        cookies = value.get("cookies")
        if isinstance(cookies, dict) and cookies:
            if any(not re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", str(k)) or
                   re.search(r"[;\r\n\x00-\x20]", str(v)) for k, v in cookies.items()):
                raise ValueError()
            return {"Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())}
    except (TypeError, ValueError):
        pass
    raise ValueError("Identity secret is missing or is not a token/cookies JSON object")


def _verify_identity(client, origin, auth, name, credentials):
    identity = auth["identities"][name]
    verification = auth.get("verification") or {}
    path = verification.get("path")
    expected = identity.get("expected_id")
    if expected is None or not path or not verification.get("identity_field"):
        raise ValueError("Trusted identity verification path, field and expected_id are required")
    result = client.request("GET", origin + path, headers=credentials[name])
    oracle = {"json_pointer": verification["identity_field"], "expected": expected}
    if not 200 <= result["status"] < 300 or not _matches(result, oracle):
        raise ValueError("Authenticated identity verification failed")
    if identity.get("expected_role") is not None:
        if not _matches(result, {"json_pointer": verification.get("role_field", ""), "expected": identity["expected_role"]}):
            raise ValueError("Authenticated role verification failed")


def _finding(origin, scenario, validation, observations):
    fingerprint = hashlib.sha256((origin + "|" + scenario["id"] + "|" + scenario["path"]).encode()).hexdigest()
    return {"finding_id": "gxsec-" + fingerprint[:20], "fingerprint": fingerprint,
            "category": "access-control", "rule_id": "gxsec.authorization.fixture-oracle",
            "title": "Cross-identity resource authorization scenario", "severity": "High",
            "validation": validation, "lifecycle": "open", "locations": [{"url": origin + scenario["path"]}],
            "observations": observations, "evidence_refs": [], "scenario_id": scenario["id"]}


def _scenario(client, origin, scenario, auth, credentials):
    if scenario.get("kind") != "authorization" or scenario.get("method", "GET").upper() != "GET":
        raise ValueError("Only trusted GET authorization scenarios are supported; writes require a cleanup contract")
    owner, subject = scenario.get("owner"), scenario.get("subject")
    identities = auth.get("identities") or {}
    if owner not in identities or subject not in identities or owner == subject or identities[owner].get("expected_id") == identities[subject].get("expected_id"):
        raise ValueError("Distinct verified A/B identities are required")
    oracle = scenario.get("oracle") or {}
    if not isinstance(oracle.get("expected"), str) or len(oracle["expected"]) < 8 or not oracle.get("json_pointer"):
        raise ValueError("A unique fixture nonce oracle is required")
    url = origin + scenario["path"]
    for name in (owner, subject):
        _verify_identity(client, origin, auth, name, credentials)
    baseline = client.request("GET", url, headers=credentials[owner])
    if not 200 <= baseline["status"] < 300 or not _matches(baseline, oracle):
        raise ValueError("Owner positive fixture oracle failed")
    anonymous = client.request("GET", url)
    other = client.request("GET", url, headers=credentials[subject])
    for name in (owner, subject):
        _verify_identity(client, origin, auth, name, credentials)
    observations = [{"owner_status": baseline["status"], "owner_oracle": True,
                     "anonymous_status": anonymous["status"], "anonymous_oracle": _matches(anonymous, oracle),
                     "subject_status": other["status"], "subject_oracle": _matches(other, oracle)}]
    if _matches(anonymous, oracle) or _matches(other, oracle):
        return "complete", _finding(origin, scenario, "runtime-verified", observations)
    denied = lambda response: response["status"] in {401, 403} or _matches(response, oracle.get("denied"))
    if denied(other) and denied(anonymous):
        return "complete", None
    return "partial", _finding(origin, scenario, "undetermined", observations)


def _finish(checks, findings, policy, scenarios):
    for check in checks:
        if check["id"] == "dynamic:readiness":
            check["id"] = "readiness"
        elif check["id"] == "dynamic:auth":
            check["id"] = "auth"
        if check["status"] == "complete":
            check["coverage"].setdefault("eligible", check["coverage"].get("count", 1))
            check["coverage"].setdefault("scanned", check["coverage"]["eligible"])
    if not any(c["id"] == "auth" for c in checks):
        checks.append(_check("auth", "skipped", ["Readiness or execution is incomplete"]))
    ids = {"dynamic:" + str(s.get("id", i)) for i, s in enumerate(scenarios) if isinstance(s, dict)}
    scenario_checks = [c for c in checks if c["id"] in ids]
    complete = sum(c["status"] == "complete" for c in scenario_checks)
    checks.append(_check("authorization", "complete" if scenarios and complete == len(scenarios) else "partial",
        [] if scenarios and complete == len(scenarios) else ["Required trusted authorization scenarios are incomplete"],
        coverage={"eligible": len(scenarios), "scanned": complete, "complete": bool(scenarios and complete == len(scenarios))}))
    engines = [c for c in checks if c["id"] in {"dynamic:zap", "dynamic:browser"} and c["required"]]
    count = sum(c["status"] == "complete" for c in engines)
    checks.append(_check("dast", "complete" if engines and count == len(engines) else "partial",
        [] if engines and count == len(engines) else ["Required DAST engine coverage is incomplete or not declared in trusted plan"],
        coverage={"eligible": len(engines), "scanned": count, "complete": bool(engines and count == len(engines))}))
    return checks, findings


def run_dynamic_checks(source: Path, config: dict, *, execute: bool = False) -> tuple[list, list]:
    policy = _trusted(config)
    duration = min((policy.get("budgets") or {}).get("max_duration_seconds", 60),
                   (config.get("budgets") or {}).get("max_duration_seconds", 60))
    deadline_epoch = time.time() + duration
    execution_run_id = policy.get("run_id") or uuid.uuid4().hex
    findings = []
    checks = []
    try:
        endpoints = discover_endpoints(source, config)
        checks.append(_check("dynamic:discovery", "complete" if endpoints else "partial",
                             [] if endpoints else ["No local OpenAPI endpoints supplied"],
                             coverage={"planned_routes": endpoints, "count": len(endpoints)}))
    except (ValueError, OSError, ImportError) as error:
        checks.append(_check("dynamic:discovery", "failed", [type(error).__name__ + ": local OpenAPI import failed"]))
    checks[-1]["required"] = False
    scenarios = policy.get("scenarios") or []
    if not isinstance(scenarios, list) or not scenarios:
        checks.append(_check("dynamic:scenarios", "partial", ["Trusted required scenario manifest is missing"]))
        scenarios = []
    try:
        plan = generate_zap_plan(config)
    except TransportError:
        plan = {"execution_status": "unsupported", "reason": "Target origin is invalid"}
    checks.append(_check("dynamic:zap", "unsupported", ["ZAP requires a trusted confined runner"], plan=plan))
    checks[-1]["required"] = (policy.get("zap") or {}).get("required") is True
    if policy.get("browser"):
        checks.append(_check("dynamic:browser", "unsupported", ["Browser requires a trusted confined runner"]))
        checks[-1]["required"] = (policy.get("browser") or {}).get("required") is True
    errors = _readiness(Path(source), config, policy, deadline_epoch=deadline_epoch) if execute else ["Dynamic execution was not requested (dry run)"]
    checks.append(_check("dynamic:readiness", "complete" if not errors else "skipped", errors,
                         coverage={"executed": bool(execute and not errors), "planned_scenarios": len(scenarios)}))
    if errors:
        checks.extend(_check("dynamic:" + str(s.get("id", index)), "skipped", list(errors))
                      for index, s in enumerate(scenarios) if isinstance(s, dict))
        return _finish(checks, findings, policy, scenarios)
    target = policy["target"]
    origin = target["origin"].rstrip("/")
    try:
        budgets = {"max_requests": 50, "max_duration_seconds": 60, **(policy.get("budgets") or {})}
        for key, value in (config.get("budgets") or {}).items():
            budgets[key] = min(value, budgets[key]) if key in budgets and isinstance(value, (int, float)) else value
        client = BoundedTransport(origin, paths=target["paths"], allowed_ips=target["allowed_ips"], budgets=budgets,
                                  lease_expires_at=min(deadline_epoch, _time(policy["readiness"]["expires_at"])))
        auth = policy.get("auth") or {}
        identities = auth.get("identities") or {}
        if not identities:
            raise ValueError("Trusted identities are missing")
        credentials = {name: _headers(identity, config) for name, identity in identities.items()}
        # Validate every trusted identity before touching business resources.
        for name in identities:
            _verify_identity(client, origin, auth, name, credentials)
        checks.append(_check("dynamic:auth", "complete", coverage={"verified_identities": list(identities),
                                                                   "eligible": len(identities), "scanned": len(identities)}))
    except (TransportError, ValueError, KeyError, TypeError):
        checks.append(_check("dynamic:auth", "failed", ["Trusted scope, budget, credential or identity verification failed"]))
        checks.extend(_check("dynamic:" + str(s.get("id", index)), "skipped", ["Authentication precondition failed"])
                      for index, s in enumerate(scenarios) if isinstance(s, dict))
        return _finish(checks, findings, policy, scenarios)
    seen = set()
    for index, scenario in enumerate(scenarios):
        sid = str(scenario.get("id", index)) if isinstance(scenario, dict) else str(index)
        check = _check("dynamic:" + sid, "failed", coverage={"attempted": 1, "planned": 1})
        checks.append(check)
        try:
            if not isinstance(scenario, dict) or not scenario.get("id") or sid in seen:
                raise ValueError("Scenario IDs must be present and unique")
            seen.add(sid)
            status, finding = _scenario(client, origin, scenario, auth, credentials)
            check["status"] = status
            if status != "complete":
                check["errors"].append("Response has neither fixture nonce nor explicit denial oracle; result is undetermined")
            if finding:
                check["findings"].append(finding["finding_id"])
                findings.append(finding)
        except (TransportError, ValueError, KeyError, TypeError):
            check["errors"].append("Scenario scope, identity, fixture oracle or execution precondition failed")
    for engine in ("zap", "browser"):
        if policy.get(engine):
            engine_check, engine_findings = run_confined_engine(source, config, engine, budget_client=client,
                                                               run_id=execution_run_id, deadline_epoch=deadline_epoch)
            if engine == "zap":
                engine_check["plan"] = plan
            checks = [c for c in checks if c["id"] != "dynamic:" + engine]
            checks.append(engine_check)
            findings.extend(engine_findings)
    if (_readiness(source, config, policy, deadline_epoch=time.time())
            or time.time() > deadline_epoch or _time(policy["readiness"]["expires_at"]) <= time.time()):
        for check in checks:
            if check["status"] == "complete" and check["id"] != "dynamic:discovery":
                check["status"] = "partial"
                check["errors"].append("Readiness expired or target revision changed before acceptance")
    return _finish(checks, findings, policy, scenarios)
