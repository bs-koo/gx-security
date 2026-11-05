#!/usr/bin/env python3
"""Reference ZAP/Playwright runner for an already confined, protected host.

Install outside the inspected source and approve its digest in protected policy.
This wrapper does not create firewall/broker confinement; the protected launcher
must supervise its process tree and enforce the approved egress lease. A bare
local invocation is not approved release evidence.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlencode

from gxsec.models import content_hash
from gxsec.transport import BoundedTransport, parse_url
from gxsec.source import runtime_environment
from gxsec.dynamic import validate_runtime_bundle


@contextmanager
def _only_environment(environment):
    previous = dict(os.environ)
    os.environ.clear()
    os.environ.update(environment)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(previous)


def _verify_auth(plan, client, credentials):
    from gxsec.dynamic import _headers, _verify_identity
    auth = plan.get("auth") or {}
    identities = auth.get("identities") or {}
    if not identities:
        raise ValueError("Authenticated engine execution requires trusted identities")
    scope = plan["scope"]
    for name in identities:
        _verify_identity(client, scope["origin"].rstrip("/"), auth, name, credentials)
    return credentials


def _browser(plan, executable, credentials, client, child_environment):
    from playwright.sync_api import sync_playwright
    scope = plan["scope"]
    results = []
    with _only_environment(child_environment), sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, executable_path=str(executable), env=child_environment)
        try:
            for scenario in plan["scenarios"]:
                if scenario.get("identity") not in credentials or scenario.get("path") not in scope["paths"]:
                    raise ValueError("Browser scenario identity/path is missing")
                if not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", scenario.get("property", "__xss_fired")):
                    raise ValueError("Browser assertion must name one window property")
                if not scenario.get("param") or scenario["nonce"] not in scenario.get("payload", "") or not scenario.get("control_text"):
                    raise ValueError("Reflected browser check requires nonce payload and positive page control")
                context = browser.new_context(service_workers="block", extra_http_headers=credentials[scenario["identity"]])
                try:
                    # Every HTTP navigation/subresource uses the same pinned broker.
                    def route_request(route):
                        try:
                            response = client.request(route.request.method, route.request.url,
                                headers=credentials[scenario["identity"]], body=route.request.post_data,
                                timeout=min(10, plan["budgets"]["max_duration_seconds"]))
                            headers = {k: v for k, v in response["headers"].items()
                                       if k.lower() not in {"content-length", "transfer-encoding", "content-encoding", "set-cookie"}}
                            route.fulfill(status=response["status"], headers=headers, body=response["body"])
                        except Exception:
                            route.abort()
                    context.route("**/*", route_request)
                    if not hasattr(context, "route_web_socket"):
                        raise ValueError("Playwright WebSocket blocking support is required")
                    context.route_web_socket("**/*", lambda websocket: websocket.close())
                    page = context.new_page()
                    page.set_default_timeout(min(10000, plan["budgets"]["max_duration_seconds"] * 1000))
                    url = scope["origin"].rstrip("/") + scenario["path"]
                    page.goto(url, wait_until="domcontentloaded")
                    if scenario["control_text"] not in (page.text_content("body") or ""):
                        raise ValueError("Browser positive page control failed")
                    page.goto(url + "?" + urlencode({scenario["param"]: scenario["payload"]}), wait_until="domcontentloaded")
                    observed = page.evaluate("key => window[key]", scenario.get("property", "__xss_fired"))
                    defense = bool(scenario.get("safe_text") and scenario["safe_text"] in (page.text_content("body") or ""))
                    results.append({"id": scenario["id"], "executed_nonce": observed if observed == scenario["nonce"] else None,
                                    "defense_oracle_passed": defense, "identity_verified": True, "control_passed": True})
                finally:
                    context.close()
        finally:
            browser.close()
    return {"scenarios": results}


def _execute_plan(plan, zap_home):
    if plan.get("schema_version") != 1 or not plan.get("confinement_record_id"):
        raise ValueError("Approved confinement plan is required")
    engine = plan["engine"]
    if engine.get("name") not in {"zap", "browser"}:
        raise ValueError("Unsupported engine")
    validate_runtime_bundle(plan.get("bundle"), engine["name"], executable=engine.get("executable"))
    lease = plan.get("broker_lease") or {}
    if lease.get("enforced") is not True or lease.get("run_id") != plan.get("run_id") or not lease.get("all_processes"):
        raise ValueError("An independently authenticated enforcing broker lease is required")
    import time
    if plan.get("deadline_epoch", 0) <= time.time():
        raise ValueError("Execution lease expired")
    executable = Path(engine.get("executable", ""))
    if not executable.is_absolute() or not executable.is_file() or executable.stat().st_size > 512 * 1024 * 1024:
        raise ValueError("Pinned engine executable is missing")
    if engine.get("digest") != "sha256:" + hashlib.sha256(executable.read_bytes()).hexdigest():
        raise ValueError("Engine executable digest mismatch")
    scope = plan["scope"]
    client = BoundedTransport(scope["origin"], paths=scope["paths"], allowed_ips=scope["allowed_ips"], budgets=plan["budgets"],
                              lease_expires_at=plan["deadline_epoch"])
    client._next_request = time.monotonic() + max(0, plan.get("not_before_epoch", time.time()) - time.time())
    # Materialize only selected identity references in Python, then remove them
    # before any version/engine/browser subprocess is created.
    from gxsec.dynamic import _headers
    secrets = {}
    for identity in (plan.get("auth") or {}).get("identities", {}).values():
        ref = identity.get("secret_ref")
        value = os.environ.pop(ref, None)
        if value is None:
            raise ValueError("Selected identity credential is missing")
        secrets[ref] = value
    credentials = {name: _headers(identity, {"_credentials": secrets})
                   for name, identity in (plan.get("auth") or {}).get("identities", {}).items()}
    child_environment = runtime_environment()
    child_environment["PATH"] = os.pathsep.join(sorted({str(Path(path).parent) for path in plan["bundle"]["files"]}))
    if engine["name"] == "zap":
        native = plan["bundle"]["zap_runtime"]
        child_environment["JAVA_HOME"] = native["java_home"]
        child_environment["JRE_HOME"] = native["java_home"]
        child_environment["PATH"] = str(Path(native["java_executable"]).parent) + os.pathsep + child_environment["PATH"]
    timeout = BoundedTransport._limit(plan["budgets"]["max_duration_seconds"], "max_duration_seconds", 1200)
    version_flag = "-version" if engine["name"] == "zap" else "--version"
    version_command = ([str(executable), "-dir", zap_home, version_flag] if engine["name"] == "zap"
                       else [str(executable), version_flag])
    version = subprocess.run(version_command, stdin=subprocess.DEVNULL, capture_output=True,
                             text=True, timeout=min(timeout, 10), check=False, env=child_environment)
    if version.returncode or not re.search(r"(?<![0-9.])" + re.escape(engine["version"]) + r"(?![0-9.])", version.stdout or ""):
        raise ValueError("Pinned engine version mismatch")
    credentials = _verify_auth(plan, client, credentials)
    if engine["name"] == "browser":
        evidence = _browser(plan, executable, credentials, client, child_environment)
    else:
        import yaml
        # Reconstruct the small fixed requestor/passive/report plan. Untrusted
        # files cannot append spider, script, add-on update or active jobs.
        identity = (plan.get("auth") or {}).get("default_identity") or next(iter(credentials))
        if identity not in credentials:
            raise ValueError("Default ZAP identity is missing")
        origin = scope["origin"].rstrip("/")
        automation = {"env": {"contexts": [{"name": "gxsec", "urls": [origin],
            "includePaths": [re.escape(origin + path) + r"(?:\?.*)?$" for path in scope["paths"]]}]},
            "jobs": [{"type": "requestor", "requests": [{"url": origin + path, "method": "GET",
                "headers": [key + ": " + value for key, value in credentials[identity].items()]} for path in scope["paths"]]},
                {"type": "passiveScan-wait"}, {"type": "report", "parameters": {"template": "traditional-json",
                    "reportDir": ".", "reportFile": "zap-report.json", "displayReport": False}}]}
        if len(scope["paths"]) + client.requests_sent + len(credentials) > plan["budgets"]["max_requests"]:
            raise ValueError("ZAP plan exceeds request budget")
        with tempfile.TemporaryDirectory(prefix="gxsec-zap-") as directory:
            automation_path = Path(directory) / "automation.yaml"
            automation_path.write_text(yaml.safe_dump(automation), encoding="utf-8")
            process = subprocess.run([str(executable), "-cmd", "-autorun", str(automation_path), "-dir", zap_home], cwd=directory,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=max(0.001, min(timeout, client.remaining_seconds())), check=False, env=child_environment)
            report = Path(directory) / "zap-report.json"
            if process.returncode or not report.is_file() or report.stat().st_size > 4 * 1024 * 1024:
                raise ValueError("ZAP jobs did not complete without errors/warnings")
            evidence = {"report": json.loads(report.read_text(encoding="utf-8"))}
            if not evidence["report"].get("site"):
                raise ValueError("Empty ZAP report does not establish engine coverage")
    _verify_auth(plan, client, credentials)
    if client.remaining_seconds() <= 0:
        raise ValueError("Execution lease expired before evidence acceptance")
    # The child reports raw evidence only. An independent protected broker must
    # sign actual route/auth/job receipts and total process-tree measurements.
    return {"engine": engine, "execution_status": "executed", "plan_digest": content_hash(plan),
            "source_revision": plan["source_revision"], "auth_verified": True,
            "python_observed_paths": sorted(client.observed_paths),
            "python_measurements": {"requests": client.requests_sent, "response_bytes": client.bytes_received}, **evidence}


def execute_plan(plan):
    # Prevent user-home add-ons/templates/config from extending the approved
    # installation closure, including during the version probe.
    with tempfile.TemporaryDirectory(prefix="gxsec-zap-home-") as zap_home:
        return _execute_plan(plan, zap_home)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gxsec-plan", required=True)
    parser.add_argument("--gxsec-result", required=True)
    args = parser.parse_args()
    try:
        path = Path(args.gxsec_plan)
        if path.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("Plan exceeds byte limit")
        result = execute_plan(json.loads(path.read_text(encoding="utf-8")))
        Path(args.gxsec_result).write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
        return 0
    except Exception:
        Path(args.gxsec_result).write_text('{"execution_status":"failed","errors":["Confined runner failed; inspect protected host logs"]}', encoding="utf-8")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
