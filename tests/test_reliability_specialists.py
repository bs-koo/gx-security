"""Specialist verdict controls and evidence minimization (mock/loopback only)."""
import contextlib
import http.server
import importlib.util
import io
import json
import threading
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

import pytest
import requests

from tools import dyn_session
from tools.redaction import redact

ROOT = Path(__file__).resolve().parents[1]


def load(skill, script):
    spec = importlib.util.spec_from_file_location(
        "reliability_" + script, ROOT / "skills" / skill / "scripts" / (script + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SQLI = load("exploiting-sql-injection", "attack_sqli")
SSRF = load("exploiting-ssrf-and-open-redirect", "attack_ssrf")
PATH = load("exploiting-path-traversal-upload", "attack_pathupload")
ERROR = "You have an error in your SQL syntax"
PASSWD = "root:x:0:0:root:/root:/bin/bash"
PRIVATE = "person@example.invalid 4111111111111111 password=synthetic-password"


def response(status=200, body="", headers=None):
    return {"status": status, "body": body, "headers": headers or {}, "elapsed": 0.01}


class Listener:
    def url_for(self, nonce):
        return "http://127.0.0.1:9/c/" + nonce

    def received(self, nonce, timeout):
        return False


def test_ssrf_absent_callback_remains_undetermined_in_human_output():
    with patch.object(dyn_session, "request", return_value=response(body="queued")):
        result = SSRF.run_ssrf("http://127.0.0.1", "/fetch?url=", Listener(), timeout=0)
    assert result["vulnerable"] is False
    assert result.get("validation") == "undetermined"
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        dyn_session.emit({"findings": [result]}, False)
    assert "미확정" in output.getvalue()
    assert "방어/정상" not in output.getvalue()


@pytest.mark.parametrize("status", [200, 201, 304, 400, 500])
def test_location_without_redirect_status_is_not_a_redirect(status):
    with patch.object(dyn_session, "request", return_value=response(status, headers={"Location": "https://evil.test/"})):
        result = SSRF.run_open_redirect("http://127.0.0.1", "/go?url=", "127.0.0.1")
    assert result["vulnerable"] is False
    assert result.get("undetermined") is True


@pytest.mark.parametrize("location", ["ftp://evil.test/", "javascript://evil.test/x", "https://evil.test:invalid/", "https://evil.test/\r\nX: injected"])
def test_non_http_or_invalid_location_does_not_confirm_redirect(location):
    with patch.object(dyn_session, "request", return_value=response(302, headers={"Location": location})):
        result = SSRF.run_open_redirect("http://127.0.0.1", "/go?url=", "127.0.0.1")
    assert result["vulnerable"] is False


def test_static_external_redirect_does_not_establish_input_effect():
    with patch.object(dyn_session, "request", return_value=response(302, headers={"Location": "https://evil.test"})):
        result = SSRF.run_open_redirect("http://127.0.0.1", "/go?url=", "127.0.0.1")
    assert result["vulnerable"] is False
    assert result["validation"] == "undetermined"


def test_redirect_missing_normal_control_cannot_be_runtime_verified():
    def request(_method, url, **_kwargs):
        value = parse_qs(urlsplit(url).query).get("url", [""])[0]
        if value not in {p["value"] for p in SSRF.make_redirect_payloads("127.0.0.1")}:
            raise TimeoutError("normal control unavailable")
        return response(302, headers={"Location": "https://evil.test"})
    with patch.object(dyn_session, "request", side_effect=request):
        result = SSRF.run_open_redirect("http://127.0.0.1", "/go?url=", "127.0.0.1")
    assert result["vulnerable"] is False
    assert result["validation"] == "undetermined"


def test_redirect_must_reproduce_the_injected_destination():
    seen = set()
    def request(_method, url, **_kwargs):
        value = parse_qs(urlsplit(url).query).get("url", [""])[0]
        if value in {p["value"] for p in SSRF.make_redirect_payloads("127.0.0.1")} and value not in seen:
            seen.add(value)
            return response(302, headers={"Location": "https://evil.test"})
        return response(200)
    with patch.object(dyn_session, "request", side_effect=request):
        result = SSRF.run_open_redirect("http://127.0.0.1", "/go?url=", "127.0.0.1")
    assert result["vulnerable"] is False
    assert result["validation"] == "undetermined"


def test_unrelated_external_destination_is_not_controlled_redirect_evidence():
    def request(_method, url, **_kwargs):
        value = parse_qs(urlsplit(url).query).get("url", [""])[0]
        if value in {p["value"] for p in SSRF.make_redirect_payloads("127.0.0.1")}:
            return response(302, headers={"Location": "https://unrelated.invalid"})
        return response(200)
    with patch.object(dyn_session, "request", side_effect=request):
        result = SSRF.run_open_redirect("http://127.0.0.1", "/go?url=", "127.0.0.1")
    assert result["vulnerable"] is False


@pytest.mark.parametrize("as_json", [False, True])
def test_redirect_evidence_does_not_collect_private_location_path_or_testcase(as_json):
    private_location = "https://evil.test/customer/person@example.invalid/card/4111111111111111?testcase=person@example.invalid"
    def request(_method, url, **_kwargs):
        value = parse_qs(urlsplit(url).query).get("url", [""])[0]
        if value in {p["value"] for p in SSRF.make_redirect_payloads("127.0.0.1")}:
            return response(302, headers={"Location": private_location})
        return response(200)
    with patch.object(dyn_session, "request", side_effect=request):
        result = SSRF.run_open_redirect("http://127.0.0.1", "/go?url=", "127.0.0.1")
    assert result["vulnerable"] is True
    collected = json.dumps(result)
    assert "person@example.invalid" not in collected
    assert "4111111111111111" not in collected
    assert all("location" not in finding for finding in result["findings"])
    hit = next(finding for finding in result["findings"] if finding["vulnerable"])
    assert hit["location_origin"] == "https://evil.test"
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        dyn_session.emit({"findings": [result]}, as_json)
    assert "person@example.invalid" not in output.getvalue()
    assert "4111111111111111" not in output.getvalue()


def test_static_database_error_page_does_not_establish_input_effect():
    with patch.object(SQLI, "_send", return_value=(SimpleNamespace(status_code=200, text=ERROR), 0.01)):
        evidence, error = SQLI._try_error_based("http://127.0.0.1", "id", "get", {}, False)
    assert error is None
    assert evidence is None


def test_failed_sql_control_cannot_establish_input_effect():
    def send(_target, _param, payload, *_args, **_kwargs):
        if payload in SQLI._ERROR_PAYLOADS:
            return SimpleNamespace(status_code=500, text=ERROR), 0.01
        return None
    with patch.object(SQLI, "_send", side_effect=send):
        evidence, error = SQLI._try_error_based("http://127.0.0.1", "id", "get", {}, False)
    assert evidence is None
    assert error == "CONNECTION_FAILED"


def test_input_dependent_sql_error_keeps_metadata_without_response_content():
    def send(_target, _param, payload, *_args, **_kwargs):
        body = ERROR + "; " + PRIVATE if payload in SQLI._ERROR_PAYLOADS else "normal"
        return SimpleNamespace(status_code=500 if body != "normal" else 200, text=body), 0.01
    with patch.object(SQLI, "_send", side_effect=send):
        evidence, error = SQLI._try_error_based("http://127.0.0.1", "id", "get", {}, False)
    assert error is None
    assert evidence is not None
    assert evidence.get("validation") == "undetermined"
    assert evidence.get("evidence_level") == "input-dependent-db-error"
    assert "response_snippet" not in evidence
    assert "person@example.invalid" not in json.dumps(evidence)
    assert "4111111111111111" not in json.dumps(evidence)


@pytest.mark.parametrize("as_json", [False, True])
def test_sql_output_does_not_export_raw_excerpt_or_matched_text(as_json):
    result = {"target": "http://127.0.0.1", "param": "id", "technique": "error-based",
              "exploited": True, "evidence": {"response_snippet": PRIVATE, "marker_found": PRIVATE}}
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        SQLI._output(result, as_json)
    assert "person@example.invalid" not in output.getvalue()
    assert "4111111111111111" not in output.getvalue()
    assert "synthetic-password" not in output.getvalue()


def test_common_redactor_omits_opaque_response_excerpt_and_raw_match():
    safe = redact({"response_snippet": PRIVATE, "marker_found": PRIVATE})
    assert "person@example.invalid" not in json.dumps(safe)
    assert "4111111111111111" not in json.dumps(safe)


def test_sql_verbose_preamble_does_not_echo_url_credentials():
    args = SQLI._build_parser().parse_args([
        "http://127.0.0.1/search?password=synthetic-password", "--param", "id"])
    output = io.StringIO()
    with patch.object(SQLI, "assert_in_scope", return_value="loopback"), \
         patch.object(dyn_session, "request", return_value=response()), \
         patch.object(SQLI, "_try_error_based", return_value=(None, None)), \
         patch.object(SQLI, "_try_boolean_based", return_value=(None, None)), \
         patch.object(SQLI, "_try_time_based", return_value=(None, None)), \
         contextlib.redirect_stdout(output):
        SQLI.run_attack(args)
    assert "synthetic-password" not in output.getvalue()


@pytest.mark.parametrize("as_json", [False, True])
def test_sql_connection_failure_does_not_echo_url_credentials(as_json):
    output = io.StringIO()
    with pytest.raises(SystemExit), contextlib.redirect_stdout(output):
        SQLI._conn_failed_exit("http://127.0.0.1/?password=synthetic-password", as_json)
    assert "synthetic-password" not in output.getvalue()


@pytest.mark.parametrize("module", [SSRF, PATH])
@pytest.mark.parametrize("as_json", [False, True])
def test_specialist_failures_do_not_echo_arbitrary_request_or_credential_text(module, as_json):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        module._fail(SimpleNamespace(json=as_json), "request_failed", RuntimeError(PRIVATE))
    assert "synthetic-password" not in output.getvalue()
    assert "person@example.invalid" not in output.getvalue()


@pytest.mark.parametrize("error, expected", [(TimeoutError(PRIVATE), "timeout"),
                                             (ConnectionError(PRIVATE), "connection_error"),
                                             (requests.exceptions.Timeout(PRIVATE), "timeout"),
                                             (requests.exceptions.ConnectionError(PRIVATE), "connection_error"),
                                             (KeyError(PRIVATE), "invalid_response"),
                                             (RuntimeError(PRIVATE), "request_failed")])
def test_structured_upload_error_cause_survives_safe_output(error, expected):
    with patch.object(dyn_session, "request", side_effect=error):
        result = PATH.run_upload("http://127.0.0.1", "/upload")
    assert result.get("error_type") == expected
    assert redact(result)["error_type"] == expected
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        dyn_session.emit({"findings": [result]}, False)
    assert "발사실패: " + expected in output.getvalue()
    assert "person@example.invalid" not in output.getvalue()
    assert "synthetic-password" not in output.getvalue()


@pytest.mark.parametrize("runner", ["redirect", "traversal", "ssrf"])
def test_specialist_control_failures_expose_safe_error_code(runner):
    with patch.object(dyn_session, "request", side_effect=TimeoutError(PRIVATE)):
        if runner == "redirect":
            result = SSRF.run_open_redirect("http://127.0.0.1", "/go?url=", "127.0.0.1")
        elif runner == "traversal":
            result = PATH.run_path_traversal("http://127.0.0.1", "/download?file=")
        else:
            result = SSRF.run_ssrf("http://127.0.0.1", "/fetch?url=", Listener(), timeout=0)
    assert result.get("error_type") == "timeout"
    assert result.get("error")
    assert "person@example.invalid" not in json.dumps(result)


@pytest.mark.parametrize("unsafe_type", [PRIVATE, {"token": PRIVATE}, [PRIVATE], None])
def test_human_diagnostic_rejects_arbitrary_error_type_prose(unsafe_type):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        dyn_session.emit({"findings": [{"error": True, "error_type": unsafe_type}]}, False)
    assert "발사실패: request_failed" in output.getvalue()
    assert "person@example.invalid" not in output.getvalue()


def test_sql_connection_failure_exposes_safe_error_code():
    output = io.StringIO()
    with pytest.raises(SystemExit), contextlib.redirect_stdout(output):
        SQLI._conn_failed_exit("http://127.0.0.1/", True)
    assert json.loads(output.getvalue()).get("error_type") == "request_failed"


def test_sql_error_signal_does_not_skip_independent_confirmation():
    args = SQLI._build_parser().parse_args(["http://127.0.0.1", "--param", "id", "--json"])
    evidence = {"technique": "error-based", "validation": "undetermined",
                "evidence_level": "input-dependent-db-error"}
    with patch.object(SQLI, "assert_in_scope", return_value="loopback"), \
         patch.object(dyn_session, "request", return_value=response()), \
         patch.object(SQLI, "_try_error_based", return_value=(evidence, None)), \
         patch.object(SQLI, "_try_boolean_based", return_value=(None, None)) as boolean, \
         patch.object(SQLI, "_try_time_based", return_value=(None, None)) as timing, \
         patch.object(SQLI, "_output") as output:
        SQLI.run_attack(args)
    boolean.assert_called_once()
    timing.assert_called_once()
    result = output.call_args.args[0]
    assert result["exploited"] is False
    assert result["validation"] == "undetermined"
    assert result["evidence"] == evidence


def test_static_file_signature_page_does_not_confirm_any_traversal():
    with patch.object(dyn_session, "request", return_value=response(body="help: " + PASSWD)):
        result = PATH.run_path_traversal("http://127.0.0.1", "/download?file=")
    assert result["vulnerable"] is False
    assert result["findings"] == []
    assert result.get("undetermined") is True


def test_traversal_requires_target_specific_signature():
    def request(_method, url, **_kwargs):
        return response(body=PASSWD if ".." in url or "%2" in url else "normal")
    with patch.object(dyn_session, "request", side_effect=request):
        result = PATH.run_path_traversal("http://127.0.0.1", "/download?file=")
    assert result["vulnerable"] is True
    assert [item["target_file"] for item in result["findings"]] == ["unix"]


@pytest.mark.parametrize("status", [302, 400, 404, 500])
def test_failed_http_response_with_signature_is_not_confirmed_leak(status):
    def request(_method, url, **_kwargs):
        return response(status, PASSWD) if ".." in url or "%2" in url else response(body="normal")
    with patch.object(dyn_session, "request", side_effect=request):
        result = PATH.run_path_traversal("http://127.0.0.1", "/download?file=")
    assert result["vulnerable"] is False
    assert result.get("undetermined") is True


def test_failed_traversal_control_cannot_confirm_leak():
    def request(_method, url, **_kwargs):
        if ".." not in url and "%2" not in url:
            raise TimeoutError("control unavailable")
        return response(body=PASSWD)
    with patch.object(dyn_session, "request", side_effect=request):
        result = PATH.run_path_traversal("http://127.0.0.1", "/download?file=")
    assert result["vulnerable"] is False
    assert result.get("undetermined") is True


def test_retrieved_upload_is_observation_without_execution_or_cleanup_claim():
    marker = ("gxmarker_synthetic.jsp", "GXMARKER-synthetic", "synthetic")
    with patch.object(PATH, "make_marker_upload", return_value=marker), \
         patch.object(dyn_session, "request", side_effect=[response(201), response(body=marker[1])]) as request:
        result = PATH.run_upload("http://127.0.0.1", "/upload", retrieve_base="http://127.0.0.1/files")
    assert result["accepted"] is True
    assert result["retrievable"] is True
    assert result["vulnerable"] is False
    assert result["undetermined"] is True
    assert result.get("execution_confirmed") is False
    assert result.get("cleanup", {}).get("status") == "manual-required"
    assert result["cleanup"]["leftover_status"] == "confirmed"
    assert result["cleanup"]["marker"] == marker[0]
    assert [call.args[0] for call in request.call_args_list] == ["POST", "GET"]


def test_upload_timeout_retains_possible_leftover_without_false_cleanup():
    marker = ("gxmarker_synthetic.jsp", "GXMARKER-synthetic", "synthetic")
    with patch.object(PATH, "make_marker_upload", return_value=marker), \
         patch.object(dyn_session, "request", side_effect=TimeoutError("possibly stored")):
        result = PATH.run_upload("http://127.0.0.1", "/upload")
    assert result.get("cleanup", {}).get("status") == "manual-required"
    assert result["cleanup"]["leftover_status"] == "possible"
    assert result.get("leftover") == marker[0]


@pytest.mark.parametrize("failure, expected", [(TimeoutError(PRIVATE), "timeout"),
                                               (ConnectionError(PRIVATE), "connection_error")])
def test_upload_retrieval_failure_keeps_acceptance_cleanup_and_safe_cause(failure, expected):
    marker = ("gxmarker_synthetic.jsp", "GXMARKER-synthetic", "synthetic")
    with patch.object(PATH, "make_marker_upload", return_value=marker), \
         patch.object(dyn_session, "request", side_effect=[response(201), failure]):
        result = PATH.run_upload("http://127.0.0.1", "/upload", retrieve_base="http://127.0.0.1/files")
    assert result["accepted"] is True
    assert result["retrievable"] is False
    assert result.get("error")
    assert result.get("error_type") == expected
    assert result["cleanup"]["status"] == "manual-required"
    assert result["cleanup"]["leftover_status"] == "possible"
    assert result["leftover"] == marker[0]
    assert "person@example.invalid" not in json.dumps(result)


def test_upload_retrieval_404_is_distinct_from_request_failure():
    with patch.object(dyn_session, "request", side_effect=[response(201), response(404)]):
        result = PATH.run_upload("http://127.0.0.1", "/upload", retrieve_base="http://127.0.0.1/files")
    assert result["accepted"] is True
    assert result["retrievable"] is False
    assert not result.get("error")
    assert "error_type" not in result
    assert result["cleanup"]["leftover_status"] == "possible"


@pytest.mark.parametrize("status", [200, 201, 302, 400, 401, 403, 404, 409, 422, 500, 503])
def test_every_attempted_upload_retains_possible_marker_until_verified_absent(status):
    marker = ("gxmarker_synthetic.jsp", "GXMARKER-synthetic", "synthetic")
    with patch.object(PATH, "make_marker_upload", return_value=marker), \
         patch.object(dyn_session, "request", return_value=response(status)):
        result = PATH.run_upload("http://127.0.0.1", "/upload")
    assert result["accepted"] is (200 <= status < 300)
    assert result["leftover"] == marker[0]
    assert result["cleanup"]["status"] == "manual-required"
    assert result["cleanup"]["leftover_status"] == "possible"
    assert result["cleanup"]["attempted"] is False


class StoreThenRejectHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        # A server may persist the object before a business-rule 409/422 response.
        self.server.stored = self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(409)
        self.end_headers()

    def log_message(self, *_args):
        pass


def test_loopback_store_then_reject_keeps_manual_cleanup_requirement():
    marker = ("gxmarker_synthetic.jsp", "GXMARKER-synthetic", "synthetic")
    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), StoreThenRejectHandler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch.object(PATH, "make_marker_upload", return_value=marker):
                result = PATH.run_upload(f"http://127.0.0.1:{server.server_port}", "/upload")
            assert marker[0].encode() in server.stored
            assert marker[1].encode() in server.stored
        finally:
            server.shutdown()
            thread.join(2)
    assert result["accepted"] is False
    assert result["cleanup"]["status"] == "manual-required"
    assert result["leftover"] == marker[0]


class ControlledHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        value = parse_qs(urlsplit(self.path).query).get("file", [""])[0]
        body = PASSWD if value.startswith("../") and value.endswith("etc/passwd") else "not found"
        self.send_response(200 if body == PASSWD else 404)
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *_args):
        pass


def test_loopback_traversal_retains_valid_positive_and_target_identity():
    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), ControlledHandler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = PATH.run_path_traversal(f"http://127.0.0.1:{server.server_port}", "/download?file=")
        finally:
            server.shutdown()
            thread.join(2)
    assert result["vulnerable"] is True
    assert [item["target_file"] for item in result["findings"]] == ["unix"]
