"""Specialist transport controls, using loopback peers only."""
import gzip
import importlib.util
import io
import socket
import threading
import time
from contextlib import contextmanager
from unittest.mock import patch

import pytest
import requests


def test_specialist_transport_boundary_exists():
    assert importlib.util.find_spec("tools.specialist_transport") is not None, "Pinned specialist transport is missing"


@contextmanager
def peer(response, *, pause=0, split_at=None, drip_delay=None):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(2)
    seen = []

    def serve():
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(2)
                request = b""
                while b"\r\n\r\n" not in request:
                    chunk = connection.recv(65536)
                    if not chunk:
                        return
                    request += chunk
                headers, _, body = request.partition(b"\r\n\r\n")
                length = 0
                for line in headers.split(b"\r\n")[1:]:
                    if line.lower().startswith(b"content-length:"):
                        length = int(line.split(b":", 1)[1])
                while len(body) < length:
                    body += connection.recv(65536)
                seen.append(headers + b"\r\n\r\n" + body)
                if drip_delay is not None:
                    for byte in response:
                        connection.sendall(bytes([byte]))
                        time.sleep(drip_delay)
                elif split_at is not None:
                    connection.sendall(response[:split_at])
                    time.sleep(pause)
                    connection.sendall(response[split_at:])
                else:
                    time.sleep(pause)
                    connection.sendall(response)
        except (OSError, ValueError):
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{listener.getsockname()[1]}", seen
    finally:
        listener.close()
        thread.join(3)
        assert not thread.is_alive()


def api():
    from tools import specialist_transport
    return specialist_transport


def fetch(operation, url, **kwargs):
    with requests.Session() as session:
        session.trust_env = False
        session.mount("http://", api().BoundedAdapter(operation))
        session.mount("https://", api().BoundedAdapter(operation))
        return session.get(url, timeout=1, allow_redirects=False, **kwargs)


def response(body=b"ok", headers=b"", status=b"200 OK"):
    return b"HTTP/1.1 " + status + b"\r\nContent-Length: " + str(len(body)).encode() + b"\r\n" + headers + b"\r\n" + body


@pytest.mark.parametrize("url", ["http://user:secret@a.test/", "http://a.test./", "http://a.test:0/", "http://a.test:/", "http://a.test/#x", "http://a.test/\\x", "http://a.test/\nx", "http://a.test:65536/", "http://a.test/#", "http://[fe80::1%25x]/"])
def test_invalid_origin_is_fixed_policy_error(url):
    with pytest.raises(api().PolicyError) as error:
        api().canonical_origin(url)
    assert str(error.value) == "scope_blocked"


def test_canonical_origin_allows_attack_path_and_normalizes_idna():
    assert api().canonical_origin("https://BÜCHER.test/a/../%2e%2e?q=%00") == "https://xn--bcher-kva.test:443"
    assert api().canonical_origin("http://[::1]/") == "http://[::1]:80"


@pytest.mark.parametrize("field,value", [("max_requests", 0), ("max_requests", True), ("max_duration_seconds", float("inf")), ("max_duration_seconds", float("nan")), ("max_response_wire_bytes", -1), ("max_requests", 101), ("max_response_wire_bytes", 100.0)])
def test_limits_are_finite_positive_and_cannot_expand_defaults(field, value):
    with pytest.raises(api().PolicyError):
        api().Limits(**{field: value})


@pytest.mark.parametrize("address", ["169.254.169.254", "fd00:ec2::254", "::", "0.0.0.1", "224.0.0.1", "::ffff:127.0.0.1", "fe80::1"])
def test_forbidden_map_never_creates_socket(address):
    with patch("socket.socket") as create, pytest.raises(api().PolicyError):
        api().OperationContext(["http://fixture.test/"], target_ips={"http://fixture.test:80": [address]})
    create.assert_not_called()


def test_missing_mapping_and_denied_original_host_are_preflight(monkeypatch):
    monkeypatch.setenv("SECURITY_PLUGIN_DENY_HOSTS", "blocked.test")
    with patch("socket.socket") as create:
        for url, mapping in [("http://fixture.test/", {}), ("http://blocked.test/", {"http://blocked.test:80": ["127.0.0.1"]})]:
            with pytest.raises(api().PolicyError):
                api().OperationContext([url], target_ips=mapping)
    create.assert_not_called()


def test_pinned_hostname_uses_no_dns_and_retains_host_url_and_404():
    with peer(response(status=b"404 Not Found")) as (origin, seen):
        url = origin.replace("127.0.0.1", "fixture.test") + "/%2f%2e%2e/secrets?q=%00"
        prepared_url = requests.Request("GET", url).prepare().url
        operation = api().OperationContext([url], target_ips={api().canonical_origin(url): ["127.0.0.1"]})
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS")), patch("socket.gethostbyname", side_effect=AssertionError("DNS")):
            result = fetch(operation, url)
        assert result.status_code == 404
        assert result.url == prepared_url and result.request.url == prepared_url
        assert result.content == b"ok"
        assert b"Host: fixture.test:" in seen[0]
        assert b"GET /%2F../secrets?q=%00 HTTP/1.1" in seen[0]


def test_multipart_auth_and_duplicate_set_cookie_are_preserved():
    payload = response(headers=b"Set-Cookie: first=one; Path=/\r\nSet-Cookie: second=two; Path=/\r\n")
    with peer(payload) as (origin, seen):
        operation = api().OperationContext([origin])
        with requests.Session() as session:
            session.trust_env = False
            session.mount("http://", api().BoundedAdapter(operation))
            result = session.post(origin + "/upload", files={"file": ("fixture.txt", b"payload")}, auth=("alice", "fixture"), timeout=1)
            assert session.cookies.get("first") == "one"
            assert session.cookies.get("second") == "two"
            assert result.raw.headers.getlist("Set-Cookie") == ["first=one; Path=/", "second=two; Path=/"]
        assert b"Authorization: Basic " in seen[0]
        assert b"multipart/form-data; boundary=" in seen[0] and b"payload" in seen[0]


@pytest.mark.parametrize("payload", [b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx", b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nx", b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nx", b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\nx"])
def test_malformed_or_truncated_response_never_returns_partial_response(payload):
    with peer(payload) as (origin, _):
        with pytest.raises(api().TransportError) as error:
            fetch(api().OperationContext([origin]), origin)
        assert str(error.value) == "invalid_response"


@pytest.mark.parametrize("split", [0, 12, 32, -1])
def test_request_timeout_is_absolute_in_status_headers_and_body(split):
    payload = response(b"hello")
    with peer(payload, pause=0.15, split_at=split) as (origin, _):
        operation = api().OperationContext([origin])
        with pytest.raises(api().DeadlineError):
            with requests.Session() as session:
                session.trust_env = False
                session.mount("http://", api().BoundedAdapter(operation))
                session.get(origin, timeout=0.06)


def test_chunk_metadata_has_absolute_timeout():
    payload = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n"
    with peer(payload, pause=0.15, split_at=payload.index(b"1\r\n") + 1) as (origin, _):
        with pytest.raises(api().DeadlineError):
            fetch(api().OperationContext([origin], limits=api().Limits(max_duration_seconds=0.06)), origin)


@pytest.mark.parametrize("extra", [0, 1])
def test_wire_cap_includes_response_status_and_headers(extra):
    payload = response(b"abc" + b"x" * extra)
    base_length = len(response(b"abc"))
    with peer(payload) as (origin, _):
        operation = api().OperationContext([origin], limits=api().Limits(max_response_wire_bytes=base_length))
        if extra:
            with pytest.raises(api().BudgetError) as error:
                fetch(operation, origin)
            assert error.value.code == "response_limit"
        else:
            assert fetch(operation, origin).content == b"abc"
        assert operation.counters["wire_bytes"] == len(payload)


@pytest.mark.parametrize("extra", [0, 1])
def test_decoded_cap_and_bounded_gzip(extra):
    body = b"x" * (65_536 + extra)
    with peer(response(gzip.compress(body), b"Content-Encoding: gzip\r\n")) as (origin, _):
        operation = api().OperationContext([origin], limits=api().Limits(max_response_decoded_bytes=65_536))
        if extra:
            with pytest.raises(api().BudgetError) as error:
                fetch(operation, origin)
            assert error.value.code == "response_limit"
        else:
            assert fetch(operation, origin).content == body


@pytest.mark.parametrize("body,encoding", [(gzip.compress(b"x")[:-1], b"gzip"), (gzip.compress(b"x") * 2, b"gzip"), (gzip.compress(b"x"), b"gzip, gzip"), (b"x", b"br")])
def test_truncated_concatenated_stacked_and_unknown_encoding_fail(body, encoding):
    with peer(response(body, b"Content-Encoding: " + encoding + b"\r\n")) as (origin, _):
        with pytest.raises(api().TransportError):
            fetch(api().OperationContext([origin]), origin)


def test_attempt_budget_survives_new_adapters_and_session_close():
    with peer(response()) as (origin, _):
        operation = api().OperationContext([origin], limits=api().Limits(max_requests=1))
        assert fetch(operation, origin).content == b"ok"
        with patch("socket.socket") as create, pytest.raises(api().BudgetError) as error:
            fetch(operation, origin)
        create.assert_not_called()
        assert error.value.code == "budget_exhausted"
        assert operation.counters["requests"] == 1


def test_decoded_total_is_shared_across_requests_and_origins():
    with peer(response(b"ab")) as (one, _), peer(response(b"cd")) as (two, _):
        operation = api().OperationContext([one, two], limits=api().Limits(max_total_decoded_bytes=3))
        assert fetch(operation, one).content == b"ab"
        with pytest.raises(api().BudgetError) as error:
            fetch(operation, two)
        assert error.value.code == "budget_exhausted"
        assert operation.counters["decoded_bytes"] == 4


def test_streaming_request_body_and_transport_overrides_fail_before_socket():
    operation = api().OperationContext(["http://localhost/"])
    adapter = api().BoundedAdapter(operation)
    prepared = requests.Request("POST", "http://localhost/", data=io.BytesIO(b"fixture")).prepare()
    with patch("socket.socket") as create:
        with pytest.raises(api().PolicyError):
            adapter.send(prepared)
        for kwargs in [{"verify": False}, {"cert": "fixture"}, {"proxies": {"http": "http://127.0.0.1:9"}}]:
            with pytest.raises(api().PolicyError):
                adapter.send(requests.Request("GET", "http://localhost/").prepare(), **kwargs)
    create.assert_not_called()


@pytest.mark.parametrize("proxy", ["https://127.0.0.1:8080", "http://proxy.test:8080", "http://127.0.0.1:8080/", "http://user:secret@127.0.0.1:8080", "http://127.0.0.1:8080?"])
def test_unsupported_proxy_is_preflight_without_socket(proxy):
    with patch("socket.socket") as create, pytest.raises(api().PolicyError):
        api().OperationContext(["http://localhost/"], proxy_url=proxy)
    create.assert_not_called()


@pytest.mark.parametrize("framing", [b"1\r\nxXX0\r\n\r\n", b"-1\r\nx\r\n0\r\n\r\n", b"1\r\nx\r\n0\r\n", b"0\r\nContent-Length: 4\r\n\r\n"])
def test_chunk_framing_must_be_complete_and_unambiguous(framing):
    with peer(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + framing) as (origin, _):
        with pytest.raises(api().TransportError):
            fetch(api().OperationContext([origin]), origin)


def test_public_operation_policy_cannot_be_replaced_after_preflight():
    operation = api().OperationContext(["http://localhost/"])
    for name, value in [("limits", api().Limits()), ("proxy_url", "http://127.0.0.1:9"), ("origins", frozenset()), ("approved_ips", {}), ("ca_file", "other.pem")]:
        with pytest.raises(AttributeError):
            setattr(operation, name, value)


def test_head_with_encoding_and_representation_length_has_no_body():
    with peer(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nContent-Encoding: gzip\r\n\r\n") as (origin, _):
        operation = api().OperationContext([origin])
        with requests.Session() as session:
            session.trust_env = False
            session.mount("http://", api().BoundedAdapter(operation))
            result = session.head(origin, timeout=1)
        assert result.content == b""


@pytest.mark.parametrize("payload", [b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n", b"HTTP/1.1 200 OK\nContent-Length: 0\n\n"])
def test_response_headers_require_complete_crlf_terminator(payload):
    with peer(payload) as (origin, _):
        with pytest.raises(api().TransportError):
            fetch(api().OperationContext([origin]), origin)


def test_continuous_status_trickle_cannot_restart_request_timeout():
    with peer(response(), drip_delay=0.01) as (origin, _):
        started = time.monotonic()
        with pytest.raises(api().DeadlineError):
            with requests.Session() as session:
                session.trust_env = False
                session.mount("http://", api().BoundedAdapter(api().OperationContext([origin])))
                session.get(origin, timeout=0.06)
        assert time.monotonic() - started < 0.3


def test_wire_total_is_shared_between_distinct_sessions():
    payload = response()
    with peer(payload) as (one, _), peer(payload) as (two, _):
        operation = api().OperationContext([one, two], limits=api().Limits(max_total_wire_bytes=len(payload) * 2 - 1))
        assert fetch(operation, one).content == b"ok"
        with pytest.raises(api().BudgetError) as error:
            fetch(operation, two)
        assert error.value.code == "budget_exhausted"
        assert operation.counters["wire_bytes"] == len(payload) * 2


def test_failed_connection_attempt_consumes_request_budget():
    operation = api().OperationContext(["http://127.0.0.1:1"], limits=api().Limits(max_requests=1))
    with patch("socket.socket") as create:
        create.return_value.connect.side_effect = OSError("secret connection detail")
        with pytest.raises(api().NetworkError) as error:
            fetch(operation, "http://127.0.0.1:1")
        assert str(error.value) == "connection_error"
        create.return_value.close.assert_called_once()
    with patch("socket.socket") as create, pytest.raises(api().BudgetError):
        fetch(operation, "http://127.0.0.1:1")
    create.assert_not_called()


def test_operation_snapshot_ignores_later_mapping_and_gate_changes(monkeypatch):
    with peer(response()) as (origin, _):
        target = origin.replace("127.0.0.1", "fixture.test")
        mapping = {api().canonical_origin(target): ["127.0.0.1"]}
        operation = api().OperationContext([target], target_ips=mapping)
        mapping[api().canonical_origin(target)][0] = "169.254.169.254"
        monkeypatch.setenv("SECURITY_PLUGIN_DENY_HOSTS", "fixture.test")
        assert fetch(operation, target).content == b"ok"
        assert operation.approved_ips[api().canonical_origin(target)] == ("127.0.0.1",)


def test_environment_mapping_is_strict_and_copied(monkeypatch):
    monkeypatch.setenv("SECURITY_PLUGIN_TARGET_IPS", '{"http://fixture.test:80":["127.0.0.1"]}')
    operation = api().OperationContext(["http://fixture.test"])
    assert operation.approved_ips["http://fixture.test:80"] == ("127.0.0.1",)
    for value in ['{"http://fixture.test:80":[],"http://fixture.test:80":["127.0.0.1"]}', '{"http://fixture.test":["127.0.0.1"]}', '[]', 'not json']:
        monkeypatch.setenv("SECURITY_PLUGIN_TARGET_IPS", value)
        with pytest.raises(api().PolicyError):
            api().OperationContext(["http://fixture.test"])


def test_mapped_private_ip_requires_existing_private_authorization(monkeypatch):
    monkeypatch.delenv("SECURITY_PLUGIN_ALLOW_PRIVATE", raising=False)
    monkeypatch.delenv("SECURITY_PLUGIN_AUTHORIZED", raising=False)
    kwargs = {"target_ips": {"http://fixture.test:80": ["10.0.0.1"]}}
    with pytest.raises(api().PolicyError):
        api().OperationContext(["http://fixture.test"], **kwargs)
    monkeypatch.setenv("SECURITY_PLUGIN_ALLOW_PRIVATE", "1")
    assert api().OperationContext(["http://fixture.test"], **kwargs).origins == {"http://fixture.test:80"}


def test_http_proxy_connect_uses_numeric_authority_and_original_inner_host():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(2)
    seen = []

    def proxy():
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(2)
                for reply in [b"HTTP/1.1 200 Connection Established\r\n\r\n", response()]:
                    request = b""
                    while b"\r\n\r\n" not in request:
                        request += connection.recv(65536)
                    seen.append(request)
                    connection.sendall(reply)
        except OSError:
            pass

    thread = threading.Thread(target=proxy, daemon=True)
    thread.start()
    proxy_url = f"http://127.0.0.1:{listener.getsockname()[1]}"
    origin = "http://fixture.test:9876"
    operation = api().OperationContext([origin], proxy_url=proxy_url,
                                      target_ips={origin: ["127.0.0.2"]})
    try:
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS")):
            result = fetch(operation, origin + "/probe", proxies={"http": proxy_url, "https": proxy_url})
        assert result.content == b"ok"
        assert seen[0].startswith(b"CONNECT 127.0.0.2:9876 HTTP/1.1\r\n")
        assert b"Host: fixture.test:9876\r\n" in seen[1]
        assert b"GET /probe HTTP/1.1\r\n" in seen[1]
        assert operation.counters["wire_bytes"] == len(b"HTTP/1.1 200 Connection Established\r\n\r\n") + len(response())
    finally:
        listener.close()
        thread.join(3)
        assert not thread.is_alive()


def test_socket_closes_when_response_close_raises(monkeypatch):
    operation = api().OperationContext(["http://127.0.0.1:1"])
    prepared = requests.Request("GET", "http://127.0.0.1:1").prepare()
    with patch("socket.socket") as create, patch.object(api()._StrictResponse, "begin", side_effect=api().TransportError()), patch.object(api()._StrictResponse, "close", side_effect=RuntimeError("close failure")):
        with pytest.raises(api().TransportError) as error:
            api().BoundedAdapter(operation).send(prepared)
        assert str(error.value) == "invalid_response"
        create.return_value.close.assert_called_once()


def test_zlib_deflate_is_supported_without_unbounded_flush():
    import zlib
    with peer(response(zlib.compress(b"fixture"), b"Content-Encoding: deflate\r\n")) as (origin, _):
        assert fetch(api().OperationContext([origin]), origin).content == b"fixture"
