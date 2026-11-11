"""Pinned, bounded HTTP for the specialist attack-payload clients.

Scope is an exact origin, not a path allowlist: percent encodings and traversal
payloads remain available to the specialists. Host policy and numeric-address
policy are checked separately, and target names are never resolved. HTTP local
proxies use CONNECT to the approved numeric destination for both HTTP and HTTPS.
HTTPS proxies are deliberately unsupported; TLS to targets always verifies the
original hostname. Operation budgets outlive individual Requests sessions.
"""
from __future__ import annotations

import http.client
import io
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import sys
import threading
import time
import zlib
from dataclasses import dataclass
from types import MappingProxyType
from urllib.parse import urlsplit

from requests.adapters import HTTPAdapter
from urllib3._collections import HTTPHeaderDict
from urllib3.response import HTTPResponse as BufferedHTTPResponse

from tools.scope_guard import ScopeError, assert_in_scope


class PolicyError(ScopeError):
    code = "scope_blocked"

    def __init__(self):
        super().__init__(self.code)


class BudgetError(RuntimeError):
    def __init__(self, code="budget_exhausted"):
        self.code = code if code in {"response_limit", "budget_exhausted"} else "budget_exhausted"
        super().__init__(self.code)


class DeadlineError(TimeoutError):
    code = "timeout"

    def __init__(self):
        super().__init__(self.code)


class TransportError(RuntimeError):
    code = "invalid_response"

    def __init__(self):
        super().__init__(self.code)


class NetworkError(ConnectionError):
    code = "connection_error"

    def __init__(self):
        super().__init__(self.code)


def _parts(url):
    try:
        if not isinstance(url, str) or re.search(r"[\x00-\x20\x7f-\x9f\\]", url) or "#" in url:
            raise ValueError
        parsed = urlsplit(url)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.netloc.endswith(":")):
            raise ValueError
        host = parsed.hostname
        if host.endswith(".") or "%" in host:
            raise ValueError
        try:
            address = ipaddress.ip_address(host)
            host = address.compressed
        except ValueError:
            host = host.encode("idna").decode("ascii").lower()
            if len(host) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")):
                raise ValueError
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        if not 1 <= port <= 65535:
            raise ValueError
        return parsed, host, port
    except (ValueError, TypeError, UnicodeError):
        raise PolicyError() from None


def canonical_origin(url):
    """Return an explicit-port ASCII origin without restricting attack paths."""
    parsed, host, port = _parts(url)
    authority = f"[{host}]" if ":" in host else host
    return f"{parsed.scheme}://{authority}:{port}"


@dataclass(frozen=True)
class Limits:
    max_requests: int = 100
    max_duration_seconds: float = 120
    max_response_wire_bytes: int = 1_048_576
    max_response_decoded_bytes: int = 1_048_576
    max_total_wire_bytes: int = 8_388_608
    max_total_decoded_bytes: int = 8_388_608

    def __post_init__(self):
        ceilings = {"max_requests": 100, "max_duration_seconds": 120,
                    "max_response_wire_bytes": 1_048_576, "max_response_decoded_bytes": 1_048_576,
                    "max_total_wire_bytes": 8_388_608, "max_total_decoded_bytes": 8_388_608}
        for name, maximum in ceilings.items():
            value = getattr(self, name)
            if (isinstance(value, bool) or not isinstance(value, (int, float))
                    or not math.isfinite(value) or value <= 0 or value > maximum
                    or (name != "max_duration_seconds" and type(value) is not int)):
                raise PolicyError()


def _literal(value):
    try:
        if not isinstance(value, str) or "%" in value:
            raise ValueError
        address = ipaddress.ip_address(value)
        if (address.is_unspecified or address.is_link_local or address.is_multicast
                or address == ipaddress.ip_address("fd00:ec2::254")
                or address == ipaddress.ip_address("255.255.255.255")
                or (address.version == 6 and address.ipv4_mapped is not None)
                or (address.version == 4 and address in ipaddress.ip_network("0.0.0.0/8"))):
            raise ValueError
        return address.compressed
    except (ValueError, TypeError):
        raise PolicyError() from None


def _checked_scope(origin, authorized_flag):
    try:
        assert_in_scope(origin, authorized_flag=authorized_flag)
    except ScopeError:
        raise PolicyError() from None


def _proxy(value):
    if value is None:
        return None
    parsed, host, _ = _parts(value)
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise PolicyError() from None
    if (parsed.scheme != "http" or not address.is_loopback
            or (address.version == 6 and address.ipv4_mapped is not None)
            or parsed.path or "?" in value):
        raise PolicyError()
    return canonical_origin(value)


def _json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError()
        result[key] = value
    return result


class OperationContext:
    """One immutable policy snapshot and one cumulative, serialized run budget.

    Mapping a reserved hostname to a private/global IP does not grant that IP
    authorization: both the original host and its literal destination must pass
    the existing scope guard. Environment approvals are consulted only here.
    """
    _POLICY_FIELDS = frozenset({"limits", "proxy_url", "ca_file", "approved_ips", "origins", "_tls_context"})

    def __setattr__(self, name, value):
        if name in self._POLICY_FIELDS and hasattr(self, name):
            raise AttributeError("Operation policy is immutable")
        object.__setattr__(self, name, value)

    def __init__(self, target_urls, *, authorized_flag=False, target_ips=None,
                 limits=None, proxy_url=None, ca_file=None):
        self.limits = limits if limits is not None else Limits()
        if not isinstance(self.limits, Limits) or not isinstance(authorized_flag, bool):
            raise PolicyError()
        self.proxy_url = _proxy(proxy_url)
        if ca_file is not None and (not isinstance(ca_file, str) or not ca_file or not os.path.isfile(ca_file)):
            raise PolicyError()
        self.ca_file = ca_file
        # Load the CA now so a missing/invalid CA cannot lead to any connection.
        try:
            self._tls_context = ssl.create_default_context(cafile=ca_file)
        except (OSError, ValueError, ssl.SSLError):
            raise PolicyError() from None
        if target_ips is None:
            try:
                target_ips = json.loads(os.environ.get("SECURITY_PLUGIN_TARGET_IPS", "{}"), object_pairs_hook=_json_pairs)
            except (ValueError, TypeError):
                raise PolicyError() from None
        if not isinstance(target_ips, dict):
            raise PolicyError()
        mapping = {}
        for origin, values in target_ips.items():
            parsed, _, _ = _parts(origin)
            if canonical_origin(origin) != origin or parsed.path or parsed.query or not isinstance(values, (list, tuple)) or not values:
                raise PolicyError()
            mapping[origin] = tuple(dict.fromkeys(_literal(value) for value in values))
        if isinstance(target_urls, str):
            target_urls = [target_urls]
        try:
            urls = tuple(target_urls)
        except TypeError:
            raise PolicyError() from None
        if not urls:
            raise PolicyError()
        approved = {}
        for url in urls:
            origin = canonical_origin(url)
            parsed, host, port = _parts(origin)
            _checked_scope(origin, authorized_flag)
            try:
                literal = ipaddress.ip_address(host)
            except ValueError:
                literal = None
            if literal is not None:
                addresses = (_literal(host),)
                if origin in mapping and mapping[origin] != addresses:
                    raise PolicyError()
            elif host == "localhost":
                addresses = mapping.get(origin, ("127.0.0.1", "::1"))
                if any(address not in {"127.0.0.1", "::1"} for address in addresses):
                    raise PolicyError()
            else:
                addresses = mapping.get(origin)
                if not addresses:
                    raise PolicyError()
            for address in addresses:
                numeric_host = f"[{address}]" if ":" in address else address
                _checked_scope(f"{parsed.scheme}://{numeric_host}:{port}", authorized_flag)
            approved[origin] = addresses
        self.approved_ips = MappingProxyType(approved)
        self.origins = frozenset(approved)
        self._lock = threading.RLock()
        self._started = time.monotonic()
        self._deadline = self._started + self.limits.max_duration_seconds
        self._requests = 0
        self._wire_bytes = 0
        self._decoded_bytes = 0

    @property
    def counters(self):
        with self._lock:
            return MappingProxyType({"requests": self._requests, "wire_bytes": self._wire_bytes,
                                     "decoded_bytes": self._decoded_bytes})

    def ensure_origin(self, url):
        origin = canonical_origin(url)
        if origin not in self.origins:
            raise PolicyError()
        return origin

    def _begin(self, request_deadline):
        if time.monotonic() >= self._deadline:
            raise DeadlineError()
        if (self._requests >= self.limits.max_requests
                or self._wire_bytes >= self.limits.max_total_wire_bytes
                or self._decoded_bytes >= self.limits.max_total_decoded_bytes):
            raise BudgetError()
        self._requests += 1
        return _Meter(self, min(self._deadline, request_deadline))


class _Meter:
    def __init__(self, operation, deadline):
        self.operation = operation
        self.deadline = deadline
        self.wire = 0
        self.decoded = 0

    def remaining(self):
        seconds = self.deadline - time.monotonic()
        if seconds <= 0:
            raise DeadlineError()
        return seconds

    def allowance(self, decoded=False):
        limits = self.operation.limits
        if decoded:
            return min(limits.max_response_decoded_bytes - self.decoded,
                       limits.max_total_decoded_bytes - self.operation._decoded_bytes)
        return min(limits.max_response_wire_bytes - self.wire,
                   limits.max_total_wire_bytes - self.operation._wire_bytes)

    def charge(self, amount, decoded=False):
        if decoded:
            self.decoded += amount
            self.operation._decoded_bytes += amount
        else:
            self.wire += amount
            self.operation._wire_bytes += amount
        limits = self.operation.limits
        if (self.operation._wire_bytes > limits.max_total_wire_bytes
                or self.operation._decoded_bytes > limits.max_total_decoded_bytes):
            raise BudgetError()
        if self.wire > limits.max_response_wire_bytes or self.decoded > limits.max_response_decoded_bytes:
            raise BudgetError("response_limit")


class _Reader(io.RawIOBase):
    def __init__(self, sock, meter):
        self.sock = sock
        self.meter = meter

    def readable(self):
        return True

    def readinto(self, buffer):
        self.sock.settimeout(self.meter.remaining())
        size = min(len(buffer), 65_536, max(1, self.meter.allowance() + 1))
        count = self.sock.recv_into(memoryview(buffer)[:size])
        self.meter.charge(count)
        self.meter.remaining()
        return count


class _ResponseSocket:
    def __init__(self, sock, meter):
        self.sock = sock
        self.meter = meter

    def makefile(self, mode):
        if mode != "rb":
            raise TransportError()
        return io.BufferedReader(_Reader(self.sock, self.meter))


def _send(sock, data, meter):
    # Each write gets the same absolute deadline, including proxy/TLS work.
    view = memoryview(data)
    while view:
        sock.settimeout(meter.remaining())
        count = sock.send(view[:65_536])
        if not count:
            raise TransportError()
        view = view[count:]
    meter.remaining()


def _validate_response(response):
    headers = response.headers
    lengths = headers.get_all("Content-Length", [])
    transfers = headers.get_all("Transfer-Encoding", [])
    if len(lengths) > 1 or (lengths and transfers):
        raise TransportError()
    if lengths and not re.fullmatch(r"[0-9]+", lengths[0].strip()):
        raise TransportError()
    if transfers and (len(transfers) != 1 or transfers[0].strip().lower() != "chunked"):
        raise TransportError()
    if response.status < 200 or response.status > 599 or headers.defects:
        raise TransportError()
    for name, value in headers.items():
        if (not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                or re.search(r"[\x00-\x08\x0a-\x1f\x7f]", value)):
            raise TransportError()


class _HeaderLines:
    def __init__(self, reader):
        self.reader = reader

    def __getattr__(self, name):
        return getattr(self.reader, name)

    def readline(self, limit=-1):
        line = self.reader.readline(limit)
        if not line.endswith(b"\r\n"):
            raise TransportError()
        return line


class _StrictResponse(http.client.HTTPResponse):
    """Retain stdlib headers/cookies while rejecting permissive chunk parsing."""
    def begin(self):
        original = self.fp
        self.fp = _HeaderLines(original)
        try:
            super().begin()
        finally:
            if self.fp is not None:
                self.fp = original

    def _line(self):
        line = self.fp.readline(65_537)
        if len(line) > 65_536 or not line.endswith(b"\r\n"):
            raise TransportError()
        return line[:-2]

    def _read_next_chunk_size(self):
        line = self._line()
        if not re.fullmatch(rb"[0-9a-fA-F]+(?:;[^\x00-\x1f\x7f]*)?", line):
            raise TransportError()
        return int(line.split(b";", 1)[0], 16)

    def _get_chunk_left(self):
        left = self.chunk_left
        if left == 0 and self._safe_read(2) != b"\r\n":
            raise TransportError()
        if left is None or left == 0:
            left = self._read_next_chunk_size()
            if left == 0:
                self._read_and_discard_trailer()
                self._close_conn()
                left = None
            self.chunk_left = left
        return left

    def _read_and_discard_trailer(self):
        for _ in range(101):
            line = self._line()
            if not line:
                return
            name, colon, value = line.partition(b":")
            if (not colon or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                    or re.search(rb"[\x00-\x08\x0a-\x1f\x7f]", value)
                    or name.lower() in {b"content-length", b"transfer-encoding", b"content-encoding", b"host"}):
                raise TransportError()
        raise TransportError()


def _read_body(response, meter):
    if response._method == "HEAD" or response.status in {204, 304}:
        meter.remaining()
        return b""
    encodings = response.headers.get_all("Content-Encoding", [])
    if len(encodings) > 1:
        raise TransportError()
    encoding = encodings[0].strip().lower() if encodings else "identity"
    if encoding not in {"identity", "gzip", "deflate"}:
        raise TransportError()
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS if encoding == "gzip" else zlib.MAX_WBITS) if encoding != "identity" else None
    body = bytearray()
    while True:
        meter.remaining()
        # read1 avoids waiting to fill 64KiB while every raw read still checks the
        # deadline and accounts header/chunk framing bytes.
        chunk = response.read1(65_536)
        if not chunk:
            if response.length not in {None, 0}:
                raise TransportError()
            break
        if decoder is None:
            meter.charge(len(chunk), decoded=True)
            body.extend(chunk)
            continue
        pending = chunk
        while pending:
            meter.remaining()
            decoded = decoder.decompress(pending, max(1, min(65_536, meter.allowance(decoded=True) + 1)))
            meter.charge(len(decoded), decoded=True)
            body.extend(decoded)
            if decoder.unused_data:
                raise TransportError()
            pending = decoder.unconsumed_tail
    if decoder is not None and (not decoder.eof or decoder.unused_data or decoder.unconsumed_tail):
        raise TransportError()
    meter.remaining()
    return bytes(body)


def _timeout_seconds(timeout):
    if isinstance(timeout, tuple):
        if len(timeout) != 2:
            raise PolicyError()
        values = timeout
    else:
        values = (timeout,)
    if any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0 for value in values):
        raise PolicyError()
    return min(values)


def _request_bytes(request, host, port, scheme):
    method = request.method
    if not isinstance(method, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", method):
        raise PolicyError()
    body = request.body
    if body is None:
        body = b""
    elif isinstance(body, str):
        body = body.encode("utf-8")
    elif not isinstance(body, bytes):
        raise PolicyError()
    parsed = urlsplit(request.url)
    target = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
    authority = f"[{host}]" if ":" in host else host
    if port != (443 if scheme == "https" else 80):
        authority += f":{port}"
    headers = []
    for name, value in request.headers.items():
        if (not isinstance(name, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                or not isinstance(value, str) or re.search(r"[\x00-\x1f\x7f]", value)):
            raise PolicyError()
        lowered = name.lower()
        if lowered == "host":
            if value.lower() != authority.lower():
                raise PolicyError()
            continue
        if lowered in {"transfer-encoding", "proxy-authorization", "proxy-connection", "upgrade"}:
            raise PolicyError()
        if lowered in {"content-length", "connection", "accept-encoding"}:
            continue
        headers.append((name, value))
    supplied_length = request.headers.get("Content-Length")
    if supplied_length is not None and (not re.fullmatch(r"[0-9]+", supplied_length) or int(supplied_length) != len(body)):
        raise PolicyError()
    headers = [("Host", authority), ("Connection", "close"), ("Accept-Encoding", "gzip, deflate")] + headers
    if body or supplied_length is not None or method.upper() in {"POST", "PUT", "PATCH"}:
        headers.append(("Content-Length", str(len(body))))
    try:
        head = (method + " " + target + " HTTP/1.1\r\n" + "".join(name + ": " + value + "\r\n" for name, value in headers) + "\r\n").encode("latin-1")
    except UnicodeError:
        raise PolicyError() from None
    return head, body


class BoundedAdapter(HTTPAdapter):
    """Requests adapter which returns a response only after complete validation."""
    def __init__(self, operation):
        if not isinstance(operation, OperationContext):
            raise PolicyError()
        self.operation = operation
        super().__init__(max_retries=0)

    def close(self):
        # No pooled sockets; Session.close must not reset the shared run budget.
        super().close()

    def send(self, request, stream=False, timeout=10, verify=True, cert=None, proxies=None):
        seconds = _timeout_seconds(timeout)
        request_deadline = time.monotonic() + seconds
        operation = self.operation
        origin = operation.ensure_origin(request.url)
        tls_context = operation._tls_context
        if not tls_context.check_hostname or tls_context.verify_mode != ssl.CERT_REQUIRED:
            raise PolicyError()
        parsed, host, port = _parts(request.url)
        expected_verify = operation.ca_file or True
        if verify != expected_verify or cert is not None or stream not in {True, False}:
            raise PolicyError()
        if operation.proxy_url:
            if not isinstance(proxies, dict) or set(proxies) - {"http", "https"} or proxies.get(parsed.scheme) != operation.proxy_url or any(value != operation.proxy_url for value in proxies.values()):
                raise PolicyError()
        elif proxies:
            raise PolicyError()
        head, body = _request_bytes(request, host, port, parsed.scheme)
        wait_seconds = min(operation._deadline, request_deadline) - time.monotonic()
        if wait_seconds <= 0 or not operation._lock.acquire(timeout=wait_seconds):
            raise DeadlineError()
        try:
            meter = operation._begin(request_deadline)
            sock = None
            response = None
            try:
                address = operation.approved_ips[origin][0]
                if operation.proxy_url:
                    _, connect_address, connect_port = _parts(operation.proxy_url)
                else:
                    connect_address, connect_port = address, port
                family = socket.AF_INET6 if ":" in connect_address else socket.AF_INET
                sock = socket.socket(family, socket.SOCK_STREAM)
                sock.settimeout(meter.remaining())
                endpoint = (connect_address, connect_port, 0, 0) if family == socket.AF_INET6 else (connect_address, connect_port)
                sock.connect(endpoint)
                meter.remaining()
                if operation.proxy_url:
                    authority = f"[{address}]:{port}" if ":" in address else f"{address}:{port}"
                    _send(sock, (f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").encode("ascii"), meter)
                    response = _StrictResponse(_ResponseSocket(sock, meter), method="CONNECT")
                    response.begin()
                    _validate_response(response)
                    if response.status != 200 or response.headers.get("Transfer-Encoding") or response.headers.get("Content-Length", "0").strip() != "0":
                        raise TransportError()
                    response.close()
                    response = None
                if parsed.scheme == "https":
                    sock.settimeout(meter.remaining())
                    # Explicit handshake below lets each TLS step share the
                    # absolute request deadline; no hostname socket helper runs.
                    sock = tls_context.wrap_socket(sock, server_hostname=host, do_handshake_on_connect=False)
                    sock.settimeout(meter.remaining())
                    sock.do_handshake()
                    meter.remaining()
                _send(sock, head, meter)
                if body:
                    _send(sock, body, meter)
                response = _StrictResponse(_ResponseSocket(sock, meter), method=request.method.upper())
                response.begin()
                _validate_response(response)
                content = _read_body(response, meter)
                headers = HTTPHeaderDict()
                for name, value in response.getheaders():
                    headers.add(name, value)
                raw = BufferedHTTPResponse(body=io.BytesIO(content), headers=headers,
                                           status=response.status, version=response.version,
                                           reason=response.reason, original_response=response,
                                           request_method=request.method, request_url=request.url,
                                           preload_content=False, decode_content=False)
                result = self.build_response(request, raw)
                result._content = content
                result._content_consumed = True
                meter.remaining()
                return result
            except (PolicyError, BudgetError, DeadlineError, TransportError):
                raise
            except (socket.timeout, TimeoutError):
                raise DeadlineError() from None
            except OSError:
                raise NetworkError() from None
            except (ValueError, http.client.HTTPException, zlib.error, OverflowError):
                raise TransportError() from None
            finally:
                error_in_flight = sys.exc_info()[0] is not None
                cleanup_error = None
                try:
                    if response is not None:
                        try:
                            response.close()
                        except Exception:
                            cleanup_error = TransportError()
                finally:
                    if sock is not None:
                        try:
                            sock.close()
                        except Exception:
                            if cleanup_error is None:
                                cleanup_error = NetworkError()
                if cleanup_error is not None and not error_in_flight:
                    raise cleanup_error from None
        finally:
            operation._lock.release()
