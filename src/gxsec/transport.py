"""Bounded HTTP transport with exact scope and a pinned destination socket.

This boundary covers this Python client only. It does not confine browsers or
third-party subprocesses. Environment proxy settings are deliberately ignored.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import math
import re
import socket
import ssl
import threading
import time
from urllib.parse import unquote, urljoin, urlsplit


class TransportError(RuntimeError):
    """A scope, budget, or HTTP execution precondition failed."""


def parse_url(url):
    if not isinstance(url, str) or re.search(r"[\x00-\x20\x7f\\]", url):
        raise TransportError("URL contains forbidden characters")
    try:
        p = urlsplit(url)
        if p.scheme not in {"http", "https"} or not p.hostname or p.username is not None or p.password is not None:
            raise ValueError()
        if p.fragment:
            raise ValueError()
        host = p.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        if p.hostname.endswith("."):
            raise ValueError()
        port = p.port or (443 if p.scheme == "https" else 80)
        if not 1 <= port <= 65535:
            raise ValueError()
        path = p.path or "/"
        decoded = unquote(path)
        if decoded != path or "//" in path or any(s in {".", ".."} for s in path.split("/")):
            raise ValueError()
        if ";" in path:
            raise ValueError()
    except (ValueError, UnicodeError):
        raise TransportError("URL must have a canonical HTTP(S) origin and path") from None
    return p, (p.scheme, host, port), path


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, port, address, *, timeout, use_tls=False):
        super().__init__(host, port=port, timeout=timeout)
        self.address = address
        self.use_tls = use_tls

    def connect(self):
        # address is already numeric and authorized. No hostname is re-resolved
        # between the policy decision and the actual TCP connection.
        family = socket.AF_INET6 if ipaddress.ip_address(self.address).version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect((self.address, self.port))
            if self.use_tls:
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=self.host)
            self.sock = sock
        except BaseException:
            sock.close()
            raise


class BoundedTransport:
    def __init__(self, origin, *, paths, allowed_ips, budgets=None, lease_expires_at=None):
        parsed, self.origin, origin_path = parse_url(origin)
        if origin_path != "/" or parsed.query:
            raise TransportError("Scope origin must not contain a path or query")
        self.origin_url = origin.rstrip("/")
        self.paths = set(paths or [])
        if not self.paths:
            raise TransportError("Exact allowed paths are required")
        for path in self.paths:
            _, _, checked = parse_url(self.origin_url + path)
            if not path.startswith("/") or checked != path or "?" in path:
                raise TransportError("Allowed paths must be exact canonical paths")
        try:
            self.allowed_ips = {str(ipaddress.ip_address(ip)) for ip in allowed_ips or []}
        except ValueError:
            raise TransportError("Allowed IPs must be literal addresses") from None
        if not self.allowed_ips:
            raise TransportError("Explicit destination IPs are required")
        b = budgets or {}
        self.max_requests = self._limit(b.get("max_requests", 50), "max_requests", 500)
        self.max_bytes = self._limit(b.get("max_response_bytes", 1024 * 1024), "max_response_bytes", 8 * 1024 * 1024)
        self.max_total_bytes = self._limit(b.get("max_total_response_bytes", 8 * 1024 * 1024), "max_total_response_bytes", 64 * 1024 * 1024)
        self.max_redirects = self._limit(b.get("max_redirects", 3), "max_redirects", 10, zero=True)
        self.max_seconds = self._limit(b.get("max_duration_seconds", b.get("max_seconds", 60)), "max_duration_seconds", 1200)
        rate = b.get("requests_per_second", 2)
        if isinstance(rate, bool) or not isinstance(rate, (int, float)) or not math.isfinite(rate) or not 0.1 <= rate <= 20:
            raise TransportError("Invalid requests_per_second")
        self.requests_per_second = rate
        # The client serializes requests, so effective concurrency is always 1.
        # A configured cap of 2 is respected without creating worker threads.
        self._limit(b.get("concurrency", 1), "concurrency", 2)
        self._request_lock = threading.RLock()
        self.requests_sent = 0
        self.bytes_received = 0
        self.observed_paths = set()
        self.lease_expires_at = lease_expires_at
        self.started = time.monotonic()
        self._next_request = self.started

    def remaining_seconds(self):
        remaining = self.max_seconds - (time.monotonic() - self.started)
        if self.lease_expires_at is not None:
            remaining = min(remaining, self.lease_expires_at - time.time())
        return remaining

    def allowance(self):
        return {"max_requests": max(0, self.max_requests - self.requests_sent),
                "max_total_response_bytes": max(0, self.max_total_bytes - self.bytes_received),
                "max_response_bytes": self.max_bytes, "requests_per_second": self.requests_per_second,
                "concurrency": 1, "max_duration_seconds": max(0, int(self.remaining_seconds()))}

    @staticmethod
    def _limit(value, name, maximum, zero=False):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise TransportError(f"Invalid {name}")
        if value < (0 if zero else 1) or value > maximum or int(value) != value:
            raise TransportError(f"Invalid {name}")
        return int(value)

    def _check(self, url):
        parsed, origin, path = parse_url(url)
        if origin != self.origin or path not in self.paths:
            raise TransportError("Request is outside exact origin/path scope")
        if self.requests_sent >= self.max_requests or self.remaining_seconds() <= 0 or self.bytes_received >= self.max_total_bytes:
            raise TransportError("Request budget exhausted")
        try:
            records = socket.getaddrinfo(origin[1], origin[2], type=socket.SOCK_STREAM)
            addresses = list(dict.fromkeys(str(ipaddress.ip_address(record[4][0])) for record in records))
        except (OSError, ValueError):
            raise TransportError("Destination resolution failed") from None
        if not addresses or any(ip not in self.allowed_ips for ip in addresses):
            raise TransportError("Resolved destination is outside allowed IPs")
        return parsed, origin, addresses[0]

    def request(self, method, url, *, headers=None, json_body=None, body=None,
                timeout=10, follow_redirects=False):
        with self._request_lock:
            return self._perform(method, url, headers=headers, json_body=json_body,
                                 body=body, timeout=timeout, follow_redirects=follow_redirects)

    def _perform(self, method, url, *, headers=None, json_body=None, body=None,
                 timeout=10, follow_redirects=False):
        method = str(method).upper()
        if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
            raise TransportError("Unsupported HTTP method")
        headers = dict(headers or {})
        for key, val in headers.items():
            if not isinstance(key, str) or not isinstance(val, str) or re.search(r"[\r\n]", key + val):
                raise TransportError("Invalid HTTP header")
            if key.lower() in {"host", "proxy-authorization", "transfer-encoding", "content-length", "connection"}:
                raise TransportError("Reserved HTTP header")
        if json_body is not None:
            if body is not None:
                raise TransportError("Ambiguous request body")
            body = json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if isinstance(body, str):
            body = body.encode("utf-8")
        if body is not None and (not isinstance(body, bytes) or len(body) > self.max_bytes):
            raise TransportError("Request body exceeds budget")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise TransportError("Invalid request timeout")
        started = time.monotonic()
        for redirects in range(self.max_redirects + 1):
            parsed, origin, address = self._check(url)
            while True:
                now = time.monotonic()
                pause = self._next_request - now
                if pause <= 0:
                    break
                if pause >= self.remaining_seconds():
                    raise TransportError("Duration budget exhausted while waiting for rate limit")
                time.sleep(min(pause, 0.05))
            remaining = self.remaining_seconds()
            if remaining <= 0:
                raise TransportError("Duration budget exhausted")
            connection = _PinnedHTTP(origin[1], origin[2], address,
                                     timeout=min(timeout, remaining), use_tls=origin[0] == "https")
            self.requests_sent += 1
            self._next_request = time.monotonic() + 1 / self.requests_per_second
            try:
                request_path = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
                connection.request(method, request_path, body=body, headers=headers)
                response = connection.getresponse()
                # Read incrementally so a slow body cannot reset the total time budget.
                chunks = []
                size = 0
                while True:
                    remaining = self.remaining_seconds()
                    if remaining <= 0:
                        raise TransportError("Duration budget exhausted")
                    if connection.sock:
                        connection.sock.settimeout(min(timeout, remaining))
                    chunk = response.read1(min(65536, self.max_bytes + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    self.bytes_received += len(chunk)
                    if self.bytes_received > self.max_total_bytes:
                        raise TransportError("Total response byte budget exhausted")
                    if size > self.max_bytes:
                        raise TransportError("Response exceeds byte budget")
                result = {"status": response.status, "body": b"".join(chunks).decode("utf-8", errors="replace"),
                          "headers": dict(response.getheaders()), "elapsed": round(time.monotonic() - started, 3)}
                self.observed_paths.add(parsed.path or "/")
            except TransportError:
                raise
            except (OSError, http.client.HTTPException, ValueError):
                raise TransportError("HTTP request failed") from None
            finally:
                connection.close()
            location = next((value for key, value in result["headers"].items() if key.lower() == "location"), None)
            if not follow_redirects or result["status"] not in {301, 302, 303, 307, 308} or not location:
                return result
            if redirects >= self.max_redirects:
                raise TransportError("Redirect budget exhausted")
            url = urljoin(url, location)
            # _check on the next iteration rejects cross-origin redirects before
            # sending any credential, even if the redirect was server supplied.
            if result["status"] == 303 or (result["status"] in {301, 302} and method == "POST"):
                method, body = "GET", None
        raise TransportError("Redirect budget exhausted")
