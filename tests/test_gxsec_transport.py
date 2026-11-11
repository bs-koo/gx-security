"""Real loopback HTTP tests; no external application is contacted."""
import json
import socket
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from gxsec.transport import BoundedTransport, TransportError


class Handler(BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        type(self).hits.append((self.path, self.headers.get("Authorization")))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", self.server.redirect)
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write((b"x" * 200 if self.path == "/large" else b'{"ok":true}'))

    def log_message(self, *_):
        pass


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        Handler.hits.clear()

    def transport(self, **budgets):
        return BoundedTransport(self.origin, paths=["/ok", "/redirect", "/large"],
                                allowed_ips=["127.0.0.1"], budgets=budgets)

    def test_real_pinned_request_and_query(self):
        out = self.transport().request("GET", self.origin + "/ok?q=1")
        self.assertEqual(out["status"], 200)
        self.assertTrue(json.loads(out["body"])["ok"])

    def test_non_http_userinfo_and_scope_bypasses_make_no_request(self):
        t = self.transport()
        for url in ["file://127.0.0.1/ok", "ftp://127.0.0.1/ok",
                    self.origin.replace("://", "://secret@") + "/ok",
                    self.origin + "/ok/child", self.origin + "/%6fk",
                    self.origin + "/x/../ok", self.origin + "/ok#fragment"]:
            with self.subTest(url=url), self.assertRaises(TransportError):
                t.request("GET", url)
        self.assertEqual(Handler.hits, [])

    def test_cross_origin_redirect_never_receives_credentials(self):
        self.server.redirect = "http://127.0.0.1:1/ok"
        with self.assertRaises(TransportError):
            self.transport().request("GET", self.origin + "/redirect",
                                     headers={"Authorization": "Bearer fixture"},
                                     follow_redirects=True)
        self.assertEqual(Handler.hits, [("/redirect", "Bearer fixture")])

    def test_same_origin_redirect_revalidates_path_and_budget(self):
        self.server.redirect = "/outside"
        with self.assertRaises(TransportError):
            self.transport().request("GET", self.origin + "/redirect", follow_redirects=True)
        self.server.redirect = "/ok"
        with self.assertRaises(TransportError):
            self.transport(max_requests=1).request("GET", self.origin + "/redirect",
                                                   follow_redirects=True)
        self.assertFalse(any(p == "/ok" for p, _ in Handler.hits))

    def test_dns_allowed_set_pins_socket_without_second_hostname_resolution(self):
        origin = f"http://fixture.test:{self.server.server_port}"
        original = socket.getaddrinfo
        resolved = []

        def resolver(host, port, *args, **kwargs):
            resolved.append(host)
            return original("127.0.0.1", port, *args, **kwargs)

        t = BoundedTransport(origin, paths=["/ok"], allowed_ips=["127.0.0.1"])
        with patch("gxsec.transport.socket.getaddrinfo", side_effect=resolver):
            self.assertEqual(t.request("GET", origin + "/ok")["status"], 200)
        self.assertEqual(resolved.count("fixture.test"), 1)
        self.assertNotIn("fixture.test", resolved[1:])

    def test_dns_disallowed_destination_and_response_budget(self):
        t = BoundedTransport(self.origin, paths=["/ok"], allowed_ips=["127.0.0.2"])
        with self.assertRaises(TransportError):
            t.request("GET", self.origin + "/ok")
        self.assertEqual(Handler.hits, [])
        with self.assertRaises(TransportError):
            self.transport(max_response_bytes=20).request("GET", self.origin + "/large")

    def test_proxy_environment_is_not_used(self):
        with patch.dict("os.environ", {"HTTP_PROXY": "http://127.0.0.1:1", "NO_PROXY": ""}):
            self.assertEqual(self.transport().request("GET", self.origin + "/ok")["status"], 200)

    def test_explicit_request_rate_budget_is_enforced(self):
        client = self.transport(requests_per_second=2)
        started = time.monotonic()
        client.request("GET", self.origin + "/ok")
        client.request("GET", self.origin + "/ok")
        self.assertGreaterEqual(time.monotonic() - started, 0.45)

    def test_total_response_bytes_and_expiring_lease_are_shared(self):
        client = self.transport(max_total_response_bytes=15)
        client.request("GET", self.origin + "/ok")
        with self.assertRaises(TransportError):
            client.request("GET", self.origin + "/ok")
        expired = BoundedTransport(self.origin, paths=["/ok"], allowed_ips=["127.0.0.1"],
                                   lease_expires_at=time.time() - 1)
        with self.assertRaises(TransportError):
            expired.request("GET", self.origin + "/ok")

    def test_rate_wait_uses_short_sleeps_and_respects_total_duration(self):
        now = [1000.0]
        sleeps = []

        def advance(seconds):
            sleeps.append(seconds)
            now[0] += seconds

        with patch("gxsec.transport.time.monotonic", side_effect=lambda: now[0]), \
             patch("gxsec.transport.time.sleep", side_effect=advance):
            client = self.transport(requests_per_second=2)
            client.request("GET", self.origin + "/ok")
            client.request("GET", self.origin + "/ok")
            self.assertTrue(sleeps)
            self.assertLessEqual(max(sleeps), 0.05)
            self.assertGreaterEqual(sum(sleeps), 0.49)
            slow = self.transport(requests_per_second=0.1, max_duration_seconds=1)
            slow.request("GET", self.origin + "/ok")
            with self.assertRaises(TransportError):
                slow.request("GET", self.origin + "/ok")


class AbsoluteDeadlineTests(unittest.TestCase):
    def drip_request(self, prefix, chunks, *, lease_seconds=None):
        stop = threading.Event()
        finished = threading.Event()

        class DripHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                try:
                    self.connection.sendall(prefix)
                    for chunk in chunks:
                        if stop.wait(0.1):
                            break
                        self.connection.sendall(chunk)
                except OSError:
                    pass
                finally:
                    finished.set()

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), DripHandler)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        origin = f"http://127.0.0.1:{server.server_port}"
        client = BoundedTransport(origin, paths=["/drip"], allowed_ips=["127.0.0.1"],
                                  budgets={"max_duration_seconds": 1 if lease_seconds is None else 10},
                                  lease_expires_at=None if lease_seconds is None else time.time() + lease_seconds)
        original_socket = socket.socket
        caller = threading.current_thread()
        client_sockets = []

        def capture_socket(*args, **kwargs):
            sock = original_socket(*args, **kwargs)
            if threading.current_thread() is caller:
                client_sockets.append(sock)
            return sock

        started = time.monotonic()
        try:
            # Retaining the traceback must not keep a detached response socket open.
            held_error = None
            with patch("gxsec.transport.socket.socket", new=capture_socket):
                try:
                    client.request("GET", origin + "/drip")
                except TransportError as error:
                    held_error = error
            self.assertIsNotNone(held_error)
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 1.7, "Every status/header receive must use the absolute deadline")
            self.assertEqual([sock.fileno() for sock in client_sockets], [-1])
            self.assertEqual(client.requests_sent, 1)
            self.assertFalse(client.observed_paths)
        finally:
            stop.set()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            self.assertTrue(finished.wait(2), "The loopback response worker must stop after cancellation")

    def test_slow_status_line_cannot_reset_total_duration(self):
        self.drip_request(b"", [bytes([byte]) for byte in b"HTTP/1.1 200 OK\r\n"] +
                          [b"Content-Length: 2\r\n\r\n{}"])

    def test_slow_headers_cannot_reset_total_duration(self):
        self.drip_request(b"HTTP/1.1 200 OK\r\nX-Slow: ", [b"x"] * 25 +
                          [b"\r\nContent-Length: 2\r\n\r\n{}"])

    def test_slow_headers_respect_the_earlier_lease_deadline(self):
        self.drip_request(b"HTTP/1.1 200 OK\r\nX-Slow: ", [b"x"] * 25 +
                          [b"\r\nContent-Length: 2\r\n\r\n{}"], lease_seconds=1)

    def test_slow_body_respects_deadline_after_connection_close_headers(self):
        self.drip_request(b"HTTP/1.0 200 OK\r\nContent-Length: 30\r\n\r\n", [b"x"] * 30)

    def test_slow_chunk_metadata_respects_absolute_deadline(self):
        self.drip_request(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
                          [bytes([byte]) for byte in b"1;slow=" + b"x" * 25 + b"\r\nx\r\n0\r\n\r\n"])


if __name__ == "__main__":
    unittest.main()
