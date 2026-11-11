"""Independent real TLS and CONNECT proof; all endpoints and keys are synthetic."""
import contextlib
from datetime import datetime, timedelta, timezone
import http.server
import ipaddress
import json
import select
import socket
import socketserver
import ssl
import threading
from urllib.parse import urlsplit

import pytest
import requests

from tools.specialist_transport import BoundedAdapter, NetworkError, OperationContext, PolicyError


@pytest.fixture
def certificate(tmp_path):
    pytest.importorskip('cryptography', reason='Synthetic TLS certificate generation needs cryptography')
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'allowed.test')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('allowed.test')]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / 'synthetic-ca.pem', tmp_path / 'synthetic-key.pem'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return str(cert_path), str(key_path)


class Target(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        observed = {'host': self.headers.get('Host'), 'cookie': self.headers.get('Cookie'),
                    'authorization': self.headers.get('Authorization'), 'path': self.path}
        self.server.observed.append(observed)
        body = json.dumps(observed).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        if self.path.startswith('/cookies'):
            self.send_header('Set-Cookie', 'first=fixture-one; Path=/; Secure')
            self.send_header('Set-Cookie', 'second=fixture-two; Path=/; Secure')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


@contextlib.contextmanager
def target_server(certificate=None):
    with http.server.ThreadingHTTPServer(('127.0.0.1', 0), Target) as server:
        server.observed, server.sni = [], []
        if certificate:
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(*certificate)
            tls.set_servername_callback(lambda _socket, name, _context: server.sni.append(name))
            server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join(2)


class Tunnel(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(2)
        try:
            line = self.rfile.readline(65537).decode('ascii').strip()
            while self.rfile.readline(65537) != b'\r\n':
                pass
            method, authority, _protocol = line.split(' ')
            self.server.observed.append((method, authority))
            endpoint = urlsplit('http://' + authority)
            address = ipaddress.ip_address(endpoint.hostname)
            if method != 'CONNECT' or not address.is_loopback:
                return
            family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM) as upstream:
                upstream.settimeout(2)
                upstream.connect((str(address), endpoint.port))
                self.wfile.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
                self.wfile.flush()
                while True:
                    ready, _, _ = select.select([self.connection, upstream], [], [], 2)
                    if not ready:
                        return
                    for source in ready:
                        data = source.recv(65536)
                        if not data:
                            return
                        (upstream if source is self.connection else self.connection).sendall(data)
        except (OSError, ValueError):
            return


class ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


@contextlib.contextmanager
def proxy_server():
    with ProxyServer(('127.0.0.1', 0), Tunnel) as server:
        server.observed = []
        server.url = f'http://127.0.0.1:{server.server_address[1]}'
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join(2)


@contextlib.contextmanager
def bounded_session(operation):
    with requests.Session() as session:
        session.trust_env = False
        session.verify = operation.ca_file or True
        session.proxies = ({'http': operation.proxy_url, 'https': operation.proxy_url}
                           if operation.proxy_url else {})
        session.adapters.clear()
        adapter = BoundedAdapter(operation)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        yield session


def no_dns(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError('A pinned target or numeric proxy must not be resolved')
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    monkeypatch.setattr(socket, 'gethostbyname', forbidden)


def test_real_tls_uses_original_hostname_and_preserves_multiple_cookies(certificate, monkeypatch):
    with target_server(certificate) as server:
        origin = f'https://allowed.test:{server.server_port}'
        operation = OperationContext([origin], target_ips={origin: ['127.0.0.1']}, ca_file=certificate[0])
        no_dns(monkeypatch)
        with bounded_session(operation) as session:
            first = session.get(origin + '/cookies', timeout=2)
            second = session.get(origin + '/observe?q=%2e%2e', timeout=2)
        assert first.status_code == second.status_code == 200
        assert second.url == origin + '/observe?q=..' or second.url == origin + '/observe?q=%2E%2E'
        assert server.sni == ['allowed.test', 'allowed.test']
        assert server.observed[-1]['host'] == f'allowed.test:{server.server_port}'
        assert 'first=fixture-one' in server.observed[-1]['cookie']
        assert 'second=fixture-two' in server.observed[-1]['cookie']


def test_real_tls_still_rejects_wrong_hostname(certificate, monkeypatch):
    with target_server(certificate) as server:
        origin = f'https://wrong.test:{server.server_port}'
        operation = OperationContext([origin], target_ips={origin: ['127.0.0.1']}, ca_file=certificate[0])
        no_dns(monkeypatch)
        with bounded_session(operation) as session, pytest.raises(NetworkError):
            session.get(origin + '/', timeout=2)
        assert server.observed == []


@pytest.mark.parametrize('secure', [False, True])
def test_real_proxy_receives_numeric_connect_and_preserves_inner_host(certificate, monkeypatch, secure):
    with target_server(certificate if secure else None) as target, proxy_server() as proxy:
        origin = f'{"https" if secure else "http"}://allowed.test:{target.server_port}'
        operation = OperationContext([origin], target_ips={origin: ['127.0.0.1']},
                                     proxy_url=proxy.url, ca_file=certificate[0] if secure else None)
        no_dns(monkeypatch)
        with bounded_session(operation) as session:
            response = session.get(origin + '/observe', headers={'Authorization': 'Bearer fixture-only'}, timeout=2)
        assert response.status_code == 200
        assert proxy.observed == [('CONNECT', f'127.0.0.1:{target.server_port}')]
        assert target.observed[-1]['host'] == f'allowed.test:{target.server_port}'
        assert target.observed[-1]['authorization'] == 'Bearer fixture-only'
        if secure:
            assert target.sni == ['allowed.test']


def test_unsupported_https_proxy_is_blocked_before_any_socket(monkeypatch):
    created = []
    monkeypatch.setattr(socket, 'socket', lambda *_args, **_kwargs: created.append(True))
    with pytest.raises(PolicyError):
        OperationContext(['http://127.0.0.1'], proxy_url='https://127.0.0.1:8080')
    assert created == []
