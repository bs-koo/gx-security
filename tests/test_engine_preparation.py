"""Preparation retries transient transport failures, never integrity failures."""
import hashlib
import importlib.util
import io
from pathlib import Path
import platform
import time
from types import SimpleNamespace
import urllib.error

import pytest


@pytest.fixture
def installer():
    path = Path(__file__).resolve().parents[1] / 'scripts/install-engines.py'
    spec = importlib.util.spec_from_file_location('engine_preparation', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def item(raw=b'verified-test-engine'):
    return {'url': 'https://engines.example.invalid/binary', 'sha256': hashlib.sha256(raw).hexdigest()}


def test_transient_download_recovers_and_only_verified_bytes_are_cached(installer, monkeypatch, tmp_path):
    replies = [urllib.error.HTTPError(item()['url'], 504, 'unavailable', {}, None), b'verified-test-engine']
    def open_url(*args, **kwargs):
        result = replies.pop(0)
        if isinstance(result, Exception):
            raise result
        return io.BytesIO(result)
    monkeypatch.setattr(installer.urllib.request, 'urlopen', open_url)
    monkeypatch.setattr('time.sleep', lambda _: None)
    assert installer.download_verified(item(), cache_dir=tmp_path) == b'verified-test-engine'
    assert (tmp_path / item()['sha256']).read_bytes() == b'verified-test-engine'


def test_verified_cache_works_without_network(installer, monkeypatch, tmp_path):
    (tmp_path / item()['sha256']).write_bytes(b'verified-test-engine')
    monkeypatch.setattr(installer.urllib.request, 'urlopen', lambda *a, **k: pytest.fail('valid cache downloaded again'))
    assert installer.download_verified(item(), cache_dir=tmp_path) == b'verified-test-engine'


def test_corrupt_cache_is_never_returned(installer, monkeypatch, tmp_path):
    (tmp_path / item()['sha256']).write_bytes(b'untrusted')
    monkeypatch.setattr(installer.urllib.request, 'urlopen', lambda *a, **k: io.BytesIO(b'verified-test-engine'))
    assert installer.download_verified(item(), cache_dir=tmp_path) == b'verified-test-engine'


def test_hash_mismatch_is_not_retried_or_cached(installer, monkeypatch, tmp_path):
    requests = []
    def open_url(*args, **kwargs):
        requests.append(args)
        return io.BytesIO(b'untrusted')
    monkeypatch.setattr(installer.urllib.request, 'urlopen', open_url)
    with pytest.raises(RuntimeError, match='hash/size'):
        installer.download_verified(item(), cache_dir=tmp_path)
    assert len(requests) == 1
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize('status,attempts', [(404, 1), (429, 3), (503, 3)])
def test_download_stops_on_permanent_error_or_retry_budget(installer, monkeypatch, status, attempts):
    requests = []
    def open_url(*args, **kwargs):
        requests.append(args)
        raise urllib.error.HTTPError(item()['url'], status, 'unavailable', {}, None)
    monkeypatch.setattr(installer.urllib.request, 'urlopen', open_url)
    monkeypatch.setattr('time.sleep', lambda _: None)
    with pytest.raises(urllib.error.HTTPError):
        installer.download_verified(item())
    assert len(requests) == attempts


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def use_clock(installer, monkeypatch, budget):
    clock = FakeClock()
    monkeypatch.setattr(installer.time, 'monotonic', clock.monotonic)
    monkeypatch.setattr(installer.time, 'sleep', clock.sleep)
    monkeypatch.setattr(installer, 'DOWNLOAD_TIMEOUT_SECONDS', budget, raising=False)
    return clock


def test_continuous_small_chunks_stop_at_overall_deadline(installer, monkeypatch, tmp_path):
    clock = use_clock(installer, monkeypatch, 3)
    requests = []
    reads = []

    class Trickle(io.BytesIO):
        def read(self, size=-1):
            # A large buffered read keeps receiving bytes without hitting an idle timeout.
            clock.now += 20
            return super().read(size)

        def read1(self, size=-1):
            reads.append(size)
            clock.now += 1
            return super().read(1)

    def open_url(*args, **kwargs):
        requests.append(kwargs['timeout'])
        return Trickle(b'x' * 20)

    monkeypatch.setattr(installer.urllib.request, 'urlopen', open_url)
    with pytest.raises(TimeoutError, match='deadline'):
        installer.download_verified(item(b'x' * 20), cache_dir=tmp_path)
    assert clock.now == 3
    assert len(requests) == 1
    assert reads and max(reads) <= 64 * 1024
    assert not list(tmp_path.iterdir())


def test_retry_backoff_and_open_share_one_budget(installer, monkeypatch):
    clock = use_clock(installer, monkeypatch, 3)
    requests = []

    def open_url(*args, **kwargs):
        requests.append(kwargs['timeout'])
        clock.now += 2.5
        raise urllib.error.URLError('transient transport failure')

    monkeypatch.setattr(installer.urllib.request, 'urlopen', open_url)
    with pytest.raises(TimeoutError, match='deadline'):
        installer.download_verified(item())
    assert len(requests) == 1
    assert requests[0] <= 3
    assert clock.now <= 3
    assert sum(clock.sleeps) <= 0.5


def test_blocking_read_timeout_shrinks_to_remaining_budget(installer, monkeypatch):
    clock = use_clock(installer, monkeypatch, 3)
    timeouts = []

    class Socket:
        def settimeout(self, timeout):
            self.timeout = timeout
            timeouts.append((clock.now, timeout))

    sock = Socket()

    class Response(io.BytesIO):
        fp = SimpleNamespace(raw=SimpleNamespace(_sock=sock))

        def read1(self, size=-1):
            if clock.now == 0:
                clock.now = 2.5
                return b'x'
            clock.now += sock.timeout
            raise TimeoutError('read idle timeout')

    monkeypatch.setattr(installer.urllib.request, 'urlopen', lambda *a, **k: Response(b'xx'))
    with pytest.raises(TimeoutError, match='deadline'):
        installer.download_verified(item(b'xx'))
    assert clock.now <= 3
    assert timeouts and all(timeout <= 3 - start for start, timeout in timeouts)
    assert timeouts[-1][1] <= 0.5


def test_chunked_read_still_rejects_oversize_without_retry_or_cache(installer, monkeypatch, tmp_path):
    monkeypatch.setattr(installer, 'MAX_DOWNLOAD_BYTES', 5)
    calls = []

    def open_url(*args, **kwargs):
        calls.append(1)
        return io.BytesIO(b'x' * 6)

    monkeypatch.setattr(installer.urllib.request, 'urlopen', open_url)
    with pytest.raises(RuntimeError, match='hash/size'):
        installer.download_verified(item(b'x' * 6), cache_dir=tmp_path)
    assert calls == [1]
    assert not list(tmp_path.iterdir())


def test_linux_deadline_covers_urlopen_and_restores_alarm(installer, monkeypatch):
    clock = use_clock(installer, monkeypatch, 3)
    original_handler = object()
    timer_calls = []
    state = {'handler': original_handler}

    def set_handler(signum, handler):
        state['handler'] = handler

    def set_timer(which, seconds, interval=0):
        timer_calls.append(seconds)

    fake_signal = SimpleNamespace(
        SIGALRM=14, ITIMER_REAL=0, getsignal=lambda _: state['handler'],
        getitimer=lambda _: (0, 0), signal=set_handler, setitimer=set_timer,
    )
    monkeypatch.setattr(installer, 'signal', fake_signal, raising=False)
    monkeypatch.setattr(installer.platform, 'system', lambda: 'Linux')
    calls = []

    def blocked_open(*args, **kwargs):
        calls.append(1)
        if state['handler'] is original_handler:
            pytest.fail('Blocking urlopen has no overall deadline guard')
        clock.now = 3
        state['handler'](14, None)

    monkeypatch.setattr(installer.urllib.request, 'urlopen', blocked_open)
    with pytest.raises(TimeoutError, match='deadline'):
        installer.download_verified(item())
    assert calls == [1]
    assert timer_calls[0] <= 3
    assert timer_calls[-1] == 0
    assert state['handler'] is original_handler


@pytest.mark.skipif(platform.system() != 'Linux', reason='Installer signal deadline is Linux-only')
@pytest.mark.parametrize('phase', ['urlopen', 'body'])
def test_linux_real_alarm_interrupts_blocking_network_phase(installer, monkeypatch, phase):
    monkeypatch.setattr(installer, 'DOWNLOAD_TIMEOUT_SECONDS', 0.05)

    class BlockedBody(io.BytesIO):
        def read1(self, size=-1):
            time.sleep(10)
            return b''

    def open_url(*args, **kwargs):
        if phase == 'urlopen':
            time.sleep(10)
        return BlockedBody(b'')

    monkeypatch.setattr(installer.urllib.request, 'urlopen', open_url)
    previous = installer.signal.getsignal(installer.signal.SIGALRM)
    start = time.monotonic()
    with pytest.raises(TimeoutError, match='deadline'):
        installer.download_verified(item())
    assert time.monotonic() - start < 1
    assert installer.signal.getsignal(installer.signal.SIGALRM) == previous
    assert installer.signal.getitimer(installer.signal.ITIMER_REAL)[0] == 0


def test_cli_failure_does_not_print_transport_secrets(installer, monkeypatch, capsys):
    secret = 'test-only-secret-in-upstream-error'

    def failed_install(*args, **kwargs):
        raise urllib.error.URLError(secret)

    monkeypatch.setattr(installer, 'install', failed_install)
    assert installer.main([]) == 2
    captured = capsys.readouterr()
    assert secret not in captured.out + captured.err
    assert 'Engine preparation failed' in captured.err


def test_known_length_response_can_close_socket_on_final_chunk(installer, monkeypatch):
    class Socket:
        closed = False

        def settimeout(self, timeout):
            if self.closed:
                raise OSError('socket already closed at HTTP Content-Length')

    sock = Socket()

    class Response(io.BytesIO):
        fp = SimpleNamespace(raw=SimpleNamespace(_sock=sock))

        def read1(self, size=-1):
            chunk = super().read1(size)
            if chunk:
                # HTTPResponse closes fp as soon as Content-Length reaches zero.
                self.fp = None
                sock.closed = True
            return chunk

    monkeypatch.setattr(installer.urllib.request, 'urlopen', lambda *a, **k: Response(b'verified-test-engine'))
    assert installer.download_verified(item()) == b'verified-test-engine'
