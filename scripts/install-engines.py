#!/usr/bin/env python3
"""Install the exact Linux binaries from a reviewed lock, verifying before extract."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import signal
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request


MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024
DOWNLOAD_TIMEOUT_SECONDS = 300
IO_TIMEOUT_SECONDS = 30
READ_CHUNK_BYTES = 64 * 1024


class DownloadDeadlineExceeded(TimeoutError):
    """The complete download/retry budget has expired; do not retry."""


def remaining_time(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise DownloadDeadlineExceeded('Engine download deadline exceeded')
    return remaining


@contextmanager
def download_deadline(deadline):
    """Linux installer guard also interrupts DNS/headers inside blocking urlopen.

    Other hosts can exercise the helper, but installation remains Linux-only.
    The standalone installer owns this otherwise-unused main-thread timer.
    """
    if platform.system() != 'Linux':
        yield
        return
    if threading.current_thread() is not threading.main_thread() or any(signal.getitimer(signal.ITIMER_REAL)):
        raise RuntimeError('Engine download requires the main thread and an unused alarm timer')
    previous_handler = signal.getsignal(signal.SIGALRM)

    def expired(signum, frame):
        raise DownloadDeadlineExceeded('Engine download deadline exceeded')

    signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, remaining_time(deadline))
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


def read_download(response, deadline):
    # read1 performs at most one raw read; read(n) can wait forever while a peer
    # trickles bytes often enough to reset the socket's inactivity timeout.
    read = getattr(response, 'read1', None)
    if read is None:
        raise RuntimeError('Engine response does not support bounded incremental reads')
    raw = bytearray()
    while True:
        timeout = min(IO_TIMEOUT_SECONDS, remaining_time(deadline))
        # HTTPResponse may close fp when its Content-Length reaches zero.
        sock = getattr(getattr(getattr(response, 'fp', None), 'raw', None), '_sock', None)
        if sock is not None:
            sock.settimeout(timeout)
        chunk = read(min(READ_CHUNK_BYTES, MAX_DOWNLOAD_BYTES + 1 - len(raw)))
        remaining_time(deadline)
        if not chunk:
            return bytes(raw)
        raw.extend(chunk)
        if len(raw) > MAX_DOWNLOAD_BYTES:
            raise RuntimeError('Download hash/size validation failed')


def download_verified(item, *, cache_dir=None):
    """Use a hash-addressed preparation cache; retry only transient transport errors."""
    digest = item['sha256']
    if not isinstance(digest, str) or not re.fullmatch(r'[a-f0-9]{64}', digest):
        raise ValueError('Invalid engine digest')
    cached = Path(cache_dir) / digest if cache_dir is not None else None
    if cached is not None and cached.exists():
        if cached.is_symlink() or not cached.is_file():
            raise ValueError('Engine cache must contain regular files')
        if cached.stat().st_size <= MAX_DOWNLOAD_BYTES:
            raw = cached.read_bytes()
            if hashlib.sha256(raw).hexdigest() == digest:
                return raw
    deadline = time.monotonic() + DOWNLOAD_TIMEOUT_SECONDS
    with download_deadline(deadline):
        for attempt in range(3):
            try:
                timeout = min(IO_TIMEOUT_SECONDS, remaining_time(deadline))
                with urllib.request.urlopen(item['url'], timeout=timeout) as response:
                    raw = read_download(response, deadline)
                break
            except DownloadDeadlineExceeded:
                raise
            except urllib.error.HTTPError as exc:
                if exc.code not in {408, 429, 500, 502, 503, 504} or attempt == 2:
                    raise
            except (urllib.error.URLError, TimeoutError):
                remaining_time(deadline)
                if attempt == 2:
                    raise
            time.sleep(min(2 ** attempt, remaining_time(deadline)))
            remaining_time(deadline)
    if len(raw) > MAX_DOWNLOAD_BYTES or hashlib.sha256(raw).hexdigest() != digest:
        raise RuntimeError('Download hash/size validation failed')
    if cached is not None:
        cached.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=cached.parent, delete=False) as handle:
                temporary = Path(handle.name)
                handle.write(raw)
            os.replace(temporary, cached)
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()
    return raw


def install(lock_path: Path, output: Path, *, cache_dir=None):
    if platform.system() != "Linux" or platform.machine().lower() not in ("x86_64", "amd64"):
        raise RuntimeError("This lock is linux/amd64. Use Docker/WSL or a reviewed platform-specific lock.")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    output.mkdir(parents=True, exist_ok=True)
    for name in ("osv", "gitleaks"):
        item = lock["engines"][name]
        raw = download_verified(item, cache_dir=cache_dir)
        if name == "gitleaks":
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
                member = archive.getmember("gitleaks")
                if not member.isfile() or member.size > 100 * 1024 * 1024:
                    raise RuntimeError("Unexpected archive member")
                stream = archive.extractfile(member)
                if stream is None:
                    raise RuntimeError("Missing binary in archive")
                binary = stream.read()
        else:
            binary = raw
        destination = output / ("osv-scanner" if name == "osv" else "gitleaks")
        destination.write_bytes(binary)
        destination.chmod(0o755)
        print(name + " " + item["version"] + " verified")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=Path(__file__).resolve().parents[1] / "runtime" / "engines.lock.json")
    parser.add_argument("--output", type=Path, default=Path("/usr/local/bin"))
    parser.add_argument("--cache-dir", type=Path, help="Optional hash-verified cache used only during preparation")
    args = parser.parse_args(argv)
    try:
        install(args.lock, args.output, cache_dir=args.cache_dir)
    except Exception:
        # Upstream exception text can include request credentials or URLs.
        print('Engine preparation failed; check the reviewed lock, supported platform, network, and cache.', file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
