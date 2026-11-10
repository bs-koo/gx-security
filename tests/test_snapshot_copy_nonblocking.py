from pathlib import Path
import sys
import hashlib
import os

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from gxsec import snapshot


def test_copy_open_cannot_wait_for_a_replaced_pipe(tmp_path, monkeypatch):
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'a.txt').write_bytes(b'content')
    # Intercept before the OS call: lacking the nonblocking flag would wait
    # indefinitely if an external actor replaced the lstat'ed file with a pipe.
    marker = getattr(os, 'O_NONBLOCK', 0x800)
    monkeypatch.setattr(snapshot.os, 'O_NONBLOCK', marker, raising=False)
    original = os.open
    def checked_open(path, flags, *args, **kwargs):
        assert flags & marker, 'A replaced FIFO must not block before fstat/deadline checks'
        return original(path, flags & ~marker if os.name == 'nt' else flags, *args, **kwargs)
    monkeypatch.setattr(snapshot.os, 'open', checked_open)
    snapshot._copy_file(source, 'a.txt', hashlib.sha256(b'content').hexdigest(), tmp_path / 'copy.txt')
