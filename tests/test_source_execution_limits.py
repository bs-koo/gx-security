import io
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from gxsec import source, execution


def test_input_limit_records_partial_inventory_without_reading_large_file(tmp_path, monkeypatch):
    (tmp_path / 'a.java').write_bytes(b'abcd')
    (tmp_path / 'z.data').write_bytes(b'12345678')
    original_open = source.os.open

    def guarded_open(path, *args, **kwargs):
        assert Path(path) != tmp_path / 'z.data', 'Over-budget input must not be opened'
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(source.os, 'open', guarded_open)
    monkeypatch.setattr(source, '_git', lambda *a, **k: pytest.fail('Git read after input exhaustion'))
    with execution.session(60, max_input_bytes=6, stream=io.StringIO()):
        with execution.phase('source-inventory'):
            result = source.collect_source(tmp_path)
    # Parallel work can finish before its ordered result is consumed; an aborted
    # window retains only its safe assembled subset, not a guaranteed prefix.
    assert set(result['files']) <= {'a.java'}
    assert {'type': 'execution_budget_exceeded', 'reason': 'input_bytes',
            'stage': 'source-inventory'} in result['errors']
    assert result['inventory_complete'] is False


def test_named_pipe_is_rejected_before_open(tmp_path, monkeypatch):
    import stat
    path = tmp_path / 'a.java'
    path.write_bytes(b'class A {}')
    original = Path.lstat
    class Pipe:
        st_mode = stat.S_IFIFO
    monkeypatch.setattr(Path, 'lstat', lambda self: Pipe() if self == path else original(self))
    monkeypatch.setattr(source, '_git', lambda *a, **k: None)
    result = source.collect_source(tmp_path)
    assert not result['files']
    assert any(e.get('type') == 'nonregular_input' for e in result['errors'])


def test_declared_vendor_junction_does_not_invalidate_source_scope(tmp_path, monkeypatch):
    (tmp_path / 'node_modules').mkdir()
    (tmp_path / 'A.java').write_text('class A {}')
    original = source.is_reparse
    monkeypatch.setattr(source, 'is_reparse', lambda p: Path(p).name == 'node_modules' or original(p))
    monkeypatch.setattr(source, '_git', lambda *a, **k: None)
    result = source.collect_source(tmp_path)
    assert not result['errors']
    assert result['exclusions'] == [{'path': 'node_modules', 'reason': 'generated-or-vendor-source'}]


def test_arbitrary_junction_remains_incomplete(tmp_path, monkeypatch):
    (tmp_path / 'app').mkdir()
    original = source.is_reparse
    monkeypatch.setattr(source, 'is_reparse', lambda p: Path(p).name == 'app' or original(p))
    monkeypatch.setattr(source, '_git', lambda *a, **k: None)
    assert source.collect_source(tmp_path)['errors'][0]['type'] == 'reparse_entry'


def test_explicit_selection_is_bound_to_scope_and_restored(tmp_path, monkeypatch):
    (tmp_path / 'data').mkdir()
    (tmp_path / 'data' / 'backup.dump').write_bytes(b'backup')
    (tmp_path / 'A.java').write_text('class A {}')
    monkeypatch.setattr(source, '_git', lambda *a, **k: None)
    full = source.collect_source(tmp_path)
    with source.selected_paths(['data']):
        selected = source.collect_source(tmp_path)
    assert selected['files'] == ['A.java']
    assert selected['scope'] == 'selected'
    assert selected['scope_hash'] != full['scope_hash']
    assert selected['exclusion_contract']['selected_directory_paths'] == ['data']
    assert selected['exclusions'][0]['reason'] == 'operator-selected-separate-review'
    assert source.collect_source(tmp_path)['scope_hash'] == full['scope_hash']


@pytest.mark.parametrize('value', ['.', '..', '../app', 'app/../data', '/app', 'C:/app', 'app\\data', 'data*', '.git'])
def test_invalid_selected_paths_rejected(value):
    with pytest.raises(ValueError):
        with source.selected_paths([value]):
            pass


def test_single_stat_detects_windows_reparse_and_posix_symlink(tmp_path, monkeypatch):
    import stat
    from types import SimpleNamespace
    path = tmp_path / 'link'
    for mode, attributes in ((stat.S_IFDIR, 0x400), (stat.S_IFLNK, 0)):
        monkeypatch.setattr(Path, 'lstat', lambda self: SimpleNamespace(st_mode=mode, st_file_attributes=attributes))
        assert source.is_reparse(path)


@pytest.mark.parametrize('operation', ['inventory', 'copy'])
def test_growing_input_stops_before_another_read(tmp_path, monkeypatch, operation):
    import os
    path = tmp_path / 'growing.log'
    path.write_bytes(b'1234')
    original = os.fdopen
    reads = []
    class GrowingReader:
        def __init__(self, handle):
            self.handle = handle
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.handle.close()
        def fileno(self):
            return self.handle.fileno()
        def read(self, size):
            reads.append(size)
            assert len(reads) <= 2, 'Growing input was read again after exceeding its admitted size'
            data = self.handle.read(size)
            if len(reads) == 1:
                with path.open('ab') as writer:
                    writer.write(b'5678')
            return data
    monkeypatch.setattr(source.os, 'fdopen', lambda *a, **k: GrowingReader(original(*a, **k)))
    with pytest.raises(ValueError, match='changed'):
        if operation == 'inventory':
            source._read_inventory_file(path, tmp_path)
        else:
            from gxsec import snapshot
            snapshot._copy_file(tmp_path, path.name, __import__('hashlib').sha256(b'1234').hexdigest(), tmp_path / 'copy')
    assert len(reads) == 2
