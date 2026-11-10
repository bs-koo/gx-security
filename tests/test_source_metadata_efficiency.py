"""Count filesystem API calls without claiming host RPC or elapsed-time savings."""
import hashlib
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from gxsec import snapshot, source


def altered(info, **changes):
    values = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
    return SimpleNamespace(**(values | changes))


def test_inventory_reuses_initial_and_final_leaf_metadata(tmp_path, monkeypatch):
    item = tmp_path / 'A.java'
    item.write_bytes(b'class A {}')
    real_lstat = Path.lstat
    calls = []

    def counted(path):
        if path == item:
            calls.append(path)
        return real_lstat(path)

    monkeypatch.setattr(Path, 'lstat', counted)
    monkeypatch.setattr(source, '_git', lambda *args, **kwargs: None)
    result = source.collect_source(tmp_path)
    assert result['inventory_complete'] and result['files'] == ['A.java']
    assert result['inventory'][0]['hash'] == hashlib.sha256(item.read_bytes()).hexdigest()
    assert len(calls) == 2, 'Only initial and final leaf metadata should be collected'


def test_copy_avoids_redundant_source_resolution(tmp_path, monkeypatch):
    root = tmp_path / 'source'
    item = root / 'nested' / 'A.java'
    item.parent.mkdir(parents=True)
    item.write_bytes(b'class A {}')
    expected = hashlib.sha256(item.read_bytes()).hexdigest()
    real_resolve = Path.resolve

    def guarded(path, *args, **kwargs):
        assert path != item, 'Source copy must use its checked opened handle, not another resolve pass'
        return real_resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'resolve', guarded)
    destination = tmp_path / 'copy'
    snapshot._copy_file(root, 'nested/A.java', expected, destination)
    assert hashlib.sha256(destination.read_bytes()).hexdigest() == expected
    assert destination.stat().st_nlink == 1


def test_linux_handle_location_does_not_stat_proc_target(monkeypatch):
    handle = SimpleNamespace(fileno=lambda: 42)
    with monkeypatch.context() as patch:
        patch.setattr(snapshot, 'os', SimpleNamespace(name='posix', readlink=lambda path: '/source/A.java'))
        patch.setattr(Path, 'exists', lambda path: pytest.fail('Proc target existence requires a redundant source stat'))
        result = snapshot._handle_path(handle)
    assert result.as_posix() == '/source/A.java'


def test_linux_handle_readlink_error_has_fixed_diagnostic(monkeypatch):
    def unreadable(path):
        raise OSError('PRIVATE_NATIVE_PATH')

    with monkeypatch.context() as patch:
        patch.setattr(snapshot, 'os', SimpleNamespace(name='posix', readlink=unreadable))
        patch.setattr(Path, 'exists', lambda path: True)
        with pytest.raises(ValueError) as error:
            snapshot._handle_path(SimpleNamespace(fileno=lambda: 42))
    assert 'PRIVATE_NATIVE_PATH' not in str(error.value)


def test_linux_handle_preserves_literal_deleted_suffix_names(monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(snapshot, 'os', SimpleNamespace(name='posix', readlink=lambda path: '/source/A.java (deleted)'))
        patch.setattr(Path, 'exists', lambda path: True)
        result = snapshot._handle_path(SimpleNamespace(fileno=lambda: 42))
    assert result.as_posix() == '/source/A.java (deleted)'


@pytest.mark.parametrize('mode,attributes', [(stat.S_IFLNK, 0), (stat.S_IFREG, 0x400), (stat.S_IFIFO, 0)])
def test_initial_unsafe_metadata_is_rejected_before_open(tmp_path, monkeypatch, mode, attributes):
    item = tmp_path / 'A.java'
    item.write_bytes(b'class A {}')
    real_lstat = Path.lstat

    def unsafe(path):
        info = real_lstat(path)
        return altered(info, st_mode=mode, st_file_attributes=attributes) if path == item else info

    monkeypatch.setattr(Path, 'lstat', unsafe)
    monkeypatch.setattr(source.os, 'open', lambda *args, **kwargs: pytest.fail('Unsafe input was opened'))
    monkeypatch.setattr(source, '_git', lambda *args, **kwargs: None)
    result = source.collect_source(tmp_path)
    assert not result['files'] and not result['inventory_complete']


def test_reused_initial_metadata_detects_same_size_mtime_replacement(tmp_path, monkeypatch):
    item = tmp_path / 'A.java'
    item.write_bytes(b'class A {}')
    initial = item.stat()
    real_open = os.open

    def replace(path, flags, *args, **kwargs):
        if Path(path) == item:
            item.rename(tmp_path / 'old-file')
            item.write_bytes(b'class B {}')
            os.utime(item, ns=(initial.st_atime_ns, initial.st_mtime_ns))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(source.os, 'open', replace)
    monkeypatch.setattr(source, '_git', lambda *args, **kwargs: None)
    result = source.collect_source(tmp_path)
    assert not result['files']
    assert result['errors'][0]['type'] == 'source_changed_while_opening'


@pytest.mark.parametrize('change', ['inode', 'mtime', 'reparse', 'symlink'])
def test_final_metadata_still_rejects_path_changes(tmp_path, monkeypatch, change):
    item = tmp_path / 'A.java'
    item.write_bytes(b'class A {}')
    real_lstat = Path.lstat
    calls = 0

    def replaced(path):
        nonlocal calls
        info = real_lstat(path)
        if path == item:
            calls += 1
            if calls >= 2:
                changes = {'inode': {'st_ino': info.st_ino + 1},
                           'mtime': {'st_mtime_ns': info.st_mtime_ns + 1},
                           'reparse': {'st_file_attributes': 0x400},
                           'symlink': {'st_mode': stat.S_IFLNK}}
                return altered(info, **changes[change])
        return info

    monkeypatch.setattr(Path, 'lstat', replaced)
    with pytest.raises(ValueError, match='source_changed_while_reading'):
        source._read_inventory_file(item, tmp_path)


def test_opened_ctime_change_still_rejects_inventory(tmp_path, monkeypatch):
    item = tmp_path / 'A.java'
    item.write_bytes(b'class A {}')
    real_fstat = os.fstat
    calls = 0

    def changed(fd):
        nonlocal calls
        calls += 1
        info = real_fstat(fd)
        return altered(info, st_ctime_ns=info.st_ctime_ns + 1) if calls == 2 else info

    monkeypatch.setattr(source.os, 'fstat', changed)
    with pytest.raises(ValueError, match='source_changed_while_reading'):
        source._read_inventory_file(item, tmp_path)


@pytest.mark.parametrize('operation', ['inventory', 'copy'])
def test_opened_handle_outside_source_is_rejected_before_read(tmp_path, monkeypatch, operation):
    root = tmp_path / 'source'
    root.mkdir()
    item = root / 'A.java'
    item.write_bytes(b'class A {}')
    monkeypatch.setattr(snapshot, '_handle_path', lambda handle: tmp_path / 'outside' / 'A.java')
    monkeypatch.setattr(snapshot.hashlib, 'sha256', lambda: SimpleNamespace(update=lambda data: pytest.fail('Read outside source')))
    with pytest.raises(ValueError):
        if operation == 'inventory':
            source._read_inventory_file(item, root)
        else:
            snapshot._copy_file(root, 'A.java', 'unused', tmp_path / 'copy')
    assert not (tmp_path / 'copy').exists()


@pytest.mark.parametrize('late', [False, True])
def test_copy_keeps_pre_and_post_ancestor_reparse_checks(tmp_path, monkeypatch, late):
    root = tmp_path / 'source'
    item = root / 'parent' / 'A.java'
    item.parent.mkdir(parents=True)
    item.write_bytes(b'class A {}')
    expected = hashlib.sha256(item.read_bytes()).hexdigest()
    real_is_reparse = source.is_reparse
    parent_checks = 0

    def replaced(path):
        nonlocal parent_checks
        if path == item.parent:
            parent_checks += 1
            return parent_checks >= (2 if late else 1)
        return real_is_reparse(path)

    monkeypatch.setattr(source, 'is_reparse', replaced)
    with pytest.raises(ValueError, match='symlink or reparse'):
        snapshot._copy_file(root, 'parent/A.java', expected, tmp_path / 'copy')
    assert parent_checks == (2 if late else 1)


@pytest.mark.skipif(os.name == 'nt', reason='Real Linux proc descriptor semantics')
def test_real_linux_literal_deleted_suffix_is_a_regular_input(tmp_path):
    item = tmp_path / 'A.java (deleted)'
    item.write_bytes(b'class A {}')
    with item.open('rb') as handle:
        assert snapshot._handle_path(handle) == item
    assert source._read_inventory_file(item, tmp_path) == (hashlib.sha256(item.read_bytes()).hexdigest(), item.stat().st_size)


@pytest.mark.skipif(os.name == 'nt', reason='Real Linux open-file unlink semantics')
@pytest.mark.parametrize('operation', ['inventory', 'copy'])
def test_real_linux_input_deleted_during_read_is_rejected(tmp_path, monkeypatch, operation):
    root = tmp_path / 'source'
    root.mkdir()
    item = root / 'A.java'
    item.write_bytes(b'class A {}')
    expected = hashlib.sha256(item.read_bytes()).hexdigest()
    real_digest = hashlib.sha256

    class UnlinkingDigest:
        def __init__(self):
            self.digest = real_digest()

        def update(self, data):
            self.digest.update(data)
            item.unlink()

        def hexdigest(self):
            return self.digest.hexdigest()

    monkeypatch.setattr(snapshot.hashlib, 'sha256', UnlinkingDigest)
    with pytest.raises((OSError, ValueError)):
        if operation == 'inventory':
            source._read_inventory_file(item, root)
        else:
            snapshot._copy_file(root, 'A.java', expected, tmp_path / 'copy')


@pytest.mark.skipif(os.name == 'nt', reason='Real POSIX ancestor symlink swaps')
def test_copy_rejects_external_parent_swap_before_read(tmp_path, monkeypatch):
    root, external = tmp_path / 'source', tmp_path / 'external'
    item = root / 'parent' / 'A.java'
    item.parent.mkdir(parents=True)
    external.mkdir()
    item.write_bytes(b'class A {}')
    (external / item.name).write_bytes(b'class A {}')
    real_open = os.open

    def swap(path, flags, *args, **kwargs):
        if Path(path) == item:
            item.parent.rename(root / 'old-parent')
            item.parent.symlink_to(external, target_is_directory=True)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(snapshot.os, 'open', swap)
    destination = tmp_path / 'copy'
    with pytest.raises(ValueError, match='not in the subpath'):
        snapshot._copy_file(root, 'parent/A.java', 'unused', destination)
    assert not destination.exists()


@pytest.mark.skipif(os.name == 'nt', reason='Real POSIX ancestor symlink swaps')
@pytest.mark.parametrize('late', [False, True])
def test_copy_rejects_internal_parent_symlink_before_and_after_read(tmp_path, monkeypatch, late):
    root = tmp_path / 'source'
    item = root / 'parent' / 'A.java'
    item.parent.mkdir(parents=True)
    item.write_bytes(b'class A {}')
    expected = hashlib.sha256(item.read_bytes()).hexdigest()

    def swap():
        item.parent.rename(root / 'old-parent')
        item.parent.symlink_to(root / 'old-parent', target_is_directory=True)

    if late:
        real_open = os.open

        def opened_then_swap(path, flags, *args, **kwargs):
            fd = real_open(path, flags, *args, **kwargs)
            if Path(path) == item:
                swap()
            return fd

        monkeypatch.setattr(snapshot.os, 'open', opened_then_swap)
    else:
        swap()
    with pytest.raises(ValueError, match='symlink or reparse'):
        snapshot._copy_file(root, 'parent/A.java', expected, tmp_path / 'copy')
