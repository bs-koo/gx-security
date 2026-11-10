"""Large-input and concurrent-change boundaries for private input verification."""
import hashlib
import io
import os
from pathlib import Path
import subprocess
import shutil
import tracemalloc

import pytest

from gxsec import snapshot
from gxsec.execution import BudgetExceeded, session
from gxsec.source import collect_source


def test_snapshot_hash_memory_is_bounded_for_large_files(tmp_path):
    target = tmp_path / 'large-input.bin'
    chunk = bytes(range(256)) * 4096
    expected = hashlib.sha256()
    with target.open('wb') as output:
        for _ in range(24):
            output.write(chunk)
            expected.update(chunk)
    tracemalloc.start()
    try:
        result = snapshot._tree_hashes(tmp_path)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result == {'large-input.bin': expected.hexdigest()}
    assert peak < 4 * 1024 * 1024, f'Hashing allocated {peak} bytes for a 24MiB input'


def test_snapshot_hash_refuses_file_changed_while_reading(tmp_path, monkeypatch):
    target = tmp_path / 'input.txt'
    target.write_bytes(b'a' * (3 * 1024 * 1024))
    original_digest = hashlib.sha256
    changed = False

    def change_once():
        nonlocal changed
        if not changed:
            changed = True
            before = target.stat()
            with target.open('r+b') as writable:
                writable.seek(2 * 1024 * 1024)
                writable.write(b'b')
            os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns + 2_000_000_000))

    class ChangingDigest:
        def __init__(self, data=b''):
            self.digest = original_digest(data)
            if data:
                change_once()

        def update(self, data):
            self.digest.update(data)
            change_once()

        def hexdigest(self):
            return self.digest.hexdigest()

    monkeypatch.setattr(snapshot.hashlib, 'sha256', ChangingDigest)
    with pytest.raises(ValueError, match='changed'):
        snapshot._tree_hashes(tmp_path)
    assert changed


def test_snapshot_hash_refuses_replaced_file_during_open(tmp_path, monkeypatch):
    target = tmp_path / 'input.txt'
    target.write_bytes(b'initial')
    original_open = os.open
    replaced = False

    def replace_then_open(path, flags, *args, **kwargs):
        nonlocal replaced
        if Path(path) == target and not replaced:
            replaced = True
            target.rename(tmp_path / 'old-input.txt')
            target.write_bytes(b'replaced')
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(snapshot.os, 'open', replace_then_open)
    with pytest.raises(ValueError, match='changed'):
        snapshot._tree_hashes(tmp_path)
    assert replaced


def test_snapshot_hash_refuses_shared_hardlink(tmp_path):
    target = tmp_path / 'input.txt'
    target.write_bytes(b'content')
    os.link(target, tmp_path / 'alias.txt')
    with pytest.raises(ValueError, match='shared'):
        snapshot._tree_hashes(tmp_path)


@pytest.mark.skipif(os.name == 'nt', reason='POSIX FIFO boundary')
def test_snapshot_hash_refuses_fifo_without_opening_it(tmp_path):
    os.mkfifo(tmp_path / 'pipe')
    with pytest.raises(ValueError, match='nonregular'):
        snapshot._tree_hashes(tmp_path)


def test_snapshot_budget_propagates_and_private_copy_is_cleaned(tmp_path):
    target = tmp_path / 'input.txt'
    target.write_text('budget fixture', encoding='utf-8')
    inventory = collect_source(tmp_path)
    now = [0.0]
    with session(1, max_input_bytes=1024, stream=io.StringIO(), clock=lambda: now[0]) as budget:
        with pytest.raises(BudgetExceeded) as error:
            with snapshot.verified_snapshot(tmp_path, inventory, include_history=False) as private:
                private_path = private.path
                now[0] = 2.0
                private.verify()
        assert error.value.diagnostic['stage'] == 'snapshot-verify'
        assert budget.phases['snapshot-copy']['bytes_read'] == target.stat().st_size
        assert budget.phases['snapshot-verify']['bytes_read'] == target.stat().st_size
    assert not private_path.exists()
    assert target.read_text(encoding='utf-8') == 'budget fixture'


@pytest.mark.parametrize('stderr,category', [
    ('fatal: detected dubious ownership in repository at SECRET_PATH', 'ownership_rejected_reported'),
    ('fatal: not a git repository SECRET_PATH', 'invalid_repository_reported'),
    ('fatal: no space left on device SECRET_PATH', 'storage_exhaustion_reported'),
    ('fatal: permission denied SECRET_PATH', 'permission_denied_reported'),
])
def test_git_copy_preserves_failure_category_without_native_prose(tmp_path, monkeypatch, stderr, category):
    target, home = tmp_path / 'copy', tmp_path / 'home'
    target.mkdir()
    home.mkdir()
    commit = 'a' * 40
    inventory = {'git': True, 'commit': commit, 'git_refs': [commit + ' HEAD']}
    monkeypatch.setattr(snapshot, 'trusted_runtime_tool', lambda *args: {'executable': 'git'})
    monkeypatch.setattr(snapshot, '_git_run', lambda *args: subprocess.CompletedProcess([], 128, '', stderr))
    result = snapshot._copy_history(tmp_path, target, inventory, home)
    assert result['status'] == 'incomplete'
    assert result['errors'][0]['category'] == category
    assert result['errors'][0]['returncode'] == 128
    assert result['errors'][0]['stage'] == 'clone'
    assert 'SECRET_PATH' not in str(result)


def test_git_copy_timeout_retains_kind_but_not_command(tmp_path, monkeypatch):
    target, home = tmp_path / 'copy', tmp_path / 'home'
    target.mkdir()
    home.mkdir()
    commit = 'a' * 40
    inventory = {'git': True, 'commit': commit, 'git_refs': [commit + ' HEAD']}
    monkeypatch.setattr(snapshot, 'trusted_runtime_tool', lambda *args: {'executable': 'git'})

    def timeout(*args):
        raise subprocess.TimeoutExpired(['git', 'SECRET_PATH'], 120)

    monkeypatch.setattr(snapshot, '_git_run', timeout)
    result = snapshot._copy_history(tmp_path, target, inventory, home)
    assert result['status'] == 'incomplete'
    assert result['errors'][0]['category'] == 'timeout'
    assert result['errors'][0]['stage'] == 'clone'
    assert 'SECRET_PATH' not in str(result)


def test_private_git_config_reaches_children_without_wildcard_or_host_config(tmp_path, monkeypatch):
    git = shutil.which('git')
    if not git:
        pytest.skip('Git unavailable')
    source, home, unrelated = tmp_path / 'repo with spaces', tmp_path / 'private-home', tmp_path / 'host-home'
    source.mkdir()
    (source / '.git').mkdir()
    home.mkdir()
    unrelated.mkdir()
    (unrelated / '.gitconfig').write_text('[safe]\n directory = *\n', encoding='utf-8')
    monkeypatch.setenv('HOME', str(unrelated))
    monkeypatch.setenv('USERPROFILE', str(unrelated))
    result = snapshot._git_run(git, ['config', '--global', '--get-all', 'safe.directory'], source, home)
    assert result.returncode == 0
    assert result.stdout.splitlines() == [str(source.resolve()), str((source / '.git').resolve())]
    assert (unrelated / '.gitconfig').read_text(encoding='utf-8') == '[safe]\n directory = *\n'


def test_private_git_config_refuses_shared_config_file(tmp_path):
    git = shutil.which('git')
    if not git:
        pytest.skip('Git unavailable')
    source, home = tmp_path / 'repo', tmp_path / 'private-home'
    source.mkdir()
    home.mkdir()
    external = tmp_path / 'do-not-touch'
    external.write_text('unchanged', encoding='utf-8')
    os.link(external, home / '.gitconfig')
    with pytest.raises(ValueError, match='shared'):
        snapshot._git_run(git, ['config', '--global', '--list'], source, home)
    assert external.read_text(encoding='utf-8') == 'unchanged'
