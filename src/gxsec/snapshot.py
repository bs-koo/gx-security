"""Private byte-verified static inputs, independent of the mutable working tree."""
from contextlib import contextmanager
import copy
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile

from .models import content_hash
from .source import directory_exclusion_reason, exclusion_contract, is_reparse, reject_reparse_path, runtime_environment, trusted_runtime_tool


def _handle_path(handle):
    if os.name == 'nt':
        import ctypes
        import msvcrt
        buffer = ctypes.create_unicode_buffer(32768)
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.GetFinalPathNameByHandleW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
        kernel.GetFinalPathNameByHandleW.restype = ctypes.c_uint32
        count = kernel.GetFinalPathNameByHandleW(msvcrt.get_osfhandle(handle.fileno()), buffer, len(buffer), 0)
        if not count or count >= len(buffer):
            raise ValueError('Could not verify the opened source handle location')
        value = buffer.value
        if value.startswith('\\\\?\\UNC\\'):
            value = '\\\\' + value[8:]
        elif value.startswith('\\\\?\\'):
            value = value[4:]
        return Path(value)
    proc = Path('/proc/self/fd') / str(handle.fileno())
    if proc.exists():
        return Path(os.readlink(proc))
    raise ValueError('This platform cannot verify source handle locations')


def _copy_file(root, relative, expected, destination):
    logical = PurePosixPath(relative)
    if logical.is_absolute() or not logical.parts or any(part in {'..', '.', '.git'} for part in logical.parts):
        raise ValueError('Invalid source inventory path')
    original = root.joinpath(*logical.parts)
    if any(directory_exclusion_reason(parent.as_posix()) for parent in original.relative_to(root).parents):
        raise ValueError('Source inventory contains an excluded directory')
    original = reject_reparse_path(original)
    original.resolve(strict=True).relative_to(root)
    before = original.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('Inventory input is not a regular file')
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    with os.fdopen(os.open(original, flags), 'rb') as source_handle:
        opened = os.fstat(source_handle.fileno())
        _handle_path(source_handle).relative_to(root)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError('Source file changed while opening the copy handle')
        with destination.open('xb') as copied:
            for chunk in iter(lambda: source_handle.read(1024 * 1024), b''):
                copied.write(chunk)
                digest.update(chunk)
            copied.flush()
            os.fsync(copied.fileno())
        after = os.fstat(source_handle.fileno())
        _handle_path(source_handle).relative_to(root)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('Source bytes changed while copying')
    reject_reparse_path(original)
    if digest.hexdigest() != expected:
        raise ValueError('Copied source bytes differ from the initial inventory hash')
    if destination.stat().st_nlink != 1:
        raise ValueError('Snapshot files must not share hard links')
    destination.chmod(0o444)


def _git_run(executable, arguments, root, home):
    environment = runtime_environment()
    environment.update({'HOME': str(home), 'USERPROFILE': str(home), 'XDG_CACHE_HOME': str(home / 'cache'), 'GIT_ALLOW_PROTOCOL': 'file'})
    return subprocess.run(
        [executable, '-c', 'protocol.allow=never', '-c', 'protocol.file.allow=always', '-c', 'core.hooksPath=', '-c', 'core.fsmonitor=false', '-c', 'safe.directory=' + str(root), *arguments],
        cwd=str(home), capture_output=True, text=True, encoding='utf-8', errors='replace',
        shell=False, timeout=120, env=environment,
    )


def _copy_history(source, target, inventory, home):
    required = bool(inventory.get('git') or (source / '.git').exists())
    result = {'required': required, 'status': 'not_available', 'reason': 'No verified initial Git history'}
    if not required:
        return result
    try:
        commit = inventory.get('commit')
        refs = inventory.get('git_refs')
        if not inventory.get('git') or not isinstance(commit, str) or not re.fullmatch(r'[a-fA-F0-9]{40}|[a-fA-F0-9]{64}', commit) or not isinstance(refs, list) or not refs:
            raise ValueError('Initial Git commit and complete ref manifest are unavailable')
        executable = trusted_runtime_tool('git', source)['executable']
        git_dir = target / '.git'
        cloned = _git_run(executable, ['clone', '--mirror', '--no-hardlinks', '--no-recurse-submodules', '--dissociate', '--', str(source), str(git_dir)], source, home)
        if cloned.returncode != 0 or not git_dir.is_dir():
            raise ValueError('Local private Git mirror clone failed')
        for directory, dirs, files in os.walk(git_dir, followlinks=False):
            for name in [*dirs, *files]:
                candidate = Path(directory) / name
                if is_reparse(candidate) or (candidate.is_file() and candidate.stat().st_nlink != 1):
                    raise ValueError('Git copy contains reparse entries or shared hard links')
        alternate = git_dir / 'objects' / 'info' / 'alternates'
        if alternate.exists() and alternate.read_text(encoding='utf-8').strip():
            raise ValueError('Git copy still depends on external object storage')
        if (git_dir / 'hooks').exists():
            shutil.rmtree(git_dir / 'hooks')
        format_result = _git_run(executable, ['--git-dir', str(git_dir), 'rev-parse', '--show-object-format'], source, home)
        object_format = format_result.stdout.strip()
        if format_result.returncode or object_format not in {'sha1', 'sha256'}:
            raise ValueError('Private Git object format is unknown')
        config = '[core]\n repositoryformatversion = ' + ('1' if object_format == 'sha256' else '0') + '\n bare = false\n logallrefupdates = false\n hooksPath =\n fsmonitor = false\n'
        if object_format == 'sha256':
            config += '[extensions]\n objectFormat = sha256\n'
        (git_dir / 'config').write_text(config, encoding='utf-8')
        head = _git_run(executable, ['--git-dir', str(git_dir), 'rev-parse', '--verify', 'HEAD'], source, home)
        copied_refs = _git_run(executable, ['--git-dir', str(git_dir), 'show-ref', '--head', '--dereference'], source, home)
        if head.returncode or head.stdout.strip() != commit or copied_refs.returncode or sorted(copied_refs.stdout.splitlines()) != sorted(refs):
            raise ValueError('Private Git history differs from the initial commit/ref manifest')
        if (git_dir / 'shallow').exists() or inventory.get('shallow'):
            raise ValueError('Private Git history is shallow')
        result.update(status='complete', commit=commit, refs_hash=content_hash(sorted(refs)), reason=None)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        result.update(status='incomplete', reason=str(exc))
        if (target / '.git').exists():
            shutil.rmtree(target / '.git')
    return result


def _tree_hashes(root):
    values = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in [*dirs, *files]:
            item = Path(directory) / name
            if is_reparse(item):
                raise ValueError('Private snapshot acquired a reparse entry')
        for name in files:
            item = Path(directory) / name
            if not stat.S_ISREG(item.stat().st_mode) or item.stat().st_nlink != 1:
                raise ValueError('Private snapshot acquired a nonregular or shared file')
            values[item.relative_to(root).as_posix()] = hashlib.sha256(item.read_bytes()).hexdigest()
    return values


def _readonly(root):
    for directory, dirs, files in os.walk(root, topdown=False):
        for name in files:
            (Path(directory) / name).chmod(0o444)
        Path(directory).chmod(0o555)


class Snapshot:
    def __init__(self, path, provenance, hashes):
        self.path = path
        self.provenance = provenance
        self._hashes = hashes

    def verify(self):
        try:
            valid = _tree_hashes(self.path) == self._hashes
        except (OSError, ValueError):
            valid = False
        self.provenance['stable_after_scan'] = valid
        return valid


def _remove_private_tree(root):
    if not root.exists():
        return
    for directory, dirs, files in os.walk(root, followlinks=False):
        Path(directory).chmod(0o700)
        for name in list(dirs):
            item = Path(directory) / name
            if is_reparse(item):
                dirs.remove(name)
                if item.is_symlink():
                    item.unlink()
                else:
                    os.rmdir(item)
        for name in files:
            item = Path(directory) / name
            if is_reparse(item):
                item.unlink()
            else:
                item.chmod(0o600)
    shutil.rmtree(root)


@contextmanager
def verified_snapshot(source, inventory, *, include_history=True):
    source = reject_reparse_path(source).resolve(strict=True)
    temporary = Path(tempfile.mkdtemp(prefix='gxsec-static-'))
    temporary.chmod(0o700)
    target = temporary / 'source'
    target.mkdir(mode=0o700)
    home = temporary / 'git-home'
    home.mkdir(mode=0o700)
    try:
        records = inventory.get('inventory')
        if not isinstance(records, list) or sorted(inventory.get('files', [])) != sorted(row.get('path') for row in records):
            raise ValueError('Initial source inventory is inconsistent')
        expected = {}
        for row in records:
            relative, digest = row.get('path'), row.get('hash')
            if not isinstance(relative, str) or relative in expected or not isinstance(digest, str) or not re.fullmatch(r'[a-f0-9]{64}', digest):
                raise ValueError('Initial source file identity is invalid')
            _copy_file(source, relative, digest, target / relative)
            expected[relative] = digest
        history = (_copy_history(source, target, inventory, home) if include_history
                   else {'required': False, 'status': 'not_available', 'reason': 'File-only snapshot'})
        hashes = _tree_hashes(target)
        if any(hashes.get(path) != digest for path, digest in expected.items()):
            raise ValueError('Private copy failed verification before scanning')
        _readonly(target)
        provenance = {'copy_verified': True, 'stable_after_scan': True, 'source_hash': inventory.get('hash'), 'source_revision': inventory.get('revision'), 'input_file_hashes': expected, 'history': history, 'digest': content_hash(hashes),
                      'exclusion_contract': exclusion_contract(), 'source_exclusions': copy.deepcopy(inventory.get('exclusions', []))}
        snapshot = Snapshot(target, provenance, hashes)
        yield snapshot
    finally:
        _remove_private_tree(temporary)
