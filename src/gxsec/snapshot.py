"""Private byte-verified static inputs, independent of the mutable working tree."""
from contextlib import closing, contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import stat
import subprocess
import tempfile

from .models import content_hash
from .parallel import ordered_bounded_map
from .execution import checkpoint, phase, timeout_for
from .diagnostics import exception_diagnostic, process_failure
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
    try:
        value = os.readlink(proc)
    except OSError:
        raise ValueError('This platform cannot verify source handle locations') from None
    # Do not resolve/stat the proc target: that repeats source filesystem
    # metadata round trips. Callers independently check the opened identity.
    return Path(value)


def _copy_file(root, relative, expected, destination):
    logical = PurePosixPath(relative)
    if logical.is_absolute() or not logical.parts or any(part in {'..', '.', '.git'} for part in logical.parts):
        raise ValueError('Invalid source inventory path')
    original = root.joinpath(*logical.parts)
    if any(directory_exclusion_reason(parent.as_posix()) for parent in original.relative_to(root).parents):
        raise ValueError('Source inventory contains an excluded directory')
    original = reject_reparse_path(original)
    # Lexical inventory validation and the canonical root bind this path;
    # the opened handle is confined to root before any byte is read below.
    before = original.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('Inventory input is not a regular file')
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    with os.fdopen(os.open(original, flags), 'rb') as source_handle:
        opened = os.fstat(source_handle.fileno())
        _handle_path(source_handle).relative_to(root)
        if (not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)):
            raise ValueError('Source file changed while opening the copy handle')
        copied_size = 0
        with destination.open('xb') as copied:
            for chunk in iter(lambda: source_handle.read(1024 * 1024), b''):
                copied_size += len(chunk)
                checkpoint(bytes_read=len(chunk))
                if copied_size > opened.st_size:
                    raise ValueError('Source bytes changed while copying')
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
    checkpoint(files=1)


def _private_git_config(root, home):
    """Pass exact validated source ownership exceptions to Git child processes."""
    root = reject_reparse_path(root).resolve(strict=True)
    home = reject_reparse_path(home).resolve(strict=True)
    allowed = [root]
    git_dir = root / '.git'
    if git_dir.exists() and git_dir.is_dir():
        git_dir = reject_reparse_path(git_dir).resolve(strict=True)
        git_dir.relative_to(root)
        allowed.append(git_dir)
    for path in allowed:
        if '*' in str(path) or any(ord(character) < 32 for character in str(path)):
            raise ValueError('Git trust paths must be exact ordinary directory names')
    config = reject_reparse_path(home / '.gitconfig')
    before = config.lstat() if config.exists() else None
    if before and (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1):
        raise ValueError('Private Git configuration is nonregular or shared')
    flags = (os.O_WRONLY | os.O_CREAT | getattr(os, 'O_BINARY', 0) |
             getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(os.open(config, flags, 0o600), 'w', encoding='utf-8', newline='\n') as handle:
        opened = os.fstat(handle.fileno())
        _handle_path(handle).relative_to(home)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise ValueError('Private Git configuration is nonregular or shared')
        if before and _file_identity(opened) != _file_identity(before):
            raise ValueError('Private Git configuration changed while opening')
        os.ftruncate(handle.fileno(), 0)
        handle.write('[safe]\n' + ''.join(' directory = ' + json.dumps(str(path), ensure_ascii=False) + '\n'
                                          for path in allowed))
    return config


def _git_run(executable, arguments, root, home):
    config = _private_git_config(root, home)
    environment = runtime_environment()
    environment.update({'HOME': str(home), 'USERPROFILE': str(home), 'XDG_CACHE_HOME': str(home / 'cache'),
                        'GIT_ALLOW_PROTOCOL': 'file', 'GIT_CONFIG_GLOBAL': str(config)})
    # A mirror copies every required Git object, unlike the small identity
    # queries. Keep its bound separate and always respect the total deadline.
    command_limit = 600 if arguments and arguments[0] == 'clone' else 120
    return subprocess.run(
        [executable, '-c', 'protocol.allow=never', '-c', 'protocol.file.allow=always', '-c', 'core.hooksPath=', '-c', 'core.fsmonitor=false', '-c', 'safe.directory=' + str(root), *arguments],
        cwd=str(home), capture_output=True, text=True, encoding='utf-8', errors='replace',
        shell=False, timeout=timeout_for(command_limit), env=environment,
    )


class _HistoryFailure(ValueError):
    """A fixed message authored by this module, safe to share in reports."""


def _git_failure(process, stage):
    diagnostic = process_failure(process)
    diagnostic.update(type='git_history_failed', stage=stage)
    stderr = process.stderr
    if isinstance(stderr, bytes):
        stderr = stderr[:65536].decode('utf-8', errors='replace')
    text = stderr[:65536].lower() if isinstance(stderr, str) else ''
    for marker, category in (
        ('detected dubious ownership', 'ownership_rejected_reported'),
        ('not a git repository', 'invalid_repository_reported'),
    ):
        if marker in text:
            diagnostic.update(category=category, evidence='stderr-marker')
            break
    return diagnostic


def _copy_history(source, target, inventory, home):
    required = bool(inventory.get('git') or (source / '.git').exists())
    result = {'required': required, 'status': 'not_available', 'reason': 'No verified initial Git history'}
    if not required:
        return result
    stage = 'inventory'
    try:
        commit = inventory.get('commit')
        refs = inventory.get('git_refs')
        if not inventory.get('git') or not isinstance(commit, str) or not re.fullmatch(r'[a-fA-F0-9]{40}|[a-fA-F0-9]{64}', commit) or not isinstance(refs, list) or not refs:
            raise _HistoryFailure('Initial Git commit and complete ref manifest are unavailable')
        executable = trusted_runtime_tool('git', source)['executable']
        git_dir = target / '.git'
        stage = 'clone'
        cloned = _git_run(executable, ['clone', '--mirror', '--no-hardlinks', '--no-recurse-submodules', '--dissociate', '--', str(source), str(git_dir)], source, home)
        if cloned.returncode != 0 or not git_dir.is_dir():
            if cloned.returncode != 0:
                result['errors'] = [_git_failure(cloned, stage)]
            raise _HistoryFailure('Local private Git mirror clone failed')
        stage = 'independent-objects'
        for directory, dirs, files in os.walk(git_dir, followlinks=False):
            for name in [*dirs, *files]:
                candidate = Path(directory) / name
                if is_reparse(candidate) or (candidate.is_file() and candidate.stat().st_nlink != 1):
                    raise _HistoryFailure('Git copy contains reparse entries or shared hard links')
        alternate = git_dir / 'objects' / 'info' / 'alternates'
        if alternate.exists() and alternate.read_text(encoding='utf-8').strip():
            raise _HistoryFailure('Git copy still depends on external object storage')
        if (git_dir / 'hooks').exists():
            shutil.rmtree(git_dir / 'hooks')
        stage = 'object-format'
        format_result = _git_run(executable, ['--git-dir', str(git_dir), 'rev-parse', '--show-object-format'], source, home)
        object_format = format_result.stdout.strip()
        if format_result.returncode or object_format not in {'sha1', 'sha256'}:
            if format_result.returncode:
                result['errors'] = [_git_failure(format_result, stage)]
            raise _HistoryFailure('Private Git object format is unknown')
        config = '[core]\n repositoryformatversion = ' + ('1' if object_format == 'sha256' else '0') + '\n bare = false\n logallrefupdates = false\n hooksPath =\n fsmonitor = false\n'
        if object_format == 'sha256':
            config += '[extensions]\n objectFormat = sha256\n'
        (git_dir / 'config').write_text(config, encoding='utf-8')
        stage = 'commit-and-refs'
        head = _git_run(executable, ['--git-dir', str(git_dir), 'rev-parse', '--verify', 'HEAD'], source, home)
        copied_refs = _git_run(executable, ['--git-dir', str(git_dir), 'show-ref', '--head', '--dereference'], source, home)
        if head.returncode or head.stdout.strip() != commit or copied_refs.returncode or sorted(copied_refs.stdout.splitlines()) != sorted(refs):
            if head.returncode or copied_refs.returncode:
                result['errors'] = [_git_failure(head if head.returncode else copied_refs, stage)]
            raise _HistoryFailure('Private Git history differs from the initial commit/ref manifest')
        if (git_dir / 'shallow').exists() or inventory.get('shallow'):
            raise _HistoryFailure('Private Git history is shallow')
        result.update(status='complete', commit=commit, refs_hash=content_hash(sorted(refs)), reason=None)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        result.update(status='incomplete', reason=str(exc) if isinstance(exc, _HistoryFailure)
                      else 'Private Git history could not be verified')
        diagnostic = exception_diagnostic('git_history_failed', exc)
        diagnostic['stage'] = stage
        # "diagnostic" is intentionally reserved for omitted raw evidence by
        # the shared redactor. These fixed fields belong to the safe errors API.
        result.setdefault('errors', [diagnostic])
        if (target / '.git').exists():
            shutil.rmtree(target / '.git')
    return result


def _file_identity(info):
    # On Windows, Python 3.12 lstat/fstat expose different ctime semantics.
    # Compare ctime only between results obtained through the same API below.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns)


def _hash_private_file(root, item):
    """Hash an independently owned regular file without loading it into memory."""
    item = reject_reparse_path(item)
    item.resolve(strict=True).relative_to(root)
    before = item.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError('Private snapshot acquired a nonregular or shared file')
    flags = (os.O_RDONLY | getattr(os, 'O_BINARY', 0) |
             getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    digest = hashlib.sha256()
    size = 0
    with os.fdopen(os.open(item, flags), 'rb') as handle:
        opened = os.fstat(handle.fileno())
        _handle_path(handle).relative_to(root)
        if _file_identity(opened) != _file_identity(before):
            raise ValueError('Private snapshot file changed while opening the hash handle')
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
            size += len(chunk)
            checkpoint(bytes_read=len(chunk))
        after = os.fstat(handle.fileno())
        _handle_path(handle).relative_to(root)
        if (_file_identity(opened) != _file_identity(after) or
                opened.st_ctime_ns != after.st_ctime_ns or size != opened.st_size):
            raise ValueError('Private snapshot file changed while hashing')
    reject_reparse_path(item)
    final = item.lstat()
    if _file_identity(final) != _file_identity(after) or before.st_ctime_ns != final.st_ctime_ns:
        raise ValueError('Private snapshot path changed while hashing')
    checkpoint(files=1)
    return digest.hexdigest()


def _tree_hashes(root):
    root = reject_reparse_path(root).resolve(strict=True)
    values = {}
    with phase('snapshot-verify'):
        for directory, dirs, files in os.walk(root, followlinks=False):
            checkpoint()
            for name in [*dirs, *files]:
                item = Path(directory) / name
                if is_reparse(item):
                    raise ValueError('Private snapshot acquired a reparse entry')
            for name in files:
                item = Path(directory) / name
                values[item.relative_to(root).as_posix()] = _hash_private_file(root, item)
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
        names = inventory.get('files')
        if (not isinstance(records, list) or not isinstance(names, list)
                or any(not isinstance(name, str) for name in names)
                or any(not isinstance(row, dict) or not isinstance(row.get('path'), str) for row in records)
                or sorted(names) != sorted(row['path'] for row in records)):
            raise ValueError('Initial source inventory is inconsistent')
        expected = {}
        normalized = set()
        def copy_input(item):
            checkpoint()
            relative, digest = item
            _copy_file(source, relative, digest, target.joinpath(*PurePosixPath(relative).parts))

        with phase('snapshot-copy'):
            for row in records:
                checkpoint()
                relative, digest = row.get('path'), row.get('hash')
                logical = PurePosixPath(relative)
                key = os.path.normcase(logical.as_posix())
                if (not logical.parts or relative != logical.as_posix() or '\\' in relative
                        or any(ord(character) < 32 for character in relative)
                        or logical.is_absolute() or PureWindowsPath(relative).drive
                        or any(part in {'..', '.', '.git'} for part in logical.parts)
                        or key in normalized or not isinstance(digest, str)
                        or not re.fullmatch(r'[a-f0-9]{64}', digest)):
                    raise ValueError('Initial source file identity is invalid')
                normalized.add(key)
                expected[relative] = digest
            with closing(ordered_bounded_map(copy_input, expected.items())) as copies:
                for _ in copies:
                    pass
        with phase('git-history'):
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
