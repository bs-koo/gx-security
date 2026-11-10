"""Read-only source inventory with content, scope, and repository identity."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import shutil
import tempfile
from .models import content_hash
from .redaction import redact
EXCLUDED_DIRS = {'.git', '.gxsec', '.worktrees', '.venv', 'venv', '__pycache__', 'node_modules', 'target', 'dist', 'build', '.gradle', '.nuxt', '.output', '.next', '.pytest_cache', '.mypy_cache', '.superpowers', '.dev', '.omc', '.humanize', '.gxsec-container', '.gxsec-tools'}
EXCLUDED_DIRECTORY_PATHS = (('.claude', 'worktrees'),)
SUPPORTED = {'.java', '.jsp', '.jspx', '.xml', '.yml', '.yaml', '.properties', '.js', '.jsx', '.ts', '.tsx', '.vue', '.html', '.htm', '.py', '.json', '.gradle', '.kt', '.kts', '.sql', '.env', '.conf', '.ini'}


def directory_exclusion_reason(relative):
    """Match directories relative to the chosen source, never its ancestors."""
    parts = PurePosixPath(relative).parts
    if not parts:
        return None
    if parts[-1] in EXCLUDED_DIRS:
        return 'generated-or-vendor-source'
    normalized = tuple(os.path.normcase(part) for part in parts)
    if normalized in EXCLUDED_DIRECTORY_PATHS:
        return 'assistant-managed-checkouts'
    return None


def exclusion_contract():
    """Bind scope identity to exclusions even when no matching directory exists."""
    return {'version': 2, 'directory_names': sorted(EXCLUDED_DIRS),
            'relative_directory_paths': ['/'.join(parts) for parts in EXCLUDED_DIRECTORY_PATHS],
            'case_sensitive_paths': os.name != 'nt'}


def full_source_scope_hash(root, modules):
    """Derive full scope using this runtime's actual collection contract."""
    return content_hash({'root': str(root).casefold(), 'scope': 'full',
                         'exclude': sorted(EXCLUDED_DIRS),
                         'exclusion_contract': exclusion_contract(), 'modules': modules})


def is_reparse(path):
    """Recognize symlinks and Windows junction/reparse entries without following them."""
    path = Path(path)
    if path.is_symlink() or getattr(path, 'is_junction', lambda: False)():
        return True
    try:
        return bool(getattr(path.lstat(), 'st_file_attributes', 0) & 0x400)
    except OSError:
        return False


def reject_reparse_path(path):
    path = Path(path).absolute()
    if any(is_reparse(part) for part in [path, *path.parents]):
        raise ValueError('Path contains a symlink or reparse entry')
    return path


def trusted_runtime_tool(name, source):
    """Resolve a digest-approved executable from protected runtime input, never PATH."""
    manifest_name = os.environ.get('GXSEC_RUNTIME_MANIFEST')
    if not manifest_name:
        raise ValueError('Digest-verified runtime manifest is unavailable')
    manifest_path = reject_reparse_path(manifest_name).resolve(strict=True)
    source = Path(source).resolve()
    if manifest_path.is_relative_to(source):
        raise ValueError('Runtime manifest must be outside inspected source')
    document = json.loads(manifest_path.read_text(encoding='utf-8-sig'))
    if document.get('schema_version') != 1:
        raise ValueError('Unsupported runtime provenance schema')
    entry = document.get('tools', {}).get(name, {})
    executable = Path(str(entry.get('executable', '')))
    if not executable.is_absolute():
        raise ValueError('Approved runtime executable must be absolute')
    executable = reject_reparse_path(executable).resolve(strict=True)
    if executable.is_relative_to(source) or not executable.is_file():
        raise ValueError('Approved executable cannot come from inspected source')
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    if not entry.get('sha256') or digest != entry['sha256']:
        raise ValueError('Runtime executable digest mismatch')
    return {'executable': str(executable), 'sha256': digest, 'manifest_hash': hashlib.sha256(manifest_path.read_bytes()).hexdigest(), 'version': entry.get('version')}


def runtime_environment():
    allowed = {'SystemRoot','WINDIR','COMSPEC','PATHEXT','TEMP','TMP','TMPDIR','LANG','LC_ALL','TZ'}
    env = {key: value for key, value in os.environ.items() if key in allowed}
    directories = []
    try:
        manifest = json.loads(Path(os.environ['GXSEC_RUNTIME_MANIFEST']).read_text(encoding='utf-8-sig'))
        directories = sorted({str(Path(item['executable']).parent) for item in manifest.get('tools', {}).values() if Path(str(item.get('executable',''))).is_absolute()})
    except (KeyError, OSError, ValueError, TypeError):
        pass
    env.update({'PATH': os.pathsep.join(directories), 'SEMGREP_SEND_METRICS':'off', 'SEMGREP_ENABLE_VERSION_CHECK':'0', 'GIT_TERMINAL_PROMPT':'0', 'GIT_CONFIG_NOSYSTEM':'1', 'GIT_OPTIONAL_LOCKS':'0', 'NO_COLOR':'1', 'PYTHONIOENCODING':'utf-8'})
    return env


def _git(root, *args, trust_source=None):
    try:
        executable = trusted_runtime_tool('git', trust_source or root)['executable']
        with tempfile.TemporaryDirectory(prefix='gxsec-git-home-') as home:
            environment = runtime_environment()
            environment.update({'HOME': home, 'USERPROFILE': home, 'XDG_CACHE_HOME': str(Path(home) / 'cache')})
            result = subprocess.run(
                [executable, '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=', '-c', 'safe.directory=' + str(root), '-C', str(root), *args],
                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=15,
                shell=False, env=environment,
            )
        return result.stdout.strip() if result.returncode == 0 else None
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None

def collect_source(source: Path, *, git_boundary=None) -> dict:
    root = reject_reparse_path(source).resolve()
    if not root.is_dir():
        raise ValueError('Source must be an existing directory')
    files = []
    inventory = []
    errors = []
    exclusions = []
    contract = exclusion_contract()
    modules = {}
    digest = hashlib.sha256()

    def onerror(exc):
        errors.append({'path': str(getattr(exc, 'filename', '')), 'error': str(exc)})
    for directory, dirs, names in os.walk(root, followlinks=False, onerror=onerror):
        base = Path(directory)
        for name in list(dirs):
            p = base / name
            reason = directory_exclusion_reason(p.relative_to(root).as_posix())
            reparse = is_reparse(p)
            if reason or reparse:
                dirs.remove(name)
                if reparse:
                    errors.append({'type': 'reparse_entry', 'path': p.relative_to(root).as_posix()})
                exclusions.append(
                    {
                        'path': p.relative_to(root).as_posix(),
                        'reason': 'reparse-entry' if reparse else reason,
                    },
                )
        dirs.sort()
        for name in sorted(names):
            p = base / name
            rel = p.relative_to(root).as_posix()
            if name == '.git':
                exclusions.append({'path': rel, 'reason': 'git-metadata'})
                continue
            if is_reparse(p):
                exclusions.append({'path': rel, 'reason': 'reparse-entry'})
                errors.append({'type': 'reparse_entry', 'path': rel})
                continue
            try:
                fdig = hashlib.sha256()
                size = 0
                with p.open('rb') as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                        fdig.update(chunk)
                        size += len(chunk)
                h = fdig.hexdigest()
                files.append(rel)
                if rel not in {'gxsec.yaml', 'gxsec.yml', 'gxsec.json'}:
                    digest.update(rel.encode('utf-8') + b'\x00' + h.encode() + b'\x00')
                supported = p.suffix.lower() in SUPPORTED or name == '.env' or name.startswith('.env.') or (name in {'Dockerfile', 'Pipfile', 'go.mod', 'go.sum', 'Gemfile', 'Gemfile.lock', 'yarn.lock', 'pnpm-lock.yaml', 'gradle.lockfile'})
                inventory.append({'path': rel, 'hash': h, 'size': size, 'supported': supported})
                if name in {'pom.xml', 'build.gradle', 'build.gradle.kts', 'package.json', 'pyproject.toml', 'go.mod'}:
                    module = p.parent.relative_to(root).as_posix()
                    modules.setdefault(module, []).append(name)
            except OSError as exc:
                errors.append({'path': rel, 'error': str(exc)})
    def git(*arguments):
        return _git(root, *arguments, trust_source=git_boundary) if git_boundary is not None else _git(root, *arguments)
    commit = git('rev-parse', 'HEAD')
    status = git('status', '--porcelain=v1', '--untracked-files=all')
    # Scope identity is content independent, allowing later full clean rescans to prove absence.
    scope_hash = full_source_scope_hash(root, modules)
    return redact(
        {
            'source_id': content_hash(str(root).casefold()),
            'path': str(root),
            'hash': digest.hexdigest(),
            'working_tree_hash': digest.hexdigest(),
            'commit': commit,
            'revision': commit if commit and status == '' else digest.hexdigest(),
            'dirty': bool(status) if status is not None else None,
            'git': commit is not None,
            'git_refs': sorted((git('show-ref', '--head', '--dereference') or '').splitlines()),
            'files': files,
            'inventory': inventory,
            'supported_files': [x['path'] for x in inventory if x['supported']],
            'modules': [{'path': p, 'manifests': m} for p, m in sorted(modules.items())],
            'exclusions': exclusions,
            'exclusion_contract': contract,
            'errors': errors,
            'scope': 'full',
            'scope_hash': scope_hash,
            'shallow': git('rev-parse', '--is-shallow-repository') == 'true',
        },
    )
