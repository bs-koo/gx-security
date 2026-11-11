#!/usr/bin/env python3
"""Build, compare and import the wheel offline, outside the source checkout."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]


class VerificationError(RuntimeError):
    pass


def _runtime_files(source):
    source = Path(source)
    modules = source / 'src' / 'gxsec'
    if not (modules / '__init__.py').is_file() or not (source / 'scan_all.py').is_file():
        raise VerificationError('source-layout-unavailable')
    expected = {}

    def include(directory, prefix):
        for path in sorted(directory.rglob('*')):
            if path.is_file() and '__pycache__' not in path.parts and path.suffix not in {'.pyc', '.pyo'}:
                expected[prefix + path.relative_to(directory).as_posix()] = path

    include(modules, 'gxsec/')
    expected['gxsec/_assets/scan_all.py'] = source / 'scan_all.py'
    if not (source / 'tools').is_dir():
        raise VerificationError('source-tools-unavailable')
    include(source / 'tools', 'gxsec/_assets/tools/')
    skills = sorted(path for path in (source / 'skills').glob('detecting-*') if path.is_dir())
    if not skills:
        raise VerificationError('source-scanners-unavailable')
    for skill in skills:
        include(skill, 'gxsec/_assets/skills/' + skill.name + '/')
    return expected


def verify_wheel(source, wheel):
    """Compare all runtime resources, rejecting missing, stale and extra files."""
    expected = _runtime_files(source)
    wheel = Path(wheel)
    parts = wheel.name.removesuffix('.whl').split('-')
    if wheel.suffix != '.whl' or len(parts) not in {5, 6} or parts[0] != 'gx_security':
        raise VerificationError('unexpected-distribution-filename')
    metadata_prefix = f'{parts[0]}-{parts[1]}.dist-info/'
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise VerificationError('duplicate-wheel-entry')
        for name in names:
            if '\\' in name or '..' in name.split('/') or name.startswith('/'):
                raise VerificationError('unsafe-wheel-entry')
            if not name.endswith('/') and name not in expected and not name.startswith(metadata_prefix):
                raise VerificationError('unexpected-wheel-entry')
        runtime = {name for name in names if name.startswith('gxsec/') and not name.endswith('/')}
        if runtime != set(expected):
            raise VerificationError('runtime-file-set-mismatch')
        if metadata_prefix + 'METADATA' not in names:
            raise VerificationError('distribution-metadata-missing')
        for name, path in expected.items():
            if archive.read(name) != path.read_bytes():
                raise VerificationError('runtime-file-content-mismatch')
    return {'matched_files': len(expected), 'sha256': hashlib.sha256(wheel.read_bytes()).hexdigest(),
            'wheel': wheel.name}


def _run(arguments, *, environment=None, cwd=None, timeout=120):
    try:
        subprocess.run(arguments, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       env=environment, cwd=cwd, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        raise VerificationError('offline-subprocess-failed') from None


def build_and_verify(source):
    source = Path(source).resolve()
    _runtime_files(source)
    with tempfile.TemporaryDirectory(prefix='gxsec-wheel-proof-') as temporary:
        temporary = Path(temporary)
        checkout = temporary / 'source'
        checkout.mkdir()
        ignore = shutil.ignore_patterns('__pycache__', '*.pyc', '*.pyo', '*.egg-info')
        for name in ('pyproject.toml', 'setup.py', 'scan_all.py'):
            shutil.copy2(source / name, checkout / name)
        for name in ('src', 'tools'):
            shutil.copytree(source / name, checkout / name, ignore=ignore)
        for skill in sorted((source / 'skills').glob('detecting-*')):
            if skill.is_dir():
                shutil.copytree(skill, checkout / 'skills' / skill.name, ignore=ignore)
        wheels = temporary / 'wheels'
        _run([sys.executable, '-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation',
              '--no-index', '--wheel-dir', str(wheels), str(checkout)])
        built = list(wheels.glob('gx_security-*.whl'))
        if len(built) != 1:
            raise VerificationError('unexpected-wheel-count')
        result = verify_wheel(source, built[0])
        installed = temporary / 'installed'
        _run([sys.executable, '-m', 'pip', 'install', '--no-deps', '--no-index',
              '--target', str(installed), str(built[0])], timeout=60)
        environment = dict(os.environ)
        environment.pop('GXSEC_PLUGIN_ROOT', None)
        environment.pop('PYTHONPATH', None)
        code = ('import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); '
                'from gxsec import adapters; root = Path(sys.argv[1]) / "gxsec" / "_assets"; '
                'assert adapters.ROOT == root; assert adapters._plugin_root() == root; '
                'assert Path(adapters.__file__).is_relative_to(Path(sys.argv[1]))')
        _run([sys.executable, '-I', '-B', '-c', code, str(installed)],
             environment=environment, cwd=temporary, timeout=30)
        result.update({'status': 'passed', 'installed_import': 'passed', 'dependencies': 'no-index-no-deps',
                       'scope': 'wheel runtime parity and isolated installation; host skills not executed'})
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--source', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        result = build_and_verify(args.source)
        code = 0
    except (VerificationError, OSError, zipfile.BadZipFile) as error:
        diagnostic = str(error) if isinstance(error, VerificationError) else 'artifact-verification-failed'
        result = {'status': 'incomplete', 'diagnostic': diagnostic}
        code = 2
    payload = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + '\n', encoding='utf-8')
    print(payload)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
