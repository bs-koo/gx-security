"""Inventory scope must survive native default and project ignore policies."""
import json
import hashlib
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from gxsec import adapters, config, policy, source


JAVA_PATHS = ('src/main/A.java', 'src/test/B.java', 'src/testsuite/C.java', 'tests/D.java')


def fixture(tmp_path, monkeypatch, *, ignores=False, kotlin=False, command='approved-semgrep'):
    root = tmp_path / 'input'
    for index, name in enumerate(JAVA_PATHS):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f'class Fixture{index} {{}}', encoding='utf-8')
    if ignores:
        (root / '.semgrepignore').write_text('*\n', encoding='utf-8')
        (root / 'src/test/.semgrepignore').write_text('*\n', encoding='utf-8')
    if kotlin:
        (root / 'build.gradle.kts').write_text('plugins { java }', encoding='utf-8')
        (root / 'settings.gradle.kts').write_text('rootProject.name = "fixture"', encoding='utf-8')
    monkeypatch.setattr(source, '_git', lambda *args, **kwargs: None)
    inventory = source.collect_source(root)
    cfg = config.default_config(root)
    cfg['_state_dir'] = tmp_path / 'state'
    cfg['tools']['semgrep']['timeout_seconds'] = 60

    def probe(name, options, path, check, **kwargs):
        # CI latest intentionally tests argument compatibility, independently
        # of the production runtime's separate exact-version approval gate.
        check['engine'] = {'name': name, 'version': 'fixture', 'available': True}
        return command

    monkeypatch.setattr(adapters, '_probe', probe)
    return root, cfg, inventory


@pytest.mark.parametrize('ignores', [False, True])
def test_sast_disables_default_and_root_nested_ignore_filters(tmp_path, monkeypatch, ignores):
    root, cfg, inventory = fixture(tmp_path, monkeypatch, ignores=ignores)
    commands = []

    def execute(command, **kwargs):
        commands.append(command)
        scanned = list(JAVA_PATHS) if '--x-ignore-semgrepignore-files' in command else [JAVA_PATHS[0]]
        return subprocess.CompletedProcess(command, 0, json.dumps({'results': [], 'errors': [], 'paths': {'scanned': scanned}}), '')

    monkeypatch.setattr(adapters, '_run', execute)
    check, findings = adapters._sast(root, cfg, inventory, 'release')
    assert check['status'] == 'complete'
    assert check['coverage']['eligible'] == check['coverage']['scanned'] == 4
    assert check['coverage']['missing'] == [] and not findings
    assert len(commands) == 1 and '--strict' in commands[0] and '--no-git-ignore' in commands[0]
    assert commands[0].count('--x-ignore-semgrepignore-files') == 1
    if ignores:
        assert (root / '.semgrepignore').read_text() == '*\n'
        assert (root / 'src/test/.semgrepignore').read_text() == '*\n'


def test_unsupported_ignore_override_stays_incomplete_without_retry(tmp_path, monkeypatch):
    root, cfg, inventory = fixture(tmp_path, monkeypatch)
    commands = []

    def execute(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 2, '', 'unknown option --x-ignore-semgrepignore-files fixture-private-value')

    monkeypatch.setattr(adapters, '_run', execute)
    check, findings = adapters._sast(root, cfg, inventory, 'release')
    assert len(commands) == 1 and '--x-ignore-semgrepignore-files' in commands[0]
    assert check['status'] == 'incomplete' and check['coverage']['partial']
    assert policy.evaluate([check], findings)['status'] == 'INCOMPLETE'
    assert 'fixture-private-value' not in json.dumps(check)


def test_kotlin_rule_gap_stays_in_missing_scope_and_gets_explicit_diagnostic(tmp_path, monkeypatch):
    root, cfg, inventory = fixture(tmp_path, monkeypatch, kotlin=True)
    result = {'results': [], 'errors': [], 'paths': {'scanned': list(JAVA_PATHS)}}
    monkeypatch.setattr(adapters, '_run', lambda *args, **kwargs: subprocess.CompletedProcess([], 0, json.dumps(result), ''))
    check, findings = adapters._sast(root, cfg, inventory, 'release')
    missing = ['build.gradle.kts', 'settings.gradle.kts']
    assert check['status'] == 'incomplete'
    assert check['coverage']['eligible'] == 6 and check['coverage']['scanned'] == 4
    assert check['coverage']['missing'] == missing
    gap = next(item for item in check['errors'] if item['type'] == 'rule_coverage_unavailable')
    assert gap == {'type': 'rule_coverage_unavailable', 'language': 'kotlin',
                   'reason': 'no_language_specific_rules', 'files': missing}
    assert policy.evaluate([check], findings)['status'] == 'INCOMPLETE'


@pytest.mark.skipif(os.name == 'nt' or bool(os.environ.get('GXSEC_NO_SEMGREP')) or not shutil.which('semgrep'),
                    reason='Real-engine scope regression runs in pinned/latest Linux Semgrep CI jobs')
@pytest.mark.parametrize('ignores', [False, True])
def test_real_engine_preserves_test_files_despite_native_ignores(tmp_path, monkeypatch, ignores):
    command = Path(shutil.which('semgrep')).resolve()
    # Match the runtime's protected executable-directory PATH without passing
    # the CI host's full environment or changing production version approval.
    manifest = tmp_path / 'runtime-provenance.json'
    manifest.write_text(json.dumps({'schema_version': 1, 'tools': {'semgrep': {
        'executable': str(command), 'sha256': hashlib.sha256(command.read_bytes()).hexdigest()}}}), encoding='utf-8')
    monkeypatch.setenv('GXSEC_RUNTIME_MANIFEST', str(manifest))
    root, cfg, inventory = fixture(tmp_path, monkeypatch, ignores=ignores, command=str(command))
    initial = {name: (root / name).read_bytes() for name in inventory['files']}
    check, _ = adapters._sast(root, cfg, inventory, 'release')
    assert check['status'] == 'complete', check['errors']
    assert set(JAVA_PATHS) <= set(check['coverage']['scanned_files'])
    assert check['coverage']['eligible'] == check['coverage']['scanned'] == 4
    assert check['coverage']['missing'] == []
    assert {name: (root / name).read_bytes() for name in inventory['files']} == initial
