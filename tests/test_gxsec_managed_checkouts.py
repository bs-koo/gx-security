"""Assistant-managed checkout stores are explicit exclusions, not app source."""
import hashlib
import os
from pathlib import Path

import pytest

from gxsec import preflight, source
from gxsec.models import content_hash
from gxsec.snapshot import verified_snapshot


def write(root, relative, body='class Example {}'):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding='utf-8')
    return path


@pytest.fixture(autouse=True)
def no_git_probe(monkeypatch):
    monkeypatch.setattr(source, '_git', lambda *args, **kwargs: None)


@pytest.mark.parametrize('collector', [source.collect_source, preflight.collect_framework_signatures])
def test_managed_checkouts_are_pruned_before_directory_discovery(tmp_path, monkeypatch, collector):
    write(tmp_path, '.claude/worktrees/other/src/main/java/WebSecurityConfig.java')
    write(tmp_path, 'src/main/java/WebSecurityConfig.java')
    blocked = tmp_path / '.claude/worktrees'
    scandir = os.scandir
    def protected_scandir(path):
        if Path(path) == blocked:
            raise AssertionError('Managed checkout content was traversed')
        return scandir(path)
    monkeypatch.setattr(os, 'scandir', protected_scandir)
    inventory = collector(tmp_path)
    assert inventory['files'] == ['src/main/java/WebSecurityConfig.java']
    assert {'path': '.claude/worktrees', 'reason': 'assistant-managed-checkouts'} in inventory['exclusions']


@pytest.mark.parametrize('collector', [source.collect_source, preflight.collect_framework_signatures])
def test_nested_claude_worktrees_remain_in_selected_source(tmp_path, collector):
    write(tmp_path, '.claude/worktrees/other/JwtTokenProvider.java')
    nested = 'module/.claude/worktrees/other/WebSecurityConfig.java'
    write(tmp_path, nested)
    inventory = collector(tmp_path)
    assert inventory['files'] == [nested]
    assert inventory['exclusions'] == [{'path': '.claude/worktrees', 'reason': 'assistant-managed-checkouts'}]


def test_application_worktrees_and_claude_configuration_remain_source(tmp_path):
    expected = {'.claude/settings.json', '.claude/config.json', '.claude/rules/security.md',
                '.claude/worktrees.txt', 'worktrees/normal/App.java', 'feature/worktrees/App.java'}
    for relative in expected:
        write(tmp_path, relative)
    inventory = source.collect_source(tmp_path)
    assert set(inventory['files']) == expected
    assert not inventory['exclusions']


def test_explicitly_selected_managed_checkout_is_scanned_as_root(tmp_path):
    root = tmp_path / '.claude/worktrees/selected'
    write(root, 'src/main/java/WebSecurityConfig.java')
    write(root, '.claude/settings.json', '{}')
    inventory = source.collect_source(root)
    assert set(inventory['files']) == {'src/main/java/WebSecurityConfig.java', '.claude/settings.json'}
    assert not inventory['exclusions']
    prepared = preflight.collect_framework_signatures(root)
    assert prepared['files'] == ['src/main/java/WebSecurityConfig.java']
    with verified_snapshot(root, inventory, include_history=False) as snapshot:
        assert (snapshot.path / '.claude/settings.json').exists()
        assert snapshot.verify()


def test_exclusion_contract_changes_scope_even_without_managed_directories(tmp_path):
    write(tmp_path, 'App.java')
    inventory = source.collect_source(tmp_path)
    old_scope = content_hash({'root': str(tmp_path.resolve()).casefold(), 'scope': 'full',
                              'exclude': sorted(source.EXCLUDED_DIRS), 'modules': {}})
    assert inventory['scope_hash'] != old_scope
    assert inventory['exclusion_contract']['relative_directory_paths'] == ['.claude/worktrees']
    prepared = preflight.collect_framework_signatures(tmp_path)
    old_preflight_scope = content_hash({'source': str(tmp_path.resolve()), 'scope': 'known-framework-signatures'})
    assert prepared['scope_hash'] != old_preflight_scope
    assert prepared['exclusion_contract'] == inventory['exclusion_contract']


def test_snapshot_and_preflight_keep_same_managed_exclusion_contract(tmp_path):
    write(tmp_path, '.claude/worktrees/other/WebSecurityConfig.java')
    write(tmp_path, 'module/.claude/worktrees/other/JwtTokenProvider.java')
    write(tmp_path, '.claude/config.json', '{}')
    write(tmp_path, 'worktrees/ordinary/WebSecurityConfig.java')
    inventory = source.collect_source(tmp_path)
    prepared = preflight.collect_framework_signatures(tmp_path)
    assert prepared['files'] == ['module/.claude/worktrees/other/JwtTokenProvider.java',
                                'worktrees/ordinary/WebSecurityConfig.java']
    assert prepared['exclusions'] == inventory['exclusions']
    with verified_snapshot(tmp_path, inventory, include_history=False) as snapshot:
        assert not (snapshot.path / '.claude/worktrees').exists()
        assert (snapshot.path / 'module/.claude/worktrees/other/JwtTokenProvider.java').exists()
        assert (snapshot.path / '.claude/config.json').exists()
        assert (snapshot.path / 'worktrees/ordinary/WebSecurityConfig.java').exists()
        assert snapshot.provenance['source_exclusions'] == inventory['exclusions']
        assert snapshot.provenance['exclusion_contract'] == inventory['exclusion_contract']
        assert snapshot.verify()


def test_snapshot_rejects_inventory_that_reintroduces_managed_checkouts(tmp_path):
    relative = '.claude/worktrees/other/App.java'
    path = write(tmp_path, relative)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    inventory = {'files': [relative], 'inventory': [{'path': relative, 'hash': digest}], 'git': False}
    with pytest.raises(ValueError, match='excluded'):
        with verified_snapshot(tmp_path, inventory, include_history=False):
            pytest.fail('An excluded checkout was copied into the active snapshot')


@pytest.mark.parametrize('relative', ['.claude/worktrees/injected/App.java',
                                    'module/.claude/worktrees/injected/App.java', '.git/objects/injected'])
def test_snapshot_verification_does_not_ignore_late_excluded_path_injection(tmp_path, relative):
    write(tmp_path, 'App.java')
    inventory = source.collect_source(tmp_path)
    with verified_snapshot(tmp_path, inventory, include_history=False) as snapshot:
        snapshot.path.chmod(0o700)
        write(snapshot.path, relative)
        assert not snapshot.verify()
