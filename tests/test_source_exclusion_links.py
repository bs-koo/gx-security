"""Declared exclusions must survive broken-link file/directory classification."""
import os

import pytest

from gxsec import preflight, source


@pytest.fixture(autouse=True)
def no_external_git(monkeypatch):
    monkeypatch.setattr(source, '_git', lambda *args, **kwargs: None)


def directory_link(path, target):
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip('Directory symlink creation is unavailable')


@pytest.mark.parametrize('relative,selected,reason', [
    ('frontend/dist', [], 'generated-or-vendor-source'),
    ('.claude/worktrees', [], 'assistant-managed-checkouts'),
    ('docs/design', ['docs/design'], 'operator-selected-exclusion'),
])
@pytest.mark.parametrize('collector', [source.collect_source, preflight.inspect_inputs])
def test_declared_broken_directory_link_is_excluded_without_error(tmp_path, collector, relative, selected, reason):
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'App.java').write_text('class App {}', encoding='utf-8')
    link = project / relative
    target = tmp_path / 'missing-directory'
    directory_link(link, target)
    # This is the actual os.walk classification that exposed frontend/dist.
    assert any(link.name in names for directory, _, names in os.walk(project, followlinks=False)
               if directory == str(link.parent))
    with source.selected_paths(selected):
        result = collector(project)
    assert not result['errors']
    assert result['exclusions'] == [{'path': relative, 'reason': reason}]
    assert result['files'] == (['App.java'] if collector is source.collect_source else 1)
    assert not target.exists()


def test_declared_link_scope_does_not_depend_on_target_availability(tmp_path):
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'App.java').write_text('class App {}', encoding='utf-8')
    target = tmp_path / 'outside-project'
    directory_link(project / 'frontend/dist', target)
    broken = source.collect_source(project)
    target.mkdir()
    (target / 'External.java').write_text('must not enter the source inventory', encoding='utf-8')
    live = source.collect_source(project)
    assert broken['inventory_complete'] and live['inventory_complete']
    for field in ('files', 'inventory', 'hash', 'scope_hash', 'exclusion_contract', 'exclusions'):
        assert broken[field] == live[field]
    assert live['files'] == ['App.java']


@pytest.mark.parametrize('collector', [source.collect_source, preflight.inspect_inputs])
def test_regular_file_named_like_excluded_directory_is_still_collected(tmp_path, collector):
    (tmp_path / 'dist').write_bytes(b'ordinary source file')
    (tmp_path / 'design').write_bytes(b'ordinary selected-name file')
    with source.selected_paths(['design']):
        result = collector(tmp_path)
    assert not result['errors'] and not result['exclusions']
    assert result['files'] == (['design', 'dist'] if collector is source.collect_source else 2)


@pytest.mark.parametrize('collector', [source.collect_source, preflight.inspect_inputs])
def test_undeclared_broken_directory_link_stays_incomplete(tmp_path, collector):
    directory_link(tmp_path / 'app', tmp_path / 'outside-unavailable')
    result = collector(tmp_path)
    assert result['errors']
    assert result['files'] == ([] if collector is source.collect_source else 0)
    if collector is source.collect_source:
        assert result['inventory_complete'] is False
        assert result['errors'] == [{'type': 'reparse_entry', 'path': 'app'}]
    else:
        assert result['status'] == 'incomplete'
