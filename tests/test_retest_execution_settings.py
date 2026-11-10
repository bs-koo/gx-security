"""Retests reuse bounded settings from the original saved run, never report authority."""
import copy
import json
import os
from pathlib import Path

import pytest

from gxsec import cli, source
from gxsec.models import make_finding
from gxsec.state import Store


@pytest.fixture
def saved_run(tmp_path):
    project = tmp_path / 'project'
    project.mkdir()
    finding = make_finding(category='sast', rule='synthetic', path='App.java', check_id='sast')
    run = {'schema_version': 1, 'run_id': 'original', 'project_id': 'synthetic', 'profile': 'check',
           'source': {'path': str(project.resolve()), 'exclusion_contract': {'selected_directory_paths': ['archives']}},
           'checks': [], 'findings': [finding],
           'execution_metrics': {'max_duration_seconds': 600.0, 'max_input_bytes': 2 * 1024**3}}
    return project, tmp_path / 'state', run, finding['finding_id']


def execute_saved(case, monkeypatch, *options):
    project, state, run, finding_id = case
    Store(state).save_run(run)
    seen = {}
    def execute(args, retest_id, budget, *, previous_run=None):
        seen.update(budget.summary())
        seen['selected'] = source.exclusion_contract()['selected_directory_paths']
        return 0
    monkeypatch.setattr(cli, '_execute_run', execute)
    args = cli.build_parser().parse_args(['retest', finding_id, '--source', str(project),
        '--state-dir', str(state), '--run-id', 'original', *options])
    result = cli._execute(args, finding_id)
    return result, seen


def test_retest_preserves_original_limits_and_selected_scope(saved_run, monkeypatch):
    status, seen = execute_saved(saved_run, monkeypatch)
    assert status == 0
    assert seen['max_duration_seconds'] == 600 and seen['max_input_bytes'] == 2 * 1024**3
    assert seen['selected'] == ['archives']


def test_explicit_limits_and_scope_override_saved_values(saved_run, monkeypatch):
    _, seen = execute_saved(saved_run, monkeypatch, '--max-duration-seconds', '1200',
        '--max-input-bytes', '4294967296', '--exclude-source-path', 'outputs')
    assert seen['max_duration_seconds'] == 1200 and seen['max_input_bytes'] == 4 * 1024**3
    assert seen['selected'] == ['outputs']


def test_legacy_saved_run_uses_defaults(saved_run, monkeypatch):
    saved_run[2].pop('execution_metrics')
    _, seen = execute_saved(saved_run, monkeypatch)
    assert seen['max_duration_seconds'] == 1200 and seen['max_input_bytes'] == 4 * 1024**3


@pytest.mark.parametrize('field,value', [
    ('max_duration_seconds', True), ('max_duration_seconds', '600 --other'),
    ('max_duration_seconds', None),
    ('max_duration_seconds', float('nan')), ('max_duration_seconds', float('inf')),
    ('max_duration_seconds', 0), ('max_duration_seconds', 86401),
    ('max_input_bytes', True), ('max_input_bytes', '1024'),
    ('max_input_bytes', None),
    ('max_input_bytes', 0), ('max_input_bytes', 1.5), ('max_input_bytes', 1024**4 + 1),
])
def test_invalid_saved_limits_are_rejected_before_execution(saved_run, monkeypatch, field, value):
    saved_run[2]['execution_metrics'][field] = value
    with pytest.raises(ValueError, match='execution limit'):
        execute_saved(saved_run, monkeypatch)


def test_explicit_override_does_not_consume_invalid_saved_value(saved_run, monkeypatch):
    saved_run[2]['execution_metrics']['max_duration_seconds'] = 'invalid'
    _, seen = execute_saved(saved_run, monkeypatch, '--max-duration-seconds', '300')
    assert seen['max_duration_seconds'] == 300 and seen['max_input_bytes'] == 2 * 1024**3


def test_saved_settings_from_other_source_are_not_reused(saved_run, monkeypatch):
    saved_run[2]['source']['path'] = str(saved_run[0].parent / 'another-project')
    with pytest.raises(ValueError, match='source'):
        execute_saved(saved_run, monkeypatch)


def test_report_context_cannot_override_execution_metrics(saved_run, monkeypatch):
    saved_run[2]['execution_context'] = {'authority': 'protected-ci',
        'max_duration_seconds': 999999, 'max_input_bytes': 999999999999999,
        'exclude_source_path': ['everything']}
    _, seen = execute_saved(saved_run, monkeypatch)
    assert seen['max_duration_seconds'] == 600 and seen['max_input_bytes'] == 2 * 1024**3
    assert seen['selected'] == ['archives']


def test_concurrent_latest_run_cannot_replace_the_validated_retest_baseline(saved_run, monkeypatch):
    project, state, original, finding_id = saved_run
    (project / 'App.java').write_text('class App {}', encoding='utf-8')
    Store(state).save_run(original)
    newer = copy.deepcopy(original)
    newer.update(run_id='concurrent', profile='static-release')
    newer['source']['exclusion_contract']['selected_directory_paths'] = ['different-scope']
    newer['execution_metrics'] = {'max_duration_seconds': 900, 'max_input_bytes': 3 * 1024**3}
    load_config = cli._config
    def concurrent_save(args, root):
        Store(state).save_run(newer)
        return load_config(args, root)
    monkeypatch.setattr(cli, '_config', concurrent_save)
    monkeypatch.setattr(source, '_git', lambda *args, **kwargs: None)
    monkeypatch.setattr(cli.adapters, 'run_static_checks', lambda *args: ([], []))
    output = project.parent / 'report'
    assert cli.main(['retest', finding_id, '--source', str(project), '--state-dir', str(state),
                     '--output', str(output), '--json']) == 2
    result = json.loads((output / 'result.json').read_text(encoding='utf-8'))
    assert result['retest_of']['run_id'] == 'original'
    assert result['profile'] == 'check'
    assert result['execution_metrics']['max_duration_seconds'] == 600
    assert result['source']['exclusion_contract']['selected_directory_paths'] == ['archives']


def test_saved_source_comparison_performs_no_resolve_on_untrusted_path(saved_run, monkeypatch):
    raw = r'\\gxsec-invalid-host\share\private' if os.name == 'nt' else '/gxsec-invalid-external-source'
    saved_run[2]['source']['path'] = raw
    resolve = Path.resolve
    def forbid_saved_path(path, *args, **kwargs):
        if str(path) == str(Path(raw)):
            raise AssertionError('Saved paths must not trigger external filesystem resolution')
        return resolve(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'resolve', forbid_saved_path)
    with pytest.raises(ValueError, match='source'):
        execute_saved(saved_run, monkeypatch)


@pytest.mark.parametrize('suffix', ['\x00private', 'x' * 4096])
def test_saved_source_path_rejects_controls_and_oversized_strings(saved_run, monkeypatch, suffix):
    saved_run[2]['source']['path'] += suffix
    with pytest.raises(ValueError, match='source'):
        execute_saved(saved_run, monkeypatch)
