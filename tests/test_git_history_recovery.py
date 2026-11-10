"""Git preparation diagnostics survive storage and shared redaction."""
import copy
import io
import json
import subprocess

import pytest

from gxsec import execution, redaction, reporting, snapshot, state


@pytest.mark.parametrize('arguments,expected', [
    (['clone', '--mirror', '--', '/source', '/copy'], 600),
    (['rev-parse', '--verify', 'HEAD'], 120),
    (['show-ref', '--head', '--dereference'], 120),
])
def test_only_git_clone_receives_larger_subprocess_budget(tmp_path, monkeypatch, arguments, expected):
    home = tmp_path / 'home'
    home.mkdir()
    observed = []

    def completed(*args, **kwargs):
        observed.append(kwargs['timeout'])
        return subprocess.CompletedProcess(args[0], 0, '', '')

    monkeypatch.setattr(snapshot.subprocess, 'run', completed)
    snapshot._git_run('git', arguments, tmp_path, home)
    assert observed == [expected]


def test_git_clone_budget_remains_capped_by_total_execution_deadline(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    home.mkdir()
    ticks = [0.0]
    observed = []

    def completed(*args, **kwargs):
        observed.append(kwargs['timeout'])
        return subprocess.CompletedProcess(args[0], 0, '', '')

    monkeypatch.setattr(snapshot.subprocess, 'run', completed)
    with execution.session(600, max_input_bytes=1024, stream=io.StringIO(), clock=lambda: ticks[0]):
        with execution.phase('git-history'):
            ticks[0] = 577
            snapshot._git_run('git', ['clone', '--mirror', '--', '/source', '/copy'], tmp_path, home)
            ticks[0] = 601
            with pytest.raises(execution.BudgetExceeded):
                snapshot._git_run('git', ['clone', '--mirror', '--', '/source', '/copy'], tmp_path, home)
    assert observed == [23]


@pytest.mark.parametrize('failure,category', [
    (subprocess.TimeoutExpired(['git', 'PRIVATE_REPOSITORY'], 120), 'timeout'),
    (subprocess.CompletedProcess([], 128, 'PRIVATE_STDOUT',
        'fatal: detected dubious ownership in repository at PRIVATE_REPOSITORY'), 'ownership_rejected_reported'),
])
def test_safe_git_error_survives_real_redaction_storage_and_shared_json(tmp_path, monkeypatch, failure, category):
    target, home = tmp_path / 'copy', tmp_path / 'home'
    target.mkdir()
    home.mkdir()
    commit = 'a' * 40
    inventory = {'git': True, 'commit': commit, 'git_refs': [commit + ' HEAD']}
    monkeypatch.setattr(snapshot, 'trusted_runtime_tool', lambda *args: {'executable': 'git'})

    def failed(*args, **kwargs):
        if isinstance(failure, BaseException):
            raise failure
        return failure

    monkeypatch.setattr(snapshot, '_git_run', failed)
    history = snapshot._copy_history(tmp_path, target, inventory, home)
    assert history['status'] == 'incomplete'
    assert history['errors'][0]['category'] == category
    assert history['errors'][0]['type'] == 'git_history_failed'
    assert history['errors'][0]['stage'] == 'clone'
    assert 'diagnostic' not in history
    history['diagnostic'] = {'raw': 'PRIVATE_RAW_DIAGNOSTIC'}
    run = {'schema_version': 1, 'run_id': 'git-diagnostic-run', 'project_id': 'git-fixture',
           'profile': 'static-release', 'source': {'source_id': 'fixture', 'scope_hash': 'scope'},
           'checks': [{'id': 'secrets', 'status': 'incomplete', 'required': True,
                       'errors': [{'type': 'missing_history'}],
                       'coverage': {'eligible': 1, 'scanned': 0},
                       'snapshot': {'history': history}}],
           'findings': [], 'started_at': '2026-11-10T00:00:00Z',
           'gate': {'status': 'INCOMPLETE', 'exit_code': 2, 'incomplete': ['secrets']}}
    safe = redaction.redact(copy.deepcopy(run))
    saved_path = state.Store(tmp_path / 'state').save_run(safe)
    persisted = state.Store(tmp_path / 'state').get_run(run['run_id'])
    output = tmp_path / 'report'
    reporting.write_reports(persisted, output)
    for document in (safe, persisted, json.loads(saved_path.read_text(encoding='utf-8')),
                     json.loads((output / 'result.json').read_text(encoding='utf-8'))):
        recovered = document['checks'][0]['snapshot']['history']
        assert recovered['errors'][0]['category'] == category
        assert recovered['errors'][0]['stage'] == 'clone'
        assert recovered['diagnostic'] == redaction.OMITTED
        serialized = json.dumps(document)
        assert 'PRIVATE_' not in serialized
    assert all('PRIVATE_' not in path.read_text(encoding='utf-8') for path in output.iterdir())
