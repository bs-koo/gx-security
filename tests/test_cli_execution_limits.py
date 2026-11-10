import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from gxsec import cli, source, policy, config


def test_initial_byte_limit_saves_incomplete_report(tmp_path, monkeypatch, capsys):
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'Large.java').write_text('class Large {}')
    monkeypatch.setattr(source, '_git', lambda *a, **k: None)
    def forbidden(*a, **k):
        raise AssertionError('Engines must not run after exhausted inventory budget')
    monkeypatch.setattr(cli.adapters, 'run_static_checks', forbidden)
    output = tmp_path / 'report'
    status = cli.main(['release', str(project), '--profile', 'static-release', '--max-input-bytes', '2',
                       '--state-dir', str(tmp_path / 'state'), '--output', str(output), '--json'])
    assert status == 2
    run = json.loads((output / 'result.json').read_text(encoding='utf-8'))
    assert run['gate']['status'] == 'INCOMPLETE'
    assert run['execution_metrics']['budget_exceeded']['reason'] == 'input_bytes'
    assert any(c['id'] == 'execution' for c in run['checks'])
    assert '[gxsec]' in capsys.readouterr().err


def test_report_records_successful_execution_timings(tmp_path, monkeypatch, capsys):
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'a.txt').write_text('hello')
    monkeypatch.setattr(source, '_git', lambda *a, **k: None)
    monkeypatch.setattr(cli.adapters, 'run_static_checks', lambda *a: ([], []))
    output = tmp_path / 'report'
    cli.main(['release', str(project), '--profile', 'static-release', '--max-duration-seconds', '30',
              '--state-dir', str(tmp_path / 'state'), '--output', str(output)])
    run = json.loads((output / 'result.json').read_text(encoding='utf-8'))
    metrics = run['execution_metrics']
    assert metrics['bytes_read'] == 10
    assert metrics['input_bytes'] == 5
    assert metrics['phases']['source-inventory']['calls'] == 1
    assert metrics['phases']['source-recheck']['calls'] == 1


def test_selected_scope_cannot_pass_full_static_release_gate():
    checks = [{'id': name, 'status': 'complete', 'required': True, 'errors': [],
               'coverage': {'eligible': 1, 'scanned': 1, 'scope': 'selected'}}
              for name in config.PROFILE_REQUIREMENTS['static-release']]
    gate = policy.evaluate(checks, [], policy={'profile': 'static-release'})
    assert gate['status'] == 'INCOMPLETE'


def test_exhausted_initial_budget_skips_change_plan_and_still_saves_report(tmp_path, monkeypatch):
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'Large.java').write_text('class Large {}')
    monkeypatch.setattr(source, '_git', lambda *a, **k: None)
    def forbidden(*args, **kwargs):
        raise AssertionError('No change-plan command or engine may start after budget exhaustion')
    monkeypatch.setattr(cli, '_base_scope', forbidden)
    monkeypatch.setattr(cli.adapters, 'run_static_checks', forbidden)
    output = tmp_path / 'report'
    status = cli.main(['check', str(project), '--base', 'HEAD', '--max-input-bytes', '2',
        '--state-dir', str(tmp_path / 'state'), '--output', str(output), '--json'])
    assert status == 2
    run = json.loads((output / 'result.json').read_text(encoding='utf-8'))
    assert run['gate']['status'] == 'INCOMPLETE'
    check = next(check for check in run['checks'] if check['id'] == 'change-plan')
    assert check['status'] == 'incomplete'
    assert check['errors'][0]['type'] == 'execution_budget_exceeded'
