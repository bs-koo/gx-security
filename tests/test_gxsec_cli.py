import json
import os
from pathlib import Path
import subprocess
import sys
import hashlib
from types import SimpleNamespace
import pytest

ROOT = Path(__file__).resolve().parents[1]


def cli(*args, cwd=None):
    env = dict(os.environ, PYTHONUTF8="1", GXSEC_NO_SEMGREP="1", SEMGREP_SEND_METRICS="off")
    return subprocess.run([sys.executable, str(ROOT / "gxsec.py"), *map(str, args)],
                          cwd=cwd or ROOT, env=env, text=True, encoding="utf-8", capture_output=True, timeout=120)


def test_init_creates_secret_free_profile_and_wont_overwrite(tmp_path):
    source = tmp_path / "sample"
    source.mkdir()
    first = cli("init", source)
    assert first.returncode == 0, first.stderr
    config = source / "gxsec.yaml"
    assert config.exists()
    text = config.read_text(encoding="utf-8")
    assert "local-only" in text and "static-release" in text
    assert cli("init", source).returncode == 2
    assert config.read_text(encoding="utf-8") == text


def test_explicit_missing_config_is_rejected_before_scan(tmp_path, monkeypatch, capsys):
    from gxsec import cli as module
    def unexpected(*args):
        raise AssertionError('missing explicit config reached scanner')
    monkeypatch.setattr(module.adapters, 'run_static_checks', unexpected)
    assert module.main(['release', str(tmp_path), '--config', str(tmp_path / 'missing.yml'), '--json']) == 2
    result = json.loads(capsys.readouterr().out)
    assert 'config' in result.get('detail', '').lower()
    assert not (tmp_path / '.gxsec').exists()


def test_policy_object_and_digest_use_one_read(tmp_path, monkeypatch):
    from gxsec import cli as module
    source = tmp_path / 'source'
    source.mkdir()
    path = tmp_path / 'policy.json'
    original = b'{"required_reviews": ["original-review"]}'
    replacement = b'{"required_reviews": ["changed-review"]}'
    path.write_bytes(original)
    real_read = Path.read_bytes
    real_text = Path.read_text
    def raced_read(file):
        data = real_read(file)
        if file == path:
            path.write_bytes(replacement)
        return data
    monkeypatch.setattr(Path, 'read_bytes', raced_read)
    def raced_text(file, *args, **kwargs):
        data = real_text(file, *args, **kwargs)
        if file == path:
            path.write_bytes(replacement)
        return data
    monkeypatch.setattr(Path, 'read_text', raced_text)
    policy = module._trusted_policy(SimpleNamespace(policy=str(path)), source)
    actual = json.dumps({'required_reviews': policy['required_reviews']}).encode()
    assert policy['_policy_sha256'] == hashlib.sha256(actual).hexdigest()


def test_saved_report_keeps_native_custom_state_for_retest(tmp_path, monkeypatch, capsys):
    from gxsec import cli as module
    source, state = tmp_path / 'source', tmp_path / 'custom-state'
    source.mkdir()
    (source / 'App.java').write_text('class App {}', encoding='utf-8')
    monkeypatch.setattr(module.adapters, 'run_static_checks', lambda *args: ([], []))
    assert module.main(['release', str(source), '--profile', 'static-release', '--state-dir', str(state), '--json']) == 2
    run = json.loads(capsys.readouterr().out)
    assert run['execution_context']['state_dir'] == str(state.resolve())
    assert run['execution_context']['source'] == str(source.resolve())
    saved = json.loads((state / 'runs' / (run['run_id'] + '.json')).read_text(encoding='utf-8'))
    assert saved['execution_context'] == run['execution_context']


def test_expected_framework_reaches_scan_without_project_setup(tmp_path, monkeypatch, capsys):
    from gxsec import cli as module
    observed = []
    def scan(source, config, profile):
        observed.append(config['framework']['expected_family'])
        return [], []
    monkeypatch.setattr(module.adapters, 'run_static_checks', scan)
    assert module.main(['release', str(tmp_path), '--profile', 'static-release', '--expected-framework', 'SEF', '--json']) == 2
    assert observed == ['SEF']
    assert not (tmp_path / 'gxsec.yaml').exists()
    assert json.loads(capsys.readouterr().out)['framework_expectation']['expected_family'] == 'SEF'


def test_retest_keeps_prior_framework_expectation_without_repeating_flag(tmp_path, monkeypatch, capsys):
    from gxsec import cli as module, models, config
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'App.java').write_text('class App {}', encoding='utf-8')
    observed = []
    def scan(root, cfg, profile):
        observed.append(cfg.get('framework'))
        return [], [models.make_finding(category='sast', rule='example-rule', path='App.java',
                                        line=1, title='Example', severity='High', check_id='sast')]
    monkeypatch.setattr(module.adapters, 'run_static_checks', scan)
    assert module.main(['release', str(source), '--profile', 'static-release', '--expected-framework', 'SEF', '--json']) == 2
    first = json.loads(capsys.readouterr().out)
    assert module.main(['retest', first['findings'][0]['finding_id'], '--source', str(source), '--json']) == 2
    second = json.loads(capsys.readouterr().out)
    assert observed[0] == observed[1] == second['framework_expectation']
    assert set(second['framework_expectation']['required_contracts']) == set(config.FRAMEWORK_CONTRACTS)


def test_doctor_reports_missing_tools_without_false_success(tmp_path):
    config = tmp_path / "tools.json"
    config.write_text(json.dumps({"schema_version": 1, "project": {"id": "sample"},
                                 "tools": {"semgrep": {"command": "gxsec-nonexistent-semgrep"},
                                           "osv": {"command": "gxsec-nonexistent-osv"},
                                           "gitleaks": {"command": "gxsec-nonexistent-gitleaks"}}}), encoding="utf-8")
    proc = cli("doctor", "--config", config, "--json")
    assert proc.returncode == 2, proc.stdout + proc.stderr
    data = json.loads(proc.stdout)
    assert data["status"] == "INCOMPLETE"
    assert {t["id"] for t in data["tools"]} >= {"semgrep", "osv", "gitleaks"}


def test_release_missing_engines_saves_incomplete_snapshot_and_report(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "App.java").write_text("class App {}", encoding="utf-8")
    assert cli("init", source).returncode == 0
    config = source / "gxsec.yaml"
    import yaml
    data = yaml.safe_load(config.read_text(encoding="utf-8"))
    for tool in ("semgrep", "osv", "gitleaks"):
        data["tools"][tool]["command"] = "gxsec-missing-" + tool
    config.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    out = tmp_path / "result"
    proc = cli("release", source, "--profile", "static-release", "--output", out, "--json")
    assert proc.returncode == 2, proc.stdout + proc.stderr
    run = json.loads(proc.stdout)
    assert run["gate"]["status"] == "INCOMPLETE"
    assert run["profile"] == "static-release"
    assert (out / "report.html").exists()
    assert (source / ".gxsec" / "state.sqlite3").exists()
    exported = tmp_path / "export"
    again = cli("report", run["run_id"], "--state-dir", source / ".gxsec", "--output", exported)
    assert again.returncode == 0, again.stderr
    assert json.loads((exported / "result.json").read_text(encoding="utf-8"))["run_id"] == run["run_id"]


def test_project_policy_cannot_grant_network_execution(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    policy = source / "policy.json"
    policy.write_text('{"allow_dynamic":true}', encoding="utf-8")
    proc = cli("release", source, "--policy", policy, "--execute-dynamic", "--json")
    assert proc.returncode == 2
    assert "policy" in proc.stderr.lower() or "policy" in proc.stdout.lower()


def test_default_state_symlink_is_rejected(tmp_path):
    import pytest
    source, outside = tmp_path / "source", tmp_path / "outside"
    source.mkdir()
    outside.mkdir()
    try:
        (source / ".gxsec").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation unavailable on this host")
    proc = cli("release", source, "--profile", "static-release", "--json")
    assert proc.returncode == 2
    assert not list(outside.iterdir())


def test_project_added_required_check_cannot_be_silently_omitted(tmp_path, monkeypatch, capsys):
    from gxsec import cli as module
    import yaml
    source = tmp_path / "source"
    source.mkdir()
    (source / "gxsec.yaml").write_text(yaml.safe_dump({"schema_version": 1, "project": {"id": "example"},
        "profiles": {"static-release": {"required_checks": ["iac"]}}}), encoding="utf-8")
    complete = [{"id": name, "status": "complete", "required": True, "errors": [],
                 "coverage": {"eligible": 1, "scanned": 1, "scope": "full"}} for name in ("sast", "sca", "secrets")]
    monkeypatch.setattr(module.adapters, "run_static_checks", lambda *args: (complete, []))
    result = module.main(["release", str(source), "--profile", "static-release", "--json"])
    assert result == 2
    run = json.loads(capsys.readouterr().out)
    assert run["gate"]["status"] == "INCOMPLETE"
    assert any(c["id"] == "iac" and c["status"] != "complete" for c in run["checks"])


def test_imported_run_cannot_choose_an_output_path(tmp_path):
    source_file = tmp_path / "untrusted.json"
    outside = tmp_path / "outside"
    source_file.write_text(json.dumps({"schema_version": 1, "run_id": str(outside), "project_id": "example",
        "profile": "static-release", "source": {}, "checks": [], "findings": [],
        "gate": {"status": "PASS", "exit_code": 0}}), encoding="utf-8")
    result = cli("report", source_file, "--state-dir", tmp_path / "state")
    assert result.returncode == 2
    assert not outside.exists()


def test_source_drift_while_scanning_prevents_pass(tmp_path, monkeypatch, capsys):
    from gxsec import cli as module
    source = tmp_path / "source"
    source.mkdir()
    app = source / "App.java"
    app.write_text("class Before {}", encoding="utf-8")
    def scanner(*args):
        app.write_text("class After {}", encoding="utf-8")
        return ([{"id": name, "status": "complete", "required": True, "errors": [],
                  "coverage": {"eligible": 1, "scanned": 1, "scope": "full"}} for name in ("sast", "sca", "secrets")], [])
    monkeypatch.setattr(module.adapters, "run_static_checks", scanner)
    assert module.main(["release", str(source), "--profile", "static-release", "--json"]) == 2
    run = json.loads(capsys.readouterr().out)
    assert run["gate"]["status"] == "INCOMPLETE"
    integrity = next(c for c in run['checks'] if c['id'] == 'source-integrity')
    assert integrity['status'] == 'incomplete'
    assert integrity['errors'] == ['Source identity changed during scanning']


@pytest.mark.parametrize('source_changed', [False, True])
def test_source_inventory_error_is_distinct_from_identity_change(tmp_path, monkeypatch, capsys, source_changed):
    from gxsec import cli as module
    source = tmp_path / 'source'
    source.mkdir()
    app = source / 'App.java'
    app.write_text('class Before {}', encoding='utf-8')
    original_collect = module.collect_source
    scans = []
    def collect(root):
        result = original_collect(root)
        if scans:
            result['errors'] = [{'type': 'reparse_entry', 'path': 'private-path-marker'}]
        scans.append(result)
        return result
    def scanner(*args):
        if source_changed:
            app.write_text('class After {}', encoding='utf-8')
        return [], []
    monkeypatch.setattr(module, 'collect_source', collect)
    monkeypatch.setattr(module.adapters, 'run_static_checks', scanner)
    assert module.main(['release', str(source), '--profile', 'static-release', '--json']) == 2
    run = json.loads(capsys.readouterr().out)
    integrity = next(c for c in run['checks'] if c['id'] == 'source-integrity')
    assert integrity['status'] == 'incomplete'
    expected = ['Source identity changed during scanning'] if source_changed else []
    assert integrity['errors'] == expected + ['Source inventory could not be completely verified']
    assert (integrity['before_hash'] != integrity['after_hash']) == source_changed
    assert integrity['coverage']['scanned'] == 0
    assert 'private-path-marker' not in json.dumps(integrity)


def test_dynamic_lease_uses_the_saved_execution_identity(tmp_path, monkeypatch, capsys):
    from gxsec import cli as module, dynamic
    source = tmp_path / "source"
    source.mkdir()
    (source / "App.java").write_text("class App {}", encoding="utf-8")
    observed = []
    monkeypatch.setattr(module.adapters, "run_static_checks", lambda *args: ([], []))
    def planned(source, config, **kwargs):
        observed.append(config["dynamic"]["run_id"])
        return [], []
    monkeypatch.setattr(dynamic, "run_dynamic_checks", planned)
    assert module.main(["release", str(source), "--execution-id", "broker-run-123", "--json"]) == 2
    run = json.loads(capsys.readouterr().out)
    assert "run_id" in run, run
    assert observed == [run["run_id"]] == ["broker-run-123"]


def test_invalid_execution_identity_is_rejected_before_scanning(tmp_path, monkeypatch, capsys):
    from gxsec import cli as module
    source = tmp_path / "source"
    source.mkdir()
    def unexpected(*args):
        raise AssertionError("invalid identity reached scanner")
    monkeypatch.setattr(module.adapters, "run_static_checks", unexpected)
    assert module.main(["release", str(source), "--execution-id", "../outside", "--json"]) == 2
    assert "identity" in capsys.readouterr().out.lower()
