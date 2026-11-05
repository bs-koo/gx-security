import json
import os
from pathlib import Path
import subprocess
import sys

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
    assert any(c["id"] == "source-integrity" and c["status"] != "complete" for c in run["checks"])


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
