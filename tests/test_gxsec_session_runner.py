"""Exercise the Windows session runner without engines, network or project code."""
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

import pytest


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / 'scripts/gxsec.ps1'
POWERSHELL = shutil.which('powershell.exe') if os.name == 'nt' else None
CSC = Path(os.environ.get('WINDIR', 'C:/Windows')) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
pytestmark = pytest.mark.skipif(not POWERSHELL or not CSC.exists(), reason='Windows PowerShell and .NET fixture compiler required')
IMAGE_ID = 'sha256:' + 'f' * 64


FAKE_DOCKER = r'''
using System;
using System.IO;
using System.Text;
using System.Threading;
class FakeDocker {
    static int Main(string[] args) {
        string line = "";
        foreach (string arg in args) {
            if (line.Length > 0) line += "\t";
            line += Convert.ToBase64String(Encoding.UTF8.GetBytes(arg));
        }
        File.AppendAllText(Environment.GetEnvironmentVariable("GXSEC_FAKE_LOG"), line + "\n");
        if (args.Length > 0 && args[0] == "info") {
            string mode = Environment.GetEnvironmentVariable("GXSEC_FAKE_DAEMON");
            if (mode == "timeout") {
                File.WriteAllText(Environment.GetEnvironmentVariable("GXSEC_FAKE_PROBE_STARTED"),
                    DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString());
                Thread.Sleep(60000);
            }
            if (mode == "down") { Console.Error.WriteLine("PRETEND_SECRET_SHOULD_NOT_LEAK"); return 1; }
            Console.WriteLine(mode == "windows" ? "windows" : "linux");
            return 0;
        }
        if (args.Length > 1 && args[0] == "image" && args[1] == "inspect") {
            string mode = Environment.GetEnvironmentVariable("GXSEC_FAKE_IMAGE");
            if (mode == "missing") { Console.Error.WriteLine("PRETEND_SECRET_SHOULD_NOT_LEAK"); return 1; }
            Console.WriteLine("sha256:" + new String('f', 64) + "|" + (mode == "windows" ? "windows" : "linux"));
            return 0;
        }
        if (args.Length > 0 && args[0] == "run") {
            Console.WriteLine("{\"fixture\":\"docker-run\"}");
            string code = Environment.GetEnvironmentVariable("GXSEC_FAKE_RUN_EXIT");
            return code == null ? 0 : Int32.Parse(code);
        }
        Console.Error.WriteLine("Unexpected fake Docker operation");
        return 90;
    }
}
'''


@pytest.fixture(scope='module')
def fake_docker(tmp_path_factory):
    directory = tmp_path_factory.mktemp('docker-cli')
    source = directory / 'FakeDocker.cs'
    source.write_text(FAKE_DOCKER, encoding='utf-8')
    executable = directory / 'docker.exe'
    built = subprocess.run([str(CSC), '/nologo', '/target:exe', '/out:' + str(executable), str(source)],
                           capture_output=True, text=True, timeout=60)
    assert built.returncode == 0, built.stdout + built.stderr
    return executable


@pytest.fixture
def case(tmp_path, fake_docker):
    source = tmp_path / 'project [literal] with spaces'
    source.mkdir()
    (source / 'App.java').write_text('class App {}\n', encoding='utf-8')
    log = tmp_path / 'docker-argv.log'
    environment = os.environ.copy()
    environment.update({'PATH': str(fake_docker.parent), 'GXSEC_FAKE_LOG': str(log),
                        'GXSEC_FAKE_PROBE_STARTED': str(tmp_path / 'probe-started'),
                        'GXSEC_FAKE_DAEMON': '', 'GXSEC_FAKE_IMAGE': '', 'GXSEC_FAKE_RUN_EXIT': '0'})
    return source, log, environment


def invoke(case, *arguments, timeout=60):
    source, _, environment = case
    return subprocess.run([POWERSHELL, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                           '-File', str(RUNNER), '-Source', str(source), *arguments],
                          env=environment, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout)


def calls(case):
    log = case[1]
    if not log.exists():
        return []
    return [[base64.b64decode(part).decode('utf-8') for part in line.split('\t')]
            for line in log.read_text(encoding='utf-8').splitlines()]


def incomplete(result, reason):
    assert result.returncode == 2, result.stdout + result.stderr
    data = json.loads(result.stdout)
    assert data['status'] == 'INCOMPLETE' and data['phase'] == 'preparation', data
    assert data['reason'] == reason, data
    assert 'PRETEND_SECRET_SHOULD_NOT_LEAK' not in result.stdout + result.stderr


def test_doctor_uses_ready_local_image_without_creating_or_mounting_output(case):
    result = invoke(case, '-Action', 'doctor')
    assert result.returncode == 0, result.stdout + result.stderr
    operations = calls(case)
    assert [row[0] for row in operations] == ['info', 'image', 'run']
    run = operations[-1]
    assert '--pull' in run and run[run.index('--pull') + 1] == 'never'
    assert IMAGE_ID in run and run[run.index(IMAGE_ID) + 1:] == ['doctor', '--source', '/workspace', '--json']
    assert not any('target=/results' in arg for arg in run)
    assert not (case[0] / '.gxsec-container').exists()


def test_release_preserves_literal_mounts_security_options_and_state(case):
    output = case[0].parent / 'shared reports ; literal'
    result = invoke(case, '-Action', 'release', '-Output', str(output), '-Json')
    assert result.returncode == 0, result.stdout + result.stderr
    run = calls(case)[-1]
    assert run[:3] == ['run', '--rm', '--pull']
    for name, value in [('--network', 'none'), ('--cap-drop', 'ALL'), ('--security-opt', 'no-new-privileges')]:
        assert run[run.index(name) + 1] == value
    assert '--read-only' in run
    assert 'type=bind,source=' + str(case[0]) + ',target=/workspace,readonly' in run
    assert 'type=bind,source=' + str(output) + ',target=/results' in run
    assert run[run.index(IMAGE_ID) + 1:] == ['release', '/workspace', '--profile', 'static-release',
        '--state-dir', '/results/state', '--output', '/results/report',
        '--max-duration-seconds', '1200', '--max-input-bytes', '4294967296', '--json']
    assert output.is_dir()
    encoded = next(value.split('=', 1)[1] for value in run if value.startswith('GXSEC_REPORT_CONTEXT_B64='))
    hint = json.loads(base64.b64decode(encoded).decode('utf-8'))
    assert hint['source'] == str(case[0])
    assert hint['state_dir'] == str(output / 'state')
    assert hint['output'] == str(output)
    assert hint['image'] == IMAGE_ID
    assert hint['temporary_size'] == '512m'
    assert run[run.index('--tmpfs') + 1] == '/tmp:rw,nosuid,nodev,size=512m'


@pytest.mark.parametrize('size', ['512m', '1g', '2g', '4g'])
def test_temporary_size_changes_only_bounded_tmpfs_and_handoff(case, size):
    result = invoke(case, '-Action', 'release', '-TemporarySize', size, '-Json')
    assert result.returncode == 0, result.stdout + result.stderr
    run = calls(case)[-1]
    assert run[run.index('--tmpfs') + 1] == '/tmp:rw,nosuid,nodev,size=' + size
    assert run[run.index('--network') + 1] == 'none'
    assert run[run.index('--cap-drop') + 1] == 'ALL'
    assert '--read-only' in run
    assert run[run.index('--security-opt') + 1] == 'no-new-privileges'
    encoded = next(value.split('=', 1)[1] for value in run if value.startswith('GXSEC_REPORT_CONTEXT_B64='))
    assert json.loads(base64.b64decode(encoded))['temporary_size'] == size
    assert '-TemporarySize' not in run and '--temporary-size' not in run


@pytest.mark.parametrize('size', ['8g', '4g,exec', '4g --privileged', '4G'])
def test_invalid_temporary_size_is_rejected_before_docker(case, size):
    incomplete(invoke(case, '-TemporarySize', size, '-Json'), 'invalid_arguments')
    assert not calls(case)
    assert not (case[0] / '.gxsec-container').exists()


def saved_temporary_run(case, size='4g'):
    from tests.test_gxsec_reporting import sample_run
    from gxsec.reporting import write_reports
    output = case[0] / '.gxsec-container'
    (output / 'state/runs').mkdir(parents=True)
    (output / 'state/state.sqlite3').write_bytes(b'opaque-existing-state')
    saved = sample_run()
    saved['execution_context'] = {'authority': 'report-hint-only', 'runner': 'powershell-docker',
        'source': str(case[0]), 'output': str(output), 'state_dir': str(output / 'state'),
        'temporary_size': size}
    write_reports(saved, output / 'report')
    snapshot = output / 'state/runs/run-example.json'
    snapshot.write_text((output / 'report/result.json').read_text(encoding='utf-8'), encoding='utf-8')
    return output, snapshot


@pytest.mark.parametrize('run_id', [None, 'run-example'])
def test_report_to_retest_keeps_original_temporary_size(case, run_id):
    output, _ = saved_temporary_run(case)
    assert '-TemporarySize 4g' in (output / 'report/developer.md').read_text(encoding='utf-8')
    args = ['-Action', 'retest', '-FindingId', 'GXSEC-123', '-Json']
    if run_id:
        args += ['-RunId', run_id]
    result = invoke(case, *args)
    assert result.returncode == 0, result.stdout + result.stderr
    run = calls(case)[-1]
    assert run[run.index('--tmpfs') + 1] == '/tmp:rw,nosuid,nodev,size=4g'
    assert run[run.index('--state-dir') + 1] == '/results/state'
    encoded = next(value.split('=', 1)[1] for value in run if value.startswith('GXSEC_REPORT_CONTEXT_B64='))
    assert json.loads(base64.b64decode(encoded))['temporary_size'] == '4g'


def test_explicit_temporary_size_overrides_saved_hint(case):
    saved_temporary_run(case)
    result = invoke(case, '-Action', 'retest', '-FindingId', 'GXSEC-123', '-RunId', 'run-example',
                    '-TemporarySize', '1g', '-Json')
    assert result.returncode == 0, result.stdout + result.stderr
    run = calls(case)[-1]
    assert run[run.index('--tmpfs') + 1] == '/tmp:rw,nosuid,nodev,size=1g'


def test_legacy_saved_context_without_temporary_size_uses_default(case):
    _, snapshot = saved_temporary_run(case, size='512m')
    saved = json.loads(snapshot.read_text(encoding='utf-8'))
    saved['execution_context'].pop('temporary_size')
    snapshot.write_text(json.dumps(saved), encoding='utf-8')
    result = invoke(case, '-Action', 'retest', '-FindingId', 'GXSEC-123', '-RunId', 'run-example', '-Json')
    assert result.returncode == 0, result.stdout + result.stderr
    run = calls(case)[-1]
    assert run[run.index('--tmpfs') + 1] == '/tmp:rw,nosuid,nodev,size=512m'


@pytest.mark.parametrize('tamper', ['invalid-json', 'invalid-size', 'wrong-store', 'oversized', 'directory', 'wrong-run', 'missing'])
def test_unreadable_or_untrusted_saved_temporary_hint_is_not_silently_used(case, tamper):
    output, snapshot = saved_temporary_run(case)
    if tamper == 'invalid-json':
        snapshot.write_text('not-json-PRETEND_SECRET_SHOULD_NOT_LEAK', encoding='utf-8')
    elif tamper == 'oversized':
        with snapshot.open('wb') as handle:
            handle.truncate(16 * 1024 * 1024 + 1)
    elif tamper == 'directory':
        snapshot.unlink()
        snapshot.mkdir()
    elif tamper == 'missing':
        snapshot.unlink()
    else:
        saved = json.loads(snapshot.read_text(encoding='utf-8'))
        if tamper == 'invalid-size':
            saved['execution_context']['temporary_size'] = '8g,exec'
        elif tamper == 'wrong-store':
            saved['execution_context']['state_dir'] = str(case[0].parent / 'different/state')
        else:
            saved['run_id'] = 'other-run'
        snapshot.write_text(json.dumps(saved), encoding='utf-8')
    incomplete(invoke(case, '-Action', 'retest', '-FindingId', 'GXSEC-123', '-RunId', 'run-example', '-Json'),
               'previous_context_unavailable')
    assert not calls(case)


@pytest.mark.parametrize('parent', [False, True])
@pytest.mark.parametrize('trailing_separator', [False, True])
def test_output_cannot_expose_writable_source_alias(case, parent, trailing_separator):
    output = case[0].parent if parent else case[0]
    argument = str(output) + ('\\' if trailing_separator else '')
    incomplete(invoke(case, '-Output', argument, '-Json'), 'invalid_output')
    assert calls(case) == []


@pytest.mark.parametrize('location', ['source', 'output'])
def test_database_cannot_overlap_writable_source_or_output(case, location):
    policy = case[0].parent / 'approved.json'
    policy.write_text('{}', encoding='utf-8')
    output = case[0].parent / 'results'
    output.mkdir()
    database = case[0] if location == 'source' else output
    incomplete(invoke(case, '-Action', 'release', '-Output', str(output), '-Policy', str(policy),
                      '-Database', str(database), '-Json'), 'invalid_database')
    assert calls(case) == []


def test_check_preserves_base_as_one_argument(case):
    result = invoke(case, '-Action', 'check', '-Base', 'feature/demo;literal')
    assert result.returncode == 0, result.stdout + result.stderr
    run = calls(case)[-1]
    assert run[run.index('--base') + 1] == 'feature/demo;literal'


def test_protected_policy_and_database_are_readonly_and_preserve_isolation(case):
    policy = case[0].parent / 'approved policy.json'
    policy.write_text('{"sca":{"offline_db":"/advisories"}}', encoding='utf-8')
    database = case[0].parent / 'approved database'
    database.mkdir()
    result = invoke(case, '-Action', 'release', '-Policy', str(policy), '-Database', str(database), '-Json')
    assert result.returncode == 0, result.stdout + result.stderr
    run = calls(case)[-1]
    assert f'type=bind,source={policy},target=/trusted/policy.json,readonly' in run
    assert f'type=bind,source={database},target=/advisories,readonly' in run
    assert run[run.index('--policy') + 1] == '/trusted/policy.json'
    assert run[run.index('--network') + 1] == 'none'
    assert run[run.index('--pull') + 1] == 'never'


def test_policy_inside_inspected_source_is_rejected_before_docker(case):
    policy = case[0] / 'pretend-approved.json'
    policy.write_text('{}', encoding='utf-8')
    incomplete(invoke(case, '-Action', 'release', '-Policy', str(policy), '-Json'), 'invalid_policy')
    assert calls(case) == []
    assert not (case[0] / '.gxsec-container').exists()


def test_database_without_policy_is_rejected_before_docker(case):
    database = case[0].parent / 'db'
    database.mkdir()
    incomplete(invoke(case, '-Action', 'release', '-Database', str(database), '-Json'), 'invalid_arguments')
    assert calls(case) == []


def test_policy_mount_separator_is_rejected_before_docker(case):
    policy = case[0].parent / 'policy,readonly.json'
    policy.write_text('{}', encoding='utf-8')
    incomplete(invoke(case, '-Action', 'release', '-Policy', str(policy), '-Json'), 'invalid_policy')
    assert calls(case) == []


def test_review_records_use_protected_readonly_input(case):
    policy = case[0].parent / 'policy.json'
    policy.write_text('{}', encoding='utf-8')
    reviews = case[0].parent / 'review records.json'
    reviews.write_text('{"reviews":[]}', encoding='utf-8')
    result = invoke(case, '-Action', 'release', '-Policy', str(policy), '-ReviewRecords', str(reviews), '-Json')
    assert result.returncode == 0, result.stdout + result.stderr
    run = calls(case)[-1]
    assert f'type=bind,source={reviews},target=/trusted/reviews.json,readonly' in run
    assert run[run.index('--review-records') + 1] == '/trusted/reviews.json'


def test_expected_framework_is_additive_without_generating_config(case):
    result = invoke(case, '-Action', 'release', '-ExpectedFramework', 'SEF', '-Json')
    assert result.returncode == 0, result.stdout + result.stderr
    run = calls(case)[-1]
    assert run[run.index('--expected-framework') + 1] == 'SEF'
    assert not (case[0] / 'gxsec.yaml').exists()


def test_project_review_records_are_rejected_before_docker(case):
    policy = case[0].parent / 'policy.json'
    policy.write_text('{}', encoding='utf-8')
    reviews = case[0] / 'reviews.json'
    reviews.write_text('{}', encoding='utf-8')
    incomplete(invoke(case, '-Action', 'release', '-Policy', str(policy), '-ReviewRecords', str(reviews), '-Json'),
               'invalid_review_records')
    assert calls(case) == []


def test_check_defaults_to_check_profile(case):
    result = invoke(case, '-Action', 'check')
    assert result.returncode == 0, result.stdout + result.stderr
    run = calls(case)[-1]
    assert run[run.index('--profile') + 1] == 'check'


def test_check_preserves_an_explicit_profile(case):
    result = invoke(case, '-Action', 'check', '-Profile', 'static-release')
    assert result.returncode == 0, result.stdout + result.stderr
    run = calls(case)[-1]
    assert run[run.index('--profile') + 1] == 'static-release'


def test_retest_uses_original_id_profile_and_same_output_state(case):
    from tests.test_gxsec_reporting import sample_run
    output = case[0] / '.gxsec-container'
    (output / 'state').mkdir(parents=True)
    marker = output / 'state/history-marker'
    marker.write_text('existing-state', encoding='utf-8')
    database = output / 'state/state.sqlite3'
    database.write_bytes(b'opaque-existing-state')
    (output / 'state/runs').mkdir()
    legacy = sample_run()
    legacy['run_id'] = '20261105T120000Z-old'
    (output / 'state/runs/20261105T120000Z-old.json').write_text(json.dumps(legacy), encoding='utf-8')
    result = invoke(case, '-Action', 'retest', '-FindingId', 'GXSEC-0123456789abcdef0123',
                    '-RunId', '20261105T120000Z-old', '-Profile', 'check', '-Json')
    assert result.returncode == 0, result.stdout + result.stderr
    run = calls(case)[-1]
    assert run[run.index(IMAGE_ID) + 1:] == ['retest', 'GXSEC-0123456789abcdef0123', '--source', '/workspace',
        '--profile', 'check', '--state-dir', '/results/state', '--output', '/results/report',
        '--run-id', '20261105T120000Z-old', '--json']
    assert marker.read_text(encoding='utf-8') == 'existing-state'
    assert database.read_bytes() == b'opaque-existing-state'


@pytest.mark.parametrize('run_id', [None, 'previous-release-run'])
def test_retest_without_explicit_profile_defers_to_saved_run(case, run_id):
    from tests.test_gxsec_reporting import sample_run
    state = case[0] / '.gxsec-container/state'
    state.mkdir(parents=True)
    (state / 'state.sqlite3').write_bytes(b'opaque-existing-state')
    legacy = sample_run()
    legacy['run_id'] = run_id or 'previous-release-run'
    record = state / 'runs' / (run_id + '.json') if run_id else state.parent / 'report/result.json'
    record.parent.mkdir(parents=True)
    record.write_text(json.dumps(legacy), encoding='utf-8')
    arguments = ['-Action', 'retest', '-FindingId', 'GXSEC-0123456789abcdef0123', '-Json']
    if run_id:
        arguments += ['-RunId', run_id]
    result = invoke(case, *arguments)
    assert result.returncode == 0, result.stdout + result.stderr
    run = calls(case)[-1]
    assert '--profile' not in run, 'An omitted profile must be inherited by the CLI from saved history'
    assert run[run.index('--tmpfs') + 1] == '/tmp:rw,nosuid,nodev,size=512m'
    assert run[run.index('--state-dir') + 1] == '/results/state'
    if run_id:
        assert run[run.index('--run-id') + 1] == run_id


def test_retest_without_saved_state_does_not_create_a_new_store(case):
    incomplete(invoke(case, '-Action', 'retest', '-FindingId', 'GXSEC-0123456789abcdef0123', '-Json'),
               'previous_state_unavailable')
    assert calls(case) == []
    assert not (case[0] / '.gxsec-container').exists()


@pytest.mark.parametrize('code', [1, 2, 3, 137])
def test_engine_exit_codes_are_preserved(case, code):
    case[2]['GXSEC_FAKE_RUN_EXIT'] = str(code)
    result = invoke(case, '-Action', 'release')
    assert result.returncode == code, result.stdout + result.stderr


@pytest.mark.parametrize(('arguments', 'reason'), [
    (['-Action', 'retest'], 'invalid_arguments'),
    (['-Action', 'release', '-FindingId', 'GXSEC-synthetic'], 'invalid_arguments'),
    (['-Action', 'release', '-RunId', 'previous'], 'invalid_arguments'),
    (['-Action', 'release', '-Base', 'HEAD~1'], 'invalid_arguments'),
    (['-Action', 'check', '-Base', '--bad-option'], 'invalid_arguments'),
    (['-Action', 'retest', '-FindingId', 'GXSEC-synthetic', '-RunId', '../other'], 'invalid_arguments'),
    (['-Action', 'unknown'], 'invalid_arguments'),
    (['-Image', '--pull'], 'invalid_arguments'),
])
def test_invalid_arguments_fail_before_docker_or_source_output(case, arguments, reason):
    incomplete(invoke(case, *arguments, '-Json'), reason)
    assert calls(case) == []
    assert not (case[0] / '.gxsec-container').exists()


def test_named_option_cannot_be_smuggled_as_finding_id(case):
    # PowerShell binds the new Policy option before the script can emit JSON.
    result = invoke(case, '-Action', 'retest', '-FindingId', '--policy', '-Json')
    assert result.returncode != 0
    assert calls(case) == []
    assert not (case[0] / '.gxsec-container').exists()


def test_missing_docker_is_preparation_incomplete_without_output(case):
    case[2]['PATH'] = ''
    incomplete(invoke(case, '-Action', 'release', '-Json'), 'docker_cli_unavailable')
    assert not (case[0] / '.gxsec-container').exists()


@pytest.mark.parametrize(('variable', 'value', 'reason', 'expected_calls'), [
    ('GXSEC_FAKE_DAEMON', 'down', 'docker_unavailable', 1),
    ('GXSEC_FAKE_DAEMON', 'windows', 'docker_linux_required', 1),
    ('GXSEC_FAKE_IMAGE', 'missing', 'image_unavailable', 2),
    ('GXSEC_FAKE_IMAGE', 'windows', 'image_linux_required', 2),
])
def test_unready_runtime_never_scans_pulls_or_creates_output(case, variable, value, reason, expected_calls):
    case[2][variable] = value
    incomplete(invoke(case, '-Action', 'release', '-Json'), reason)
    operations = calls(case)
    assert len(operations) == expected_calls
    assert not any(row[0] in {'pull', 'build', 'run'} for row in operations)
    assert not (case[0] / '.gxsec-container').exists()


def test_docker_probe_has_bounded_wait(case):
    case[2]['GXSEC_FAKE_DAEMON'] = 'timeout'
    incomplete(invoke(case, '-Action', 'doctor', '-Json', timeout=60), 'docker_probe_timeout')
    # Exclude PowerShell/fixture startup on loaded Windows hosts; measure the blocked probe.
    started = int(Path(case[2]['GXSEC_FAKE_PROBE_STARTED']).read_text()) / 1000
    assert time.time() - started < 14
    assert len(calls(case)) == 1


def test_docker_executable_from_project_is_never_executed(case, fake_docker):
    local_bin = case[0] / 'bin'
    local_bin.mkdir()
    shutil.copy2(fake_docker, local_bin / 'docker.exe')
    case[2]['PATH'] = str(local_bin)
    incomplete(invoke(case, '-Action', 'doctor', '-Json'), 'untrusted_docker_location')
    assert calls(case) == []


def test_output_file_is_rejected_before_docker_probe(case):
    output = case[0].parent / 'not-a-directory'
    output.write_text('preserve', encoding='utf-8')
    incomplete(invoke(case, '-Output', str(output), '-Json'), 'invalid_output')
    assert output.read_text(encoding='utf-8') == 'preserve'
    assert calls(case) == []


def discussion_state(case, run_id='previous-run'):
    output = case[0] / '.gxsec-container'
    state = output / 'state'
    (state / 'runs').mkdir(parents=True)
    (state / 'state.sqlite3').write_bytes(b'opaque-existing-state')
    (state / 'runs' / (run_id + '.json')).write_text('{}', encoding='utf-8')
    return output


def test_discuss_uses_original_saved_run_without_overwriting_scan_report(case):
    output = discussion_state(case)
    report = output / 'report/result.json'
    report.parent.mkdir()
    report.write_text('immutable scan report', encoding='utf-8')
    result = invoke(case, '-Action', 'discuss', '-RunId', 'previous-run', '-Json')
    assert result.returncode == 0, result.stdout + result.stderr
    run = calls(case)[-1]
    assert run[run.index(IMAGE_ID) + 1:] == ['discuss', 'previous-run', '--source', '/workspace',
        '--state-dir', '/results/state', '--json']
    assert '--profile' not in run and '--output' not in run
    assert run[run.index('--network') + 1] == 'none'
    assert run[run.index('--pull') + 1] == 'never'
    assert '--read-only' in run
    assert report.read_text(encoding='utf-8') == 'immutable scan report'


def test_discuss_passes_record_as_literal_readonly_mount(case):
    discussion_state(case)
    record = case[0].parent / '응답 [literal] ; question.json'
    payload = '{"expected_revision": 1, "type": "answer", "answer": "본인 자료"}'
    record.write_text(payload, encoding='utf-8')
    result = invoke(case, '-Action', 'discuss', '-RunId', 'previous-run',
                    '-SessionId', 'session-123', '-Record', str(record), '-Json')
    assert result.returncode == 0, result.stdout + result.stderr
    run = calls(case)[-1]
    assert 'type=bind,source=' + str(record) + ',target=/discussion-input/record.json,readonly' in run
    assert run[run.index(IMAGE_ID) + 1:] == ['discuss', 'previous-run', '--source', '/workspace',
        '--state-dir', '/results/state', '--session-id', 'session-123',
        '--record', '/discussion-input/record.json', '--json']
    assert record.read_text(encoding='utf-8') == payload


@pytest.mark.parametrize('seed_database,seed_snapshot', [(False, False), (True, False), (False, True)])
def test_discuss_missing_original_state_does_not_create_store_or_probe_docker(case, seed_database, seed_snapshot):
    output = case[0] / '.gxsec-container'
    if seed_database or seed_snapshot:
        (output / 'state/runs').mkdir(parents=True)
    if seed_database:
        (output / 'state/state.sqlite3').write_bytes(b'original')
    if seed_snapshot:
        (output / 'state/runs/previous-run.json').write_text('{}', encoding='utf-8')
    before = sorted(str(p.relative_to(output)) for p in output.rglob('*')) if output.exists() else []
    incomplete(invoke(case, '-Action', 'discuss', '-RunId', 'previous-run', '-Json'),
               'previous_state_unavailable')
    assert calls(case) == []
    after = sorted(str(p.relative_to(output)) for p in output.rglob('*')) if output.exists() else []
    assert after == before


@pytest.mark.parametrize('arguments', [
    ['-Action', 'discuss'],
    ['-Action', 'discuss', '-RunId', 'previous-run', '-Profile', 'static-release'],
    ['-Action', 'discuss', '-RunId', 'previous-run', '-Base', 'HEAD'],
    ['-Action', 'discuss', '-RunId', 'previous-run', '-FindingId', 'GXSEC-test'],
    ['-Action', 'discuss', '-RunId', '../escape'],
    ['-Action', 'discuss', '-RunId', 'previous-run', '-SessionId', '../escape'],
    ['-Action', 'discuss', '-RunId', 'previous-run', '-Record', 'answer.json'],
    ['-Action', 'release', '-SessionId', 'session-123'],
    ['-Action', 'doctor', '-Record', 'answer.json'],
])
def test_discussion_arguments_are_rejected_before_any_files_or_docker(case, arguments):
    incomplete(invoke(case, *arguments, '-Json'), 'invalid_arguments')
    assert calls(case) == []
    assert not (case[0] / '.gxsec-container').exists()


@pytest.mark.parametrize('record_kind', ['missing', 'directory', 'comma'])
def test_discuss_invalid_record_is_rejected_before_docker(case, record_kind):
    discussion_state(case)
    record = case[0].parent / ('record,extra.json' if record_kind == 'comma' else 'record.json')
    if record_kind == 'directory':
        record.mkdir()
    elif record_kind == 'comma':
        record.write_text('{}', encoding='utf-8')
    incomplete(invoke(case, '-Action', 'discuss', '-RunId', 'previous-run', '-SessionId', 'session-123',
                      '-Record', str(record), '-Json'), 'invalid_record')
    assert calls(case) == []


@pytest.mark.parametrize('link_kind', ['record', 'run'])
def test_discuss_reparse_inputs_are_never_forwarded_to_docker(case, link_kind):
    output = discussion_state(case)
    original = case[0].parent / 'outside.json'
    original.write_text('{}', encoding='utf-8')
    if link_kind == 'run':
        link = output / 'state/runs/previous-run.json'
        link.unlink()
        arguments = []
        reason = 'previous_state_unavailable'
    else:
        link = case[0].parent / 'record-link.json'
        arguments = ['-SessionId', 'session-123', '-Record', str(link)]
        reason = 'invalid_record'
    try:
        link.symlink_to(original)
    except OSError:
        pytest.skip('symlink creation unavailable on this host')
    incomplete(invoke(case, '-Action', 'discuss', '-RunId', 'previous-run', *arguments, '-Json'), reason)
    assert calls(case) == []
    assert original.read_text(encoding='utf-8') == '{}'


def test_discuss_show_forwards_only_saved_session_identity(case):
    discussion_state(case)
    result = invoke(case, '-Action', 'discuss', '-RunId', 'previous-run', '-SessionId', 'session-123', '-Json')
    assert result.returncode == 0, result.stdout + result.stderr
    run = calls(case)[-1]
    assert run[run.index(IMAGE_ID) + 1:] == ['discuss', 'previous-run', '--source', '/workspace',
        '--state-dir', '/results/state', '--session-id', 'session-123', '--json']


def test_retest_omits_unset_limits_so_cli_can_restore_saved_run(case):
    saved_temporary_run(case)
    result = invoke(case, '-Action', 'retest', '-FindingId', 'GXSEC-123', '-RunId', 'run-example', '-Json')
    assert result.returncode == 0, result.stdout + result.stderr
    run = calls(case)[-1]
    assert '--max-duration-seconds' not in run and '--max-input-bytes' not in run
    assert '--exclude-source-path' not in run


def test_retest_forwards_only_explicit_limit_override(case):
    saved_temporary_run(case)
    result = invoke(case, '-Action', 'retest', '-FindingId', 'GXSEC-123', '-RunId', 'run-example',
                    '-MaxDurationSeconds', '600', '-Json')
    assert result.returncode == 0, result.stdout + result.stderr
    run = calls(case)[-1]
    assert run[run.index('--max-duration-seconds') + 1] == '600'
    assert '--max-input-bytes' not in run


def test_plan_uses_metadata_only_mount_and_literal_exclusion(case):
    result = invoke(case, '-Action', 'plan', '-ExcludeSourcePath', 'archive data', '-Json')
    assert result.returncode == 0, result.stdout + result.stderr
    run = calls(case)[-1]
    assert run[run.index(IMAGE_ID) + 1:] == ['plan', '/workspace', '--max-duration-seconds', '30',
        '--exclude-source-path', 'archive data']
    assert '--read-only' in run and run[run.index('--network') + 1] == 'none'
    assert not any('target=/results' in item for item in run)
    assert not (case[0] / '.gxsec-container').exists()


@pytest.mark.parametrize('path', ['--profile=release', '../escape', '/absolute', 'C:/absolute',
                                 'data//nested', 'data/../secret', 'data/*', '.git', 'data\\nested'])
def test_invalid_selected_exclusion_is_rejected_before_docker(case, path):
    result = invoke(case, '-Action', 'release', '-ExcludeSourcePath', path, '-Json')
    assert result.returncode != 0
    assert calls(case) == []
    assert not (case[0] / '.gxsec-container').exists()
