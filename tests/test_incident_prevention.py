"""Regression coverage for the first incident-prevention checks."""
import hashlib
import io
import json
import shutil
import subprocess
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from gxsec import adapters, config
from gxsec.models import content_hash
from gxsec.source import collect_source


ROOT = Path(__file__).resolve().parents[1]
FAKE_KEY = 'synthetic-key-fixture-0123456789'
DOWNLOAD_RULE = 'sqisoft-download-lexical-boundary'


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')


def archive(entries):
    buffer = io.BytesIO()
    with ZipFile(buffer, 'w', compression=ZIP_DEFLATED) as output:
        for name, data in entries:
            output.writestr(name, data)
    return buffer.getvalue()


def checked(tmp_path, source, *, entries=None, mutate=False, approve=True, profile='static-release', release_digest=None):
    inventory = collect_source(source)
    settings = config.default_config(source)
    settings['_inventory'] = inventory
    settings['_state_dir'] = tmp_path / 'state'
    for engine in ('gitleaks', 'osv', 'semgrep'):
        settings['tools'][engine]['command'] = f'gxsec-missing-{engine}'
    if entries is not None:
        artifact = tmp_path / 'app.war'
        data = archive(entries)
        artifact.write_bytes(data)
        record = {'id': 'fixture-archive', 'source_revision': inventory['revision'],
                  'artifact': {'path': str(artifact), 'sha256': hashlib.sha256(data).hexdigest()}}
        settings['_trusted_policy'] = {'artifact_secrets': record, 'trusted_approvals': [
            {'record_id': record['id'], 'kind': 'artifact-secret-scan',
             'digest': content_hash(record), 'roles': ['protected-ci']}] if approve else []}
        if release_digest is not None:
            settings['_trusted_policy']['release_evidence'] = {'artifact_digest': release_digest}
        if mutate:
            artifact.write_bytes(archive([('changed.txt', 'changed')]))
    checks, findings = adapters.run_static_checks(source, settings, profile)
    return {check['id']: check for check in checks}, findings


def test_packaged_dotenv_and_nested_aes_key_report_without_values(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    checks, findings = checked(tmp_path, source, entries=[
        ('WEB-INF/classes/.env', 'CRYPTO_AES_KEY_V1=' + FAKE_KEY),
        ('WEB-INF/lib/component.jar', archive([
            ('application.yaml', 'crypto:\n  aes:\n    keys:\n      v1: ' + FAKE_KEY),
            ('application.properties', 'crypto.aes.keys.v2=' + FAKE_KEY),
            ('.env.example', 'CRYPTO_AES_KEY_V1=${CRYPTO_AES_KEY_V1}')]))])
    check = checks['artifact-secrets']
    assert check['status'] == 'complete' and check['required']
    assert check['coverage']['scanned'] == check['coverage']['eligible']
    assert [f['rule_id'] for f in findings].count('artifact-sensitive-literal') == 3
    assert [f['rule_id'] for f in findings].count('artifact-dotenv-bundled') == 1
    assert FAKE_KEY not in json.dumps((checks, findings))


def test_packaged_references_and_encrypted_configs_are_not_plaintext(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    checks, findings = checked(tmp_path, source, entries=[
        ('application.yml', 'crypto:\n  aes:\n    keys:\n      v1: "${CRYPTO_AES_KEY_V1}"'),
        ('secrets.properties', 'CRYPTO_AES_KEY_V1=ENC(encrypted-fixture)'),
        ('.env.template', 'SPRING_DATASOURCE_PASSWORD=\nCRYPTO_AES_KEY_V1=${SEF_KEY}')])
    assert checks['artifact-secrets']['status'] == 'complete'
    assert not findings


@pytest.mark.parametrize('mutate,approve', [(True, True), (False, False)])
def test_artifact_approval_or_byte_mismatch_is_incomplete(tmp_path, mutate, approve):
    source = tmp_path / 'source'
    source.mkdir()
    checks, findings = checked(tmp_path, source, entries=[('.env', 'CRYPTO_AES_KEY_V1=' + FAKE_KEY)],
                               mutate=mutate, approve=approve)
    assert checks['artifact-secrets']['status'] == 'incomplete'
    assert not findings


@pytest.mark.parametrize('name', ['../example.txt', 'library.jar'])
def test_unsafe_archive_member_or_unreadable_nested_archive_keeps_check_incomplete(tmp_path, name):
    source = tmp_path / 'source'
    source.mkdir()
    checks, _ = checked(tmp_path, source, entries=[(name, 'synthetic unsupported bytes')])
    assert checks['artifact-secrets']['status'] == 'incomplete'
    assert not (tmp_path / 'example.txt').exists()


@pytest.mark.parametrize('entries', [[], [('.env', 'KEY=fixture'), ('.ENV', 'KEY=fixture')]])
def test_empty_or_ambiguous_archive_keeps_check_incomplete(tmp_path, entries):
    source = tmp_path / 'source'
    source.mkdir()
    checks, _ = checked(tmp_path, source, entries=entries)
    assert checks['artifact-secrets']['status'] == 'incomplete'


def test_release_requires_same_artifact_digest_as_the_scan(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    checks, findings = checked(tmp_path, source, entries=[('.env', 'CRYPTO_AES_KEY_V1=' + FAKE_KEY)],
                               profile='release', release_digest='0' * 64)
    assert checks['artifact-secrets']['errors'] == [{'type': 'artifact_release_digest_mismatch'}]
    assert not findings


def test_ci_files_are_scanned_without_running_any_job(tmp_path):
    source = tmp_path / 'source'
    write(source / '.github/workflows/build.yml', """on: pull_request_target
permissions: write-all
jobs:
  build:
    steps:
      - uses: actions/checkout@main
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: printf "%s" "${{ github.event.pull_request.title }}"
""")
    write(source / 'Jenkinsfile', """pipeline {
    environment { TEST_DB = credentials('fixture-id') }
    stages { stage('Build') { steps { echo 'fixture' } } }
}
""")
    write(source / '.jenkins/jenkins.yaml', 'jenkins:\n  authorizationStrategy:\n    unsecured: {}\n')
    checks, findings = checked(tmp_path, source)
    check = checks['pipeline']
    assert check['coverage']['scanned'] == check['coverage']['eligible'] == 3
    assert {'gha-untrusted-checkout', 'gha-write-all', 'gha-unpinned-dependency',
            'gha-untrusted-run-expression', 'jenkins-global-credentials', 'jenkins-unsecured-authorization'} <= {
                finding['rule_id'] for finding in findings}
    assert 'fixture-id' not in json.dumps(findings)


def test_normal_pipeline_and_commented_credentials_are_not_flagged(tmp_path):
    source = tmp_path / 'source'
    write(source / '.github/workflows/build.yml', """on: pull_request
permissions: {contents: read}
jobs:
  build:
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
        with: {persist-credentials: false}
""")
    write(source / 'Jenkinsfile', """pipeline {
  // environment { TEST_DB = credentials('fixture-id') }
  stages { stage('Build') { steps { echo 'fixture' } } }
}
""")
    checks, findings = checked(tmp_path, source)
    assert checks['pipeline']['status'] == 'complete'
    assert not findings


def test_duplicate_workflow_keys_cannot_establish_coverage(tmp_path):
    source = tmp_path / 'source'
    write(source / '.github/workflows/build.yml', 'on: pull_request\non: push\njobs: {}\n')
    checks, findings = checked(tmp_path, source)
    assert checks['pipeline']['status'] == 'incomplete'
    assert not findings


def test_download_rule_is_in_the_normal_sast_catalog():
    import yaml
    rules = yaml.safe_load((ROOT / 'skills/detecting-path-traversal/rules/path-traversal.yml').read_text(encoding='utf-8'))
    assert DOWNLOAD_RULE in {rule['id'] for rule in rules['rules']}


@pytest.mark.skipif(shutil.which('semgrep') is None, reason='Requires the real Semgrep parser')
def test_download_rule_distinguishes_lexical_and_real_path_boundaries(tmp_path):
    write(tmp_path / 'Download.java', """class Download {
    Object lexical(Path root, String name) throws Exception {
        Path selected = root.resolve(name).normalize();
        return new FileSystemResource(selected);
    }
    Object confined(Path root, String name) throws Exception {
        Path base = root.toRealPath();
        Path selected = base.resolve(name).normalize();
        Path real = selected.toRealPath();
        if (!real.startsWith(base)) { throw new AccessDeniedException("fixture"); }
        return new FileSystemResource(real);
    }
    Object rawBytes(Path root, String name) throws Exception {
        Path selected = root.resolve(name).normalize();
        return Files.readAllBytes(selected);
    }
}
""")
    rules = ROOT / 'skills/detecting-path-traversal/rules/path-traversal.yml'
    result = subprocess.run(['semgrep', 'scan', '--metrics=off', '--disable-version-check',
                             '--json', '--config', str(rules), str(tmp_path)],
                            capture_output=True, timeout=120, check=True)
    payload = json.loads(result.stdout)
    assert not payload['errors']
    hits = [row for row in payload['results'] if row['check_id'].endswith(DOWNLOAD_RULE)]
    assert sorted(hit['start']['line'] for hit in hits) == [4, 15]


@pytest.mark.skipif(shutil.which('semgrep') is None, reason='Requires the real Semgrep parser')
def test_dotenv_sast_detects_aes_and_ignores_runtime_references(tmp_path):
    env = tmp_path / 'application.env'
    write(env, "CRYPTO_AES_KEY_V1=" + FAKE_KEY + "\n"
               "CRYPTO_AES_KEY_V2=\"${SEF_KEY}\"\n"
               "CRYPTO_AES_KEY_V3=ENC(encrypted-fixture)\n")
    rules = ROOT / 'skills/detecting-sensitive-data-exposure/rules/sensitive-data.yml'
    result = subprocess.run(['semgrep', 'scan', '--metrics=off', '--disable-version-check',
                             '--json', '--config', str(rules), str(env)],
                            capture_output=True, timeout=120, check=True)
    payload = json.loads(result.stdout)
    assert not payload['errors']
    hits = [row for row in payload['results'] if row['check_id'].endswith('hardcoded-credential-dotenv')]
    assert [hit['start']['line'] for hit in hits] == [1]
