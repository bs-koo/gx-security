#!/usr/bin/env python3
"""Offline integration proof using synthetic inputs and the installed engines.

Creates only a private temporary repository. The generated advisory is an
explicit test fixture and must never be used as a real advisory database.
"""
from contextlib import redirect_stdout
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import zipfile

from gxsec.cli import main
from gxsec.models import content_hash
from gxsec.source import collect_source, runtime_environment, trusted_runtime_tool


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute(arguments):
    output = io.StringIO()
    with redirect_stdout(output):
        code = main(arguments + ['--json'])
    result = json.loads(output.getvalue())
    if 'run_id' not in result:
        raise AssertionError('Synthetic run did not save a result: ' + str(result.get('error')))
    return code, result


def run_smoke():
    with tempfile.TemporaryDirectory(prefix='gxsec-synthetic-runtime-') as temporary:
        root = Path(temporary)
        source, database, state = root / 'source', root / 'database', root / 'state'
        source.mkdir()
        (source / 'App.java').write_text('class App { String name = "synthetic"; }\n', encoding='utf-8')
        (source / 'package.json').write_text('{"name":"gxsec-synthetic-runtime","version":"1.0.0"}\n', encoding='utf-8')
        lock = source / 'package-lock.json'
        def dependency(version):
            lock.write_text(json.dumps({'name': 'gxsec-synthetic-runtime', 'version': '1.0.0', 'lockfileVersion': 3,
                'packages': {'': {'name': 'gxsec-synthetic-runtime', 'version': '1.0.0', 'dependencies': {'gxsec-synthetic-package': version}},
                             'node_modules/gxsec-synthetic-package': {'version': version,
                                 'resolved': f'https://registry.npmjs.org/gxsec-synthetic-package/-/gxsec-synthetic-package-{version}.tgz'}}}), encoding='utf-8')
        dependency('1.0.0')
        git = trusted_runtime_tool('git', source)['executable']
        environment = runtime_environment()
        home = root / 'home'
        home.mkdir()
        environment.update({'HOME': str(home), 'USERPROFILE': str(home), 'GIT_CONFIG_GLOBAL': '/dev/null'})
        def git_command(*args):
            subprocess.run([git, '-c', 'core.hooksPath=', '-c', 'core.fsmonitor=false', '-C', str(source), *args],
                           check=True, capture_output=True, env=environment, timeout=30)
        git_command('init', '--initial-branch=main')
        git_command('add', '--all')
        git_command('-c', 'user.name=GX Security Synthetic Test', '-c', 'user.email=synthetic@example.invalid',
                    'commit', '-m', 'Synthetic offline runtime fixture')
        archive = database / 'osv-scalibr' / 'npm' / 'all.zip'
        archive.parent.mkdir(parents=True)
        now = datetime.now(timezone.utc).isoformat()
        advisory = {'schema_version': '1.6.0', 'id': 'GXSEC-SYNTHETIC-0001', 'modified': now,
            'published': now, 'summary': 'Synthetic offline adapter test; not a real advisory',
            'database_specific': {'severity': 'HIGH'}, 'affected': [{'package': {'name': 'gxsec-synthetic-package', 'ecosystem': 'npm'},
                'versions': ['1.0.0'], 'database_specific': {'severity': 'HIGH'}}]}
        with zipfile.ZipFile(archive, 'w') as bundle:
            bundle.writestr('GXSEC-SYNTHETIC-0001.json', json.dumps(advisory))
        manifest = database / 'snapshot.json'
        manifest.write_text(json.dumps({'schema_version': 1, 'generated_at': now, 'advisory_as_of': now,
            'files': {'osv-scalibr/npm/all.zip': sha(archive)}}), encoding='utf-8')
        policy_path = root / 'protected-synthetic-policy.json'
        def policy():
            inventory = collect_source(source)
            proof = {'id': 'synthetic-resolved-inputs', 'source_revision': inventory['revision'],
                'scope_hash': inventory['scope_hash'], 'input_hashes': {'package-lock.json': sha(lock)},
                'modules': [item['path'] for item in inventory['modules']], 'runtime_complete': True,
                'artifact_digest': 'sha256:' + sha(lock)}
            policy_path.write_text(json.dumps({'sca': {'offline_db': str(database), 'db_manifest_sha256': sha(manifest), 'provenance': proof},
                'trusted_approvals': [{'record_id': proof['id'], 'digest': content_hash(proof), 'kind': 'dependency-provenance',
                                      'roles': ['protected-ci']}]}), encoding='utf-8')
        args = ['release', str(source), '--profile', 'static-release', '--state-dir', str(state), '--policy', str(policy_path)]
        policy()
        blocked_code, blocked = execute(args)
        assert blocked_code == 1 and blocked['gate']['status'] == 'BLOCK', {
            'case': 'synthetic-vulnerable-dependency', 'gate': blocked.get('gate'), 'checks': blocked.get('checks')}
        assert any(item['rule_id'] == 'GXSEC-SYNTHETIC-0001' for item in blocked['findings'])
        assert all(item['status'] == 'complete' for item in blocked['checks']), blocked['checks']
        dependency('1.0.1')
        policy()
        clean_code, clean = execute(args)
        assert clean_code == 0 and clean['gate']['status'] == 'PASS', {
            'case': 'synthetic-fixed-dependency', 'gate': clean.get('gate'), 'checks': clean.get('checks')}
        assert any(item.get('lifecycle') == 'fixed-verified' for item in clean['findings']), clean['findings']
        print(json.dumps({'fixture': 'synthetic-only', 'network': 'run with --network none',
            'vulnerable_dependency': blocked['gate']['status'], 'fixed_dependency': clean['gate']['status'],
            'engines': {item['id']: {'status': item['status'], 'version': item.get('engine', {}).get('version')}
                        for item in blocked['checks']}, 'git_history': 'private clone scanned',
            'reconciliation': 'fixed-verified'}, ensure_ascii=False))


if __name__ == '__main__':
    run_smoke()
