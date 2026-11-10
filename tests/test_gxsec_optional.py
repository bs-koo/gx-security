"""Optional-engine contracts use native fixtures; no licensed or live scans run."""
import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from gxsec.models import content_hash
from gxsec.source import collect_source


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class OptionalTests(unittest.TestCase):
    def setUp(self):
        # These fixtures are deliberately not Git checkouts; exercise content identity.
        git = patch('gxsec.source._git', return_value=None)
        git.start()
        self.addCleanup(git.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        # Windows TEMP can contain an 8.3 alias; use the same canonical root as collect_source.
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / 'source'
        self.source.mkdir()
        (self.source / 'app.py').write_text('print("fixture")\n', encoding='utf-8')
        self.inventory = collect_source(self.source)
        self.policy = {'source_revision': self.inventory['revision'], 'scope_hash': self.inventory['scope_hash'],
                       'optional': {}, 'trusted_approvals': []}
        self.config = {'tools': {}, '_trusted_policy': self.policy}

    def approve(self, record, kind='scanner-evidence', roles=('protected-ci',)):
        self.policy['trusted_approvals'].append({'record_id': record['id'], 'digest': content_hash(record),
                                               'kind': kind, 'roles': list(roles)})

    def tree(self, name, files):
        directory = self.root / name
        directory.mkdir(exist_ok=True)
        hashes = {}
        for name, text in files.items():
            path = directory / name
            path.parent.mkdir(exist_ok=True, parents=True)
            path.write_text(text, encoding='utf-8')
            hashes[name] = digest(path)
        return {'path': str(directory), 'files': hashes, 'sha256': content_hash(hashes)}

    def runtime(self, name):
        directory = self.root / name
        directory.mkdir(exist_ok=True)
        executable = directory / 'entrypoint.exe'
        executable.write_bytes(Path(sys.executable).read_bytes())
        (directory / 'runtime.dat').write_text('complete synthetic distribution', encoding='utf-8')
        files = {p.name: digest(p) for p in directory.iterdir()}
        return {'path': str(directory), 'files': files, 'sha256': content_hash(files), 'entrypoint': executable.name}

    def quotas(self):
        return {'limits': {'cpu_seconds': 30, 'memory_bytes': 512 * 1024 ** 2, 'disk_bytes': 1024 ** 3,
                           'pids': 16, 'output_bytes': 1024 ** 2}, 'limits_enforced': True,
                'resource_evidence_refs': ['host-kernel-quota-fixture']}

    def evidence(self, engine, report):
        path = self.root / (engine + '.json')
        path.write_text(report if isinstance(report, str) else json.dumps(report), encoding='utf-8')
        record = {'id': engine + '-evidence', 'engine': {'name': engine, 'version': {'trivy': '0.69.0', 'codeql': '2.24.0', 'nuclei': '3.7.0'}[engine],
                  'digest': 'sha256:' + 'a' * 64}, 'artifact': {'path': str(path), 'sha256': digest(path)},
                  'source_revision': self.inventory['revision'], 'source_hash': self.inventory['hash'],
                  'scope_hash': self.inventory['scope_hash'], 'expires_at': '2999-01-01T00:00:00Z',
                  'execution_status': 'complete', 'coverage': {'eligible': ['app.py'], 'scanned': ['app.py'], 'complete': True},
                  'inputs': {}}
        if engine == 'trivy':
            record['inputs'] = {'target': {'kind': 'filesystem'},
                                'database': self.tree('trivy-db', {'db/trivy.db': 'fixture db', 'db/metadata.json': '{}'})}
            record['inputs']['database']['expires_at'] = '2999-01-01T00:00:00Z'
        elif engine == 'codeql':
            record['inputs'] = {'database': {**self.tree('codeql-db', {'codeql-database.yml': 'finalised: true\n'}),
                                             'source_revision': self.inventory['revision'], 'prebuilt': True},
                                'runtime': self.runtime('codeql-runtime'),
                                'queries': {**self.tree('queries', {'reviewed.qls': '- query: fixture.ql\n', 'fixture.ql': 'select 1\n',
                                    'codeql-pack.lock.yml': 'dependencies:\n  codeql/python-all:\n    version: 1.0.0\n'}),
                                            'suite': 'reviewed.qls', 'rule_ids': ['py/test'], 'lockfile': 'codeql-pack.lock.yml'},
                                'query_packs': {**self.tree('packs', {'python-all/qlpack.yml': 'name: codeql/python-all\nversion: 1.0.0\n'}),
                                                'resolved': {'codeql/python-all': {'version': '1.0.0'}}}}
            record['engine']['digest'] = 'sha256:' + record['inputs']['runtime']['files']['entrypoint.exe']
            rights = {'id': 'codeql-rights', 'permitted': True, 'basis': 'organization-approved-use',
                      'evidence_refs': ['license-register/fixture'], 'source_revision': self.inventory['revision'],
                      'scope_hash': self.inventory['scope_hash'], 'expires_at': '2999-01-01T00:00:00Z'}
            record['inputs']['use_rights'] = rights
            self.approve(rights, 'engine-use-rights', ('protected-ci', 'license-owner'))
        self.config['tools'][engine] = {'enabled': True, 'required': True}
        self.policy['optional'][engine] = {'evidence': record}
        self.approve(record)
        return record

    def run_optional(self):
        from gxsec.optional import run_optional_checks
        return run_optional_checks(self.source, self.config, 'release')

    def trivy(self, rows=None):
        return {'SchemaVersion': 2, 'ArtifactName': str(self.source), 'ArtifactType': 'filesystem',
                'Metadata': {}, 'Results': [] if rows is None else rows}

    def sarif(self, results=None):
        return {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'CodeQL', 'semanticVersion': '2.24.0',
                'rules': [{'id': 'py/test', 'properties': {'security-severity': '8.1'}}]}},
                'invocations': [{'executionSuccessful': True}], 'results': results or []}]}

    def test_missing_prerequisites_never_launch_bare_engines(self):
        self.config['tools'] = {name: {'enabled': True, 'required': True} for name in ('trivy', 'codeql', 'nuclei')}
        with patch('subprocess.run') as run:
            checks, findings = self.run_optional()
        self.assertEqual([c['status'] for c in checks], ['unsupported'] * 3)
        self.assertEqual(findings, [])
        run.assert_not_called()

    def test_native_trivy_findings_and_complete_zero_findings(self):
        self.evidence('trivy', self.trivy([{'Target': 'app.py', 'Class': 'lang-pkgs', 'Vulnerabilities': [{
            'VulnerabilityID': 'CVE-fixture', 'PkgName': 'fixture', 'InstalledVersion': '1.0',
            'Severity': 'HIGH', 'Title': 'Fixture vulnerability', 'Description': 'Authorization: Bearer fixture-secret'}]}]))
        checks, findings = self.run_optional()
        self.assertEqual(checks[0]['status'], 'complete')
        self.assertEqual((checks[0]['coverage']['eligible'], checks[0]['coverage']['scanned']), (1, 1))
        self.assertEqual(findings[0]['rule_id'], 'trivy.CVE-fixture')
        self.assertEqual(findings[0]['validation'], 'candidate')
        self.assertNotIn('fixture-secret', json.dumps([checks, findings]))
        self.evidence('trivy', self.trivy())
        self.assertEqual(self.run_optional()[0][0]['status'], 'complete')

    def test_unsigned_project_evidence_or_in_source_artifact_is_incomplete(self):
        record = self.evidence('trivy', self.trivy())
        self.policy['trusted_approvals'] = []
        self.assertEqual(self.run_optional()[0][0]['status'], 'incomplete')
        path = self.source / 'claimed-clean.json'
        path.write_text(json.dumps(self.trivy()), encoding='utf-8')
        record['artifact'] = {'path': str(path), 'sha256': digest(path)}
        self.approve(record)
        self.assertEqual(self.run_optional()[0][0]['status'], 'incomplete')

    def test_stale_scope_tamper_missing_coverage_and_malformed_json_fail_closed(self):
        record = self.evidence('trivy', self.trivy())
        baseline = copy.deepcopy(record)
        mutations = [lambda r: r.update(source_revision='b' * 40),
                     lambda r: r.update(scope_hash='bad'),
                     lambda r: r.update(coverage={'eligible': ['app.py'], 'scanned': [], 'complete': True}),
                     lambda r: r['artifact'].update(sha256='0' * 64)]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                record.clear(); record.update(copy.deepcopy(baseline)); mutate(record); self.approve(record)
                self.assertEqual(self.run_optional()[0][0]['status'], 'incomplete')
        self.evidence('trivy', {})
        self.assertEqual(self.run_optional()[0][0]['status'], 'incomplete')

    def test_changed_offline_database_and_missing_image_archive_are_incomplete(self):
        record = self.evidence('trivy', self.trivy())
        (Path(record['inputs']['database']['path']) / 'db/trivy.db').write_text('changed', encoding='utf-8')
        self.assertEqual(self.run_optional()[0][0]['status'], 'incomplete')
        record = self.evidence('trivy', self.trivy())
        record['inputs']['target'] = {'kind': 'image-archive', 'path': str(self.root / 'missing.tar'), 'sha256': '0' * 64}
        self.approve(record)
        self.assertEqual(self.run_optional()[0][0]['status'], 'incomplete')

    def test_codeql_native_sarif_requires_rights_finalized_database_and_success(self):
        record = self.evidence('codeql', self.sarif([{'ruleId': 'py/test', 'message': {'text': 'Fixture alert'},
            'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'app.py'}, 'region': {'startLine': 1}}}]}]))
        checks, findings = self.run_optional()
        self.assertEqual(checks[0]['status'], 'complete')
        self.assertEqual(findings[0]['severity'], 'High')
        record['inputs'].pop('use_rights'); self.approve(record)
        self.assertEqual(self.run_optional()[0][0]['status'], 'incomplete')
        record = self.evidence('codeql', {'version': '2.1.0', 'runs': []})
        self.assertEqual(self.run_optional()[0][0]['status'], 'incomplete')

    def test_native_result_outside_approved_file_scope_is_rejected(self):
        self.evidence('trivy', self.trivy([{'Target': '../outside', 'Class': 'lang-pkgs', 'Vulnerabilities': []}]))
        self.assertEqual(self.run_optional()[0][0]['status'], 'incomplete')

    def nuclei(self, report=''):
        record = self.evidence('nuclei', report)
        template = self.root / 'reviewed.yaml'
        template.write_text('id: fixture-check\ninfo:\n  name: Fixture\n  author: fixture\n  severity: low\nhttp:\n  - method: GET\n    path: ["{{BaseURL}}"]\n    matchers:\n      - type: status\n        status: [200]\n# digest: fixture-signature\n', encoding='utf-8')
        record['inputs'] = {'templates': [{'id': 'fixture-check', 'path': str(template), 'sha256': digest(template), 'reviewed': True, 'signed': True}],
                            'target': {'origin': 'https://fixture.test', 'paths': ['/ok'], 'allowed_ips': ['127.0.0.1']}}
        pair = 'fixture-check@https://fixture.test/ok'
        record['coverage'] = {'eligible': [pair], 'scanned': [pair], 'complete': True}
        certificate = self.root / 'org-signer.pem'
        certificate.write_text('-----BEGIN CERTIFICATE-----\npublic-certificate-fixture\n-----END CERTIFICATE-----\n', encoding='ascii')
        self.policy['template_signers'] = {'org-security': digest(certificate)}
        signature = {'id': 'verified-fixture-template-signature', 'template_sha256': digest(template), 'status': 'verified',
                     'signer_id': 'org-security', 'certificate': {'path': str(certificate), 'sha256': digest(certificate)},
                     'verification_evidence_refs': ['protected-signature-verifier/fixture'], 'expires_at': '2999-01-01T00:00:00Z'}
        record['inputs']['templates'][0]['signature_verification'] = signature
        self.approve(signature, 'template-signature', ('protected-ci', 'security-owner'))
        confinement = {'id': 'nuclei-confinement', 'status': 'verified', 'source_revision': self.inventory['revision'],
                       'scope_hash': self.inventory['scope_hash'], 'scope': record['inputs']['target'],
                       'engine_digest': record['engine']['digest'], 'expires_at': '2999-01-01T00:00:00Z',
                       'process_tree': True, 'network': 'exact-scope', 'filesystem': 'source-read-only',
                       'firewall_evidence_refs': ['firewall-fixture'], 'broker_evidence_refs': ['broker-fixture'], **self.quotas()}
        record['confinement'] = confinement
        self.approve(confinement, 'network-confinement', ('protected-ci', 'security-owner'))
        self.approve(record)
        return record

    def test_nuclei_native_jsonl_scope_redaction_and_clean_attestation(self):
        row = {'template-id': 'fixture-check', 'type': 'http', 'matched-at': 'https://fixture.test/ok',
               'info': {'name': 'Fixture', 'severity': 'low'}, 'request': 'Authorization: Bearer fixture-secret',
               'response': 'secret=fixture-secret'}
        self.nuclei(json.dumps(row) + '\n')
        checks, findings = self.run_optional()
        self.assertEqual(checks[0]['status'], 'complete')
        self.assertEqual(findings[0]['locations'][0]['url'], 'https://fixture.test/ok')
        self.assertNotIn('fixture-secret', json.dumps([checks, findings]))
        self.nuclei('')
        self.assertEqual(self.run_optional()[0][0]['status'], 'complete')

    def test_nuclei_refuses_unreviewed_unsafe_templates_and_missing_confinement(self):
        record = self.nuclei()
        record.pop('confinement'); self.approve(record)
        self.assertEqual(self.run_optional()[0][0]['status'], 'incomplete')
        record = self.nuclei()
        template = Path(record['inputs']['templates'][0]['path'])
        template.write_text('id: fixture-check\ncode:\n  - engine: [sh]\n    source: echo unsafe\n# digest: fixture\n', encoding='utf-8')
        record['inputs']['templates'][0]['sha256'] = digest(template); self.approve(record)
        self.assertEqual(self.run_optional()[0][0]['status'], 'incomplete')

    def load_runner(self):
        path = Path(__file__).resolve().parents[1] / 'scripts/gxsec-optional-runner.py'
        self.assertTrue(path.is_file(), 'Reference optional runner is missing')
        spec = importlib.util.spec_from_file_location('optional_runner', path)
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        return runner

    def plan(self, engine='trivy'):
        record = self.evidence(engine, self.sarif() if engine == 'codeql' else self.trivy()) if engine != 'nuclei' else self.nuclei()
        record.pop('artifact')
        runtime = self.runtime(engine + '-runtime')
        record['inputs']['runtime'] = runtime
        executable = Path(runtime['path']) / runtime['entrypoint']
        record['engine'].update(executable=str(executable), digest='sha256:' + digest(executable))
        runner_runtime = self.runtime('runner-runtime')
        record['runner'] = {'path': str(Path(runner_runtime['path']) / runner_runtime['entrypoint']),
                            'sha256': runner_runtime['files'][runner_runtime['entrypoint']], 'runtime': runner_runtime}
        target = record['inputs'].get('target', {})
        record['confinement'] = {'id': engine + '-confinement', 'status': 'verified', 'scope': target,
            'source_revision': self.inventory['revision'], 'scope_hash': self.inventory['scope_hash'],
            'engine_digest': record['engine']['digest'], 'runner_digest': record['runner']['sha256'],
            'expires_at': '2999-01-01T00:00:00Z', 'process_tree': True, 'filesystem': 'source-read-only',
            'network': 'exact-scope' if engine == 'nuclei' else 'deny-all',
            'firewall_evidence_refs': ['firewall-fixture'], 'broker_evidence_refs': ['broker-fixture'],
            'runtime_digests': {'engine': runtime['sha256'], 'runner': runner_runtime['sha256']}, **self.quotas()}
        if engine == 'codeql':
            record['confinement']['runtime_digests']['query_packs'] = record['inputs']['query_packs']['sha256']
        record['timeout_seconds'] = 30
        self.policy['optional'][engine] = {'enabled': True, 'required': True, 'plan': record}
        self.approve(record['confinement'], 'network-confinement', ('protected-ci', 'security-owner'))
        self.approve(record, 'scanner-plan', ('protected-ci', 'security-owner'))
        return record

    def test_confined_plan_executes_only_digest_pinned_runner_with_bounded_environment(self):
        from gxsec.optional import run_optional_checks
        record = self.plan()

        def child(command, **kwargs):
            self.assertNotEqual(command[0], record['runner']['path'])
            self.assertEqual(digest(command[0]), record['runner']['sha256'])
            self.assertEqual(kwargs['timeout'], 30)
            self.assertNotIn('GXSEC_FIXTURE_SECRET', kwargs['environment'])
            plan = json.loads(Path(command[2]).read_text(encoding='utf-8'))
            result = {'engine': plan['engine'], 'plan_digest': content_hash(plan), 'execution_status': 'complete',
                      'source_revision': plan['source_revision'], 'source_hash': plan['source_hash'], 'scope_hash': plan['scope_hash'],
                      'coverage': plan['coverage'], 'confinement_record_id': plan['confinement']['id'],
                      'native_report': self.trivy()}
            Path(command[4]).write_text(json.dumps(result), encoding='utf-8')
            return subprocess.CompletedProcess(command, 0)

        with patch('gxsec.optional._bounded_process', side_effect=child), patch.dict('os.environ', {'GXSEC_FIXTURE_SECRET': 'do-not-forward'}):
            checks, findings = run_optional_checks(self.source, self.config, 'release')
        self.assertEqual(checks[0]['status'], 'complete')
        self.assertEqual(findings, [])

    def test_runner_actual_trivy_command_is_offline_and_uses_existing_input(self):
        runner = self.load_runner()
        plan = self.runner_plan()

        def child(command, **kwargs):
            if '--version' in command:
                (Path(plan['inputs']['database']['path']) / 'db/trivy.db').write_text('changed original after snapshot', encoding='utf-8')
                return self.complete_child(command, kwargs, stdout='Version: 0.69.0')
            self.assertEqual(command[1], 'filesystem')
            for flag in ('--offline-scan', '--skip-db-update', '--skip-java-db-update', '--skip-version-check'):
                self.assertIn(flag, command)
            self.assertEqual(command[-1], str(self.source / 'app.py'))
            snapshot_db = Path(command[command.index('--cache-dir') + 1])
            self.assertNotEqual(str(snapshot_db), plan['inputs']['database']['path'])
            self.assertEqual((snapshot_db / 'db/trivy.db').read_text(encoding='utf-8'), 'fixture db')
            Path(command[command.index('--output') + 1]).write_text(json.dumps(self.trivy()), encoding='utf-8')
            return self.complete_child(command, kwargs)

        with patch.object(runner, '_bounded_process', side_effect=child):
            result = runner.execute_plan(plan)
        self.assertEqual(result['execution_status'], 'complete')
        self.assertEqual(result['coverage']['scanned'], ['app.py'])

    def test_runner_codeql_uses_only_prebuilt_database_and_local_queries(self):
        runner = self.load_runner()
        plan = self.runner_plan('codeql')

        def child(command, **kwargs):
            if command[1] == 'version':
                (Path(plan['inputs']['query_packs']['path']) / 'python-all/qlpack.yml').write_text('changed original after snapshot', encoding='utf-8')
                return self.complete_child(command, kwargs, stdout='{"version":"2.24.0"}')
            self.assertEqual(command[1:3], ['database', 'analyze'])
            self.assertIn('--no-download', command)
            self.assertIn('--no-database-extension-packs', command)
            self.assertNotIn('create', command)
            self.assertNotIn('--command', command)
            self.assertNotEqual(command[0], plan['engine']['executable'])
            self.assertEqual(digest(command[0]), plan['engine']['digest'][7:])
            packs = Path(next(x.split('=', 1)[1] for x in command if x.startswith('--search-path=')))
            self.assertNotEqual(str(packs), plan['inputs']['query_packs']['path'])
            self.assertEqual((packs / 'python-all/qlpack.yml').read_text(encoding='utf-8'), 'name: codeql/python-all\nversion: 1.0.0\n')
            self.assertTrue(any(x.startswith('--max-disk-cache=') for x in command))
            output = next(x.split('=', 1)[1] for x in command if x.startswith('--output='))
            Path(output).write_text(json.dumps(self.sarif()), encoding='utf-8')
            return self.complete_child(command, kwargs)

        with patch.object(runner, '_bounded_process', side_effect=child):
            self.assertEqual(runner.execute_plan(plan)['execution_status'], 'complete')

    def test_runner_nuclei_requires_positive_native_completion_counters(self):
        runner = self.load_runner()
        plan = self.runner_plan('nuclei')

        def child(command, **kwargs):
            if '-version' in command:
                return self.complete_child(command, kwargs, stdout='Nuclei Engine Version: v3.7.0')
            for flag in ('-dut', '-duc', '-ni', '-dr', '-no-httpx', '-omit-raw', '-jsonl'):
                self.assertIn(flag, command)
            expected_cert = plan['inputs']['templates'][0]['signature_verification']['certificate']['sha256']
            self.assertEqual(hashlib.sha256(kwargs['environment']['NUCLEI_USER_CERTIFICATE'].encode('ascii')).hexdigest(), expected_cert)
            template = Path(command[command.index('-templates') + 1])
            self.assertNotEqual(str(template), plan['inputs']['templates'][0]['path'])
            self.assertEqual(digest(template), plan['inputs']['templates'][0]['sha256'])
            self.assertNotIn('-headless', command)
            Path(command[command.index('-output') + 1]).write_text('', encoding='utf-8')
            return self.complete_child(command, kwargs, stderr='{"templates":"1","hosts":"1","requests":"1","total":"1","errors":"0","percent":"100"}\n')

        with patch.object(runner, '_bounded_process', side_effect=child):
            self.assertEqual(runner.execute_plan(plan)['execution_status'], 'complete')

        def no_evidence(command, **kwargs):
            if '-version' in command:
                return self.complete_child(command, kwargs, stdout='Nuclei Engine Version: v3.7.0')
            Path(command[command.index('-output') + 1]).write_text('', encoding='utf-8')
            return self.complete_child(command, kwargs)

        with patch.object(runner, '_bounded_process', side_effect=no_evidence), self.assertRaises(ValueError):
            runner.execute_plan(plan)

    def test_runner_changed_digest_and_unbounded_timeout_prevent_scanner_launch(self):
        runner = self.load_runner()
        plan = self.runner_plan()
        plan['engine']['digest'] = 'sha256:' + '0' * 64
        with patch.object(runner, '_bounded_process') as child, self.assertRaises(ValueError):
            runner.execute_plan(plan)
        child.assert_not_called()
        plan = {**self.runner_plan(), 'timeout_seconds': 100000}
        with patch.object(runner, '_bounded_process') as child, self.assertRaises(ValueError):
            runner.execute_plan(plan)
        child.assert_not_called()

    def runner_plan(self, name='trivy'):
        record = self.plan(name)
        return {**record, 'source': str(self.source), 'approval_context': {
            'source_revision': self.policy['source_revision'], 'scope_hash': self.policy['scope_hash'],
            'trusted_approvals': copy.deepcopy(self.policy['trusted_approvals']),
            'template_signers': copy.deepcopy(self.policy.get('template_signers', {}))}}

    def complete_child(self, command, kwargs, stdout='', stderr=''):
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr=stderr)

    def test_org_required_selection_cannot_be_disabled_by_project(self):
        self.policy['optional']['trivy'] = {'required': True}
        self.config['tools']['trivy'] = {'enabled': False, 'required': False}
        checks, _ = self.run_optional()
        self.assertEqual(len(checks), 1)
        self.assertTrue(checks[0]['required'])
        self.assertEqual(checks[0]['status'], 'unsupported')

    def test_codeql_empty_rule_execution_is_incomplete(self):
        report = self.sarif()
        report['runs'][0]['tool']['driver']['rules'] = []
        self.evidence('codeql', report)
        self.assertEqual(self.run_optional()[0][0]['status'], 'incomplete')

    def test_nuclei_never_exports_native_request_response_fields(self):
        runner = self.load_runner()
        plan = self.runner_plan('nuclei')

        def child(command, **kwargs):
            if '-version' in command:
                return self.complete_child(command, kwargs, stdout='Nuclei Engine Version: v3.7.0')
            row = {'template-id': 'fixture-check', 'type': 'http', 'matched-at': 'https://fixture.test/ok',
                   'info': {'name': 'Fixture', 'severity': 'low'}, 'response': 'unstructured-private-data',
                   'request': 'Cookie: private-session', 'extracted-results': ['sensitive-capture']}
            Path(command[command.index('-output') + 1]).write_text(json.dumps(row), encoding='utf-8')
            return self.complete_child(command, kwargs, stderr='{"templates":"1","hosts":"1","requests":"1","total":"1","errors":"0","percent":"100"}\n')

        with patch.object(runner, '_bounded_process', side_effect=child):
            result = runner.execute_plan(plan)
        self.assertNotIn('unstructured-private-data', json.dumps(result))
        self.assertNotIn('private-session', json.dumps(result))
        self.assertNotIn('sensitive-capture', json.dumps(result))

    def test_native_report_byte_swap_cannot_replace_verified_finding_with_clean_report(self):
        import gxsec.optional as optional
        self.evidence('trivy', self.trivy([{'Target': 'app.py', 'Class': 'lang-pkgs', 'Vulnerabilities': [{
            'VulnerabilityID': 'CVE-fixture', 'PkgName': 'fixture', 'Severity': 'HIGH'}]}]))
        original = optional._sha256

        def swap(path):
            hashed = original(path)
            if Path(path).name == 'trivy.json':
                Path(path).write_text(json.dumps(self.trivy()), encoding='utf-8')
            return hashed

        with patch.object(optional, '_sha256', side_effect=swap):
            checks, findings = self.run_optional()
        self.assertTrue(checks[0]['status'] != 'complete' or findings,
                        'A report reopened after hashing silently replaced verified vulnerability bytes')

    def test_nuclei_comment_and_signed_boolean_do_not_prove_template_signature(self):
        record = self.nuclei('')
        record['inputs']['templates'][0].pop('signature_verification', None)
        self.approve(record)
        self.assertEqual(self.run_optional()[0][0]['status'], 'incomplete')

    def test_codeql_requires_complete_distribution_and_resolved_query_pack_manifests(self):
        record = self.evidence('codeql', self.sarif())
        record['inputs'].pop('runtime', None)
        record['inputs'].pop('query_packs', None)
        self.approve(record)
        self.assertEqual(self.run_optional()[0][0]['status'], 'incomplete')

    def test_confined_plan_without_numeric_enforced_host_quotas_does_not_launch(self):
        record = self.plan()
        record['confinement'].pop('limits', None)
        self.approve(record['confinement'], 'network-confinement', ('protected-ci', 'security-owner'))
        self.approve(record, 'scanner-plan', ('protected-ci', 'security-owner'))
        with patch('gxsec.optional._bounded_process') as launch:
            checks, _ = self.run_optional()
        launch.assert_not_called()
        self.assertEqual(checks[0]['status'], 'incomplete')

    def test_streaming_output_quota_kills_a_noisy_child_before_unbounded_capture(self):
        import gxsec.optional as optional
        self.assertTrue(hasattr(optional, '_bounded_process'), 'Streaming subprocess quota is missing')
        with self.assertRaisesRegex(ValueError, 'quota'):
            optional._bounded_process([sys.executable, '-c', 'import sys;sys.stdout.buffer.write(b"x"*1048576)'],
                cwd=str(self.root), environment={k: v for k, v in os.environ.items() if k.upper() == 'SYSTEMROOT'}, timeout=5, maximum=1024)


    def source_identity(self):
        return {'origin_source': str(self.source), 'source_hash': self.inventory['hash'],
                'source_revision': self.inventory['revision'], 'scope_hash': self.inventory['scope_hash'],
                'file_hashes': {row['path']: row['hash'] for row in self.inventory['inventory']}}

    def test_relocation_scope_includes_current_exclusions_and_module_layout(self):
        from gxsec.optional import execution_inventory, source_identity
        from gxsec.snapshot import verified_snapshot
        (self.source / 'package.json').write_text('{}', encoding='utf-8')
        module = self.source / 'backend'
        module.mkdir()
        (module / 'pom.xml').write_text('<project/>', encoding='utf-8')
        inventory = collect_source(self.source)
        identity = source_identity(inventory, self.source)
        self.assertEqual(identity.get('exclusion_contract'), inventory['exclusion_contract'])
        self.assertIsNot(identity['exclusion_contract'], inventory['exclusion_contract'])
        with verified_snapshot(self.source, inventory) as snap:
            rebound, actual = execution_inventory(snap.path, identity)
            self.assertEqual(rebound['scope_hash'], inventory['scope_hash'])
            self.assertEqual(rebound['modules'], inventory['modules'])
            self.assertNotEqual(actual['scope_hash'], inventory['scope_hash'])

    def test_relocation_rejects_forged_or_obsolete_scope_even_when_bytes_match(self):
        from gxsec.optional import execution_inventory
        from gxsec.snapshot import verified_snapshot
        from gxsec.source import EXCLUDED_DIRS
        base = {'root': str(self.source).casefold(), 'scope': 'full',
                'exclude': sorted(EXCLUDED_DIRS), 'modules': {}}
        obsolete_contract = copy.deepcopy(self.inventory['exclusion_contract'])
        obsolete_contract['relative_directory_paths'] = []
        scopes = {
            'forged': '0' * 64,
            'before-exclusion-contract': content_hash(base),
            'obsolete-exclusions': content_hash({**base, 'exclusion_contract': obsolete_contract}),
        }
        with verified_snapshot(self.source, self.inventory) as snap:
            for label, scope in scopes.items():
                with self.subTest(label=label), self.assertRaisesRegex(ValueError, 'scope does not derive'):
                    execution_inventory(snap.path, {**self.source_identity(), 'scope_hash': scope})

    def test_relocation_rejects_foreign_path_case_semantics(self):
        from gxsec.optional import execution_inventory
        from gxsec.snapshot import verified_snapshot
        from gxsec.source import EXCLUDED_DIRS
        contract = copy.deepcopy(self.inventory['exclusion_contract'])
        contract['case_sensitive_paths'] = not contract['case_sensitive_paths']
        foreign_scope = content_hash({'root': str(self.source).casefold(), 'scope': 'full',
            'exclude': sorted(EXCLUDED_DIRS), 'modules': {}, 'exclusion_contract': contract})
        with verified_snapshot(self.source, self.inventory) as snap:
            # A foreign contract is never authority, even with a current scope copied beside it.
            for scope in (foreign_scope, self.inventory['scope_hash']):
                with self.subTest(scope=scope), self.assertRaisesRegex(ValueError, 'exclusion contract differs'):
                    execution_inventory(snap.path, {**self.source_identity(), 'scope_hash': scope,
                                                    'exclusion_contract': contract})

    def test_imported_evidence_accepts_verified_relocation_and_original_native_paths(self):
        from gxsec.optional import run_optional_checks
        from gxsec.snapshot import verified_snapshot
        self.evidence('trivy', self.trivy([{'Target': str(self.source / 'app.py'), 'Class': 'lang-pkgs',
            'Vulnerabilities': [{'VulnerabilityID': 'CVE-fixture', 'PkgName': 'fixture', 'Severity': 'HIGH'}]}]))
        with verified_snapshot(self.source, self.inventory) as snap:
            config = {**self.config, '_inventory': self.inventory, '_source_boundary': self.source,
                      '_snapshot_object': snap, '_snapshot_provenance': snap.provenance}
            checks, findings = run_optional_checks(snap.path, config, 'release')
            self.assertEqual(checks[0]['status'], 'complete', checks)
            self.assertEqual(findings[0]['locations'][0]['path'], 'app.py')
            self.assertTrue(snap.verify())

    def test_relocation_never_trusts_an_artifact_inside_original_source(self):
        import gxsec.optional as optional
        from gxsec.snapshot import verified_snapshot
        self.evidence('trivy', self.trivy())
        with verified_snapshot(self.source, self.inventory) as snap:
            config = {**self.config, '_inventory': self.inventory, '_source_boundary': self.source,
                      '_snapshot_object': snap, '_snapshot_provenance': snap.provenance}
            original = optional._record
            boundaries = []
            def validate(record, policy, boundary, inventory, name, **kwargs):
                boundaries.append(boundary)
                return original(record, policy, boundary, inventory, name, **kwargs)
            with patch.object(optional, '_record', side_effect=validate):
                optional.run_optional_checks(snap.path, config, 'release')
            self.assertEqual(boundaries, [self.source])
        record = self.policy['optional']['trivy']['evidence']
        path = self.source / 'project-claim.json';path.write_text(json.dumps(self.trivy()), encoding='utf-8')
        self.inventory = collect_source(self.source)
        self.policy.update(source_revision=self.inventory['revision'], scope_hash=self.inventory['scope_hash'])
        record.update(source_hash=self.inventory['hash'], source_revision=self.inventory['revision'], scope_hash=self.inventory['scope_hash'],
                      artifact={'path': str(path), 'sha256': digest(path)})
        self.approve(record)
        with verified_snapshot(self.source, self.inventory) as snap:
            checks, _ = optional.run_optional_checks(snap.path, {**self.config, '_inventory': self.inventory,
                '_source_boundary': self.source, '_snapshot_object': snap}, 'release')
            self.assertEqual(checks[0]['status'], 'incomplete')

    def test_reference_runner_binds_original_identity_only_after_copy_byte_verification(self):
        from gxsec.snapshot import verified_snapshot
        runner = self.load_runner();plan = self.runner_plan()
        with verified_snapshot(self.source, self.inventory) as snap:
            plan.update(source=str(snap.path), source_identity=self.source_identity())
            def child(command, **kwargs):
                if '--version' in command:
                    return self.complete_child(command, kwargs, stdout='Version: 0.69.0')
                self.assertEqual(command[-1], str((snap.path / 'app.py').resolve()))
                self.assertEqual((snap.path / 'app.py').read_text(), 'print("fixture")\n')
                Path(command[command.index('--output') + 1]).write_text(json.dumps(self.trivy()), encoding='utf-8')
                return self.complete_child(command, kwargs)
            with patch.object(runner, '_bounded_process', side_effect=child):
                result = runner.execute_plan(plan)
            self.assertEqual(result['source_hash'], self.inventory['hash'])
            self.assertEqual(result['scope_hash'], self.inventory['scope_hash'])
            changed = snap.path / 'app.py';changed.chmod(0o600);changed.write_text('changed private copy')
            with patch.object(runner, '_bounded_process') as launch, self.assertRaises(ValueError):
                runner.execute_plan(plan)
            launch.assert_not_called()

    def test_static_adapter_invokes_selected_optional_engine_on_its_private_snapshot(self):
        from gxsec import adapters
        self.evidence('trivy', self.trivy())
        seen=[]
        def optional(copy_path, config, profile):
            seen.append((copy_path, config['_source_boundary']))
            self.assertNotEqual(copy_path, self.source)
            self.assertEqual(config['_inventory']['hash'], self.inventory['hash'])
            return [{'id':'trivy','required':True,'status':'complete','errors':[],
                     'coverage':{'eligible':1,'scanned':1,'scope':'full'},'engine':{}}], []
        with patch('gxsec.optional.run_optional_checks', side_effect=optional):
            checks, _ = adapters.run_static_checks(self.source, {**self.config, '_inventory': self.inventory}, 'check')
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0][1], self.source)
        self.assertEqual(next(c for c in checks if c['id']=='trivy')['status'], 'complete')
        self.assertTrue(all(c['snapshot']['stable_after_scan'] for c in checks))


    def test_normalized_optional_findings_omit_unstructured_native_messages(self):
        self.evidence('codeql', self.sarif([{'ruleId':'py/test','message':{'text':'fixture-sensitive-literal'},
            'locations':[{'physicalLocation':{'artifactLocation':{'uri':'app.py'},'region':{'startLine':1}}}]}]))
        checks, findings = self.run_optional()
        self.assertEqual(checks[0]['status'], 'complete')
        self.assertNotIn('fixture-sensitive-literal', json.dumps([checks,findings]))
        self.evidence('trivy', self.trivy([{'Target':'app.py','Class':'lang-pkgs','Vulnerabilities':[{
            'VulnerabilityID':'CVE-fixture','PkgName':'fixture','Severity':'HIGH',
            'Title':'fixture-sensitive-literal','Description':'fixture-sensitive-literal'}]}]))
        checks, findings = self.run_optional()
        self.assertEqual(checks[0]['status'], 'complete')
        self.assertNotIn('fixture-sensitive-literal', json.dumps([checks,findings]))
        self.nuclei(json.dumps({'template-id':'fixture-check','type':'http','matched-at':'https://fixture.test/ok',
            'info':{'name':'fixture-sensitive-literal','severity':'low'}}) + '\n')
        checks, findings = self.run_optional()
        self.assertTrue(all(check['status']=='complete' for check in checks))
        self.assertNotIn('fixture-sensitive-literal', json.dumps([checks,findings]))


if __name__ == '__main__':
    unittest.main()
