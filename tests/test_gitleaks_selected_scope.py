"""Directory-only history exclusions; the bundled runtime also runs the real engine."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from gxsec import adapters, config, source, state
from gxsec.models import content_hash, make_check, make_finding
from gxsec.snapshot import verified_snapshot


def inventory(paths=(), *, case_sensitive=True):
    return {'files': ['app.py'], 'scope_hash': 'unchanged-tree-scope', 'errors': [],
            'exclusions': [], 'exclusion_contract': {
                'selected_directory_paths': list(paths), 'case_sensitive_paths': case_sensitive}}


class SelectedHistoryScopeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='gxsec-scope-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'app.py').write_text('value = 1\n', encoding='utf-8')

    def scan(self, inv, *, history=True, history_status='complete', result_code=0, project_options=None):
        captured = []

        def probe(name, options, target, check, **kwargs):
            check['engine'] = {'name': name, 'version': '8.30.1', 'available': True}
            return 'approved-gitleaks'

        def execute(command, **kwargs):
            cfg = Path(command[command.index('--config') + 1]).read_bytes()
            captured.append((command, cfg, kwargs))
            Path(command[command.index('--report-path') + 1]).write_text('[]', encoding='utf-8')
            return subprocess.CompletedProcess(command, result_code, '', '')

        cfg = {'tools': {'gitleaks': project_options or {}}, '_snapshot_provenance': {'history': {
            'required': history, 'status': history_status if history else 'not_applicable'}}}
        with patch.object(adapters, '_probe', probe), patch.object(adapters, '_run', execute), \
                patch.object(adapters, '_local_hmac_key', return_value=b'synthetic-test-key'), \
                patch.object(adapters, 'trusted_runtime_tool', return_value={'executable': 'approved-git'}):
            checked, findings = adapters._secrets(self.root, cfg, inv, 'check')
        self.assertEqual(findings, [])
        return checked, captured

    def test_default_rules_remain_enabled_without_an_allowlist(self):
        checked, calls = self.scan(inventory())
        self.assertEqual(checked['status'], 'complete')
        self.assertEqual(tomllib.loads(calls[0][1].decode()), {'extend': {'useDefault': True}})
        self.assertEqual(checked['coverage']['history_scope']['selected_directory_paths'], [])
        self.assertEqual(checked['coverage']['history_scope_hash'],
                         content_hash(checked['coverage']['history_scope']))
        self.assertEqual(checked['engine']['rules_hash'], hashlib.sha256(calls[0][1]).hexdigest())

    def test_only_selected_relative_directory_descendants_are_allowed(self):
        checked, calls = self.scan(inventory(['docs/design']))
        self.assertEqual(checked['status'], 'complete')
        self.assertEqual({call[0][1] for call in calls}, {'dir', 'git'})
        self.assertEqual(calls[0][1], calls[1][1])
        document = tomllib.loads(calls[0][1].decode())
        self.assertEqual(document['extend'], {'useDefault': True})
        self.assertEqual(len(document['allowlists']), 1)
        allowlist = document['allowlists'][0]
        self.assertEqual(set(allowlist), {'description', 'condition', 'paths'})
        self.assertEqual(allowlist['condition'], 'OR')
        self.assertEqual(allowlist['paths'], ['^docs/design/'])
        for path, expected in [('docs/design/file.env', True), ('docs/design/sub/file.env', True),
                               ('docs/design', False), ('docs/design-copy/file.env', False),
                               ('nested/docs/design/file.env', False), ('Docs/design/file.env', False)]:
            with self.subTest(path=path):
                self.assertEqual(bool(re.search(allowlist['paths'][0], path)), expected)
        git_args = next(call[0] for call in calls if call[0][1] == 'git')
        self.assertIn('--log-opts=--all --full-history --no-show-signature --no-ext-diff --no-textconv', git_args)
        self.assertTrue(checked['coverage']['history_complete'])
        self.assertEqual(checked['engine']['rules_hash'], hashlib.sha256(calls[0][1]).hexdigest())

    def test_regex_and_toml_metacharacters_are_literal(self):
        relative = 'docs/시안 .+(v1){x}|$^\"\'\x7f'
        checked, calls = self.scan(inventory([relative]))
        self.assertEqual(checked['status'], 'complete')
        document = tomllib.loads(calls[0][1].decode())
        expressions = document['allowlists'][0]['paths']
        self.assertEqual(len(expressions), 1)
        self.assertIsNotNone(re.search(expressions[0], relative + '/file.env'))
        for outside in [relative, 'nested/' + relative + '/file.env', 'docs/arbitrary/file.env']:
            self.assertIsNone(re.search(expressions[0], outside))
        self.assertEqual(set(document), {'extend', 'allowlists'})

    def test_normalized_selection_is_stable_when_the_directory_is_absent_today(self):
        first, calls1 = self.scan(inventory(['outputs', 'docs/design', 'outputs']))
        second, calls2 = self.scan(inventory(['docs/design', 'outputs']))
        self.assertEqual(first['coverage']['history_scope'], second['coverage']['history_scope'])
        self.assertEqual(first['coverage']['history_scope']['selected_directory_paths'], ['docs/design', 'outputs'])
        self.assertEqual(calls1[0][1], calls2[0][1])
        self.assertEqual(first['engine']['rules_hash'], second['engine']['rules_hash'])
        self.assertFalse((self.root / 'docs').exists())

    def test_raw_project_configuration_cannot_add_allowlists(self):
        (self.root / '.gitleaks.toml').write_text('[allowlist]\npaths = [".*"]\n', encoding='utf-8')
        (self.root / '.gitleaksignore').write_text('*\n', encoding='utf-8')
        checked, calls = self.scan(inventory(['docs/design']), project_options={
            'config': str(self.root / '.gitleaks.toml'), 'allowlists': [{'paths': ['.*']}],
            'selected_directory_paths': ['app.py']})
        self.assertEqual(checked['status'], 'complete')
        self.assertEqual(tomllib.loads(calls[0][1].decode())['allowlists'][0]['paths'], ['^docs/design/'])
        for args, _, _ in calls:
            self.assertNotEqual(Path(args[args.index('--config') + 1]), self.root / '.gitleaks.toml')
            self.assertIn('--ignore-gitleaks-allow', args)
            self.assertIn('--redact=100', args)

    def test_invalid_selection_fails_closed_without_executing_an_engine(self):
        for invalid in ['../outside', '/absolute', 'docs\\design', 'docs/*', '.git',
                        'docs//design', 'docs/..', 'docs/\npaths = [".*"]', 1]:
            with self.subTest(path=invalid):
                checked, calls = self.scan(inventory([invalid]))
                self.assertEqual(checked['status'], 'incomplete')
                self.assertEqual(calls, [])
                self.assertTrue(any(item['type'] == 'invalid_history_scope' for item in checked['errors']))
        for malformed in [None, [], 'untrusted']:
            with self.subTest(contract=malformed):
                inv = inventory()
                inv['exclusion_contract'] = malformed
                checked, calls = self.scan(inv)
                self.assertEqual(checked['status'], 'incomplete')
                self.assertEqual(calls, [])

    def test_case_insensitive_selection_is_explicitly_unsupported_without_broadening(self):
        checked, calls = self.scan(inventory(['docs/design'], case_sensitive=False))
        self.assertEqual(checked['status'], 'incomplete')
        self.assertEqual(calls, [])
        self.assertEqual(checked['coverage']['history_scope']['selected_directory_paths'], ['docs/design'])
        self.assertTrue(any(item['type'] == 'unsupported_history_scope' for item in checked['errors']))
        default, default_calls = self.scan(inventory(case_sensitive=False))
        self.assertEqual(default['status'], 'complete')
        self.assertEqual(len(default_calls), 2)

    def test_engine_failure_and_missing_history_cannot_be_waived_by_scope(self):
        failed, _ = self.scan(inventory(['docs/design']), result_code=2)
        self.assertEqual(failed['status'], 'incomplete')
        self.assertEqual(failed['coverage']['scanned'], 0)
        self.assertFalse(failed['coverage']['history_complete'])
        self.assertTrue(failed['errors'])
        missing, calls = self.scan(inventory(['docs/design']), history_status='incomplete')
        self.assertEqual(missing['status'], 'incomplete')
        self.assertEqual(missing['coverage']['scanned'], 1)
        self.assertFalse(missing['coverage']['history_complete'])
        self.assertEqual([call[0][1] for call in calls], ['dir'])
        self.assertTrue(any(item['type'] == 'git_runtime_unverified' for item in missing['errors']))

    def test_excluded_historical_candidate_is_not_reconciled_as_a_fix(self):
        previous_check, _ = self.scan(inventory())
        current_check, _ = self.scan(inventory(['docs/design']))
        finding = make_finding(category='secrets', rule='synthetic-secret',
                               path='docs/design/old.env', severity='High', check_id='secrets')
        old = {'run_id': 'old', 'project_id': 'same-project', 'profile': 'static-release',
               'source': {'source_id': 'same-source', 'scope_hash': 'old-scope'},
               'checks': [previous_check], 'findings': [finding]}
        new = {'run_id': 'new', 'project_id': 'same-project', 'profile': 'static-release',
               'source': {'source_id': 'same-source', 'scope_hash': 'selected-scope'},
               'checks': [current_check], 'findings': []}
        result = state.Store.reconcile(object.__new__(state.Store), new, old)
        carried = result['findings'][0]
        self.assertTrue(carried['carried_forward'])
        self.assertEqual(carried['lifecycle'], 'open')
        self.assertEqual(carried['validation'], 'candidate')
        self.assertNotIn('resolution_evidence', carried)

    def test_rules_hash_changes_the_existing_coverage_signature(self):
        def unrelated(check_id):
            return lambda *args: (make_check(check_id), [])

        signatures = []
        for selected in [[], ['docs/design']]:
            checked, _ = self.scan(inventory(selected))
            cfg = {'_snapshot_object': type('Snapshot', (), {'verify': lambda self: True})()}
            with patch.object(adapters, '_sast', unrelated('sast')), \
                    patch.object(adapters, '_sca', unrelated('sca')), \
                    patch.object(adapters, '_secrets', return_value=(checked, [])), \
                    patch('gxsec.framework.run_framework_check', unrelated('framework')), \
                    patch('gxsec.optional.run_optional_checks', return_value=([], [])), \
                    patch.object(adapters, 'contextualize_findings', side_effect=lambda root, inv, items: items), \
                    patch.object(adapters, 'enrich_framework_findings', side_effect=lambda items, inv: items):
                checks, _ = adapters._run_snapshot_checks(self.root, cfg, inventory(selected), 'static-release')
            signatures.append(next(item['coverage']['signature'] for item in checks if item['id'] == 'secrets'))
        self.assertNotEqual(*signatures)


@unittest.skipUnless(os.environ.get('GXSEC_RUNTIME_MANIFEST'), 'Requires the pinned bundled runtime')
class RealGitleaksSelectedHistoryTests(unittest.TestCase):
    def test_deleted_selected_history_is_omitted_but_lookalikes_and_regular_files_remain(self):
        with tempfile.TemporaryDirectory(prefix='gxsec-real-history-scope-') as directory:
            temporary = Path(directory)
            root = temporary / 'source'
            root.mkdir()
            git = source.trusted_runtime_tool('git', root)['executable']
            environment = source.runtime_environment()
            home = temporary / 'home'
            home.mkdir()
            environment.update(HOME=str(home), USERPROFILE=str(home), GIT_CONFIG_GLOBAL=os.devnull)

            def git_run(*args):
                return subprocess.run([git, '-c', 'core.hooksPath=', '-c', 'core.fsmonitor=false',
                                       '-C', str(root), *args], capture_output=True, check=True,
                                      text=True, env=environment, timeout=30).stdout.strip()

            paths = ['app/active.env', 'docs/design/old.env', 'docs/design-copy/active.env',
                     'nested/docs/design/active.env', 'docs/regular',
                     'docs/design.a+(b)/old.env', 'docs/designXaab/active.env']
            for index, relative in enumerate(paths):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                # Deliberately synthetic, never used as a credential or sent to a service.
                value = 'ghp_' + hashlib.sha256(('gxsec-owned-fixture-' + str(index)).encode()).hexdigest()[:36]
                path.write_text('api_token = "' + value + '"\n', encoding='utf-8')
            (root / '.gitleaks.toml').write_text('[allowlist]\npaths = [".*"]\n', encoding='utf-8')
            (root / '.gitleaksignore').write_text('*\n', encoding='utf-8')
            git_run('init', '--initial-branch=main')
            git_run('add', '--all')
            git_run('-c', 'user.name=GX Security Synthetic Test', '-c', 'user.email=synthetic@example.invalid',
                    'commit', '-m', 'Owned synthetic history fixtures')
            for relative in ['docs/design/old.env', 'docs/design.a+(b)/old.env']:
                (root / relative).unlink()
            git_run('add', '--all')
            git_run('-c', 'user.name=GX Security Synthetic Test', '-c', 'user.email=synthetic@example.invalid',
                    'commit', '-m', 'Delete selected prototype files from current tree')
            refs_before = git_run('show-ref', '--head')
            outcomes = []
            for selection in [[], ['docs/design', 'docs/design.a+(b)', 'docs/regular']]:
                with source.selected_paths(selection):
                    collected = source.collect_source(root)
                    self.assertTrue(collected['inventory_complete'])
                    with verified_snapshot(root, collected) as snapshot:
                        self.assertEqual(snapshot.provenance['history']['status'], 'complete')
                        cfg = config.default_config(root)
                        cfg.update(_source_boundary=root, _state_dir=temporary / 'state',
                                   _snapshot_provenance=snapshot.provenance)
                        checked, findings = adapters._secrets(snapshot.path, cfg, collected, 'static-release')
                        self.assertTrue(snapshot.verify())
                self.assertEqual(checked['status'], 'complete', checked['errors'])
                self.assertEqual(checked['engine']['version'], '8.30.1')
                self.assertEqual(checked['coverage']['scanned'], 2)
                self.assertTrue(checked['coverage']['history_complete'])
                self.assertTrue(all(item['validation'] == 'candidate' for item in findings))
                outcomes.append((checked, {item['locations'][0]['path'] for item in findings}))
            before, after = outcomes
            self.assertTrue(set(paths).issubset(before[1]))
            self.assertEqual(after[1], before[1] - {'docs/design/old.env', 'docs/design.a+(b)/old.env'})
            self.assertIn('docs/regular', after[1])
            self.assertNotEqual(before[0]['engine']['rules_hash'], after[0]['engine']['rules_hash'])
            self.assertEqual(refs_before, git_run('show-ref', '--head'))


if __name__ == '__main__':
    unittest.main()
