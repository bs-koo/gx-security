"""SEF context is evidence, never a source of approval authority."""
import copy
import hashlib
import json
from pathlib import Path

import pytest

from gxsec import adapters, config, models, policy
from gxsec.reporting import write_reports


def _run():
    finding = models.make_finding(category='access-control', rule='SEF-ADM-01',
        path='src/Admin.java', line=3, severity='High', check_id='framework',
        title='관리자 권한 경계 검토', description='Administrator guard needs review.',
        review_required=True)
    finding['normalized_result_hash'] = models.content_hash(finding)
    finding['context'] = {'schema_version': 1, 'analyzer': 'context-test/1',
        'classification': 'admin-boundary', 'proposal': 'needs_review',
        'evidence_for': [{'path': 'src/Admin.java', 'line': 3, 'hash': 'a' * 64,
                          'reason': 'Authentication without a proven administrator predicate.'}],
        'evidence_against': [], 'unresolved': ['Deployment and effective caller roles.'],
        'instances': [], 'limitations': ['Source-only inspection.'], 'binding_digest': 'b' * 64}
    return {'schema_version': 1, 'run_id': 'sef-test', 'project_id': 'synthetic',
        'profile': 'static-release', 'source': {'revision': 'revision-1', 'hash': 'c' * 64,
            'scope_hash': 'scope-1', 'inventory': [{'path': 'src/Admin.java', 'hash': 'a' * 64},
                                                 {'path': 'src/Caller.java', 'hash': 'd' * 64}]},
        'checks': [models.make_check('framework', status='complete',
            coverage={'eligible': 1, 'scanned': 1, 'scope': 'full'},
            engine={'name': 'sef-contracts', 'version': '1', 'rules_hash': 'e' * 64},
            framework={'family': 'SEF', 'variant': 'private', 'modules': [{'path': '.'}],
                'contracts': [], 'limitations': ['Bounded source model.'],
                'baseline_manifest': [{'path': 'src/Admin.java', 'hash': 'a' * 64}]})],
        'findings': [finding], 'gate': {'status': 'INCOMPLETE', 'incomplete': ['review']},
        'reviews': [], 'exceptions': []}


def test_framework_requirement_cannot_be_removed_by_project(tmp_path):
    path = tmp_path / 'gxsec.yaml'
    path.write_text('schema_version: 1\nproject: {id: example}\nprofiles:\n  static-release:\n    required_checks: []\n', encoding='utf-8')
    loaded = config.load_config(path)
    for name in ('check', 'static-release', 'source-review', 'release'):
        assert 'framework' in loaded['profiles'][name]['required_checks']


def test_builtin_framework_runs_without_external_engines_in_verified_snapshot(tmp_path, monkeypatch):
    (tmp_path / 'App.java').write_text('class App {}', encoding='utf-8')
    monkeypatch.delenv('GXSEC_RUNTIME_MANIFEST', raising=False)
    checks, findings = adapters.run_static_checks(tmp_path, config.default_config(tmp_path), 'static-release')
    framework = next((c for c in checks if c['id'] == 'framework'), None)
    assert framework is not None, 'Built-in framework detection was omitted'
    assert framework['status'] == 'complete'
    assert framework['coverage']['eligible'] == framework['coverage']['scanned'] > 0
    assert framework['snapshot']['copy_verified'] is True
    assert framework['snapshot']['stable_after_scan'] is True
    assert policy.evaluate(checks, findings)['status'] == 'INCOMPLETE'


def test_snapshot_failure_does_not_omit_framework_requirement(tmp_path, monkeypatch):
    (tmp_path / 'App.java').write_text('class App {}', encoding='utf-8')
    def refuse(*args, **kwargs):
        raise ValueError('snapshot refused')
    monkeypatch.setattr(adapters, 'verified_snapshot', refuse)
    checks, _ = adapters.run_static_checks(tmp_path, config.default_config(tmp_path), 'check')
    assert any(c['id'] == 'framework' and c['status'] == 'incomplete' for c in checks)


def test_context_uses_snapshot_and_is_bound_by_final_result_hash(tmp_path, monkeypatch):
    (tmp_path / 'App.java').write_text('class App {}', encoding='utf-8')
    seen = []
    def runner(source, cfg, inventory, profile):
        f = models.make_finding(category='sql', rule='sql-candidate', path='App.java', severity='High', check_id='sast')
        return models.make_check('sast', status='complete', engine={},
            coverage={'eligible': 1, 'scanned': 1, 'files': ['App.java']}), [f]
    def context(source, inventory, findings):
        seen.append(Path(source).resolve())
        result = copy.deepcopy(findings)
        for item in result:
            item['context'] = {'proposal': 'needs_review', 'classification': 'synthetic', 'binding_digest': 'f' * 64}
        return result
    monkeypatch.setattr(adapters, '_sast', runner)
    monkeypatch.setattr(adapters, 'contextualize_findings', context, raising=False)
    checks, findings = adapters.run_static_checks(tmp_path, config.default_config(tmp_path), 'static-release')
    assert seen and seen[0] != tmp_path.resolve()
    finding = next(f for f in findings if f['rule_id'] == 'sql-candidate')
    assert finding['context']['proposal'] == 'needs_review'
    assert finding['normalized_result_hash'] == models.content_hash({k: v for k, v in finding.items() if k != 'normalized_result_hash'})
    assert all(c['snapshot']['stable_after_scan'] for c in checks)


def test_review_packets_preserve_members_and_bind_related_source():
    from gxsec.triage import build_review_packets
    run = _run()
    original = copy.deepcopy(run)
    first = build_review_packets(run)
    assert run == original
    assert first['authority'] == 'proposal-only'
    assert first['packets'][0]['finding_id'] == run['findings'][0]['finding_id']
    assert first['packets'][0]['proposal'] == 'needs_review'
    assert first['packets'][0]['evidence_for']
    changed = copy.deepcopy(run)
    changed['source']['inventory'][1]['hash'] = '1' * 64
    second = build_review_packets(changed)
    assert first['packets'][0]['packet_digest'] != second['packets'][0]['packet_digest']
    assert first['groups'][0]['members'][0]['finding_id'] == run['findings'][0]['finding_id']


def test_framework_baseline_is_protected_comparison_not_approval():
    from gxsec.triage import framework_manifest, compare_framework_baseline
    run = _run()
    baseline = framework_manifest(run)
    assert baseline['authority'] == 'observations-only'
    assert {row['path'] for row in baseline['files']} == {'src/Admin.java', 'src/Caller.java'}
    protected = {'framework_baseline': baseline}
    assert compare_framework_baseline(run, protected)['status'] == 'untrusted'
    protected['trusted_approvals'] = [{'record_id': baseline['id'], 'digest': models.content_hash(baseline),
        'kind': 'framework-baseline', 'roles': ['security-reviewer']}]
    assert compare_framework_baseline(run, protected)['status'] == 'matched'
    changed = copy.deepcopy(run)
    changed['source']['inventory'][1]['hash'] = '2' * 64
    assert compare_framework_baseline(changed, protected)['status'] == 'changed'
    changed['checks'][0]['framework']['variant'] = 'public'
    assert compare_framework_baseline(changed, protected)['status'] == 'incompatible'
    assert run['findings'][0]['validation'] == 'candidate'


@pytest.mark.parametrize('key', ['framework_baseline', 'framework_baselines', 'framework_policy'])
def test_project_cannot_supply_protected_framework_inputs(tmp_path, key):
    p = tmp_path / 'project.json'
    p.write_text(json.dumps({'schema_version': 1, 'project': {'id': 'example'}, key: {'trusted': True}}), encoding='utf-8')
    with pytest.raises(ValueError):
        config.load_config(p)


def test_proposal_cannot_turn_candidate_into_pass():
    run = _run()
    run['findings'][0]['context']['proposal'] = 'not_actionable'
    assert policy.evaluate(run['checks'], run['findings'])['status'] == 'INCOMPLETE'


def test_reports_export_context_and_baseline_without_active_markup(tmp_path):
    run = _run()
    run['findings'][0]['context']['evidence_against'] = [{'reason': '<img src=x onerror=alert(1)>', 'snippet': 'secret raw source'}]
    run['findings'][0]['context']['password'] = 'must-not-leak-context'
    write_reports(run, tmp_path)
    packet_path = tmp_path / 'review-packets.json'
    assert packet_path.is_file()
    packet = json.loads(packet_path.read_text(encoding='utf-8'))
    assert packet['packets'][0]['finding_id'] == run['findings'][0]['finding_id']
    assert (tmp_path / 'framework-baseline.json').is_file()
    all_text = '\n'.join(p.read_text(encoding='utf-8') for p in tmp_path.iterdir() if p.is_file())
    assert 'must-not-leak-context' not in all_text
    assert 'secret raw source' not in all_text
    html = (tmp_path / 'report.html').read_text(encoding='utf-8')
    assert '<img src=x' not in html
    assert 'SEF' in html and '판정 제안' in html
    assert 'Deployment and effective caller roles.' in (tmp_path / 'developer.md').read_text(encoding='utf-8')
    manifest = json.loads((tmp_path / 'manifest.json').read_text(encoding='utf-8'))
    assert manifest['files']['review-packets.json'] == hashlib.sha256(packet_path.read_bytes()).hexdigest()


def test_invalid_proposal_defaults_to_review_in_export():
    from gxsec.triage import build_review_packets
    run = _run()
    run['findings'][0]['context']['proposal'] = 'PASS'
    assert build_review_packets(run)['packets'][0]['proposal'] == 'needs_review'


def test_generated_framework_caches_do_not_exhaust_source_scope(tmp_path):
    from gxsec.source import collect_source
    for name in ('.gradle', '.nuxt', '.output', '.next'):
        directory = tmp_path / name
        directory.mkdir()
        (directory / 'generated.js').write_text('generated cache', encoding='utf-8')
    (tmp_path / '.env').write_text('DEMO=configuration', encoding='utf-8')
    (tmp_path / 'build.gradle.kts').write_text('// build descriptor', encoding='utf-8')
    collected = collect_source(tmp_path)
    assert {'.env', 'build.gradle.kts'} <= set(collected['files'])
    assert not any(row.startswith(('.gradle/', '.nuxt/', '.output/', '.next/')) for row in collected['files'])
    assert len(collected['exclusions']) == 4


def test_framework_implementation_digest_is_bound_to_execution(tmp_path):
    from gxsec import framework
    (tmp_path / 'App.java').write_text('class App {}', encoding='utf-8')
    checks, _ = adapters.run_static_checks(tmp_path, config.default_config(tmp_path), 'check')
    check = next(c for c in checks if c['id'] == 'framework')
    assert check['engine'].get('implementation_hash') == hashlib.sha256(Path(framework.__file__).read_bytes()).hexdigest()


def test_framework_scope_identity_ignores_evidence_bytes_but_tracks_detection_loss(tmp_path, monkeypatch):
    from gxsec import framework
    (tmp_path / 'App.java').write_text('class App {}', encoding='utf-8')
    metadata = {'family': 'SEF', 'variant': 'private', 'modules': [{'path': '.', 'variant': 'private',
        'signals': ['menu-security-expression'], 'evidence': [{'hash': 'a' * 64}]}]}
    def inspect(*args):
        return models.make_check('framework', status='complete',
            coverage={'eligible': 1, 'scanned': 1, 'files': ['App.java']}, framework=copy.deepcopy(metadata)), []
    monkeypatch.setattr(framework, 'run_framework_check', inspect)
    def signature():
        checks, _ = adapters.run_static_checks(tmp_path, config.default_config(tmp_path), 'check')
        return next(c for c in checks if c['id'] == 'framework')['coverage']['signature']
    first = signature()
    metadata['modules'][0]['evidence'][0]['hash'] = 'b' * 64
    assert signature() == first
    metadata.update(family='unknown', variant='undetermined', modules=[])
    assert signature() != first


@pytest.mark.parametrize('proposal', [{'invalid': True}, ['not_actionable']])
def test_malformed_context_proposal_is_exported_as_review(tmp_path, proposal):
    run = _run()
    run['findings'][0]['context']['proposal'] = proposal
    write_reports(run, tmp_path)
    exported = json.loads((tmp_path / 'review-packets.json').read_text(encoding='utf-8'))
    assert exported['packets'][0]['proposal'] == 'needs_review'


def test_framework_review_context_explains_existing_boundary_facts():
    from gxsec.triage import enrich_framework_findings
    run = _run()
    finding = run['findings'][0]
    finding.update(facts=['No recognized administrator predicate.'],
                   counterevidence=['Authentication is still required.'],
                   prerequisites=['Deployed route accepts the ordinary user.'])
    original = copy.deepcopy(finding)
    enriched = enrich_framework_findings([finding], run['source'])[0]
    assert finding == original
    assert enriched['finding_id'] == finding['finding_id']
    assert enriched['validation'] == 'candidate'
    assert '관리자' in enriched['title']
    assert enriched['context']['classification'].startswith('sef-')
    assert enriched['context']['evidence_for'] and enriched['context']['evidence_against']
    assert enriched['context']['unresolved'] == finding['prerequisites']


def test_contextual_review_requires_current_result_digest():
    run = _run()
    finding = run['findings'][0]
    review = {'id': 'refutation-1', 'finding_id': finding['finding_id'], 'decision': 'refuted',
        'evidence_refs': ['reviewed-current-source'], 'source_revision': 'revision-1', 'scope_hash': 'scope-1'}
    protected = {'source_revision': 'revision-1', 'scope_hash': 'scope-1'}
    def approve():
        protected['trusted_approvals'] = [{'record_id': review['id'], 'digest': models.content_hash(review),
            'kind': 'finding-refutation', 'roles': ['security-reviewer']}]
    approve()
    assert policy.evaluate(run['checks'], [finding], reviews=[review], policy=protected)['status'] == 'INCOMPLETE'
    review['normalized_result_hash'] = finding['normalized_result_hash']
    approve()
    assert policy.evaluate(run['checks'], [finding], reviews=[review], policy=protected)['status'] == 'PASS'
    finding['normalized_result_hash'] = 'f' * 64
    assert policy.evaluate(run['checks'], [finding], reviews=[review], policy=protected)['status'] == 'INCOMPLETE'


def test_engine_contract_change_invalidates_finding_review_hash(tmp_path, monkeypatch):
    (tmp_path / 'App.java').write_text('class App {}', encoding='utf-8')
    engine = {'version': '1'}
    def runner(source, cfg, inventory, profile):
        return models.make_check('sast', status='complete', engine=dict(engine),
            coverage={'eligible': 1, 'scanned': 1, 'files': ['App.java']}), [models.make_finding(
                category='sql', rule='same-rule', path='App.java', severity='High', check_id='sast')]
    monkeypatch.setattr(adapters, '_sast', runner)
    def result():
        _, findings = adapters.run_static_checks(tmp_path, config.default_config(tmp_path), 'check')
        return next(f for f in findings if f['rule_id'] == 'same-rule')
    first = result()
    engine['version'] = '2'
    second = result()
    assert first['finding_id'] == second['finding_id']
    assert first['normalized_result_hash'] != second['normalized_result_hash']


def test_cli_version_matches_installed_package():
    import subprocess
    import sys
    import gxsec
    from gxsec import __version__
    assert __version__ == '0.10.0', gxsec.__file__
    command = subprocess.run([sys.executable, str(Path(__file__).parents[1] / 'gxsec.py'), '--version'],
        capture_output=True, text=True, timeout=15)
    assert command.returncode == 0
    assert command.stdout.strip() == 'gx-security ' + __version__


def test_preflight_reads_only_declared_framework_signature_files(tmp_path, monkeypatch):
    from gxsec.preflight import collect_framework_signatures
    (tmp_path / 'WebSecurityConfig.java').write_text('class WebSecurityConfig {}', encoding='utf-8')
    (tmp_path / 'build.gradle.kts').write_text('// build descriptor', encoding='utf-8')
    unrelated = tmp_path / 'large.dat'
    unrelated.write_bytes(b'not source')
    original_open = Path.open
    def bounded(path, *args, **kwargs):
        assert path != unrelated, 'Preparation must not hash or copy unrelated assets'
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', bounded)
    inventory = collect_framework_signatures(tmp_path)
    assert set(inventory['files']) == {'WebSecurityConfig.java', 'build.gradle.kts'}
    assert inventory['git'] is False and inventory['scope'] == 'partial'
    assert not inventory['errors']


def test_doctor_does_not_collect_full_source_or_git_history(tmp_path, monkeypatch, capsys):
    from gxsec import cli
    def refuse(*args, **kwargs):
        raise AssertionError('Doctor must not inventory the entire repository')
    monkeypatch.setattr(cli, 'collect_source', refuse)
    monkeypatch.setattr(cli.adapters, 'probe_engine', lambda *a: {'status': 'complete', 'engine': {'version': 'test'}})
    monkeypatch.setattr(cli, 'trusted_runtime_tool', lambda *a: {'version': 'test'})
    assert cli.main(['doctor', '--source', str(tmp_path), '--json']) == 0
    result = json.loads(capsys.readouterr().out)
    assert result['framework']['assessment'] == 'detection-only'
    assert result['framework']['selection'] == 'known-framework-signatures'
    assert result['framework']['coverage']['scope'] == 'partial'


def test_preflight_byte_limit_is_enforced_before_reading(tmp_path, monkeypatch):
    from gxsec import preflight
    target = tmp_path / 'WebSecurityConfig.java'
    target.write_text('class WebSecurityConfig {}', encoding='utf-8')
    monkeypatch.setattr(preflight, 'MAX_TOTAL_BYTES', 1)
    def refuse(*args, **kwargs):
        raise AssertionError('Preparation exhausted its byte budget before this read')
    monkeypatch.setattr(Path, 'open', refuse)
    assert preflight.collect_framework_signatures(tmp_path)['errors']


def test_preflight_attempt_limit_counts_unavailable_signatures(tmp_path, monkeypatch):
    from gxsec import preflight
    (tmp_path / 'ApiResponse.java').write_text('class ApiResponse {}', encoding='utf-8')
    second = tmp_path / 'WebSecurityConfig.java'
    second.write_text('class WebSecurityConfig {}', encoding='utf-8')
    original_reject = preflight.reject_reparse_path
    def reject(path):
        if Path(path).name == 'ApiResponse.java':
            raise ValueError('synthetic unavailable signature')
        return original_reject(path)
    original_open = Path.open
    def bounded(path, *args, **kwargs):
        assert path != second, 'Failed signature attempts must consume the preparation budget'
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(preflight, 'reject_reparse_path', reject)
    monkeypatch.setattr(preflight, 'MAX_SIGNATURES', 1)
    monkeypatch.setattr(Path, 'open', bounded)
    assert preflight.collect_framework_signatures(tmp_path)['errors']
