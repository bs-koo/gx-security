"""A scanner's absence observation requires a current independent resolution."""
import json
from pathlib import Path
import subprocess

import pytest

from gxsec import adapters, config, models, policy, source, state


DIRECT_SQL = '''import org.springframework.jdbc.core.JdbcTemplate;
class SearchService {
 private JdbcTemplate jdbc;
 public Object search(String term) { return jdbc.queryForList("SELECT * FROM account WHERE name = '" + term + "'"); }
}
'''
HELPER_SQL = '''import org.springframework.jdbc.core.JdbcTemplate;
class SearchService {
 private JdbcTemplate jdbc;
 public Object search(String term) { return jdbc.queryForList(sql(term)); }
 private String sql(String term) { return "SELECT * FROM account WHERE name = '" + term + "'"; }
}
'''


def check(cid):
    return models.make_check(cid, status='complete', engine={'version': 'synthetic-1'},
        coverage={'eligible': 1, 'scanned': 1, 'scope': 'full', 'files': ['Sample.java'],
                  'signature': 'same-input-contract'})


def finding(severity='High', cid='sast'):
    return models.make_finding(category='sqli' if cid == 'sast' else 'dependency',
        rule='synthetic-sql' if cid == 'sast' else 'synthetic-advisory', path='Sample.java',
        severity=severity, validation='source-verified', check_id=cid,
        context={'schema_version': 1, 'proposal': 'needs_review'}, normalized_result_hash='a' * 64)


def run(name, findings):
    return {'schema_version': 1, 'run_id': name, 'project_id': 'synthetic',
        'profile': 'static-release', 'source': {'source_id': 'same-source',
            'revision': 'current-revision', 'hash': 'c' * 64, 'scope_hash': 'same-scope',
            'inventory': [{'path': 'Sample.java', 'hash': 'd' * 64}]},
        'checks': [check(cid) for cid in ('sast', 'sca', 'secrets', 'framework')],
        'findings': findings}


def reconcile(current, previous):
    return state.Store.reconcile(object.__new__(state.Store), current, previous)


def proposed(severity='High'):
    return reconcile(run('new', []), run('old', [finding(severity)]))


def review_for(result, validation='source-verified'):
    item = result['findings'][0]
    review = {'id': 'current-independent-remediation', 'finding_id': item['finding_id'],
        'decision': 'fixed-verified', 'validation': validation,
        'source_revision': result['source']['revision'], 'scope_hash': result['source']['scope_hash'],
        'normalized_result_hash': item['normalized_result_hash'],
        'reason': 'Reviewed the original input-to-query path and its replacement parameter binding.',
        'evidence_refs': ['independent-current-source-review']}
    protected = {'profile': 'static-release', 'source_revision': result['source']['revision'],
        'scope_hash': result['source']['scope_hash'], 'trusted_approvals': [{
            'record_id': review['id'], 'digest': models.content_hash(review),
            'kind': 'remediation-validation', 'roles': ['independent-reviewer', 'security-reviewer']}]}
    return review, protected


def gate(result, **kwargs):
    return policy.evaluate(result['checks'], result['findings'], **kwargs)['status']


@pytest.mark.parametrize('severity', ['High', 'Medium', None])
def test_full_scan_absence_does_not_claim_remediation(severity):
    result = proposed(severity)
    item = result['findings'][0]
    assert item['lifecycle'] == 'remediation-proposed'
    assert item['validation'] == 'undetermined'
    assert item['review_required'] is True
    assert item['absence_evidence']['method'] == 'sast-finding-not-observed'
    assert item['normalized_result_hash'] != 'a' * 64
    assert 'resolution_evidence' not in item
    assert gate(result, policy={'profile': 'static-release'}) == 'INCOMPLETE'


def test_risk_retaining_helper_rewrite_replays_engine_boundary_without_passing(tmp_path, monkeypatch):
    """Captured Semgrep shape; only the external engine and unrelated checks are controlled."""
    active = {'direct': True}

    def engine_probe(name, options, root, checked, **kwargs):
        checked['engine'].update(version='1.172.0', provenance='captured-output-regression')
        return 'captured-semgrep'

    def engine_output(command, **kwargs):
        target = str(Path(command[-1]) / 'Sample.java')
        matches = [{'check_id': 'sqisoft-spring-jdbctemplate-string-concat', 'path': target,
            'start': {'line': 4, 'col': 44}, 'end': {'line': 4, 'col': 130},
            'extra': {'severity': 'ERROR', 'message': 'synthetic capture', 'metadata': {}}}]
        output = {'version': '1.172.0', 'results': matches if active['direct'] else [],
                  'errors': [], 'paths': {'scanned': [target]}}
        return subprocess.CompletedProcess(command, 0, json.dumps(output), '')

    def unrelated(cid):
        return lambda *args: (check(cid), [])

    monkeypatch.setattr(adapters, '_probe', engine_probe)
    monkeypatch.setattr(adapters, '_run', engine_output)
    monkeypatch.setattr(adapters, '_sca', unrelated('sca'))
    monkeypatch.setattr(adapters, '_secrets', unrelated('secrets'))
    monkeypatch.setattr('gxsec.framework.run_framework_check', unrelated('framework'))
    monkeypatch.setattr('gxsec.optional.run_optional_checks', lambda *args: ([], []))
    root = tmp_path / 'project'
    root.mkdir()
    cfg = config.default_config(root)
    cfg['_state_dir'] = str(tmp_path / 'state')
    results = []
    for name, text in [('direct', DIRECT_SQL), ('helper', HELPER_SQL)]:
        active['direct'] = name == 'direct'
        (root / 'Sample.java').write_text(text, encoding='utf-8')
        checked, findings = adapters.run_static_checks(root, cfg, 'static-release')
        result = run(name, findings)
        result.update(checks=checked, source=source.collect_source(root))
        results.append(result)
    before, after = results
    assert before['checks'][0]['status'] == after['checks'][0]['status'] == 'complete'
    assert len(before['findings']) == 1 and not after['findings']
    assert before['source']['revision'] != after['source']['revision']
    result = reconcile(after, before)
    assert result['findings'][0]['lifecycle'] == 'remediation-proposed'
    assert gate(result, policy={'profile': 'static-release'}) == 'INCOMPLETE'


@pytest.mark.parametrize('mode', ['partial', 'failed', 'different-scope'])
def test_inadequate_rescan_preserves_confirmed_open_risk(mode):
    current = run('new', [])
    if mode == 'partial':
        current['checks'][0]['coverage']['scope'] = 'diff'
    elif mode == 'failed':
        current['checks'][0]['status'] = 'failed'
    else:
        current['source']['scope_hash'] = 'other'
    result = reconcile(current, run('old', [finding()]))
    assert result['findings'][0]['lifecycle'] == 'open'
    assert gate(result, policy={'profile': 'static-release'}) == 'BLOCK'


@pytest.mark.parametrize('validation', ['source-verified', 'runtime-verified'])
def test_current_independent_remediation_can_close_and_is_idempotent(validation):
    result = proposed()
    review, protected = review_for(result, validation)
    applied = policy.apply_reviews(result['findings'], [review], policy=protected)
    assert applied[0]['lifecycle'] == 'fixed-verified'
    assert applied[0]['validation'] == validation
    assert applied[0]['severity'] == 'High'
    assert applied[0]['resolution_evidence']['method'] == 'independent-remediation-review'
    assert policy.apply_reviews(applied, [review], policy=protected) == applied
    assert policy.evaluate(result['checks'], applied, reviews=[review], policy=protected)['status'] == 'PASS'


@pytest.mark.parametrize('tamper', ['untrusted', 'wrong-kind', 'wrong-digest', 'missing-security-role',
    'missing-reviewer-role', 'missing-result-hash', 'wrong-revision', 'wrong-scope', 'empty-evidence',
    'empty-reason', 'unverified-validation'])
def test_remediation_requires_bound_evidence_and_review_authority(tamper):
    result = proposed()
    review, protected = review_for(result)
    if tamper == 'untrusted':
        protected['trusted_approvals'] = []
    elif tamper == 'wrong-kind':
        protected['trusted_approvals'][0]['kind'] = 'finding-validation'
    elif tamper == 'wrong-digest':
        protected['trusted_approvals'][0]['digest'] = 'f' * 64
    elif tamper.startswith('missing-') and tamper.endswith('-role'):
        role = 'security-reviewer' if 'security' in tamper else 'independent-reviewer'
        protected['trusted_approvals'][0]['roles'].remove(role)
    else:
        if tamper == 'missing-result-hash':
            review.pop('normalized_result_hash')
        elif tamper == 'wrong-revision':
            review['source_revision'] = 'old-revision'
        elif tamper == 'wrong-scope':
            review['scope_hash'] = 'other'
        elif tamper == 'empty-evidence':
            review['evidence_refs'] = []
        elif tamper == 'empty-reason':
            review['reason'] = ''
        else:
            review['validation'] = 'candidate'
        protected['trusted_approvals'][0]['digest'] = models.content_hash(review)
    assert gate(result, reviews=[review], policy=protected) == 'INCOMPLETE'


@pytest.mark.parametrize('change', ['revision', 'inventory', 'engine', 'coverage', 'status'])
def test_absence_review_cannot_be_reused_after_inputs_change(change):
    original = proposed()
    review, protected = review_for(original)
    current = run('next', [])
    if change == 'revision':
        current['source']['revision'] = 'changed'
    elif change == 'inventory':
        current['source']['inventory'][0]['hash'] = 'e' * 64
    elif change == 'engine':
        current['checks'][0]['engine']['version'] = 'changed'
    elif change == 'coverage':
        current['checks'][0]['coverage']['scanned'] = 0
    else:
        current['checks'][0]['status'] = 'incomplete'
    result = reconcile(current, original)
    protected['source_revision'] = current['source']['revision']
    assert result['findings'][0]['normalized_result_hash'] != original['findings'][0]['normalized_result_hash']
    assert gate(result, reviews=[review], policy=protected) == 'INCOMPLETE'


def test_unchanged_absence_keeps_review_binding_but_needs_approval_input_again():
    first = proposed()
    review, protected = review_for(first)
    first['findings'] = policy.apply_reviews(first['findings'], [review], policy=protected)
    second = reconcile(run('repeat', []), first)
    assert second['findings'][0]['normalized_result_hash'] == first['findings'][0]['normalized_result_hash']
    assert gate(second, reviews=[review], policy=protected) == 'PASS'
    assert gate(second, policy=protected) == 'INCOMPLETE'


def test_forged_or_legacy_fixed_marker_is_not_current_remediation_evidence():
    result = run('legacy', [finding()])
    result['findings'][0]['lifecycle'] = 'fixed-verified'
    assert gate(result, policy={'profile': 'static-release'}) != 'PASS'
    carried = reconcile(run('new', []), result)['findings'][0]
    assert carried['lifecycle'] == 'remediation-proposed'


def test_sca_equivalent_full_scan_still_verifies_resolved_dependency():
    result = reconcile(run('new', []), run('old', [finding(cid='sca')]))
    assert result['findings'][0]['lifecycle'] == 'fixed-verified'
    assert result['findings'][0]['resolution_evidence']['method'] == 'absent-in-equivalent-full-clean-scan'
    assert gate(result, policy=current_policy(result)) == 'PASS'


def current_policy(result):
    return {'profile': result['profile'], 'run_id': result['run_id'],
            'source_revision': result['source']['revision'], 'scope_hash': result['source']['scope_hash']}


@pytest.mark.parametrize('cid', ['secrets', 'auth', 'authorization', 'dast', 'unknown', 'sca'])
def test_bare_fixed_markers_never_waive_current_evidence(cid):
    item = finding(cid=cid)
    item['lifecycle'] = 'fixed-verified'
    result = run('forged', [item])
    assert gate(result, policy=current_policy(result)) == 'INCOMPLETE'


@pytest.mark.parametrize('cid', ['secrets', 'auth', 'authorization', 'dast', 'unknown'])
def test_stale_unsupported_closure_is_reopened_for_review(cid):
    item = finding(cid=cid)
    item.update(lifecycle='fixed-verified', fixed_verified_run='old',
                resolution_evidence={'method': 'legacy-closure'})
    result = reconcile(run('new', []), run('old', [item]))
    assert result['findings'][0]['lifecycle'] == 'remediation-proposed'
    assert 'resolution_evidence' not in result['findings'][0]
    assert gate(result, policy=current_policy(result)) == 'INCOMPLETE'


@pytest.mark.parametrize('tamper', ['run', 'revision', 'scope', 'engine', 'coverage', 'missing-check', 'bare-proof'])
def test_sca_closure_is_bound_to_current_run_source_and_check(tamper):
    result = reconcile(run('new', []), run('old', [finding(cid='sca')]))
    if tamper == 'run':
        result['run_id'] = 'later-run'
    elif tamper == 'revision':
        result['source']['revision'] = 'later-revision'
    elif tamper == 'scope':
        result['source']['scope_hash'] = 'other-scope'
    elif tamper == 'engine':
        result['checks'][1]['engine']['version'] = 'other-engine'
    elif tamper == 'coverage':
        result['checks'][1]['coverage']['signature'] = 'other-input-contract'
    elif tamper == 'missing-check':
        result['checks'] = [c for c in result['checks'] if c['id'] != 'sca']
    else:
        result['findings'][0]['resolution_evidence'] = {'check_id': 'sca', 'scope_hash': 'same-scope',
            'method': 'absent-in-equivalent-full-clean-scan'}
    assert gate(result, policy=current_policy(result)) == 'INCOMPLETE'


def test_sca_old_closure_is_not_carried_through_non_equivalent_scan():
    previous = reconcile(run('fixed', []), run('old', [finding(cid='sca')]))
    current = run('later', [])
    current['checks'][1]['engine']['version'] = 'different-engine'
    result = reconcile(current, previous)
    assert result['findings'][0]['lifecycle'] == 'remediation-proposed'
    assert gate(result, policy=current_policy(result)) == 'INCOMPLETE'


def test_reappearing_positive_reopens_after_independent_resolution():
    previous = proposed()
    review, protected = review_for(previous)
    previous['findings'] = policy.apply_reviews(previous['findings'], [review], policy=protected)
    current = reconcile(run('positive', [finding()]), previous)
    assert current['findings'][0]['lifecycle'] == 'reopened'
    assert gate(current, reviews=[review], policy=protected) == 'BLOCK'


@pytest.mark.parametrize('severity,expected', [('Medium', 'PASS'), (None, 'INCOMPLETE'), ('Critical', 'INCOMPLETE')])
def test_security_review_is_required_for_high_or_unclassified_absence(severity, expected):
    result = proposed(severity)
    review, protected = review_for(result)
    protected['trusted_approvals'][0]['roles'] = ['independent-reviewer']
    assert gate(result, reviews=[review], policy=protected) == expected


def test_remediation_record_cannot_downgrade_original_risk_to_avoid_security_role():
    result = proposed('High')
    review, protected = review_for(result)
    review['severity'] = 'Low'
    protected['trusted_approvals'][0]['digest'] = models.content_hash(review)
    protected['trusted_approvals'][0]['roles'] = ['independent-reviewer']
    assert gate(result, reviews=[review], policy=protected) == 'INCOMPLETE'
    protected['trusted_approvals'][0]['roles'].append('security-reviewer')
    applied = policy.apply_reviews(result['findings'], [review], policy=protected)
    assert applied[0]['severity'] == 'High'
    assert applied[0]['lifecycle'] == 'fixed-verified'
