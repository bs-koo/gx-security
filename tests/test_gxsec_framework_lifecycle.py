"""Recognizer absence is a current observation, never independent remediation proof."""
import copy

import pytest

from gxsec import adapters, config, models, policy, source, state


ORIGINAL = '''class Files {
 boolean ok(File root, File target) {
  String base = root.getCanonicalPath();
  String file = target.getCanonicalPath();
  return file.startsWith(base);
 }
}'''
SPLIT = ORIGINAL.replace('String base =', 'String base; base =').replace('String file =', 'String file; file =')


def _check(cid='framework'):
    return models.make_check(cid, status='complete',
        engine={'name': 'synthetic-control', 'version': '1'},
        coverage={'eligible': 1, 'scanned': 1, 'scope': 'full',
                  'files': ['Files.java'], 'signature': 'same-coverage'})


def _run(run_id, findings):
    return {'schema_version': 1, 'run_id': run_id, 'project_id': 'synthetic',
        'profile': 'static-release', 'source': {'source_id': 'same-source',
            'revision': 'revision-current', 'hash': 'c' * 64, 'scope_hash': 'same-scope',
            'inventory': [{'path': 'Files.java', 'hash': 'd' * 64}]},
        'checks': [_check(cid) for cid in ('sast', 'sca', 'secrets', 'framework')],
        'findings': findings}


def _finding():
    finding = models.make_finding(category='file-confinement', rule='SEF-FILE-01',
        path='Files.java', line=5, severity='Medium', check_id='framework',
        review_required=True)
    finding['context'] = {'schema_version': 1, 'proposal': 'needs_review',
        'evidence_for': [{'path': 'Files.java', 'line': 5, 'hash': 'a' * 64}],
        'unresolved': ['Original path-control prerequisites.']}
    finding['normalized_result_hash'] = 'b' * 64
    return finding


def _reconcile(current, previous):
    # Explicit previous state avoids creating any SQLite store/database.
    return state.Store.reconcile(object.__new__(state.Store), current, previous)


def _protected_refutation(run, finding):
    review = {'id': 'independent-current-review', 'finding_id': finding['finding_id'],
        'decision': 'refuted', 'source_revision': run['source']['revision'],
        'scope_hash': run['source']['scope_hash'],
        'normalized_result_hash': finding['normalized_result_hash'],
        'evidence_refs': ['independent-remediation-evidence']}
    protected = {'profile': 'static-release', 'source_revision': run['source']['revision'],
        'scope_hash': run['source']['scope_hash'], 'trusted_approvals': [{
            'record_id': review['id'], 'digest': models.content_hash(review),
            'kind': 'finding-refutation', 'roles': ['security-reviewer']}]}
    return review, protected


def test_split_declaration_recognizer_loss_does_not_pass_static_release(tmp_path, monkeypatch):
    from gxsec import optional
    def control(cid):
        def run(*args):
            return _check(cid), []
        return run
    for cid in ('sast', 'sca', 'secrets'):
        monkeypatch.setattr(adapters, '_' + cid, control(cid))
    monkeypatch.setattr(optional, 'run_optional_checks', lambda *args: ([], []))
    (tmp_path / 'build.gradle.kts').write_text('plugins { id("org.springframework.boot") version "3.5.6" }', encoding='utf-8')
    (tmp_path / 'MethodSecurityConfig.java').write_text(
        '@Configuration @EnableMethodSecurity class MethodSecurityConfig { '
        'MenuSecurityExpressionHandler handler; MenuRoleService service; }', encoding='utf-8')
    def scan(run_id, text):
        (tmp_path / 'Files.java').write_text(text, encoding='utf-8')
        cfg = config.default_config(tmp_path)
        checks, findings = adapters.run_static_checks(tmp_path, cfg, 'static-release')
        run = _run(run_id, findings)
        run.update(checks=checks, source=source.collect_source(tmp_path))
        return run
    before = scan('observed', ORIGINAL)
    after = scan('rewritten', SPLIT)
    original = next(f for f in before['findings'] if f['rule_id'] == 'SEF-FILE-01')
    assert not after['findings']
    old_check = next(c for c in before['checks'] if c['id'] == 'framework')
    new_check = next(c for c in after['checks'] if c['id'] == 'framework')
    assert old_check['status'] == new_check['status'] == 'complete'
    assert old_check['engine'] == new_check['engine']
    assert old_check['coverage']['signature'] == new_check['coverage']['signature']
    carried_run = _reconcile(after, before)
    carried = carried_run['findings'][0]
    assert carried['finding_id'] == original['finding_id']
    assert carried['locations'] == original['locations']
    assert carried['lifecycle'] == 'remediation-proposed'
    assert carried['validation'] == 'undetermined'
    assert carried['review_required'] is True
    assert policy.evaluate(carried_run['checks'], carried_run['findings'],
                           policy={'profile': 'static-release'})['status'] == 'INCOMPLETE'
    assert carried['context']['schema_version'] == 1
    assert not carried['context']['evidence_for']
    assert carried['context']['evidence_against']
    assert any('independent' in question.lower() for question in carried['context']['unresolved'])
    absence = carried['absence_evidence']
    assert absence['source_revision'] == after['source']['revision']
    current_hashes = {row['path']: row['hash'] for row in after['source']['inventory']}
    assert absence['locations'][0]['hash'] == current_hashes['Files.java']
    assert 'resolution_evidence' not in carried


@pytest.mark.parametrize('validation,lifecycle', [('source-verified', 'open'), ('refuted', 'fixed-verified')])
def test_absence_removes_stale_approval_and_fixed_markers(validation, lifecycle):
    finding = _finding()
    finding.update(validation=validation, lifecycle=lifecycle, review_ref='old-approval',
        fixed_verified_run='old-run', resolution_evidence={'method': 'old-closure'},
        observations=[{'type': 'trusted-human-review', 'review_ref': 'old-approval'},
                      {'type': 'source-observation', 'fact': 'Earlier candidate.'}])
    carried = _reconcile(_run('new', []), _run('old', [finding]))['findings'][0]
    assert carried['validation'] == 'undetermined'
    assert carried['lifecycle'] == 'remediation-proposed'
    assert carried['review_required'] is True
    assert not {'review_ref', 'fixed_verified_run', 'resolution_evidence'} & carried.keys()
    assert all(o.get('type') != 'trusted-human-review' for o in carried['observations'])
    assert carried['locations'] == finding['locations']


def test_unchanged_absence_rescans_keep_hash_and_current_refutation_usable():
    original = _finding()
    first = _reconcile(_run('first', []), _run('observed', [original]))
    second = _reconcile(_run('second', []), first)
    third = _reconcile(_run('third', []), second)
    assert {r['findings'][0]['finding_id'] for r in (first, second, third)} == {original['finding_id']}
    hashes = {r['findings'][0]['normalized_result_hash'] for r in (first, second, third)}
    assert len(hashes) == 1
    assert original['normalized_result_hash'] not in hashes
    review, protected = _protected_refutation(first, first['findings'][0])
    assert policy.evaluate(third['checks'], third['findings'], reviews=[review], policy=protected)['status'] == 'PASS'
    review.pop('normalized_result_hash')
    protected['trusted_approvals'][0]['digest'] = models.content_hash(review)
    assert policy.evaluate(third['checks'], third['findings'], reviews=[review], policy=protected)['status'] == 'INCOMPLETE'


@pytest.mark.parametrize('mode', ['missing-check', 'partial', 'failed', 'check-profile'])
def test_framework_absence_never_inherits_verified_closure_with_unsupported_scan(mode):
    old = _finding()
    old.update(lifecycle='fixed-verified', fixed_verified_run='stale')
    current = _run('new', [])
    if mode == 'missing-check':
        current['checks'].pop()
    elif mode == 'partial':
        current['checks'][-1]['coverage']['scope'] = 'partial'
    elif mode == 'failed':
        current['checks'][-1]['status'] = 'failed'
        current['checks'][-1]['errors'] = [{'type': 'synthetic-failure'}]
    else:
        current['profile'] = 'check'
    carried = _reconcile(current, _run('old', [old]))['findings'][0]
    assert carried['lifecycle'] == 'remediation-proposed'
    assert carried['validation'] == 'undetermined'
    assert 'fixed_verified_run' not in carried
    assert carried['context']['schema_version'] == 1


def test_absence_binding_ignores_run_and_snapshot_timestamps_and_inventory_order():
    original = _finding()
    previous = _run('observed', [original])
    first = _run('first', [])
    first['source']['inventory'].append({'path': 'Related.java', 'hash': 'f' * 64})
    first['started_at'] = '2026-11-05T00:00:00Z'
    first['checks'][-1]['snapshot'] = {'created_at': 'earlier', 'path': 'temporary-first'}
    second = copy.deepcopy(first)
    second.update(run_id='second', started_at='2026-11-05T00:30:00Z')
    second['checks'][-1]['snapshot'] = {'created_at': 'later', 'path': 'temporary-second'}
    second['source']['inventory'].reverse()
    assert (_reconcile(first, previous)['findings'][0]['normalized_result_hash'] ==
            _reconcile(second, previous)['findings'][0]['normalized_result_hash'])


@pytest.mark.parametrize('change', ['revision', 'hash', 'scope_hash', 'inventory', 'engine', 'signature', 'coverage', 'status'])
def test_changed_current_source_or_analysis_contract_invalidates_absence_review(change):
    first = _reconcile(_run('first', []), _run('observed', [_finding()]))
    current = _run('next', [])
    if change in ('revision', 'hash', 'scope_hash'):
        current['source'][change] = 'changed'
    elif change == 'inventory':
        current['source']['inventory'][0]['hash'] = 'e' * 64
    else:
        check = current['checks'][-1]
        if change == 'engine':
            check['engine']['version'] = '2'
        elif change == 'signature':
            check['coverage']['signature'] = 'different-coverage'
        elif change == 'coverage':
            check['coverage']['scanned'] = 0
        else:
            check['status'] = 'incomplete'
    second = _reconcile(current, first)
    assert second['findings'][0]['finding_id'] == first['findings'][0]['finding_id']
    assert second['findings'][0]['normalized_result_hash'] != first['findings'][0]['normalized_result_hash']
    review, protected = _protected_refutation(first, first['findings'][0])
    protected.update(source_revision=current['source']['revision'], scope_hash=current['source']['scope_hash'])
    assert policy.evaluate(second['checks'], second['findings'], reviews=[review], policy=protected)['status'] == 'INCOMPLETE'


def test_ordinary_sast_equivalent_complete_scan_still_verifies_closure():
    finding = models.make_finding(category='xss', rule='xss-output', path='Files.java',
        severity='High', validation='source-verified', check_id='sast')
    result = _reconcile(_run('clean', []), _run('old', [finding]))
    assert result['findings'][0]['lifecycle'] == 'fixed-verified'
    assert result['findings'][0]['resolution_evidence']['method'] == 'absent-in-equivalent-full-clean-scan'
    assert policy.evaluate(result['checks'], result['findings'], policy={'profile': 'static-release'})['status'] == 'PASS'


def test_new_positive_observation_reopens_previously_fixed_framework_identity():
    old = _finding()
    old['lifecycle'] = 'fixed-verified'
    result = _reconcile(_run('new', [_finding()]), _run('old', [old]))
    assert result['findings'][0]['finding_id'] == old['finding_id']
    assert result['findings'][0]['lifecycle'] == 'reopened'
