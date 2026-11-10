import copy
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from gxsec import config, models, policy, redaction, source, state

def complete(name='sast'):
    return {
        'id': name,
        'status': 'complete',
        'required': True,
        'errors': [],
        'coverage': {'eligible': 1, 'scanned': 1, 'scope': 'full'},
    }

def finding(validation='source-verified', severity='High'):
    return models.make_finding(
        category='xss',
        rule='xss.output',
        path='src/A.java',
        line=2,
        snippet='print(user)',
        severity=severity,
        validation=validation,
    )

def test_gate_precedence_and_unknowns():
    f = finding()
    assert policy.evaluate([complete(), {'id': 'sca', 'required': True, 'status': 'failed'}], [f])['status'] == 'BLOCK'
    assert policy.evaluate([complete()], [finding('candidate')])['status'] == 'INCOMPLETE'
    assert policy.evaluate([complete()], [finding('candidate', None)])['status'] == 'INCOMPLETE'
    assert policy.evaluate([], [])['status'] == 'INCOMPLETE'
    assert policy.evaluate([dict(complete(), coverage={'eligible': 0, 'scanned': 0})], [])['status'] == 'INCOMPLETE'
    assert policy.evaluate([complete()], [])['status'] == 'PASS'
    assert policy.evaluate([complete()], [], reviews=[{'id': 'manual', 'required': True, 'status': 'pending'}])['status'] == 'INCOMPLETE'

def test_untrusted_refutation_exception_and_review_are_not_approvals():
    f = finding()
    f['validation'] = 'refuted'
    assert policy.evaluate([complete()], [f])['status'] == 'INCOMPLETE'
    f = finding()
    exception = {
        'id': 'ex1',
        'finding_id': f['finding_id'],
        'reason': 'temporary',
        'owner': 'team',
        'expires_at': '2099-01-01T00:00:00Z',
        'approved_by': ['security', 'pm'],
        'trusted': True,
    }
    assert policy.evaluate([complete()], [f], exceptions=[exception])['status'] == 'BLOCK'
    assert policy.evaluate(
        [complete()],
        [],
        reviews=[{'id': 'manual', 'required': True, 'status': 'complete', 'approved_by': 'QA'}],
    )['status'] == 'INCOMPLETE'

def test_trusted_exception_requires_digest_scope_and_expiry():
    f = finding()
    ex = {
        'id': 'ex1',
        'finding_id': f['finding_id'],
        'reason': 'temporary',
        'owner': 'team',
        'expires_at': '2030-01-01T00:00:00Z',
        'source_revision': 'abc',
        'scope_hash': 'scope',
    }
    p = {
        'source_revision': 'abc',
        'scope_hash': 'scope',
        'trusted_approvals': [{
            'record_id': 'ex1',
            'digest': models.content_hash(ex),
            'kind': 'risk-acceptance',
            'roles': ['security-owner', 'project-owner'],
        }],
    }
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    assert policy.evaluate([complete()], [f], exceptions=[ex], policy=p, now=now)['status'] == 'PASS_WITH_EXCEPTION'
    assert policy.evaluate([complete()], [f], exceptions=[dict(ex, source_revision='else')], policy=p, now=now)['status'] == 'BLOCK'
    assert policy.evaluate(
        [complete()],
        [f],
        exceptions=[ex],
        policy=p,
        now=dt.datetime(2031, 1, 1, tzinfo=dt.timezone.utc),
    )['status'] == 'BLOCK'

def test_config_cannot_weaken_builtin_profiles_or_trust(tmp_path):
    p = tmp_path / 'project.yml'
    p.write_text(
        'schema_version: 1\nproject: {id: demo}\nprofiles: {release: {required_checks: []}}\ndata_mode: connected-service\npolicy: {trusted_approvals: [{record_id: forged}]}\n',
    )
    with pytest.raises(ValueError):
        config.load_config(p)
    p.write_text('schema_version: 1\nproject: {id: demo}\nprofiles: {release: {required_checks: []}}\n')
    loaded = config.load_config(p)
    assert {'sast', 'sca', 'secrets'} <= set(loaded['profiles']['release']['required_checks'])
    assert loaded['data_mode'] == 'local-only'

def test_redaction_recursive_inline_and_urls():
    raw = {
        'Authorization': 'Bearer dont-show',
        'Cookie': 'sid=private',
        'nested': [{
            'password': 'abc123',
            'url': 'https://alice:pw@example.test/a?token=secret&x=1',
            'error': 'Authorization: Bearer unsafe\napi_key="topsecret"\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----',
        }],
    }
    text = json.dumps(redaction.redact(raw))
    for secret in ['dont-show', 'private', 'abc123', 'alice:pw', 'token=secret', 'unsafe', 'topsecret', 'BEGIN PRIVATE KEY', '\\nabc\\n']:
        assert secret not in text
    assert 'x=1' in text

def test_source_hash_untracked_env_and_exclusion(tmp_path):
    (tmp_path / '.env').write_text('PASSWORD=one')
    (tmp_path / 'src').mkdir()
    (tmp_path / 'src/A.java').write_text('class A {}')
    (tmp_path / 'node_modules').mkdir()
    (tmp_path / 'node_modules/a.js').write_text('vendor')
    first = source.collect_source(tmp_path)
    assert '.env' in first['files'] and 'node_modules/a.js' not in first['files']
    (tmp_path / '.env').write_text('PASSWORD=two')
    assert source.collect_source(tmp_path)['hash'] != first['hash']
    assert first['exclusions']

def test_fingerprint_ignores_line_and_semantic_whitespace():
    a = finding()
    b = models.make_finding(
        category='xss',
        rule='xss.output',
        path='src/A.java',
        line=999,
        snippet='print( user )',
        severity='High',
        validation='candidate',
    )
    assert a['fingerprint'] == b['fingerprint']

def run(run_id, findings, scope='full', status='complete', source_hash='scope'):
    c = complete()
    c['coverage']['scope'] = scope
    c['coverage']['scope_hash'] = source_hash
    c['coverage']['files'] = ['src/A.java']
    c['coverage']['signature'] = 'known-full-coverage-signature'
    c['engine'] = {'rules_hash': 'rules', 'version': '1'}
    return {
        'schema_version': 1,
        'run_id': run_id,
        'project_id': 'demo',
        'profile': 'static-release',
        'source': {'source_id': 'project', 'scope_hash': source_hash},
        'checks': [dict(c, id=i) for i in ['sast', 'sca', 'secrets']],
        'findings': findings,
        'started_at': '2026-11-05T00:00:00Z',
    }

def test_sqlite_snapshots_mask_and_reconcile_only_same_complete_full_scope(tmp_path):
    store = state.Store(tmp_path / 'state')
    f = finding()
    f['description'] = 'password=secret-value'
    f['check_id'] = 'sast'
    old = run('old', [f])
    store.save_run(old)
    assert 'secret-value' not in store.get_run('old')['findings'][0]['description']
    assert store.latest_run()['run_id'] == 'old'
    partial = store.reconcile(run('partial', [], scope='diff'))
    assert partial['findings'][0]['lifecycle'] == 'open'
    different = store.reconcile(run('different', [], source_hash='other'))
    assert different['findings'][0]['lifecycle'] == 'open'
    full = store.reconcile(run('full', []))
    assert full['findings'][0]['lifecycle'] == 'remediation-proposed'
    assert full['findings'][0]['validation'] == 'undetermined'
    bad = run('bad', [])
    bad['checks'][0]['status'] = 'failed'
    assert store.reconcile(bad)['findings'][0]['lifecycle'] == 'open'
    drift = run('drift', [])
    drift['checks'][0]['engine']['rules_hash'] = 'changed'
    assert store.reconcile(drift)['findings'][0]['lifecycle'] == 'open'
    assert store.get_run('old')['findings'][0]['lifecycle'] == 'open'

def test_project_cannot_select_executable_or_inject_runtime_trust(tmp_path):
    for field in [{'tools': {'semgrep': {'command': './malicious.py'}}}, {'_trusted_policy': {'allow_dynamic': True}}, {'tools': {'osv': {'command': ['python', 'payload.py']}}}]:
        p = tmp_path / 'gxsec.json'
        p.write_text(json.dumps({'schema_version': 1, **field}))
        with pytest.raises(ValueError):
            config.load_config(p)

def test_required_review_ids_must_exist_and_have_trusted_evidence():
    result = policy.evaluate([complete()], [], policy={'required_reviews': ['role-matrix', 'data-disclosure']})
    assert result['status'] == 'INCOMPLETE'
    assert any(('role-matrix' in str(x) for x in result['incomplete']))

def test_secret_literal_redacted_without_label():
    raw = {
        'findings': [{
            'category': 'secrets',
            'secret': 'inert-secret-marker',
            'description': 'failed with inert-secret-marker',
            'evidence_refs': ['inert-secret-marker'],
        }],
        'errors': ['inert-secret-marker'],
    }
    assert 'inert-secret-marker' not in json.dumps(redaction.redact(raw))

def test_redaction_identifier_variants_and_json_literals():
    cases = ['private String jwtSecret = "fake-sensitive-literal";', 'JWT_SECRET_KEY=fake-sensitive-literal', 'DB_PASSWORD=fake-sensitive-literal', '{"accessToken":"fake-sensitive-literal"}', 'myApiKey="fake-sensitive-literal"', 'String cookieValue = "fake-sensitive-literal";']
    for snippet in cases:
        assert 'fake-sensitive-literal' not in redaction.redact(snippet), snippet
    assert redaction.redact({'semantic_rule_id': 'token-path', 'title': 'token validation needed'})['semantic_rule_id'] == 'token-path'

def test_reviews_apply_only_independently_trusted_and_scoped_decisions():
    f = finding('candidate', None)
    review = {
        'id': 'review1',
        'finding_id': f['finding_id'],
        'decision': 'source-verified',
        'severity': 'High',
        'source_revision': 'abc',
        'scope_hash': 'scope',
        'evidence_refs': ['source:A.java:2'],
        'reason': 'Verified user flow',
    }
    p = {
        'source_revision': 'abc',
        'scope_hash': 'scope',
        'trusted_approvals': [{
            'record_id': 'review1',
            'digest': models.content_hash(review),
            'kind': 'finding-validation',
            'roles': ['independent-reviewer'],
        }],
    }
    applied = policy.apply_reviews([f], [review], policy=p)
    assert applied[0]['validation'] == 'source-verified' and applied[0]['severity'] == 'High'
    assert f['validation'] == 'candidate'
    assert policy.evaluate([complete()], [f], reviews=[review], policy=p)['status'] == 'BLOCK'
    assert policy.apply_reviews([f], [review], policy={})[0]['validation'] == 'candidate'
    forged = dict(review, decision='refuted')
    assert policy.apply_reviews([f], [forged], policy=p)[0]['validation'] == 'candidate'
    refute = dict(review, decision='refuted')
    p['trusted_approvals'] = [{
        'record_id': 'review1',
        'digest': models.content_hash(refute),
        'kind': 'finding-refutation',
        'roles': ['security-reviewer'],
    }]
    applied = policy.apply_reviews([f], [refute], policy=p)
    assert applied[0]['validation'] == 'refuted'
    assert policy.evaluate([complete()], applied, reviews=[refute], policy=p)['status'] == 'PASS'

def test_review_cannot_downgrade_high_without_security_authority():
    f = finding()
    review = {
        'id': 'downgrade',
        'finding_id': f['finding_id'],
        'decision': 'source-verified',
        'severity': 'Low',
        'source_revision': 'abc',
        'scope_hash': 'scope',
        'evidence_refs': ['source:2'],
    }
    p = {
        'source_revision': 'abc',
        'scope_hash': 'scope',
        'trusted_approvals': [{
            'record_id': review['id'],
            'digest': models.content_hash(review),
            'kind': 'finding-validation',
            'roles': ['independent-reviewer'],
        }],
    }
    assert policy.apply_reviews([f], [review], policy=p)[0]['severity'] == 'High'

def test_invalid_active_low_exception_does_not_disappear():
    f = finding(severity='Low')
    ex = {'id': 'expired', 'finding_id': f['finding_id'], 'expires_at': '2020-01-01T00:00:00Z'}
    assert policy.evaluate([complete()], [f], exceptions=[ex])['status'] == 'INCOMPLETE'

def test_profile_file_has_separate_config_hash_and_tool_cache_is_excluded(tmp_path):
    (tmp_path / 'A.java').write_text('class A {}')
    first = source.collect_source(tmp_path)
    (tmp_path / 'gxsec.yaml').write_text('profile: first')
    (tmp_path / '.gxsec-tools').mkdir()
    (tmp_path / '.gxsec-tools' / 'tool.exe').write_text('fixture')
    second = source.collect_source(tmp_path)
    assert second['hash'] == first['hash']
    assert 'gxsec.yaml' in second['files']

def test_nested_json_snippet_and_url_fragment_credentials_are_masked():
    assert 'fixture-sensitive-value' not in redaction.redact('{"user":{"accessToken":"fixture-sensitive-value"}}')
    assert 'fixture-sensitive-value' not in redaction.redact('https://example.test/callback#access_token=fixture-sensitive-value&state=xyz')

def test_source_git_reads_disable_repository_execution_hooks(tmp_path, monkeypatch):
    calls=[]
    def execute(cmd,**kwargs):
        calls.append((cmd,kwargs))
        return __import__('subprocess').CompletedProcess(cmd,0,'','')
    monkeypatch.setattr(source.subprocess,'run',execute)
    monkeypatch.setattr(source,'trusted_runtime_tool',lambda *args:{'executable':'git'})
    source.collect_source(tmp_path)
    assert calls
    assert all('core.fsmonitor=false' in cmd for cmd,_ in calls)
    assert all(kwargs['env']['GIT_OPTIONAL_LOCKS']=='0' for _,kwargs in calls)

def test_dirty_git_tree_uses_content_revision_for_review_binding(tmp_path, monkeypatch):
    (tmp_path/'A.java').write_text('class A {}')
    def git(_root,*args):
        if args==('rev-parse','HEAD'):return 'abc123'
        if args[0]=='status':return ' M A.java'
        return 'false'
    monkeypatch.setattr(source,'_git',git)
    inventory=source.collect_source(tmp_path)
    assert inventory['dirty'] is True
    assert inventory['revision']==inventory['hash']

@pytest.mark.parametrize('component', ['runs', 'state.sqlite3', 'state.sqlite3-journal'])
def test_state_rejects_symlink_storage_components(tmp_path, monkeypatch, component):
    base=tmp_path/'state';base.mkdir()
    original=Path.is_symlink
    monkeypatch.setattr(Path,'is_symlink',lambda path: str(path)==str(base/component) or original(path))
    with pytest.raises(ValueError,match='symlink'):
        state.Store(base)

def test_identical_snippets_in_different_files_keep_distinct_fingerprints():
    first=models.make_finding(category='xss',rule='xss.output',path='src/A.java',line=2,snippet='print(user)',severity='High')
    second=models.make_finding(category='xss',rule='xss.output',path='src/B.java',line=2,snippet='print(user)',severity='High')
    assert first['fingerprint']!=second['fingerprint']


def test_rename_matching_requires_unique_semantic_anchor(tmp_path):
    store=state.Store(tmp_path/'state')
    before=models.make_finding(category='xss',rule='xss.output',path='src/A.java',line=2,snippet='print(user)',severity='High')
    renamed=models.make_finding(category='xss',rule='xss.output',path='src/Renamed.java',line=90,snippet='print(user)',severity='High')
    previous=run('old',[before])
    current=store.reconcile(run('new',[renamed]),previous)
    assert len(current['findings'])==1
    assert current['findings'][0]['finding_id']==before['finding_id']
    duplicate=models.make_finding(category='xss',rule='xss.output',path='src/B.java',line=3,snippet='print(user)',severity='High')
    ambiguous=store.reconcile(run('ambiguous',[renamed]),run('previous',[before,duplicate]))
    assert ambiguous['findings'][0]['finding_id'] not in {before['finding_id'],duplicate['finding_id']}
    assert len(ambiguous['findings'])==3

@pytest.mark.parametrize('status,eligible,scanned', [('pass',1,1),('completed',1,1),('COMPLETE',1,1),('complete',True,True),('complete',1.0,1.0),('complete',1.5,1.5),('complete',float('nan'),float('nan')),('complete',float('inf'),float('inf')),('complete',1,2)])
def test_gate_rejects_noncanonical_completion_and_coverage(status,eligible,scanned):
    check=complete();check['status']=status;check['coverage'].update(eligible=eligible,scanned=scanned)
    assert policy.evaluate([check],[])['status']=='INCOMPLETE'


def test_shared_snippets_and_nested_diagnostics_are_omitted():
    value={'snippet':'<password>fixture-sensitive-value</password>','errors':[{'details':{'message':'fixture-sensitive-value'}}]}
    assert 'fixture-sensitive-value' not in json.dumps(redaction.redact(value))
    f=models.make_finding(category='sast',rule='test',path='A.java',snippet='unlabelled fixture-sensitive-value')
    assert 'fixture-sensitive-value' not in json.dumps(f)


def test_narrower_eligible_scope_cannot_close_prior_findings(tmp_path):
    store=state.Store(tmp_path/'state');f=finding();f['check_id']='sast'
    before=run('old',[f]);after=run('after',[])
    before['checks'][0]['coverage'].update(eligible=2,scanned=2,files=['A.java','B.java'])
    after['checks'][0]['coverage'].update(eligible=1,scanned=1,files=['A.java'])
    assert store.reconcile(after,before)['findings'][0]['lifecycle']=='open'


def test_reparse_entries_are_not_traversed_or_used_for_state(tmp_path,monkeypatch):
    linked=tmp_path/'junction';linked.mkdir();(linked/'secret.java').write_text('private')
    original=getattr(Path,'is_junction',lambda _:False)
    monkeypatch.setattr(Path,'is_junction',lambda p: p==linked or original(p),raising=False)
    inventory=source.collect_source(tmp_path)
    assert 'junction/secret.java' not in inventory['files'] and inventory['errors']
    with pytest.raises(ValueError):state.Store(linked)
