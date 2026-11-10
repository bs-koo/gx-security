import datetime as dt
import json
import subprocess
import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from gxsec import adapters, config, policy, source


def mock_engine_process(monkeypatch, execute):
    # Native engine and Git invocations share inert fixtures; production capture is tested separately.
    monkeypatch.setattr(adapters, '_process', execute)
    monkeypatch.setattr(adapters.subprocess, 'run', execute)


@pytest.fixture(autouse=True)
def approved_runtime(tmp_path, monkeypatch):
    directory = tmp_path.parent / (tmp_path.name + '-runtime')
    directory.mkdir(exist_ok=True)
    versions = {'semgrep':'1.172.0','osv':'2.7.0','gitleaks':'8.30.1','git':'2.47.0','python':'3.12.5'}
    names = {'osv':'osv-scanner'}
    entries = {}
    for name, version in versions.items():
        executable = directory / names.get(name, name)
        executable.write_text('approved inert test fixture ' + name)
        entries[name] = {'executable':str(executable), 'sha256':__import__('hashlib').sha256(executable.read_bytes()).hexdigest(), 'version':version}
    manifest = directory / 'tool-provenance.json'
    manifest.write_text(json.dumps({'schema_version':1,'tools':entries}))
    monkeypatch.setenv('GXSEC_RUNTIME_MANIFEST',str(manifest))

def fixture(tmp_path):
    (tmp_path / 'A.java').write_text('class A {}')
    (tmp_path / 'package-lock.json').write_text(
        '{"name":"demo","lockfileVersion":3,"packages":{"node_modules/a":{"name":"a","version":"1.0.0"}}}',
    )
    cfg = config.default_config(tmp_path)
    return cfg

def test_missing_engines_and_malformed_output_incomplete(tmp_path, monkeypatch):
    cfg = fixture(tmp_path)
    monkeypatch.delenv('GXSEC_RUNTIME_MANIFEST', raising=False)
    monkeypatch.setattr(adapters.shutil, 'which', lambda _: None)
    checks, findings = adapters.run_static_checks(tmp_path, cfg, 'static-release')
    assert {c['id'] for c in checks} >= {'sast', 'sca', 'secrets'}
    assert all(c['status'] != 'complete' for c in checks if c['id'] in {'sast', 'sca', 'secrets'})
    assert policy.evaluate(checks, findings)['status'] == 'INCOMPLETE'

def test_subprocess_boundary_semgrep_all_rules_and_parse_failures(tmp_path, monkeypatch):
    cfg = fixture(tmp_path)
    calls = []
    monkeypatch.setattr(adapters.shutil, 'which', lambda c: c)

    def execute(cmd, **kw):
        calls.append((cmd, kw))
        if '--version' in cmd:
            return subprocess.CompletedProcess(cmd, 0, '1.172.0' if 'semgrep' in cmd[0] else '8.30.1', '')
        if Path(cmd[0]).name == 'semgrep':
            return subprocess.CompletedProcess(
                cmd,
                0,
                json.dumps({'results': [], 'errors': [{'type': 'PartialParsing'}], 'paths': {'scanned': ['A.java']}}),
                '',
            )
        return subprocess.CompletedProcess(cmd, 0, '[]', '')
    mock_engine_process(monkeypatch, execute)
    checks, _ = adapters.run_static_checks(tmp_path, cfg, 'static-release')
    sast = next((c for c in checks if c['id'] == 'sast'))
    assert sast['status'] != 'complete' and sast['errors']
    semgrep = next((c for c, k in calls if Path(c[0]).name == 'semgrep' and '--version' not in c))
    assert sum((1 for x in semgrep if x == '--config')) == 10
    assert any((x.endswith('xss-frontend.yml') for x in semgrep))
    assert '--metrics=off' in semgrep and '--disable-version-check' in semgrep
    assert all((k.get('timeout', 0) > 0 and k.get('shell') is False for _, k in calls))

def test_osv_stale_missing_provenance_and_unknown_severity(tmp_path, monkeypatch):
    cfg = fixture(tmp_path)
    db = tmp_path / 'db'
    db.mkdir()
    (db / 'all.zip').write_bytes(b'fake')
    cfg['tools']['osv']['offline_db'] = str(db)
    cfg['tools']['osv']['db_generated_at'] = '2020-01-01T00:00:00Z'
    monkeypatch.setattr(adapters.shutil, 'which', lambda c: c)
    calls = []

    def execute(cmd, **kw):
        calls.append((cmd, kw))
        if '--version' in cmd:
            return subprocess.CompletedProcess(
                cmd,
                0,
                '2.7.0' if Path(cmd[0]).name == 'osv-scanner' else '1.172.0' if Path(cmd[0]).name == 'semgrep' else '8.30.1',
                '',
            )
        if Path(cmd[0]).name == 'osv-scanner':
            return subprocess.CompletedProcess(
                cmd,
                1,
                json.dumps(
                    {
                        'results': [{
                            'source': {'path': 'package-lock.json', 'type': 'lockfile'},
                            'packages': [{
                                'package': {'name': 'a', 'version': '1.0.0', 'ecosystem': 'npm'},
                                'vulnerabilities': [{'id': 'GHSA-demo', 'summary': 'example'}],
                            }],
                        }],
                    },
                ),
                '',
            )
        if Path(cmd[0]).name == 'semgrep':
            return subprocess.CompletedProcess(
                cmd,
                0,
                json.dumps({'results': [], 'errors': [], 'paths': {'scanned': ['A.java']}}),
                '',
            )
        return subprocess.CompletedProcess(cmd, 0, '[]', '')
    mock_engine_process(monkeypatch, execute)
    checks, findings = adapters.run_static_checks(tmp_path, cfg, 'static-release')
    sca = next((c for c in checks if c['id'] == 'sca'))
    assert sca['status'] != 'complete' and any(('stale' in str(e).lower() for e in sca['errors']))
    if any((Path(c[0]).name == 'osv-scanner' and '--version' not in c for c, k in calls)):
        cmd, kw = next(((c, k) for c, k in calls if Path(c[0]).name == 'osv-scanner' and '--version' not in c))
        assert '--offline' in cmd and '--all-packages' in cmd
        assert kw['env']['OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY'] != str(db)
    assert policy.evaluate(checks, findings)['status'] == 'INCOMPLETE'

def test_gitleaks_directory_and_history_reports_redacted(tmp_path, monkeypatch):
    cfg = fixture(tmp_path)
    (tmp_path / '.git').mkdir()
    (tmp_path / '.env').write_text('API_KEY=private-value')
    cfg['_inventory'] = source.collect_source(tmp_path)
    commit = 'a' * 40
    refs = [commit + ' HEAD', commit + ' refs/heads/main']
    cfg['_inventory'].update(git=True, commit=commit, git_refs=refs, shallow=False)
    calls = []
    monkeypatch.setattr(adapters.shutil, 'which', lambda c: c)

    def execute(cmd, **kw):
        calls.append(cmd)
        if '--version' in cmd:
            return subprocess.CompletedProcess(cmd, 0, '8.30.1', '')
        if Path(cmd[0]).name == 'git':
            if 'clone' in cmd:
                target = Path(cmd[-1]);target.mkdir();(target / 'HEAD').write_text('ref: refs/heads/main');(target / 'config').write_text('[core]\n bare = true\n')
                return subprocess.CompletedProcess(cmd, 0, '', '')
            if '--show-object-format' in cmd:
                return subprocess.CompletedProcess(cmd, 0, 'sha1', '')
            if 'show-ref' in cmd:
                return subprocess.CompletedProcess(cmd, 0, '\n'.join(refs), '')
            if 'rev-parse' in cmd:
                return subprocess.CompletedProcess(cmd, 0, commit, '')
            return subprocess.CompletedProcess(cmd, 0, '', '')
        if Path(cmd[0]).name == 'gitleaks':
            report = Path(cmd[cmd.index('--report-path') + 1])
            report.write_text(
                json.dumps(
                    [{
                        'RuleID': 'generic-api-key',
                        'Description': 'api_key=private-value',
                        'Secret': 'private-value',
                        'Match': 'api_key=private-value',
                        'File': '.env',
                        'StartLine': 1,
                    }],
                ),
            )
            return subprocess.CompletedProcess(cmd, 1, '', '')
        return subprocess.CompletedProcess(cmd, 0, '{}', '')
    mock_engine_process(monkeypatch, execute)
    checks, findings = adapters.run_static_checks(tmp_path, cfg, 'static-release')
    assert {c[1] for c in calls if Path(c[0]).name == 'gitleaks' and '--version' not in c} == {'git', 'dir'}
    assert all(
        ('--ignore-gitleaks-allow' in c and '--redact=100' in c for c in calls if Path(c[0]).name == 'gitleaks' and '--version' not in c),
    )
    assert any((f['category'] == 'secrets' and f['locations'][0]['path'] == '.env' for f in findings))
    assert 'private-value' not in json.dumps([checks, findings])

def test_semgrep_malformed_and_timeout_are_not_complete(tmp_path, monkeypatch):
    cfg = fixture(tmp_path)
    cfg['tools']['semgrep']['fallback'] = False
    monkeypatch.setattr(adapters.shutil, 'which', lambda c: c if c == 'semgrep' else None)

    def malformed(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 0, '1.172.0' if '--version' in cmd else 'not json', '')
    mock_engine_process(monkeypatch, malformed)
    checks, _ = adapters.run_static_checks(tmp_path, cfg, 'check')
    assert checks[0]['status'] == 'incomplete' and any((e['type'] == 'malformed_output' for e in checks[0]['errors']))

    def timeout(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, kw['timeout'])
    mock_engine_process(monkeypatch, timeout)
    checks, _ = adapters.run_static_checks(tmp_path, cfg, 'check')
    assert checks[0]['status'] == 'incomplete'

def test_engine_version_mismatch_and_repo_executable_never_run(tmp_path, monkeypatch):
    cfg = fixture(tmp_path)
    cfg['tools']['semgrep']['fallback'] = False
    calls = []
    cfg['tools']['semgrep']['command'] = 'python'
    monkeypatch.setattr(adapters.shutil, 'which', lambda c: c)

    def execute(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, '99.0.0', '')
    mock_engine_process(monkeypatch, execute)
    checks, _ = adapters.run_static_checks(tmp_path, cfg, 'static-release')
    assert not any((Path(c[0]).name == 'python' for c in calls))
    assert all(c['status'] == 'incomplete' for c in checks if c['id'] in {'sast', 'sca', 'secrets'})

def test_osv_fresh_complete_offline_input_and_unknown_advisory_severity(tmp_path, monkeypatch):
    src = tmp_path / 'source'
    src.mkdir()
    cfg = fixture(src)
    # Offline DB metadata is prepared independently of the inspected repository.
    db = tmp_path / 'db'
    db.mkdir()
    archive = db / 'osv-scalibr' / 'npm' / 'all.zip'
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b'offline-snapshot')
    manifest = {
        'schema_version': 1,
        'generated_at': dt.datetime.now(dt.timezone.utc).isoformat(),
        'advisory_as_of': '2026-11-05',
        'files': {'osv-scalibr/npm/all.zip': __import__('hashlib').sha256(archive.read_bytes()).hexdigest()},
    }
    (db / 'snapshot.json').write_text(json.dumps(manifest))
    cfg['tools']['osv']['offline_db'] = str(db)
    inventory = source.collect_source(src)
    cfg['sca'] = {
        'source_revision': inventory['commit'] or inventory['hash'],
        'input_hashes': {i['path']: i['hash'] for i in inventory['inventory'] if i['path'] == 'package-lock.json'},
        'modules': ['.'],
        'runtime_complete': True,
    }
    from gxsec.models import content_hash
    provenance={**cfg['sca'],'id':'dependencies','scope_hash':inventory['scope_hash'],'artifact_digest':'sha256:fixture-artifact'}
    cfg['_trusted_policy']={'sca':{'offline_db':str(db),'db_manifest_sha256':__import__('hashlib').sha256((db/'snapshot.json').read_bytes()).hexdigest(),'provenance':provenance},'trusted_approvals':[{'record_id':'dependencies','digest':content_hash(provenance),'kind':'dependency-provenance','roles':['protected-ci']}]}
    calls = []
    monkeypatch.setattr(adapters.shutil, 'which', lambda c: c)

    def execute(cmd, **kw):
        calls.append((cmd, kw))
        if '--version' in cmd:
            return subprocess.CompletedProcess(
                cmd,
                0,
                {'semgrep': '1.172.0', 'osv-scanner': '2.7.0', 'gitleaks': '8.30.1'}[Path(cmd[0]).name],
                '',
            )
        if Path(cmd[0]).name == 'osv-scanner':
            return subprocess.CompletedProcess(
                cmd,
                1,
                json.dumps(
                    {
                        'results': [{
                            'source': {'path': cmd[cmd.index('--lockfile') + 1], 'type': 'lockfile'},
                            'packages': [{
                                'package': {'name': 'a', 'version': '1.0.0', 'ecosystem': 'npm', 'purl': 'pkg:npm/a@1.0.0?source=PUBLIC_REGISTRY'},
                                'vulnerabilities': [{'id': 'GHSA-demo', 'summary': 'Requires classification'}],
                            }],
                        }],
                    },
                ),
                'Loaded npm local db from ' + str(Path(kw['env']['OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY']) / 'osv-scalibr/npm/all.zip') + '\n',
            )
        if Path(cmd[0]).name == 'semgrep':
            return subprocess.CompletedProcess(
                cmd,
                0,
                json.dumps({'results': [], 'errors': [], 'paths': {'scanned': [str(Path(cmd[-1]) / 'A.java')]}}),
                '',
            )
        if Path(cmd[0]).name == 'gitleaks':
            Path(cmd[cmd.index('--report-path') + 1]).write_text('[]')
            return subprocess.CompletedProcess(cmd, 0, '', '')
        return subprocess.CompletedProcess(cmd, 0, '', '')
    mock_engine_process(monkeypatch, execute)
    checks, findings = adapters.run_static_checks(src, cfg, 'static-release')
    assert next((c for c in checks if c['id'] == 'sca'))['status'] == 'complete', checks
    assert findings[0]['severity'] is None
    assert policy.evaluate(checks, findings)['status'] == 'INCOMPLETE'
    cmd, kw = next(((cmd, kw) for cmd, kw in calls if Path(cmd[0]).name == 'osv-scanner' and '--version' not in cmd))
    assert '--offline' in cmd and '--all-packages' in cmd and ('--config' in cmd)
    assert kw['env']['OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY'] != str(db)
    assert not Path(kw['env']['OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY']).exists()
    archive.write_bytes(b'tampered')
    checks, _ = adapters.run_static_checks(src, cfg, 'static-release')
    assert next((c for c in checks if c['id'] == 'sca'))['status'] == 'incomplete'
    assert any(('hash' in str(e).lower() for c in checks for e in c['errors']))

def test_gitleaks_redacted_engine_tokens_do_not_merge_distinct_locations(tmp_path, monkeypatch):
    cfg = fixture(tmp_path)
    (tmp_path / '.env').write_text('API_KEY=synthetic-one\nAPI_KEY=synthetic-two\n')
    monkeypatch.setattr(adapters.shutil, 'which', lambda c: c if c == 'gitleaks' else None)
    cfg['tools']['semgrep']['fallback'] = False

    def execute(cmd, **kw):
        if '--version' in cmd:
            return subprocess.CompletedProcess(cmd, 0, '8.30.1', '')
        if Path(cmd[0]).name == 'gitleaks':
            Path(cmd[cmd.index('--report-path') + 1]).write_text(
                json.dumps(
                    [{'RuleID': 'generic', 'Secret': 'REDACTED', 'Match': 'REDACTED', 'File': '.env', 'StartLine': i} for i in [1, 2]],
                ),
            )
            return subprocess.CompletedProcess(cmd, 1, '', '')
        return subprocess.CompletedProcess(cmd, 0, '', '')
    mock_engine_process(monkeypatch, execute)
    _, findings = adapters.run_static_checks(tmp_path, cfg, 'check')
    assert len(findings) == 2
    assert 'synthetic-one' not in json.dumps(findings)

def test_semgrep_uses_real_source_slices_and_keeps_same_file_occurrences_distinct(tmp_path,monkeypatch):
    cfg=fixture(tmp_path)
    (tmp_path/'A.java').write_text('class A {\n void show() {\n  render(user);\n  render(user);\n }\n}\n')
    cfg['tools']['semgrep']['fallback']=False
    monkeypatch.setattr(adapters.shutil,'which',lambda c:c if c=='semgrep' else None)
    def execute(cmd,**kw):
        if '--version' in cmd:return subprocess.CompletedProcess(cmd,0,'1.172.0','')
        if Path(cmd[0]).name=='semgrep':
            return subprocess.CompletedProcess(cmd,0,json.dumps({'results':[{'check_id':'demo.output','path':str(Path(cmd[-1])/'A.java'),'start':{'line':line},'end':{'line':line},'extra':{'lines':'requires login','message':'Review output'}} for line in [3,4]],'errors':[],'paths':{'scanned':[str(Path(cmd[-1])/'A.java')]}}),'')
        return subprocess.CompletedProcess(cmd,0,'','')
    mock_engine_process(monkeypatch, execute)
    _,findings=adapters.run_static_checks(tmp_path,cfg,'check')
    assert len(findings)==2
    assert len({f['finding_id'] for f in findings})==2
    assert all(f['snippet'].startswith('[OMITTED') for f in findings)
    assert all(f['file_hash']==__import__('hashlib').sha256((tmp_path/'A.java').read_bytes()).hexdigest() and len(f['normalized_result_hash'])==64 for f in findings)
    assert all(f['locations'][0]['symbol'] for f in findings)

@pytest.mark.parametrize('value', ['NaN','Infinity','-Infinity'])
def test_nonfinite_security_scores_stay_unknown(value):
    assert adapters._severity(value) is None


def test_adapters_reuse_one_inventory_and_record_honest_full_scope(tmp_path,monkeypatch):
    cfg=fixture(tmp_path);cfg['_inventory']=source.collect_source(tmp_path);cfg['_scan_scope']={'scope':'diff','base':'base','changed_files':['A.java']}
    cfg['tools']['semgrep']['fallback']=False
    monkeypatch.setattr(adapters,'collect_source',lambda _: (_ for _ in ()).throw(AssertionError('second inventory collection')))
    monkeypatch.setattr(adapters.shutil,'which',lambda _:None)
    checks,_=adapters.run_static_checks(tmp_path,cfg,'check')
    assert all(c['coverage']['scope']=='full' and c['coverage']['requested_scope']=='diff' for c in checks)


def test_project_database_path_is_never_read(tmp_path,monkeypatch):
    cfg=fixture(tmp_path);db=tmp_path/'database';db.mkdir();cfg['tools']['osv']['offline_db']=str(db);cfg['tools']['semgrep']['fallback']=False
    old=Path.rglob
    def denied(p,pattern):
        if p==db:raise AssertionError('project-directed database read')
        return old(p,pattern)
    monkeypatch.setattr(Path,'rglob',denied)
    monkeypatch.setattr(adapters.shutil,'which',lambda _:None)
    checks,_=adapters.run_static_checks(tmp_path,cfg,'static-release')
    sca=next(c for c in checks if c['id']=='sca')
    assert not any('project-directed database read' in str(e) for e in sca['errors'])
    assert sca['status']=='incomplete'


def test_absent_runtime_provenance_never_executes_engine(tmp_path,monkeypatch):
    cfg=fixture(tmp_path);cfg['tools']['semgrep']['fallback']=False;calls=[]
    monkeypatch.delenv('GXSEC_RUNTIME_MANIFEST',raising=False)
    monkeypatch.setattr(adapters.shutil,'which',lambda c:c)
    def execute(cmd,**kwargs):
        calls.append(cmd);return subprocess.CompletedProcess(cmd,0,'1.172.0','')
    mock_engine_process(monkeypatch, execute)
    checks,_=adapters.run_static_checks(tmp_path,cfg,'check')
    assert not any(Path(c[0]).name in {'semgrep','gitleaks','osv-scanner'} for c in calls)
    assert all(c['status']=='incomplete' for c in checks if c['id'] in {'sast', 'sca', 'secrets'})


def test_subprocess_environment_drops_ambient_secrets_and_proxy(tmp_path,monkeypatch):
    observed={};monkeypatch.setenv('GXSEC_TEST_SECRET','fixture-sensitive-value');monkeypatch.setenv('HTTP_PROXY','http://proxy.test')
    def execute(cmd,**kwargs):observed.update(kwargs['env']);return subprocess.CompletedProcess(cmd,0,'','')
    mock_engine_process(monkeypatch, execute)
    adapters._run(['trusted-tool'],cwd=tmp_path)
    assert 'GXSEC_TEST_SECRET' not in observed and 'HTTP_PROXY' not in observed

def test_tampered_runtime_executable_is_not_probed(tmp_path,monkeypatch):
    manifest=json.loads(Path(__import__('os').environ['GXSEC_RUNTIME_MANIFEST']).read_text())
    executable=Path(manifest['tools']['semgrep']['executable']);executable.write_text('changed after approval')
    calls=[]
    mock_engine_process(monkeypatch, lambda cmd,**kwargs:calls.append(cmd))
    result=adapters.probe_engine('semgrep',{},tmp_path)
    assert result['status']=='incomplete' and calls==[]
    assert 'digest' in str(result['errors']).lower()


def test_semgrep_unstructured_diagnostics_and_xml_secret_never_export(tmp_path,monkeypatch):
    cfg=fixture(tmp_path);(tmp_path/'A.java').write_text('class A { String x = "fixture-sensitive-value"; }')
    def execute(cmd,**kwargs):
        if '--version' in cmd:return subprocess.CompletedProcess(cmd,0,'1.172.0','')
        return subprocess.CompletedProcess(cmd,0,json.dumps({'results':[{'check_id':'demo','path':str(tmp_path/'A.java'),'start':{'line':1},'end':{'line':1},'extra':{'lines':'<password>fixture-sensitive-value</password>','message':'fixture-sensitive-value','details':{'message':'fixture-sensitive-value'}}}],'errors':[{'type':'PartialParsing','message':'fixture-sensitive-value','details':{'message':'fixture-sensitive-value'},'code':3}],'paths':{'scanned':[str(tmp_path/'A.java')]}}),'')
    mock_engine_process(monkeypatch, execute)
    check,findings=adapters._sast(tmp_path,cfg,source.collect_source(tmp_path),'check')
    assert 'fixture-sensitive-value' not in json.dumps([check,findings])
    assert check['errors']==[{'type':'semgrep_diagnostic','error_type':'PartialParsing','code':3}]

def test_subprocess_home_is_ephemeral_and_does_not_read_host_home(tmp_path,monkeypatch):
    host_home=tmp_path/'host-home';host_home.mkdir();(host_home/'credentials').write_text('fixture-sensitive-value')
    monkeypatch.setenv('HOME',str(host_home));observed={}
    def execute(cmd,**kwargs):
        observed.update(kwargs['env'])
        assert Path(observed['HOME']).exists() and observed['HOME']!=str(host_home)
        assert observed['XDG_CACHE_HOME'].startswith(observed['HOME'])
        return subprocess.CompletedProcess(cmd,0,'','')
    mock_engine_process(monkeypatch, execute)
    adapters._run(['approved-tool'],cwd=tmp_path)
    assert not Path(observed['HOME']).exists()

def test_static_engines_read_private_snapshot_during_swap_and_restore(tmp_path,monkeypatch):
    cfg=fixture(tmp_path);original='class A { String vulnerable = "input"; }';safe='class A {}'
    (tmp_path/'A.java').write_text(original);cfg['_inventory']=source.collect_source(tmp_path);observed=[]
    def execute(cmd,**kwargs):
        name=Path(cmd[0]).name
        if '--version' in cmd:return subprocess.CompletedProcess(cmd,0,{'semgrep':'1.172.0','osv-scanner':'2.7.0','gitleaks':'8.30.1'}[name],'')
        if name=='semgrep':
            (tmp_path/'A.java').write_text(safe)
            scan_root=Path(cmd[-1]);observed.append((scan_root,(scan_root/'A.java').read_text()))
            (tmp_path/'A.java').write_text(original)
            return subprocess.CompletedProcess(cmd,0,json.dumps({'results':[],'errors':[],'paths':{'scanned':[str(scan_root/'A.java')]}}),'')
        if name=='gitleaks':Path(cmd[cmd.index('--report-path')+1]).write_text('[]');return subprocess.CompletedProcess(cmd,0,'','')
        return subprocess.CompletedProcess(cmd,0,'','')
    mock_engine_process(monkeypatch, execute)
    checks,_=adapters.run_static_checks(tmp_path,cfg,'check')
    assert observed and observed[0][0]!=tmp_path and observed[0][1]==original
    assert (tmp_path/'A.java').read_text()==original
    assert all(c['snapshot']['copy_verified'] is True and c['snapshot']['stable_after_scan'] is True and c['snapshot']['digest'] for c in checks)


def test_changed_initial_source_and_modified_private_copy_are_incomplete(tmp_path,monkeypatch):
    cfg=fixture(tmp_path);cfg['_inventory']=source.collect_source(tmp_path);(tmp_path/'A.java').write_text('class Changed {}')
    calls=[]
    def execute(cmd,**kwargs):calls.append(cmd);return subprocess.CompletedProcess(cmd,0,'1.172.0','')
    mock_engine_process(monkeypatch, execute)
    checks,_=adapters.run_static_checks(tmp_path,cfg,'check')
    assert all(c['status']=='incomplete' for c in checks) and calls==[]
    cfg['_inventory']=source.collect_source(tmp_path)
    def mutate(cmd,**kwargs):
        name=Path(cmd[0]).name
        if '--version' in cmd:return subprocess.CompletedProcess(cmd,0,{'semgrep':'1.172.0','osv-scanner':'2.7.0','gitleaks':'8.30.1'}[name],'')
        if name=='semgrep':
            target=Path(cmd[-1])/'A.java';target.chmod(0o600);target.write_text('changed inside private copy')
            return subprocess.CompletedProcess(cmd,0,json.dumps({'results':[],'errors':[],'paths':{'scanned':[str(target)]}}),'')
        return subprocess.CompletedProcess(cmd,0,'[]','')
    mock_engine_process(monkeypatch, mutate)
    checks,_=adapters.run_static_checks(tmp_path,cfg,'check')
    assert all(c['status']=='incomplete' and c['snapshot']['stable_after_scan'] is False for c in checks)


def test_snapshot_preserves_original_tool_trust_boundary(tmp_path,monkeypatch):
    cfg=fixture(tmp_path);exe=tmp_path/'untrusted-engine';exe.write_text('project owned executable')
    import os,hashlib
    manifest_path=Path(os.environ['GXSEC_RUNTIME_MANIFEST']);manifest=json.loads(manifest_path.read_text());manifest['tools']['semgrep']['executable']=str(exe);manifest['tools']['semgrep']['sha256']=hashlib.sha256(exe.read_bytes()).hexdigest();manifest_path.write_text(json.dumps(manifest));calls=[]
    def execute(cmd,**kwargs):calls.append(cmd);return subprocess.CompletedProcess(cmd,0,'','')
    mock_engine_process(monkeypatch, execute)
    checks,_=adapters.run_static_checks(tmp_path,cfg,'check')
    assert not any(Path(c[0])==exe for c in calls)
    assert next(c for c in checks if c['id']=='sast')['status']=='incomplete'


def test_git_history_snapshot_is_local_independent_and_sanitized(tmp_path,monkeypatch):
    from gxsec.snapshot import verified_snapshot
    fixture(tmp_path);inventory=source.collect_source(tmp_path);commit='a'*40;refs=[commit+' HEAD',commit+' refs/heads/main'];inventory.update(git=True,commit=commit,git_refs=refs,shallow=False);calls=[]
    def execute(cmd,**kwargs):
        calls.append((cmd,kwargs))
        if 'clone' in cmd:
            destination=Path(cmd[-1]);destination.mkdir();(destination/'HEAD').write_text('ref: refs/heads/main\n');(destination/'config').write_text('[core]\n hooksPath = evil\n[remote "origin"]\n url = https://outside.test\n');(destination/'hooks').mkdir();(destination/'hooks'/'post-checkout').write_text('evil');return subprocess.CompletedProcess(cmd,0,'','')
        if '--show-object-format' in cmd:return subprocess.CompletedProcess(cmd,0,'sha1\n','')
        if 'show-ref' in cmd:return subprocess.CompletedProcess(cmd,0,'\n'.join(refs)+'\n','')
        if 'rev-parse' in cmd:return subprocess.CompletedProcess(cmd,0,commit+'\n','')
        return subprocess.CompletedProcess(cmd,0,'','')
    mock_engine_process(monkeypatch, execute)
    with verified_snapshot(tmp_path,inventory) as snap:
        assert snap.provenance['history']['status']=='complete'
        assert not (snap.path/'.git'/'hooks').exists()
        config_text=(snap.path/'.git'/'config').read_text()
        assert 'bare = false' in config_text and 'evil' not in config_text and 'https:' not in config_text
        assert snap.verify() is True
        clone=next((c,k) for c,k in calls if 'clone' in c)
        assert '--mirror' in clone[0] and '--no-hardlinks' in clone[0] and '--no-recurse-submodules' in clone[0]
        assert clone[1]['env']['GIT_ALLOW_PROTOCOL']=='file'

def test_private_history_snapshot_with_real_local_git(tmp_path):
    from gxsec.snapshot import verified_snapshot
    import os,hashlib,shutil
    git=shutil.which('git')
    if not git:pytest.skip('Git unavailable for local history fixture')
    manifest_path=Path(os.environ['GXSEC_RUNTIME_MANIFEST']);manifest=json.loads(manifest_path.read_text());manifest['tools']['git']={'executable':str(Path(git).resolve()),'sha256':hashlib.sha256(Path(git).read_bytes()).hexdigest(),'version':'local-fixture'};manifest_path.write_text(json.dumps(manifest))
    repository=tmp_path/'repo';repository.mkdir();environment=source.runtime_environment();environment.update(HOME=str(tmp_path),USERPROFILE=str(tmp_path))
    def run(*arguments):
        result=subprocess.run([git,'-c','core.hooksPath=','-c','core.fsmonitor=false',*arguments],capture_output=True,text=True,encoding='utf-8',errors='replace',env=environment,timeout=30,shell=False)
        assert result.returncode==0,result.stderr
        return result.stdout
    run('init','--initial-branch=main',str(repository));(repository/'A.java').write_text('class A {}')
    run('-C',str(repository),'add','A.java');run('-c','user.name=Fixture','-c','user.email=fixture@example.invalid','-c','commit.gpgsign=false','-C',str(repository),'commit','--no-verify','-qm','isolated fixture')
    inventory=source.collect_source(repository)
    with verified_snapshot(repository,inventory) as snap:
        assert snap.provenance['history']['status']=='complete',snap.provenance
        assert snap.verify() is True
        assert (snap.path/'A.java').stat().st_nlink==1
        assert 'url =' not in (snap.path/'.git'/'config').read_text()

def osv_matching_fixture(tmp_path):
    import hashlib,zipfile
    cfg=fixture(tmp_path);inventory=source.collect_source(tmp_path)
    db=tmp_path.parent/(tmp_path.name+'-db');archive=db/'osv-scalibr'/'npm'/'all.zip';archive.parent.mkdir(parents=True)
    with zipfile.ZipFile(archive,'w') as bundle:bundle.writestr('GXSEC-SYNTHETIC.json','{"id":"GXSEC-SYNTHETIC"}')
    manifest=db/'snapshot.json';manifest.write_text(json.dumps({'schema_version':1,'generated_at':dt.datetime.now(dt.timezone.utc).isoformat(),'files':{'osv-scalibr/npm/all.zip':hashlib.sha256(archive.read_bytes()).hexdigest()}}))
    provenance={'id':'matching-proof','source_revision':inventory['revision'],'scope_hash':inventory['scope_hash'],'input_hashes':{'package-lock.json':next(row['hash'] for row in inventory['inventory'] if row['path']=='package-lock.json')},'modules':['.'],'runtime_complete':True,'artifact_digest':'sha256:fixture-artifact'}
    cfg['_trusted_policy']={'sca':{'offline_db':str(db),'db_manifest_sha256':hashlib.sha256(manifest.read_bytes()).hexdigest(),'provenance':provenance},'trusted_approvals':[{'record_id':provenance['id'],'digest':adapters.content_hash(provenance),'kind':'dependency-provenance','roles':['protected-ci']}]}
    return cfg,inventory,archive


@pytest.mark.parametrize('origin,loaded,wrong_path,extraction_error', [('LOCAL',False,False,False),('LOCAL',True,False,False),(None,True,False,False),('PUBLIC_REGISTRY',False,False,False),('PUBLIC_REGISTRY',True,True,False),('PUBLIC_REGISTRY',True,False,True)])
def test_osv_parsed_packages_without_advisory_matching_are_incomplete(tmp_path,monkeypatch,origin,loaded,wrong_path,extraction_error):
    cfg,inventory,archive=osv_matching_fixture(tmp_path)
    package={'name':'a','version':'1.0.0','ecosystem':'npm'}
    if origin:package['purl']='pkg:npm/a@1.0.0?source='+origin
    def execute(cmd,**kwargs):
        if '--version' in cmd:return subprocess.CompletedProcess(cmd,0,'2.7.0','')
        scan_archive = Path(kwargs['env']['OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY']) / 'osv-scalibr/npm/all.zip'
        stderr=('Loaded npm local db from '+str(tmp_path/'unapproved.zip' if wrong_path else scan_archive)+'\n') if loaded else ''
        if extraction_error:stderr+='Error during extraction: (extracting as vulnmatch/osvlocal) synthetic matcher failure\n'
        return subprocess.CompletedProcess(cmd,0,json.dumps({'results':[{'source':{'path':str(tmp_path/'package-lock.json'),'type':'lockfile'},'packages':[{'package':package}]}]}),stderr)
    mock_engine_process(monkeypatch, execute)
    check,findings=adapters._sca(tmp_path,cfg,inventory,'static-release')
    assert check['status']=='incomplete'
    assert check['errors'] and findings==[]


def test_osv_approved_loaded_database_and_public_package_prove_matching(tmp_path,monkeypatch):
    cfg,inventory,archive=osv_matching_fixture(tmp_path)
    def execute(cmd,**kwargs):
        if '--version' in cmd:return subprocess.CompletedProcess(cmd,0,'2.7.0','')
        scan_archive = Path(kwargs['env']['OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY']) / 'osv-scalibr/npm/all.zip'
        return subprocess.CompletedProcess(cmd,0,json.dumps({'results':[{'source':{'path':str(tmp_path/'package-lock.json'),'type':'lockfile'},'packages':[{'package':{'name':'a','version':'1.0.0','ecosystem':'npm','purl':'pkg:npm/a@1.0.0?source=PUBLIC_REGISTRY'}}]}]}),'Loaded npm local db from '+str(scan_archive)+'\n')
    mock_engine_process(monkeypatch, execute)
    check,_=adapters._sca(tmp_path,cfg,inventory,'static-release')
    assert check['status']=='complete'
    assert check['coverage']['packages'][0]['purl']=='pkg:npm/a@1.0.0?source=PUBLIC_REGISTRY'
    assert check['coverage']['matching']['complete'] is True
    assert check['coverage']['matching']['loaded_databases'][0]['path']=='osv-scalibr/npm/all.zip'

def test_sast_uses_protected_catalog_guidance_instead_of_native_interpolated_text(tmp_path,monkeypatch):
    cfg=fixture(tmp_path);cfg['tools']['semgrep']['fallback']=False
    def execute(cmd,**kwargs):
        if '--version' in cmd:return subprocess.CompletedProcess(cmd,0,'1.172.0','')
        if Path(cmd[0]).name=='semgrep':
            scan=Path(cmd[-1]);return subprocess.CompletedProcess(cmd,0,json.dumps({'results':[{'check_id':'sqisoft-jdbc-string-concat-query','path':str(scan/'A.java'),'start':{'line':1},'end':{'line':1},'extra':{'message':'unlabelled-sensitive-fixture','severity':'ERROR','metadata':{'severity':'Critical','category':'forged-category','cwe':'forged-cwe'}}}],'errors':[],'paths':{'scanned':[str(scan/'A.java')]}}),'')
        return subprocess.CompletedProcess(cmd,0,'','')
    mock_engine_process(monkeypatch, execute)
    _,findings=adapters.run_static_checks(tmp_path,cfg,'check')
    finding=findings[0]
    assert 'PreparedStatement' in finding['description'] and '\ud50c\ub808\uc774\uc2a4\ud640\ub354' in finding['remediation']['guidance']
    assert finding['category']=='sql-injection' and finding['cwe']=='CWE-89' and finding['stack']=='jsp-legacy'
    assert finding['title']!=finding['rule_id'] and finding['severity']=='High'
    assert 'unlabelled-sensitive-fixture' not in json.dumps(finding) and 'forged-category' not in json.dumps(finding)

def test_osv_loaded_ecosystem_cannot_claim_another_approved_ecosystem_archive(tmp_path,monkeypatch):
    cfg,inventory,archive=osv_matching_fixture(tmp_path)
    database=archive.parents[2];maven=database/'osv-scalibr'/'Maven'/'all.zip';maven.parent.mkdir();maven.write_bytes(archive.read_bytes())
    import hashlib
    manifest=database/'snapshot.json';document=json.loads(manifest.read_text());document['files']['osv-scalibr/Maven/all.zip']=hashlib.sha256(maven.read_bytes()).hexdigest();manifest.write_text(json.dumps(document));cfg['_trusted_policy']['sca']['db_manifest_sha256']=hashlib.sha256(manifest.read_bytes()).hexdigest()
    def execute(cmd,**kwargs):
        if '--version' in cmd:return subprocess.CompletedProcess(cmd,0,'2.7.0','')
        wrong_archive = Path(kwargs['env']['OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY']) / 'osv-scalibr/Maven/all.zip'
        return subprocess.CompletedProcess(cmd,0,json.dumps({'results':[{'source':{'path':str(tmp_path/'package-lock.json'),'type':'lockfile'},'packages':[{'package':{'name':'a','version':'1.0.0','ecosystem':'npm','purl':'pkg:npm/a@1.0.0?source=PUBLIC_REGISTRY'}}]}]}),'Loaded npm local db from '+str(wrong_archive)+'\n')
    mock_engine_process(monkeypatch, execute)
    check,_=adapters._sca(tmp_path,cfg,inventory,'static-release')
    assert check['status']=='incomplete' and check['coverage']['matching']['complete'] is False


@pytest.mark.parametrize('change', ['original-database', 'private-snapshot', 'engine-error'])
def test_osv_scans_verified_private_database_bytes_and_rejects_snapshot_changes(tmp_path, monkeypatch, change):
    cfg, inventory, archive = osv_matching_fixture(tmp_path)
    original_bytes = archive.read_bytes()
    extra = archive.parents[2] / '.git'
    extra.mkdir()
    (extra / 'config').write_text('unapproved DB directory metadata must not be copied')
    private_roots = []

    def execute(cmd, **kwargs):
        if '--version' in cmd:
            return subprocess.CompletedProcess(cmd, 0, '2.7.0', '')
        database = Path(kwargs['env']['OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY'])
        private_roots.append(database)
        scan_archive = database / 'osv-scalibr' / 'npm' / 'all.zip'
        if change == 'original-database':
            archive.write_bytes(b'changed after initial approval verification')
            assert scan_archive.read_bytes() == original_bytes
        elif change == 'private-snapshot':
            scan_archive.chmod(0o600)
            scan_archive.write_bytes(b'changed inside the private engine input')
        assert database != archive.parents[2]
        assert not (database / '.git').exists()
        if change == 'engine-error':
            raise subprocess.TimeoutExpired(cmd, 1)
        payload = {'results': [{'source': {'path': str(tmp_path / 'package-lock.json'), 'type': 'lockfile'},
            'packages': [{'package': {'name': 'a', 'version': '1.0.0', 'ecosystem': 'npm',
                'purl': 'pkg:npm/a@1.0.0?source=PUBLIC_REGISTRY'}}]}]}
        return subprocess.CompletedProcess(cmd, 0, json.dumps(payload), 'Loaded npm local db from ' + str(scan_archive) + '\n')

    mock_engine_process(monkeypatch, execute)
    check, findings = adapters._sca(tmp_path, cfg, inventory, 'static-release')
    assert check['status'] == ('complete' if change == 'original-database' else 'incomplete'), check
    assert findings == []
    assert private_roots and all(not path.exists() for path in private_roots)


def test_osv_rejects_database_change_between_approval_check_and_private_copy(tmp_path, monkeypatch):
    cfg, inventory, archive = osv_matching_fixture(tmp_path)
    original_snapshot = adapters.verified_snapshot
    scans = []

    def changed_before_copy(database, database_inventory, **kwargs):
        archive.write_bytes(b'changed after approval check and before private copy')
        return original_snapshot(database, database_inventory, **kwargs)

    def execute(cmd, **kwargs):
        if '--version' in cmd:
            return subprocess.CompletedProcess(cmd, 0, '2.7.0', '')
        scans.append(cmd)
        raise AssertionError('Changed database must not be passed to OSV')

    monkeypatch.setattr(adapters, 'verified_snapshot', changed_before_copy)
    mock_engine_process(monkeypatch, execute)
    check, findings = adapters._sca(tmp_path, cfg, inventory, 'static-release')
    assert check['status'] == 'incomplete' and findings == [] and scans == []
    assert any(error['type'] == 'sca_failed' and error['category'] == 'invalid_engine_output'
               for error in check['errors'])
    assert str(archive) not in json.dumps(check['errors'])
