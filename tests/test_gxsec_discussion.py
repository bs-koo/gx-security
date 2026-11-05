"""Discussion intent is traceable evidence, never a security approval."""
import copy
import importlib
import json
from pathlib import Path

import pytest

from gxsec.models import content_hash, make_finding
from gxsec.source import collect_source


def core():
    assert importlib.util.find_spec('gxsec.discussion'), 'The bound discussion workflow is missing'
    return importlib.import_module('gxsec.discussion')


@pytest.fixture
def sample(tmp_path):
    source = tmp_path / 'project'
    source.mkdir()
    (source / 'App.java').write_text('class App {\n  void download() {}\n}\n', encoding='utf-8')
    (source / 'Access.java').write_text('class Access {}\n', encoding='utf-8')
    (source / 'gxsec.yaml').write_text('project: {id: sample}\n', encoding='utf-8')
    f = make_finding(category='authorization', rule='SEF-OBJ-01', path='App.java', severity='High')
    other = make_finding(category='authorization', rule='SEF-ADM-01', path='Access.java', severity='High')
    run = {'schema_version': 1, 'run_id': 'run-original', 'project_id': 'sample',
           'profile': 'static-release', 'source': collect_source(source), 'checks': [],
           'findings': [f, other], 'reviews': [], 'exceptions': [],
           'gate': {'status': 'INCOMPLETE', 'exit_code': 2}}
    state = tmp_path / 'state'
    state.mkdir()
    return source, run, state


def ref(run, path='App.java'):
    row = next(v for v in run['source']['inventory'] if v['path'] == path)
    return {'path': path, 'hash': row['hash'], 'line': 1}


def question(run, revision=0, **kwargs):
    return {'type': 'question', 'expected_revision': revision,
            'finding_ids': [run['findings'][0]['finding_id']],
            'prompt': '누구의 자료까지 다운로드할 수 있어야 하나요?',
            'purpose': '기대 자료 범위를 현재 조회 조건과 비교합니다.',
            'code_refs': [ref(run)], **kwargs}


def answer(qid, revision=1, **kwargs):
    return {'type': 'answer', 'expected_revision': revision, 'question_id': qid,
            'answer_status': 'answered', 'answer': '같은 조직의 자료까지 허용합니다.',
            'respondent': 'developer', **kwargs}


def assessment(run, qid, revision=2, **kwargs):
    return {'type': 'assessment', 'expected_revision': revision, 'question_id': qid,
            'finding_id': run['findings'][0]['finding_id'], 'outcome': 'unresolved',
            'summary': '사용자는 조직 범위를 설명했으나 코드의 귀속 검증은 추가 확인해야 합니다.',
            'evidence_refs': [ref(run)], 'remaining_questions': ['조직 판정의 기준은 무엇인가요?'], **kwargs}


def started(sample):
    source, run, _ = sample
    module = core()
    session = module.create_session(run, session_id='discussion-test')
    return module, source, run, module.apply_record(session, run, question(run), source_root=source)


def test_roundtrip_keeps_intent_separate_from_security_approval(sample):
    source, run, state = sample
    before = copy.deepcopy(run)
    module = core()
    store = module.DiscussionStore(state)
    session = store.create(run)
    assert session['revision'] == 0 and session['authority'] == 'discussion-only'
    session = store.record(run, session['session_id'], question(run), source_root=source)
    qid = session['questions'][0]['question_id']
    session = store.record(run, session['session_id'], answer(qid, answer='의도된 동작입니다. 내부망에서만 씁니다.'))
    session = store.record(run, session['session_id'], assessment(run, qid), source_root=source)
    assert session['questions'][0]['answer']['provenance'] == 'user-reported'
    assert session['questions'][0]['assessments'][0]['authority'] == 'proposal-only'
    assert store.load(run, session['session_id']) == session
    assert run == before
    files = sorted((state / 'discussions' / session['session_id']).glob('*.json'))
    assert [p.name for p in files] == ['000000.json', '000001.json', '000002.json', '000003.json']
    assert json.loads(files[0].read_text(encoding='utf-8'))['questions'] == []


def test_answer_requires_no_source_probe(sample, monkeypatch):
    module, _, run, session = started(sample)
    monkeypatch.setattr(module, 'collect_source', lambda *_: pytest.fail('Answer unexpectedly inspected source'))
    result = module.apply_record(session, run, answer(session['questions'][0]['question_id']))
    assert result['revision'] == 2


@pytest.mark.parametrize('status', ['unknown', 'deferred'])
def test_unknown_and_deferred_remain_unresolved_and_can_later_be_answered(sample, status):
    module, source, run, session = started(sample)
    qid = session['questions'][0]['question_id']
    session = module.apply_record(session, run, answer(qid, answer_status=status, answer=''))
    with pytest.raises(ValueError):
        module.apply_record(session, run, assessment(run, qid, outcome='consistent'), source_root=source)
    session = module.apply_record(session, run, assessment(run, qid), source_root=source)
    updated = module.apply_record(session, run, answer(qid, revision=3))
    assert updated['questions'][0]['answer']['answer_status'] == 'answered'
    assert updated['questions'][0]['assessments'] == []
    assert session['questions'][0]['answer']['answer_status'] == status


def test_answered_response_cannot_be_silently_replaced(sample):
    module, _, run, session = started(sample)
    qid = session['questions'][0]['question_id']
    session = module.apply_record(session, run, answer(qid))
    with pytest.raises(ValueError):
        module.apply_record(session, run, answer(qid, revision=2, answer='아무나 허용합니다.'))


def test_followup_depends_on_answer_and_stays_in_original_findings(sample):
    module, source, run, session = started(sample)
    qid = session['questions'][0]['question_id']
    follow = question(run, 1, prompt='조직 간 공유도 허용하나요?', parent_question_id=qid)
    with pytest.raises(ValueError):
        module.apply_record(session, run, follow, source_root=source)
    session = module.apply_record(session, run, answer(qid))
    follow['expected_revision'] = 2
    updated = module.apply_record(session, run, follow, source_root=source)
    assert updated['questions'][1]['parent_question_id'] == qid
    follow['finding_ids'] = [run['findings'][1]['finding_id']]
    with pytest.raises(ValueError):
        module.apply_record(session, run, follow, source_root=source)


def test_group_question_requires_each_member_to_be_assessed(sample):
    module = core()
    source, run, _ = sample
    session = module.create_session(run)
    session = module.apply_record(session, run, question(run, finding_ids=[f['finding_id'] for f in run['findings']]), source_root=source)
    qid = session['questions'][0]['question_id']
    session = module.apply_record(session, run, answer(qid))
    session = module.apply_record(session, run, assessment(run, qid), source_root=source)
    assert len(session['questions'][0]['assessments']) == 1
    assert session['questions'][0]['assessments'][0]['finding_id'] == run['findings'][0]['finding_id']
    assert run['findings'][1]['validation'] == 'candidate'


@pytest.mark.parametrize('field,value', [('gate', {'status': 'PASS'}), ('validation', 'refuted'),
                                       ('reviews', []), ('approved_by', 'security'), ('severity', 'Low')])
def test_record_cannot_supply_approval_fields(sample, field, value):
    module, source, run, session = started(sample)
    record = answer(session['questions'][0]['question_id'])
    record[field] = value
    with pytest.raises(ValueError):
        module.apply_record(session, run, record, source_root=source)


def test_duplicate_prompt_and_revision_conflict_are_rejected(sample):
    module, source, run, session = started(sample)
    with pytest.raises(ValueError):
        module.apply_record(session, run, question(run, revision=1, prompt='  누구의 자료까지   다운로드할 수 있어야 하나요? '), source_root=source)
    with pytest.raises(ValueError):
        module.apply_record(session, run, answer(session['questions'][0]['question_id'], revision=0))


@pytest.mark.parametrize('change', ['run', 'project', 'scope', 'analyzer', 'finding'])
def test_session_cannot_be_applied_to_changed_run_contract(sample, change):
    module, _, run, session = started(sample)
    altered = copy.deepcopy(run)
    if change == 'run':
        altered['run_id'] = 'another-run'
    elif change == 'project':
        altered['project_id'] = 'another-project'
    elif change == 'scope':
        altered['source']['scope_hash'] = content_hash('new scope')
    elif change == 'analyzer':
        altered['checks'].append({'id': 'sast', 'engine': {'version': 'changed'}})
    else:
        altered['findings'][0]['context'] = {'proposal': 'not_actionable'}
    with pytest.raises(ValueError):
        module.validate_session(session, altered)


@pytest.mark.parametrize('path', ['App.java', 'Access.java', 'gxsec.yaml', 'New.java'])
def test_current_source_drift_including_other_callers_and_config_is_rejected(sample, path):
    module, source, run, session = started(sample)
    qid = session['questions'][0]['question_id']
    session = module.apply_record(session, run, answer(qid))
    (source / path).write_text('changed\n', encoding='utf-8')
    with pytest.raises(ValueError):
        module.apply_record(session, run, assessment(run, qid), source_root=source)


def test_identical_snapshot_in_different_mount_root_is_allowed(sample, tmp_path):
    module, source, run, session = started(sample)
    clone = tmp_path / 'different-container-mount'
    clone.mkdir()
    for file in source.iterdir():
        (clone / file.name).write_bytes(file.read_bytes())
    session = module.apply_record(session, run, answer(session['questions'][0]['question_id']))
    updated = module.apply_record(session, run, assessment(run, session['questions'][0]['question_id']), source_root=clone)
    assert updated['revision'] == 3


@pytest.mark.parametrize('bad_ref', [{'path': '../outside.java', 'hash': 'a' * 64, 'line': 1},
                                   {'path': 'C:/outside.java', 'hash': 'a' * 64, 'line': 1},
                                   {'path': 'App.java', 'hash': 'a' * 64, 'line': 1},
                                   {'path': 'App.java', 'hash': None, 'line': 1},
                                   {'path': 'App.java', 'hash': 'a' * 64, 'line': True}])
def test_refs_must_identify_inventory_files(sample, bad_ref):
    source, run, _ = sample
    module = core()
    with pytest.raises(ValueError):
        module.apply_record(module.create_session(run), run, question(run, code_refs=[bad_ref]), source_root=source)


def test_question_and_assessment_require_current_source_and_answer(sample):
    source, run, _ = sample
    module = core()
    with pytest.raises(ValueError):
        module.apply_record(module.create_session(run), run, question(run))
    module, _, run, session = started(sample)
    with pytest.raises(ValueError):
        module.apply_record(session, run, assessment(run, session['questions'][0]['question_id'], revision=1), source_root=source)
    with pytest.raises(ValueError):
        module.apply_record(session, run, question(run, revision=1, finding_ids=['unrelated']), source_root=source)


def test_store_rejects_conflicts_and_corrupt_history(sample):
    source, run, state = sample
    module = core()
    store = module.DiscussionStore(state)
    session = store.create(run)
    latest = store.record(run, session['session_id'], question(run), source_root=source)
    with pytest.raises(ValueError):
        store.record(run, session['session_id'], question(run), source_root=source)
    folder = state / 'discussions' / session['session_id']
    path = folder / '000000.json'
    data = json.loads(path.read_text(encoding='utf-8'))
    data['created_at'] = 'changed'
    path.write_text(json.dumps(data), encoding='utf-8')
    with pytest.raises(ValueError):
        store.load(run, latest['session_id'])


@pytest.mark.parametrize('session_id', ['../escape', '..', '/absolute', 'C:drive', 'bad/id', '', False, 0, [], {}])
def test_session_identifiers_are_not_paths(sample, session_id):
    _, run, _ = sample
    with pytest.raises(ValueError):
        core().create_session(run, session_id=session_id)


def test_store_masks_answer_before_persisting(sample):
    source, run, state = sample
    module = core()
    store = module.DiscussionStore(state)
    session = store.create(run)
    session = store.record(run, session['session_id'], question(run), source_root=source)
    text = 'Use ghp_' + 'A' * 30 + ' only locally'
    session = store.record(run, session['session_id'], answer(session['questions'][0]['question_id'], answer=text))
    persisted = '\n'.join(p.read_text(encoding='utf-8') for p in (state / 'discussions' / session['session_id']).glob('*.json'))
    assert text not in persisted
    assert '[REDACTED]' in persisted
    assert store.load(run, session['session_id']) == session


def test_symlinked_state_and_revision_are_rejected(sample, tmp_path):
    _, run, state = sample
    target = tmp_path / 'linked-state'
    try:
        target.symlink_to(state, target_is_directory=True)
    except OSError:
        pytest.skip('symlink creation unavailable')
    module = core()
    with pytest.raises(ValueError):
        module.DiscussionStore(target)
    store = module.DiscussionStore(state)
    session = store.create(run)
    revision = state / 'discussions' / session['session_id'] / '000000.json'
    outside = tmp_path / 'copied.json'
    outside.write_bytes(revision.read_bytes())
    revision.unlink()
    revision.symlink_to(outside)
    with pytest.raises(ValueError):
        store.load(run, session['session_id'])


def test_atomic_publish_failure_leaves_prior_revision_usable(sample, monkeypatch):
    source, run, state = sample
    module = core()
    store = module.DiscussionStore(state)
    session = store.create(run)
    monkeypatch.setattr(module.os, 'link', lambda *_: (_ for _ in ()).throw(OSError('simulated publication failure')))
    with pytest.raises(OSError):
        store.record(run, session['session_id'], question(run), source_root=source)
    assert store.load(run, session['session_id']) == session
    assert not list((state / 'discussions' / session['session_id']).glob('*.tmp'))


def test_state_revision_publication_is_exclusive(sample):
    _, run, state = sample
    module = core()
    store = module.DiscussionStore(state)
    session = store.create(run)
    path = state / 'discussions' / session['session_id'] / '000000.json'
    original = path.read_bytes()
    with pytest.raises(ValueError):
        store._save(session)
    assert path.read_bytes() == original


@pytest.mark.parametrize('kind,bad', [('question', {'parent_question_id': []}),
                                    ('answer', {'answer_status': []}),
                                    ('assessment', {'outcome': []})])
def test_malformed_list_values_fail_as_invalid_records(sample, kind, bad):
    module, source, run, session = started(sample)
    qid = session['questions'][0]['question_id']
    if kind == 'question':
        record = question(run, 1, prompt='추가 정책은 무엇인가요?', **bad)
    elif kind == 'answer':
        record = answer(qid, **bad)
    else:
        session = module.apply_record(session, run, answer(qid))
        record = assessment(run, qid, **bad)
    with pytest.raises(ValueError):
        module.apply_record(session, run, record, source_root=source)


def test_discussion_schema_accepts_valid_roundtrip(sample):
    jsonschema = pytest.importorskip('jsonschema')
    module, source, run, session = started(sample)
    qid = session['questions'][0]['question_id']
    session = module.apply_record(session, run, answer(qid))
    session = module.apply_record(session, run, assessment(run, qid), source_root=source)
    schema = json.loads((Path(__file__).resolve().parents[1] / 'schemas' / 'discussion.json').read_text(encoding='utf-8'))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(session, schema)


@pytest.mark.parametrize('kind,span', [('question', {'line': 99999}),
                                      ('question', {'line': 1, 'end_line': 4}),
                                      ('assessment', {'line': 99999}),
                                      ('assessment', {'line': 1, 'end_line': 4})])
def test_source_reference_cannot_invent_lines_past_eof(sample, kind, span):
    source, run, _ = sample
    module = core()
    invented = {**ref(run), **span}
    if kind == 'question':
        session = module.create_session(run)
        record = question(run, code_refs=[invented])
    else:
        module, source, run, session = started(sample)
        qid = session['questions'][0]['question_id']
        session = module.apply_record(session, run, answer(qid))
        record = assessment(run, qid, evidence_refs=[invented])
    with pytest.raises(ValueError, match='line'):
        module.apply_record(session, run, record, source_root=source)


def test_reference_bytes_must_still_match_after_whole_source_verification(sample, monkeypatch):
    source, run, _ = sample
    module = core()
    original = module.collect_source

    def source_then_replaced(root):
        inventory = original(root)
        (source / 'App.java').write_text('class Replaced {}\n', encoding='utf-8')
        return inventory

    monkeypatch.setattr(module, 'collect_source', source_then_replaced)
    with pytest.raises(ValueError, match='reference'):
        module.apply_record(module.create_session(run), run, question(run), source_root=source)


@pytest.mark.parametrize('data,last', [(b'a\nb\n', 2), (b'a\r\nb\r\n', 2),
                                     (b'a\rb\r', 2), (b'a\nb', 2), (b'', 0)])
def test_reference_line_count_tracks_actual_end_of_file(sample, data, last):
    source, run, _ = sample
    module = core()
    (source / 'App.java').write_bytes(data)
    run['source'] = collect_source(source)
    record = question(run, code_refs=[{**ref(run), 'line': max(1, last)}])
    if last:
        assert module.apply_record(module.create_session(run), run, record, source_root=source)['revision'] == 1
    else:
        with pytest.raises(ValueError, match='line'):
            module.apply_record(module.create_session(run), run, record, source_root=source)


def test_reference_line_count_streams_crlf_across_chunk_boundary(sample):
    source, run, _ = sample
    module = core()
    (source / 'App.java').write_bytes(b'a' * 65535 + b'\r\nb\n')
    run['source'] = collect_source(source)
    record = question(run, code_refs=[{**ref(run), 'line': 2, 'end_line': 2}])
    assert module.apply_record(module.create_session(run), run, record, source_root=source)['revision'] == 1
    record['code_refs'][0]['end_line'] = 3
    with pytest.raises(ValueError, match='line'):
        module.apply_record(module.create_session(run), run, record, source_root=source)


@pytest.mark.parametrize('new_outcome', ['consistent', 'mismatch', 'unresolved'])
def test_later_assessment_replaces_only_that_findings_current_observation(sample, new_outcome):
    source, run, state = sample
    module = core()
    store = module.DiscussionStore(state)
    session = store.create(run)
    session = store.record(run, session['session_id'], question(run, finding_ids=[f['finding_id'] for f in run['findings']]), source_root=source)
    qid = session['questions'][0]['question_id']
    session = store.record(run, session['session_id'], answer(qid))
    session = store.record(run, session['session_id'], assessment(run, qid), source_root=source)
    other = run['findings'][1]['finding_id']
    session = store.record(run, session['session_id'], assessment(run, qid, revision=3,
        finding_id=other, outcome='consistent', summary='두 번째 발견의 의도와 관측이 일치합니다.'), source_root=source)
    previous = copy.deepcopy(session)
    session = store.record(run, session['session_id'], assessment(run, qid, revision=4,
        outcome=new_outcome, summary='추가 코드 조사로 첫 번째 발견의 현재 관측을 갱신했습니다.'), source_root=source)
    current = session['questions'][0]['assessments']
    assert len(current) == 2
    by_finding = {item['finding_id']: item for item in current}
    assert by_finding[run['findings'][0]['finding_id']]['outcome'] == new_outcome
    assert by_finding[other] == previous['questions'][0]['assessments'][1]
    assert previous['questions'][0]['assessments'][0]['outcome'] == 'unresolved'
    historical = json.loads((state / 'discussions' / session['session_id'] / '000003.json').read_text(encoding='utf-8'))
    assert historical['questions'][0]['assessments'][0]['outcome'] == 'unresolved'
    assert store.load(run, session['session_id']) == session


def test_duplicate_current_assessments_for_one_finding_are_rejected(sample):
    module, source, run, session = started(sample)
    qid = session['questions'][0]['question_id']
    session = module.apply_record(session, run, answer(qid))
    session = module.apply_record(session, run, assessment(run, qid), source_root=source)
    session['questions'][0]['assessments'].append(copy.deepcopy(session['questions'][0]['assessments'][0]))
    session['session_digest'] = content_hash({k: v for k, v in session.items() if k != 'session_digest'})
    with pytest.raises(ValueError, match='assessment'):
        module.validate_session(session, run)
