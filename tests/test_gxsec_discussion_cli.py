"""Discussion is a saved-run conversation, never a scan or an approval."""
import json

import pytest

from gxsec import cli
from gxsec.models import make_finding
from gxsec.source import collect_source
from gxsec.state import Store


@pytest.fixture(autouse=True)
def no_git_probe(monkeypatch):
    # These cases exercise content binding, not the separately tested Git runtime.
    monkeypatch.setattr('gxsec.source._git', lambda *a, **kw: None)


@pytest.fixture
def saved(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'Controller.java').write_text('class Controller { void download() {} }', encoding='utf-8')
    finding = make_finding(category='authorization', rule='SEF-OBJ-01', path='Controller.java', severity='High')
    run = {'schema_version': 1, 'run_id': 'run-one', 'project_id': 'example', 'profile': 'static-release',
           'source': collect_source(source), 'checks': [], 'findings': [finding],
           'reviews': [], 'exceptions': [], 'gate': {'status': 'INCOMPLETE', 'exit_code': 2}}
    state = tmp_path / 'state'
    path = Store(state).save_run(run)
    return source, state, run, path


def invoke(capsys, state, *args):
    code = cli.main(['discuss', 'run-one', '--state-dir', str(state), '--json', *map(str, args)])
    return code, json.loads(capsys.readouterr().out)


def test_create_and_read_discussion_never_scan_or_change_run(saved, capsys, monkeypatch):
    source, state, run, path = saved
    original = path.read_bytes()
    monkeypatch.setattr(cli.adapters, 'run_static_checks', lambda *a: pytest.fail('discussion must not scan'))
    code, session = invoke(capsys, state)
    assert code == 0
    assert session['authority'] == 'discussion-only'
    assert session['revision'] == 0 and session['questions'] == []
    assert path.read_bytes() == original
    code, again = invoke(capsys, state, '--session-id', session['session_id'])
    assert code == 0 and again['session_id'] == session['session_id']
    assert path.read_bytes() == original
    assert (state / 'discussions' / session['session_id'] / 'report' / 'discussion.html').is_file()


def test_question_answer_and_assessment_roundtrip_keeps_original_gate(saved, tmp_path, capsys):
    source, state, run, path = saved
    original = path.read_bytes()
    _, session = invoke(capsys, state)
    record = tmp_path / 'record.json'
    ref = {k: run['source']['inventory'][0][k] for k in ('path', 'hash')}
    ref['line'] = 1

    def append(payload):
        payload = {'expected_revision': session['revision'], **payload}
        record.write_text(json.dumps(payload, ensure_ascii=False), encoding='utf-8')
        return invoke(capsys, state, '--session-id', session['session_id'], '--record', record, '--source', source)

    code, session = append({'type': 'question', 'finding_ids': [run['findings'][0]['finding_id']],
                            'prompt': '자료 조회는 같은 조직까지 허용하나요?',
                            'purpose': '허용할 자료 범위가 업무 정책에 달려 있습니다.', 'code_refs': [ref]})
    assert code == 0 and session['revision'] == 1
    qid = session['questions'][0]['question_id']
    code, session = append({'type': 'answer', 'question_id': qid, 'answer_status': 'answered',
                            'answer': '같은 조직 자료까지 허용합니다.', 'respondent': 'developer'})
    assert code == 0
    assert session['questions'][0]['answer']['provenance'] == 'user-reported'
    code, session = append({'type': 'assessment', 'question_id': qid,
                            'finding_id': run['findings'][0]['finding_id'], 'outcome': 'unresolved',
                            'summary': '조직 범위 제한 근거는 추가 확인이 필요합니다.',
                            'evidence_refs': [ref], 'remaining_questions': ['조직 정책 문서를 확인해야 합니다.']})
    assert code == 0 and session['revision'] == 3
    assert session['questions'][0]['assessments'][0]['outcome'] == 'unresolved'
    assert path.read_bytes() == original
    assert Store(state).get_run('run-one')['gate']['status'] == 'INCOMPLETE'


def test_discussion_requires_existing_state_without_creating_it(tmp_path, capsys):
    state = tmp_path / 'missing-state'
    code, data = invoke(capsys, state)
    assert code == 2 and data['status'] == 'INCOMPLETE'
    assert not state.exists()


def test_record_requires_explicit_session(saved, tmp_path, capsys):
    _, state, _, _ = saved
    record = tmp_path / 'answer.json'
    record.write_text('{}', encoding='utf-8')
    code, _ = invoke(capsys, state, '--record', record)
    assert code == 2
    assert not (state / 'discussions').exists()


def test_source_drift_is_rejected_without_appending_revision(saved, tmp_path, capsys):
    source, state, run, _ = saved
    _, session = invoke(capsys, state)
    ref = {k: run['source']['inventory'][0][k] for k in ('path', 'hash')}
    ref['line'] = 1
    (source / 'Controller.java').write_text('class Changed {}', encoding='utf-8')
    record = tmp_path / 'question.json'
    record.write_text(json.dumps({'type': 'question', 'expected_revision': 0,
        'finding_ids': [run['findings'][0]['finding_id']], 'prompt': '허용 범위는 무엇인가요?',
        'purpose': '업무 정책 확인', 'code_refs': [ref]}), encoding='utf-8')
    code, _ = invoke(capsys, state, '--session-id', session['session_id'], '--record', record, '--source', source)
    assert code == 2
    code, again = invoke(capsys, state, '--session-id', session['session_id'])
    assert code == 0 and again['revision'] == 0


def test_record_size_and_non_object_input_are_rejected(saved, tmp_path, capsys):
    _, state, _, _ = saved
    _, session = invoke(capsys, state)
    record = tmp_path / 'record.json'
    for contents in ('[]', 'x' * (128 * 1024 + 1)):
        record.write_text(contents, encoding='utf-8')
        code, _ = invoke(capsys, state, '--session-id', session['session_id'], '--record', record)
        assert code == 2


def test_discussion_cannot_overwrite_existing_scan_manifest(saved, tmp_path, capsys):
    from gxsec.reporting import write_reports
    _, state, run, _ = saved
    target = tmp_path / 'scan-report'
    write_reports(run, target)
    before = {p.name: p.read_bytes() for p in target.iterdir()}
    code, _ = invoke(capsys, state, '--output', target)
    assert code == 2
    assert {p.name: p.read_bytes() for p in target.iterdir()} == before


def test_discussion_rejects_session_path_traversal(saved, tmp_path, capsys):
    _, state, _, _ = saved
    code, _ = invoke(capsys, state, '--session-id', '../outside')
    assert code == 2 and not (tmp_path / 'outside').exists()
