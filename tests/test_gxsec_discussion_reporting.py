"""Supplemental intent/evidence reports must be inert and cannot approve a run."""
import copy
import hashlib
import json

import pytest

from gxsec.models import make_finding
from gxsec.source import collect_source


@pytest.fixture(autouse=True)
def no_git_probe(monkeypatch):
    monkeypatch.setattr('gxsec.source._git', lambda *a, **kw: None)


def example(tmp_path, text='같은 조직 자료까지 허용합니다.'):
    from gxsec.discussion import create_session, apply_record
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'Controller.java').write_text('class Controller {}', encoding='utf-8')
    finding = make_finding(category='authorization', rule='SEF-OBJ-01', path='Controller.java', severity='High')
    run = {'schema_version': 1, 'run_id': 'run-one', 'project_id': 'example', 'profile': 'static-release',
           'source': collect_source(source), 'checks': [], 'findings': [finding],
           'gate': {'status': 'INCOMPLETE', 'exit_code': 2}}
    session = create_session(run)
    ref = {k: run['source']['inventory'][0][k] for k in ('path', 'hash')}
    ref['line'] = 1
    session = apply_record(session, run, {'expected_revision': 0, 'type': 'question',
        'finding_ids': [finding['finding_id']], 'prompt': '자료 조회 범위는 어디까지인가요?',
        'purpose': '업무 의도 확인', 'code_refs': [ref]}, source_root=source)
    qid = session['questions'][0]['question_id']
    session = apply_record(session, run, {'expected_revision': 1, 'type': 'answer',
        'question_id': qid, 'answer_status': 'answered', 'answer': text, 'respondent': 'developer'})
    session = apply_record(session, run, {'expected_revision': 2, 'type': 'assessment',
        'question_id': qid, 'finding_id': finding['finding_id'], 'outcome': 'unresolved',
        'summary': '업무 의도와 코드의 일치 여부는 미확정입니다.', 'evidence_refs': [ref],
        'remaining_questions': ['조직 제한의 적용 경로를 더 조사해야 합니다.']}, source_root=source)
    return run, session


def test_supplement_preserves_run_and_separates_claim_evidence_and_status(tmp_path):
    from gxsec.discussion_reporting import write_discussion_reports
    run, session = example(tmp_path)
    original = copy.deepcopy(run)
    output = tmp_path / 'discussion-report'
    paths = write_discussion_reports(session, run, output)
    assert {p.name for p in paths} == {'discussion.json', 'discussion.md', 'discussion.html', 'manifest.json'}
    document = json.loads((output / 'discussion.json').read_text(encoding='utf-8'))
    assert document['authority'] == 'discussion-only'
    page = (output / 'discussion.html').read_text(encoding='utf-8')
    assert '사용자 설명' in page and '조사 근거' in page and '미확정' in page
    assert 'INCOMPLETE' in page and '출시 승인' in page
    assert run == original
    manifest = json.loads((output / 'manifest.json').read_text(encoding='utf-8'))
    assert manifest['authority'] == 'discussion-only'
    for name, digest in manifest['files'].items():
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == digest


def test_answers_cannot_inject_html_or_markdown_and_secret_is_masked(tmp_path):
    from gxsec.discussion_reporting import write_discussion_reports
    run, session = example(tmp_path, '<script>alert(1)</script> [open](javascript:alert(1)) password=demo-credential-123')
    output = tmp_path / 'view'
    write_discussion_reports(session, run, output)
    for path in output.iterdir():
        value = path.read_text(encoding='utf-8')
        assert 'demo-credential-123' not in value
    html = (output / 'discussion.html').read_text(encoding='utf-8')
    md = (output / 'discussion.md').read_text(encoding='utf-8')
    assert '<script>' not in html and 'href="javascript:' not in html
    assert '<script>' not in md and '[open](javascript:' not in md


def test_empty_and_pending_sessions_are_not_presented_as_review_complete(tmp_path):
    from gxsec.discussion import create_session
    from gxsec.discussion_reporting import write_discussion_reports
    run, _ = example(tmp_path)
    session = create_session(run)
    output = tmp_path / 'empty'
    write_discussion_reports(session, run, output)
    page = (output / 'discussion.html').read_text(encoding='utf-8')
    assert '아직' in page and 'INCOMPLETE' in page


def test_report_rejects_output_symlink_without_touching_target(tmp_path):
    from gxsec.discussion_reporting import write_discussion_reports
    run, session = example(tmp_path)
    target = tmp_path / 'outside'
    target.mkdir()
    link = tmp_path / 'link'
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip('symlink creation unavailable')
    with pytest.raises(ValueError):
        write_discussion_reports(session, run, link)
    assert not list(target.iterdir())


def test_non_object_existing_manifest_is_rejected_without_writing(tmp_path):
    from gxsec.discussion_reporting import write_discussion_reports
    run, session = example(tmp_path)
    output = tmp_path / 'invalid-manifest'
    output.mkdir()
    manifest = output / 'manifest.json'
    for contents in ('[]', 'null', '123', '"text"'):
        manifest.write_text(contents, encoding='utf-8')
        with pytest.raises(ValueError):
            write_discussion_reports(session, run, output)
        assert manifest.read_text(encoding='utf-8') == contents
        assert {p.name for p in output.iterdir()} == {'manifest.json'}
