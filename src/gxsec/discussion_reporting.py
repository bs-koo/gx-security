"""Inert supplemental views: user intent and investigation never approve a scan."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import html
import json
from pathlib import Path
import re

from .discussion import validate_session
from .redaction import redact
from .reporting import _atomic_write
from .source import reject_reparse_path


OUTCOMES = {'consistent': '의도와 구현의 일치 관측', 'mismatch': '의도와 구현의 불일치', 'unresolved': '미확정'}
ANSWER_STATES = {'answered': '답변 받음', 'unknown': '모름', 'deferred': '나중에 답변'}
NOTICE = ('사용자 설명은 업무 의도이며, 조사 결과는 제안입니다. 의도와 구현이 일치해도 안전을 뜻하지 않습니다. '
          '공식 반증·예외·출시 승인은 기존 독립 검토 절차를 따릅니다. 원래 검사 판정과 미완료 항목은 유지합니다.')


def _h(value):
    return html.escape(str(value), quote=True)


def _md(value):
    return re.sub(r'([\\`*_{}\[\]()#+.!|>~-])', r'\\\1', html.escape(str(value), quote=True))


def _refs_html(refs):
    return '<ul>' + ''.join('<li><code>' + _h(ref['path']) + ':' + str(ref['line']) +
        '</code> · <code>' + _h(ref['hash']) + '</code></li>' for ref in refs) + '</ul>'


def _views(session, run):
    safe = redact(deepcopy(session))
    gate = redact(run.get('gate', {}))
    safe['original_gate'] = gate
    safe['notice'] = NOTICE
    status = str(gate.get('status', 'INCOMPLETE'))
    heading = f"질문·답변 기반 추가 검토 · {safe['session_id']}"
    body = ['<header><p>GX Security · 추가 검토 기록</p><h1>' + _h(heading) + '</h1></header>',
            '<p class="notice">' + _h(NOTICE) + '</p>',
            '<dl><dt>원래 실행</dt><dd>' + _h(safe['run_id']) + '</dd><dt>원래 판정</dt><dd>' + _h(status) +
            '</dd><dt>기록 revision</dt><dd>' + str(safe['revision']) + '</dd></dl>',
            '<p>근거는 원래 검사 snapshot에 연결됩니다. 현재 코드의 새 검사 결과나 자동 취약성 검증이 아닙니다.</p>']
    md = ['# 질문·답변 기반 추가 검토', '', _md(NOTICE), '',
          '원래 실행: ' + _md(safe['run_id']), '원래 판정: ' + _md(status),
          '세션: ' + _md(safe['session_id']), '기록 revision: ' + str(safe['revision']), '']
    if not safe['questions']:
        body.append('<p>아직 질문·답변·조사 기록이 없습니다. 후보 검토 완료를 뜻하지 않습니다.</p>')
        md.extend(['아직 질문·답변·조사 기록이 없습니다.', ''])
    for index, question in enumerate(safe['questions'], 1):
        body.extend(['<article><h2>' + str(index) + '. ' + _h(question['prompt']) + '</h2>',
                     '<p>' + _h(question['purpose']) + '</p>',
                     '<p>대상 발견: <code>' + _h(', '.join(question['finding_ids'])) + '</code></p>',
                     '<h3>질문 전 조사 근거</h3>', _refs_html(question['code_refs'])])
        md.extend(['## ' + str(index) + '. ' + _md(question['prompt']), '', _md(question['purpose']), '',
                   '대상 발견: ' + _md(', '.join(question['finding_ids'])), '', '### 질문 전 조사 근거', ''])
        for ref in question['code_refs']:
            md.append('- ' + _md(f"{ref['path']}:{ref['line']} · {ref['hash']}"))
        if question.get('parent_question_id'):
            body.append('<p>후속 질문 · 이전 질문: <code>' + _h(question['parent_question_id']) + '</code></p>')
            md.extend(['', '후속 질문 · 이전 질문: ' + _md(question['parent_question_id'])])
        body.append('<h3>사용자 설명</h3>')
        md.extend(['', '### 사용자 설명', ''])
        answer = question.get('answer')
        if answer:
            label = ANSWER_STATES.get(answer['answer_status'], '미확정')
            body.append('<p>' + _h(label) + ' · 사용자 진술 · ' + _h(answer.get('respondent', '')) + '</p><p class="text">' +
                        _h(answer.get('answer', '')) + '</p>')
            md.extend([_md(label + ' · 사용자 진술 · ' + str(answer.get('respondent', ''))), '', _md(answer.get('answer', ''))])
        else:
            body.append('<p>답변 대기 · 관련 조건은 미확정입니다.</p>')
            md.append('답변 대기 · 관련 조건은 미확정입니다.')
        assessed = set()
        for assessment in question['assessments']:
            assessed.add(assessment['finding_id'])
            label = OUTCOMES[assessment['outcome']]
            body.extend(['<section><h3>' + _h(label) + ' · <code>' + _h(assessment['finding_id']) + '</code></h3>',
                         '<p class="text">' + _h(assessment['summary']) + '</p><h4>조사 근거</h4>',
                         _refs_html(assessment['evidence_refs'])])
            md.extend(['', '### ' + _md(label + ' · ' + assessment['finding_id']), '', _md(assessment['summary']), '', '조사 근거:', ''])
            for ref in assessment['evidence_refs']:
                md.append('- ' + _md(f"{ref['path']}:{ref['line']} · {ref['hash']}"))
            if assessment['remaining_questions']:
                body.append('<h4>남은 확인 사항</h4><ul>' + ''.join('<li>' + _h(q) + '</li>' for q in assessment['remaining_questions']) + '</ul>')
                md.extend(['', '남은 확인 사항:', ''] + ['- ' + _md(q) for q in assessment['remaining_questions']])
            body.append('</section>')
        pending = [fid for fid in question['finding_ids'] if fid not in assessed]
        if pending:
            text = '조사 미완료 · ' + ', '.join(pending)
            body.append('<p>' + _h(text) + '</p>')
            md.extend(['', _md(text)])
        body.append('</article>')
        md.append('')
    page = ('<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>GX Security · 질문·답변 기반 추가 검토</title><style>'
            'body{margin:0;background:#faf9f5;color:#141413;font:16px/1.7 system-ui,sans-serif;overflow-wrap:anywhere}'
            'main{max-width:900px;margin:auto;padding:32px 20px}h1{font-size:clamp(24px,4vw,36px);line-height:1.3}'
            'h2{font-size:22px}h3{font-size:18px}.notice{border-left:3px solid #141413;padding:12px 16px;background:#efeee8}'
            'article{border-top:1px solid #bbb;padding:24px 0}section{padding:12px 0}dt{font-weight:700}dd{margin:0 0 12px}'
            'code{font-size:.9em}ul{padding-left:22px}.text{white-space:pre-wrap}</style><main>' + ''.join(body) + '</main></html>')
    return safe, '\n'.join(md), page


def write_discussion_reports(session, run, output):
    """Export a sidecar only; refuse to replace an existing scan or another session."""
    validate_session(session, run)
    directory = reject_reparse_path(output)
    protected = {'result.json', 'report.html', 'developer.md', 'qa-checklist.md', 'results.sarif', 'state.sqlite3'}
    if any((directory / name).exists() for name in protected):
        raise ValueError('Discussion reports require a separate directory from scan results and state')
    for name in ('discussion.json', 'discussion.md', 'discussion.html', 'manifest.json'):
        reject_reparse_path(directory / name)
    previous = directory / 'manifest.json'
    if previous.exists():
        if previous.stat().st_size > 128 * 1024:
            raise ValueError('Invalid existing discussion manifest')
        prior = json.loads(previous.read_text(encoding='utf-8'))
        if (not isinstance(prior, dict) or prior.get('authority') != 'discussion-only'
                or prior.get('session_id') != session['session_id']):
            raise ValueError('Output belongs to a different report')
    safe, markdown, page = _views(session, run)
    contents = {'discussion.json': json.dumps(safe, ensure_ascii=False, indent=2),
                'discussion.md': markdown, 'discussion.html': page}
    directory.mkdir(parents=True, exist_ok=True)
    paths = []
    for name, content in contents.items():
        path = directory / name
        _atomic_write(path, content)
        paths.append(path)
    manifest = {'schema_version': 1, 'authority': 'discussion-only', 'session_id': session['session_id'],
                'run_id': run['run_id'], 'revision': session['revision'],
                'files': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}}
    path = directory / 'manifest.json'
    _atomic_write(path, json.dumps(manifest, ensure_ascii=False, indent=2))
    return paths + [path]
