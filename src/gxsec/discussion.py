"""Source-bound user intent discussions; no record grants security authority."""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
import uuid

from .models import content_hash, validate_run
from .redaction import redact
from .source import collect_source, reject_reparse_path
from .triage import build_review_packets

MAX_REVISION = 1024
MAX_BYTES = 8 * 1024 * 1024
_SESSION_FIELDS = {'schema_version', 'session_id', 'run_id', 'project_id', 'revision',
                   'authority', 'run_digest', 'source_binding', 'packet_bindings',
                   'questions', 'parent_digest', 'session_digest', 'created_at', 'updated_at'}
_QUESTION_FIELDS = {'question_id', 'finding_ids', 'prompt', 'purpose', 'code_refs',
                    'options', 'parent_question_id', 'answer', 'assessments'}
_ANSWER_FIELDS = {'answer_status', 'answer', 'respondent', 'provenance', 'recorded_at'}
_ASSESSMENT_FIELDS = {'finding_id', 'outcome', 'summary', 'evidence_refs',
                      'remaining_questions', 'authority', 'recorded_at'}
_RECORD_FIELDS = {
    'question': {'type', 'expected_revision', 'finding_ids', 'prompt', 'purpose',
                 'code_refs', 'options', 'parent_question_id'},
    'answer': {'type', 'expected_revision', 'question_id', 'answer_status', 'answer', 'respondent'},
    'assessment': {'type', 'expected_revision', 'question_id', 'finding_id', 'outcome',
                   'summary', 'evidence_refs', 'remaining_questions'},
}


def _utc():
    return datetime.now(timezone.utc).isoformat()


def _identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,95}', value):
        raise ValueError('Invalid discussion identity')
    return value


def _text(value, *, empty=False, limit=4096):
    if not isinstance(value, str) or len(value) > limit or '\x00' in value or (not empty and not value.strip()):
        raise ValueError('Discussion text is missing or exceeds the supported limit')
    return value


def _exact(value, fields, *, required=None):
    if not isinstance(value, dict) or set(value) - fields or (fields if required is None else required) - set(value):
        raise ValueError('Invalid discussion fields; approval fields are not supported')


def _digest(value):
    return isinstance(value, str) and bool(re.fullmatch('[a-f0-9]{64}', value))


def _inventory(run):
    source = run.get('source')
    if not isinstance(source, dict) or not _digest(source.get('hash')) or not isinstance(source.get('inventory'), list):
        raise ValueError('Discussion requires a saved source inventory and hash')
    result = {}
    for row in source['inventory']:
        if not isinstance(row, dict):
            raise ValueError('Invalid saved source inventory')
        path, digest = row.get('path'), row.get('hash')
        if not isinstance(path, str) or not path or '\\' in path or ':' in path or PurePosixPath(path).is_absolute() or '..' in PurePosixPath(path).parts or not _digest(digest) or path in result:
            raise ValueError('Invalid saved source inventory')
        result[path] = digest
    return result


def _contract(run):
    validate_run(run)
    _inventory(run)
    safe = redact(run)
    _text(safe['project_id'], limit=256)
    packets = build_review_packets(safe)
    bindings = [{'finding_id': p['finding_id'], 'normalized_result_hash': p['normalized_result_hash'],
                 'packet_digest': p['packet_digest']} for p in packets['packets']]
    if any(not isinstance(p['finding_id'], str) for p in bindings) or len({p['finding_id'] for p in bindings}) != len(bindings):
        raise ValueError('Saved findings must have distinct identities')
    return safe, packets['source_binding'], bindings


def _refs(value, inventory, *, required=True):
    if not isinstance(value, list) or len(value) > 64 or (required and not value):
        raise ValueError('Source references are required and must be bounded')
    for ref in value:
        _exact(ref, {'path', 'hash', 'line', 'end_line'}, required={'path', 'hash', 'line'})
        if (not isinstance(ref['path'], str) or inventory.get(ref['path']) != ref['hash']
                or not _digest(ref['hash']) or type(ref['line']) is not int or ref['line'] < 1
                or ('end_line' in ref and (type(ref['end_line']) is not int or ref['end_line'] < ref['line']))):
            raise ValueError('Source reference does not match the saved inventory')


def _strings(value, *, maximum=32):
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError('Invalid discussion text list')
    for text in value:
        _text(text)


def _finding_ids(value, known):
    if (not isinstance(value, list) or not value or len(value) > 64
            or any(not isinstance(v, str) or v not in known for v in value)
            or len(set(value)) != len(value)):
        raise ValueError('Question must refer to distinct findings in the saved run')


def _answer(value):
    _exact(value, _ANSWER_FIELDS)
    if not isinstance(value['answer_status'], str) or value['answer_status'] not in {'answered', 'unknown', 'deferred'} or value['provenance'] != 'user-reported':
        raise ValueError('Answer is user-reported intent, not an approval')
    _text(value['answer'], empty=value['answer_status'] != 'answered', limit=8192)
    _text(value['respondent'], limit=256)
    _text(value['recorded_at'], limit=64)


def _assessment(value, question, inventory):
    _exact(value, _ASSESSMENT_FIELDS)
    if (value['finding_id'] not in question['finding_ids'] or value['authority'] != 'proposal-only'
            or not isinstance(value['outcome'], str) or value['outcome'] not in {'consistent', 'mismatch', 'unresolved'}):
        raise ValueError('Assessment is a per-finding intent comparison, not security validation')
    reply = question['answer']
    if reply is None or (reply['answer_status'] != 'answered' and value['outcome'] != 'unresolved'):
        raise ValueError('A source assessment requires an answer; unknown intent stays unresolved')
    _text(value['summary'])
    _text(value['recorded_at'], limit=64)
    _refs(value['evidence_refs'], inventory, required=value['outcome'] != 'unresolved')
    _strings(value['remaining_questions'])


def _session_digest(session):
    return content_hash({k: v for k, v in session.items() if k != 'session_digest'})


def create_session(run, *, session_id=None):
    """Start empty; choosing meaningful questions remains the host reviewer's job."""
    safe, binding, packets = _contract(run)
    now = _utc()
    session = {'schema_version': 1, 'session_id': _identifier('GXSEC-DISC-' + uuid.uuid4().hex if session_id is None else session_id),
               'run_id': safe['run_id'], 'project_id': safe['project_id'], 'revision': 0,
               'authority': 'discussion-only', 'run_digest': content_hash(safe),
               'source_binding': binding, 'packet_bindings': packets, 'questions': [],
               'parent_digest': None, 'created_at': now, 'updated_at': now}
    session['session_digest'] = _session_digest(session)
    return session


def validate_session(session, run):
    """Validate identity and structure without changing the historical run."""
    _exact(session, _SESSION_FIELDS)
    _identifier(session['session_id'])
    safe, binding, packets = _contract(run)
    if (type(session['schema_version']) is not int or session['schema_version'] != 1 or session['authority'] != 'discussion-only'
            or session['run_id'] != safe['run_id'] or session['project_id'] != safe['project_id']
            or session['run_digest'] != content_hash(safe) or session['source_binding'] != binding
            or session['packet_bindings'] != packets):
        raise ValueError('Discussion is bound to a different run, source, or analysis contract')
    if (type(session['revision']) is not int or not 0 <= session['revision'] <= MAX_REVISION
            or session['parent_digest'] is not None and not _digest(session['parent_digest'])
            or (session['revision'] == 0) != (session['parent_digest'] is None)
            or session.get('session_digest') != _session_digest(session) or session != redact(session)):
        raise ValueError('Discussion revision or integrity is invalid')
    _text(session['created_at'], limit=64)
    _text(session['updated_at'], limit=64)
    inventory, known = _inventory(run), {p['finding_id'] for p in packets}
    if not isinstance(session['questions'], list) or len(session['questions']) > min(256, session['revision']):
        raise ValueError('Discussion questions exceed the supported limit')
    seen, signatures = {}, set()
    for question in session['questions']:
        _exact(question, _QUESTION_FIELDS)
        _identifier(question['question_id'])
        _finding_ids(question['finding_ids'], known)
        _text(question['prompt'])
        _text(question['purpose'])
        _refs(question['code_refs'], inventory)
        _strings(question['options'], maximum=8)
        signature = (tuple(sorted(question['finding_ids'])), ' '.join(question['prompt'].split()).casefold())
        if question['question_id'] in seen or signature in signatures:
            raise ValueError('Duplicate discussion question')
        parent = question['parent_question_id']
        if parent is not None:
            _identifier(parent)
            prior = seen.get(parent)
            if (prior is None or prior['answer'] is None or prior['answer']['answer_status'] != 'answered'
                    or not set(question['finding_ids']) <= set(prior['finding_ids'])):
                raise ValueError('Follow-up requires an answered parent about the same findings')
        if question['answer'] is not None:
            _answer(question['answer'])
        if not isinstance(question['assessments'], list) or len(question['assessments']) > MAX_REVISION:
            raise ValueError('Invalid assessment list')
        assessed = set()
        for observation in question['assessments']:
            _assessment(observation, question, inventory)
            if observation['finding_id'] in assessed:
                raise ValueError('Duplicate current assessment for a finding')
            assessed.add(observation['finding_id'])
        seen[question['question_id']] = question
        signatures.add(signature)
    return session


def _current_source(run, source_root):
    if source_root is None:
        raise ValueError('Question and assessment records require current source verification')
    root = reject_reparse_path(source_root)
    current = collect_source(root)
    # Container and host mount roots differ; content and complete file manifests must agree.
    if (current.get('errors') or run['source'].get('errors')
            or current.get('hash') != run['source']['hash']
            or _inventory({'source': current}) != _inventory(run)):
        raise ValueError('Current source differs from the saved snapshot; run a new check and discussion')
    return root.resolve(strict=True)


def _reference_locations(root, refs):
    """Check inert bytes and real line bounds without retaining source excerpts."""
    observed = {}
    for ref in refs:
        path = reject_reparse_path(root / ref['path'])
        if not path.resolve(strict=True).is_relative_to(root):
            raise ValueError('Source reference escapes the inspected snapshot')
        if ref['path'] not in observed:
            digest, breaks, size, previous_cr, final = hashlib.sha256(), 0, 0, False, None
            with path.open('rb') as handle:
                for chunk in iter(lambda: handle.read(65536), b''):
                    digest.update(chunk)
                    size += len(chunk)
                    breaks += chunk.count(b'\n') + chunk.count(b'\r') - chunk.count(b'\r\n')
                    if previous_cr and chunk.startswith(b'\n'):
                        breaks -= 1
                    previous_cr, final = chunk.endswith(b'\r'), chunk[-1]
            reject_reparse_path(path)
            if digest.hexdigest() != ref['hash']:
                raise ValueError('Source reference changed after snapshot verification')
            observed[ref['path']] = breaks + int(bool(size) and final not in (10, 13))
        if ref.get('end_line', ref['line']) > observed[ref['path']]:
            raise ValueError('Source reference line range exceeds the actual file')


def apply_record(session, run, record, *, source_root=None):
    """Apply one explicit event, preserving prior revisions and all scan decisions."""
    validate_session(session, run)
    kind = record.get('type') if isinstance(record, dict) else None
    if not isinstance(kind, str) or kind not in _RECORD_FIELDS:
        raise ValueError('Unknown discussion record type')
    required = _RECORD_FIELDS[kind] - ({'options', 'parent_question_id'} if kind == 'question' else set())
    _exact(record, _RECORD_FIELDS[kind], required=required)
    if type(record['expected_revision']) is not int or record['expected_revision'] != session['revision']:
        raise ValueError('Discussion revision conflict; reload before recording')
    if session['revision'] >= MAX_REVISION:
        raise ValueError('Discussion revision limit reached')
    updated, event = copy.deepcopy(session), redact(copy.deepcopy(record))
    if kind in {'question', 'assessment'}:
        references = event['code_refs'] if kind == 'question' else event['evidence_refs']
        _refs(references, _inventory(run), required=kind == 'question' or event['outcome'] != 'unresolved')
        _reference_locations(_current_source(run, source_root), references)
    if kind == 'question':
        updated['questions'].append({'question_id': 'GXSEC-Q-' + uuid.uuid4().hex[:20],
            'finding_ids': event['finding_ids'], 'prompt': event['prompt'], 'purpose': event['purpose'],
            'code_refs': event['code_refs'], 'options': event.get('options', []),
            'parent_question_id': event.get('parent_question_id'), 'answer': None, 'assessments': []})
    else:
        question = next((q for q in updated['questions'] if q['question_id'] == event['question_id']), None)
        if question is None:
            raise ValueError('Question is not in this discussion')
        if kind == 'answer':
            prior = question['answer']
            if prior is not None and (prior['answer_status'] == 'answered' or event['answer_status'] != 'answered'):
                raise ValueError('An existing response cannot be silently replaced')
            question['answer'] = {k: event[k] for k in ('answer_status', 'answer', 'respondent')}
            question['answer'].update({'provenance': 'user-reported', 'recorded_at': _utc()})
            # Earlier unresolved observations describe the earlier non-answer, retained in history.
            question['assessments'] = []
        else:
            observation = {k: event[k] for k in ('finding_id', 'outcome', 'summary', 'evidence_refs', 'remaining_questions')}
            observation.update({'authority': 'proposal-only', 'recorded_at': _utc()})
            for index, current in enumerate(question['assessments']):
                if current['finding_id'] == observation['finding_id']:
                    question['assessments'][index] = observation
                    break
            else:
                question['assessments'].append(observation)
    updated['revision'] += 1
    updated['parent_digest'] = session['session_digest']
    updated['updated_at'] = _utc()
    updated['session_digest'] = _session_digest(updated)
    return validate_session(updated, run)


class DiscussionStore:
    """Append complete immutable JSON revisions; concurrent writes never overwrite."""

    def __init__(self, state_dir):
        self.path = reject_reparse_path(state_dir)
        if not self.path.is_dir():
            raise ValueError('An existing scan state directory is required')
        self.root = reject_reparse_path(self.path / 'discussions')

    def _folder(self, session_id):
        reject_reparse_path(self.path)
        reject_reparse_path(self.root)
        return reject_reparse_path(self.root / _identifier(session_id))

    def _save(self, session):
        folder = self._folder(session['session_id'])
        folder.mkdir(parents=True, exist_ok=True)
        destination = reject_reparse_path(folder / f"{session['revision']:06d}.json")
        data = json.dumps(session, ensure_ascii=False, indent=2).encode('utf-8')
        if len(data) > MAX_BYTES:
            raise ValueError('Discussion exceeds the supported size')
        fd, temporary = tempfile.mkstemp(prefix='.revision-', suffix='.tmp', dir=folder)
        try:
            with os.fdopen(fd, 'wb') as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            self._folder(session['session_id'])
            reject_reparse_path(destination)
            try:
                os.link(temporary, destination)
            except FileExistsError:
                raise ValueError('Discussion revision conflict; reload before recording') from None
        finally:
            os.unlink(temporary)

    def create(self, run):
        session = create_session(run)
        self._save(session)
        return session

    def load(self, run, session_id):
        folder = self._folder(session_id)
        if not folder.is_dir():
            raise KeyError('Unknown discussion session')
        paths = sorted(folder.glob('*.json'))
        if not paths or len(paths) > MAX_REVISION + 1:
            raise ValueError('Discussion revision history is missing or excessive')
        previous, session = None, None
        for revision, path in enumerate(paths):
            reject_reparse_path(path)
            if path.name != f'{revision:06d}.json' or path.stat().st_size > MAX_BYTES:
                raise ValueError('Discussion revision history is invalid')
            try:
                session = json.loads(path.read_text(encoding='utf-8'))
            except (UnicodeError, json.JSONDecodeError):
                raise ValueError('Discussion revision is incomplete or invalid') from None
            validate_session(session, run)
            if (session['session_id'] != session_id or session['revision'] != revision
                    or session['parent_digest'] != previous):
                raise ValueError('Discussion revision chain is invalid')
            previous = session['session_digest']
        return session

    def record(self, run, session_id, record, *, source_root=None):
        session = self.load(run, session_id)
        updated = apply_record(session, run, record, source_root=source_root)
        self._save(updated)
        return updated
