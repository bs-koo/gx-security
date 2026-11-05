"""Atomic masked snapshots and SQLite lookup with conservative reconciliation."""
import copy
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from .models import validate_run, content_hash
from .source import is_reparse, reject_reparse_path
from .redaction import redact


def _carry_absent_framework(finding, run, check):
    """Bind a reviewable absence observation to current inputs, never infer a fix."""
    finding['lifecycle'] = 'remediation-proposed'
    finding['validation'] = 'undetermined'
    finding['review_required'] = True
    for key in ('fixed_verified_run', 'resolution_evidence', 'review_ref'):
        finding.pop(key, None)
    finding['observations'] = [observation for observation in finding.get('observations', [])
                               if not isinstance(observation, dict)
                               or observation.get('type') != 'trusted-human-review']
    source = run.get('source', {})
    manifest = sorted(({'path': row.get('path'), 'hash': row.get('hash')}
                       for row in source.get('inventory', [])), key=lambda row: str(row['path']))
    hashes = {row['path']: row['hash'] for row in manifest}
    contract = {'engine': check.get('engine', {}), 'coverage': check.get('coverage', {}),
                'status': check.get('status', 'not-executed'),
                'errors': [{'type': error.get('type'), 'path': error.get('path')}
                           for error in check.get('errors', []) if isinstance(error, dict)]}
    finding['analysis_contract_hash'] = content_hash(contract)
    absence = {
        'method': 'framework-finding-not-observed', 'check_id': 'framework',
        'source_revision': source.get('revision') or source.get('commit') or source.get('hash'),
        'source_hash': source.get('hash'), 'scope_hash': source.get('scope_hash'),
        'file_manifest_digest': content_hash(manifest),
        'analysis_contract_hash': finding['analysis_contract_hash'],
        'check_status': contract['status'],
        'locations': [{'path': location.get('path'), 'hash': hashes.get(location.get('path')),
                       'present': location.get('path') in hashes}
                      for location in finding.get('locations', [])],
        'fact': 'The current framework result does not contain this earlier finding. '
                'Recognizer absence does not establish remediation or current source safety.',
    }
    finding['absence_evidence'] = absence
    locations = finding.get('locations') or [{}]
    finding['expected_file_hash'] = hashes.get(locations[0].get('path'))
    # The earlier claim and its locations remain historical. Only the current
    # absence is evidence against it; do not re-export old context as a fresh scan.
    context = {'schema_version': 1, 'analyzer': 'gxsec-framework-absence/1',
        'classification': 'framework-finding-not-observed', 'proposal': 'needs_review',
        'evidence_for': [], 'evidence_against': [copy.deepcopy(absence)],
        'unresolved': ['Does independent review of the current source establish remediation '
                       'of the original claim, or did the bounded recognizer lose the pattern?'],
        'instances': [], 'limitations': ['Original claim locations describe an earlier observation. '
            'No per-finding remediation evaluation was established by this scan.']}
    context['binding_digest'] = content_hash(absence)
    finding['context'] = context
    # Explicit stable claim fields exclude run IDs, review observations and any
    # previous digest. Repeated unchanged absence scans must remain reviewable.
    claim = {key: finding.get(key) for key in ('finding_id', 'fingerprint', 'semantic_fingerprint',
        'rule_id', 'semantic_rule_id', 'category', 'severity', 'locations', 'title', 'description',
        'file_hash', 'facts', 'counterevidence', 'prerequisites')}
    finding['normalized_result_hash'] = content_hash({'claim': claim, 'context': context,
        'absence_evidence': absence, 'analysis_contract_hash': finding['analysis_contract_hash'],
        'lifecycle': finding['lifecycle'], 'validation': finding['validation'], 'review_required': True})


class Store:

    def __init__(self, state_dir: Path):
        requested = reject_reparse_path(state_dir)
        if requested.is_symlink():
            raise ValueError('State directory must not be a symlink')
        self.path = requested.resolve()
        self.path.mkdir(parents=True, exist_ok=True)
        self.snapshots = self.path / 'runs'
        self.db = self.path / 'state.sqlite3'
        self._assert_storage()
        self.snapshots.mkdir(exist_ok=True)
        with self._connect() as db:
            db.execute(
                'CREATE TABLE IF NOT EXISTS runs (sequence INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT UNIQUE NOT NULL, project_id TEXT NOT NULL, snapshot TEXT NOT NULL, payload TEXT NOT NULL)',
            )
            db.execute('PRAGMA user_version=1')

    def _assert_storage(self):
        paths = [self.path, self.snapshots, self.db]
        paths.extend(Path(str(self.db) + suffix) for suffix in ('-journal', '-wal', '-shm'))
        if any(is_reparse(path) for path in paths):
            raise ValueError('State storage components must not be symlinks')

    def _connect(self):
        self._assert_storage()
        return sqlite3.connect(self.db, timeout=20)

    def save_run(self, run) -> Path:
        self._assert_storage()
        validate_run(run)
        safe = redact(copy.deepcopy(run))
        data = json.dumps(safe, ensure_ascii=False, indent=2, default=str)
        dest = self.snapshots / (safe['run_id'] + '.json')
        # Persist full payload in one transaction: a failed/partial write cannot replace prior state.
        fd, tmp = tempfile.mkstemp(prefix='.snapshot-', suffix='.tmp', dir=self.snapshots)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            with self._connect() as db:
                existing = db.execute('SELECT payload FROM runs WHERE run_id=?', (safe['run_id'],)).fetchone()
                if existing and json.loads(existing[0]) != safe:
                    raise ValueError('A saved run is immutable; create a new run_id')
                os.replace(tmp, dest)
                db.execute(
                    'INSERT OR IGNORE INTO runs(run_id,project_id,snapshot,payload) VALUES(?,?,?,?)',
                    (safe['run_id'], safe['project_id'], str(dest), data),
                )
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return dest

    def get_run(self, id) -> dict:
        with self._connect() as db:
            row = db.execute('SELECT payload FROM runs WHERE run_id=?', (str(id),)).fetchone()
        if row is None:
            raise KeyError('Unknown run ' + str(id))
        return json.loads(row[0])

    def latest_run(self) -> dict | None:
        with self._connect() as db:
            row = db.execute('SELECT payload FROM runs ORDER BY sequence DESC LIMIT 1').fetchone()
        return json.loads(row[0]) if row else None

    def reconcile(self, run, previous=None) -> dict:
        result = copy.deepcopy(run)
        previous = copy.deepcopy(previous) if previous is not None else self.latest_run()
        if not previous or previous.get('project_id') != result.get('project_id'):
            return result
        if previous.get('source', {}).get('source_id') != result.get('source', {}).get('source_id'):
            return result
        old = {f.get('fingerprint'): f for f in previous.get('findings', []) if f.get('fingerprint')}
        present = set()
        matched_previous = set()
        old_anchors = {}
        new_anchors = {}
        for earlier in old.values():
            anchor = earlier.get('semantic_fingerprint')
            if anchor:
                old_anchors.setdefault(anchor, []).append(earlier)
        for current in result.get('findings', []):
            anchor = current.get('semantic_fingerprint')
            if anchor:
                new_anchors.setdefault(anchor, []).append(current)
        for f in result.get('findings', []):
            fp = f.get('fingerprint')
            present.add(fp)
            earlier = old.get(fp)
            anchor = f.get('semantic_fingerprint')
            if earlier is None and anchor and len(old_anchors.get(anchor, [])) == 1 and len(new_anchors.get(anchor, [])) == 1:
                earlier = old_anchors[anchor][0]
            if earlier is not None:
                matched_previous.add(earlier['fingerprint'])
                f['finding_id'] = earlier['finding_id']
                f['first_seen_run'] = earlier.get('first_seen_run', previous['run_id'])
                if earlier.get('lifecycle') == 'fixed-verified':
                    f['lifecycle'] = 'reopened'
        old_checks = {c['id']: c for c in previous.get('checks', [])}
        new_checks = {c['id']: c for c in result.get('checks', [])}
        same_scope = bool(
            previous.get('source', {}).get('scope_hash') and previous['source']['scope_hash'] == result.get('source', {}).get('scope_hash'),
        )
        for fp, earlier in old.items():
            if fp in present or fp in matched_previous:
                continue
            carried = copy.deepcopy(earlier)
            cid = earlier.get('check_id')
            before = old_checks.get(cid, {})
            after = new_checks.get(cid, {})

            def complete(c):
                cov = c.get('coverage', {})
                eligible = cov.get('eligible')
                scanned = cov.get('scanned')
                return c.get('status') == 'complete' and not c.get('errors') and cov.get('scope') == 'full' and type(eligible) is int and type(scanned) is int and eligible > 0 and scanned == eligible and not cov.get('missing') and cov.get('complete', True) is True

            engines_match = bool(before.get('engine') and before.get('engine') == after.get('engine'))
            signatures_match = bool(before.get('coverage', {}).get('signature') and before.get('coverage', {}).get('signature') == after.get('coverage', {}).get('signature'))
            eligible_match = sorted(before.get('coverage', {}).get('files', [])) == sorted(after.get('coverage', {}).get('files', []))
            if cid == 'framework':
                _carry_absent_framework(carried, result, after)
            elif result.get('profile') != 'check' and same_scope and cid and complete(before) and complete(after) and engines_match and signatures_match and eligible_match and (not earlier.get('category') in {'secrets', 'authorization', 'auth', 'dast'}):
                carried['lifecycle'] = 'fixed-verified'
                carried['fixed_verified_run'] = result['run_id']
                carried['resolution_evidence'] = {
                    'check_id': cid,
                    'scope_hash': result['source']['scope_hash'],
                    'method': 'absent-in-equivalent-full-clean-scan',
                }
            carried['carried_forward'] = True
            result.setdefault('findings', []).append(carried)
        return result
