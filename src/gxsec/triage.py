"""Evidence bundles for review; neither proposals nor baselines grant approval."""
from __future__ import annotations

import copy
from pathlib import PurePosixPath
import re

from .models import content_hash
from .policy import _trusted
from .redaction import redact

PROPOSALS = {'confirmed', 'not_actionable', 'needs_review'}
FRAMEWORK_TITLES = {
    'SEF-ADM-01': '관리자 기능의 권한 검사 확인',
    'SEF-JWT-01': '인증 토큰의 용도 구분 확인',
    'SEF-OBJ-01': '메뉴와 객체의 권한 연결 확인',
    'SEF-ROUTE-01': '업무 경로의 보호 범위 확인',
    'SEF-FILE-01': '파일 저장소의 경계 확인',
}


def _dict(value):
    return value if isinstance(value, dict) else {}


def _list(value):
    return value if isinstance(value, list) else []


def _framework_check(run):
    return next((c for c in _list(run.get('checks')) if isinstance(c, dict) and c.get('id') == 'framework'), {})


def _files(run):
    rows = _list(_dict(run.get('source')).get('inventory'))
    if not rows:
        rows = _list(_dict(_framework_check(run).get('framework')).get('baseline_manifest'))
    result = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        path = str(row.get('path', '')).replace('\\', '/')
        digest = str(row.get('hash', ''))
        if not path or ':' in path or PurePosixPath(path).is_absolute() or '..' in PurePosixPath(path).parts:
            continue
        if re.fullmatch('[a-f0-9]{64}', digest):
            result[path] = digest
    return [{'path': path, 'hash': digest} for path, digest in sorted(result.items())]


def _binding(run):
    source = _dict(run.get('source'))
    return {'source_revision': source.get('revision') or source.get('commit') or source.get('hash'),
            'source_hash': source.get('hash'), 'scope_hash': source.get('scope_hash'),
            'file_manifest_digest': content_hash(_files(run)),
            'analyzers': [{'id': c.get('id'), 'engine': c.get('engine', {}),
                           'coverage_signature': _dict(c.get('coverage')).get('signature')}
                          for c in _list(run.get('checks')) if isinstance(c, dict)]}


def enrich_framework_findings(findings, inventory):
    """Present the framework recognizer's own facts, without claiming missing models are proof."""
    result = copy.deepcopy(findings)
    for finding in result:
        rule = finding.get('rule_id')
        if finding.get('check_id') != 'framework' or rule not in FRAMEWORK_TITLES:
            continue
        finding['title'] = FRAMEWORK_TITLES[rule]
        finding['description'] = '공통 보호 기능의 실제 적용 조건과 아래 소스 관측을 검토하세요. 실행 영향은 확인되지 않았습니다.'
        context = {'schema_version': 1, 'analyzer': 'gxsec-sef-review/1',
            'classification': 'sef-' + rule.lower(), 'proposal': 'needs_review',
            'evidence_for': _list(finding.get('evidence_refs')) +
                [{'kind': 'source-observation', 'fact': fact} for fact in _list(finding.get('facts'))],
            'evidence_against': [{'kind': 'counterevidence', 'fact': fact} for fact in _list(finding.get('counterevidence'))],
            'unresolved': _list(finding.get('prerequisites')), 'instances': [],
            'limitations': ['Bounded source contract; deployment, custom guards and runtime impact require independent review.']}
        context['binding_digest'] = content_hash({'context': context, 'finding_id': finding.get('finding_id'),
            'source_hash': inventory.get('hash'), 'scope_hash': inventory.get('scope_hash'),
            'input_manifest_digest': content_hash(inventory.get('inventory', []))})
        finding['context'] = context
    return result


def build_review_packets(run):
    """Keep every source finding; grouping is display-only and cannot approve members."""
    binding = _binding(run)
    packets, groups = [], {}
    for finding in _list(run.get('findings')):
        if not isinstance(finding, dict):
            continue
        context = _dict(finding.get('context'))
        proposal = context.get('proposal')
        if not isinstance(proposal, str) or proposal not in PROPOSALS:
            proposal = 'needs_review'
        packet = {'schema_version': 1, 'finding_id': finding.get('finding_id'),
                  'normalized_result_hash': finding.get('normalized_result_hash') or content_hash(finding),
                  'authority': 'proposal-only', 'proposal': proposal,
                  'validation': finding.get('validation', 'undetermined'),
                  'claim': {'rule_id': finding.get('rule_id'), 'title': finding.get('title'),
                            'description': finding.get('description'), 'locations': finding.get('locations', [])},
                  'classification': context.get('classification', 'unmodeled'),
                  'evidence_for': _list(context.get('evidence_for')) or _list(finding.get('evidence_refs')),
                  'evidence_against': _list(context.get('evidence_against')),
                  'remaining_questions': _list(context.get('unresolved')) or ['Independent contextual review is required.'],
                  'instances': _list(context.get('instances')),
                  'limitations': _list(context.get('limitations')),
                  'binding_digest': context.get('binding_digest'), 'source_binding': binding}
        packet = redact(packet)
        packet['packet_digest'] = content_hash(packet)
        packets.append(packet)
        loc = next(iter(_list(finding.get('locations'))), {})
        key = (str(finding.get('rule_id')), str(_dict(loc).get('module') or PurePosixPath(str(_dict(loc).get('path', ''))).parent),
               str(packet['classification']))
        group = groups.setdefault(key, {'group_id': 'GXSEC-GROUP-' + content_hash(key)[:20],
            'rule_id': finding.get('rule_id'), 'classification': packet['classification'],
            'authority': 'display-only', 'approval_scope': 'individual-findings', 'members': []})
        group['members'].append({'finding_id': packet['finding_id'],
            'normalized_result_hash': packet['normalized_result_hash'], 'packet_digest': packet['packet_digest']})
    ordered = []
    for key in sorted(groups):
        group = groups[key]
        group['members'].sort(key=lambda item: str(item['finding_id']))
        group['group_digest'] = content_hash(group)
        ordered.append(group)
    return redact({'schema_version': 1, 'run_id': run.get('run_id'), 'authority': 'proposal-only',
                   'source_binding': binding, 'packets': packets, 'groups': ordered})


def framework_manifest(run):
    """Observed full source hashes, including callers; not a safe-code certificate."""
    check = _framework_check(run)
    framework = _dict(check.get('framework'))
    result = redact({'schema_version': 1, 'authority': 'observations-only',
        'family': framework.get('family', 'unknown'), 'variant': framework.get('variant', 'undetermined'),
        'analyzer': check.get('engine', {}), 'modules': framework.get('modules', []),
        'source_binding': _binding(run), 'files': _files(run),
        'contract_digest': content_hash(framework.get('contracts', [])),
        'limitations': framework.get('limitations', [])})
    result['manifest_digest'] = content_hash(result)
    result['id'] = 'GXSEC-BASE-' + result['manifest_digest'][:20]
    return result


def compare_framework_baseline(run, protected_policy):
    """Compare only a digest-approved organization record; never promote a finding."""
    record = protected_policy.get('framework_baseline')
    result = {'status': 'not_supplied', 'authority': 'comparison-only',
              'changed_files': [], 'added_files': [], 'removed_files': []}
    if record is None:
        return result
    if not isinstance(record, dict) or not _trusted(record, protected_policy, 'framework-baseline', ('security-reviewer',)):
        return {**result, 'status': 'untrusted'}
    observed = framework_manifest(run)
    if (record.get('family') != observed['family'] or record.get('variant') != observed['variant']
            or record.get('analyzer') != observed['analyzer'] or not observed['files']
            or not isinstance(record.get('files'), list)):
        return {**result, 'status': 'incompatible'}
    try:
        before = {row['path']: row['hash'] for row in record['files']}
    except (KeyError, TypeError):
        return {**result, 'status': 'incompatible'}
    after = {row['path']: row['hash'] for row in observed['files']}
    result.update({'baseline_id': record['id'], 'changed_files': sorted(p for p in before.keys() & after.keys() if before[p] != after[p]),
                   'added_files': sorted(after.keys() - before.keys()), 'removed_files': sorted(before.keys() - after.keys())})
    result['status'] = 'changed' if any(result[k] for k in ('changed_files', 'added_files', 'removed_files')) else 'matched'
    return result


def apply_framework_baseline(run, protected_policy):
    """Attach audit evidence before the gate; an optional protected requirement may fail closed."""
    comparison = compare_framework_baseline(run, protected_policy)
    check = _framework_check(run)
    if check:
        check.setdefault('framework', {})['baseline_comparison'] = comparison
        if protected_policy.get('require_framework_baseline') and comparison['status'] != 'matched':
            check['status'] = 'incomplete'
            check.setdefault('errors', []).append({'type': 'framework_baseline_unverified',
                'message': 'Protected framework baseline does not match the current source and analyzer.'})
    return comparison
