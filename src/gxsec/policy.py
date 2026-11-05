"""Fail-closed release gates computed from execution and independent trust."""
import datetime as dt
import copy
import re
from .config import PROFILE_REQUIREMENTS
from .models import content_hash
VERIFIED = {'source-verified', 'runtime-verified'}
CLOSED = {'fixed-verified'}

def _time(value):
    if isinstance(value, dt.datetime):
        return value.replace(tzinfo=dt.timezone.utc) if value.tzinfo is None else value
    if isinstance(value, str):
        try:
            return _time(dt.datetime.fromisoformat(value.replace('Z', '+00:00')))
        except ValueError:
            return None
    return None

def _trusted(record, policy, kind, roles=()):
    if not isinstance(record, dict) or not record.get('id'):
        return False
    digest = content_hash(record)
    return any(
        (isinstance(a, dict) and a.get('record_id') == record['id'] and (a.get('digest') == digest) and (a.get('kind') == kind) and (set(roles) <= set(a.get('roles', []))) for a in policy.get('trusted_approvals', [])),
    )

def _scope(record, policy):
    for key in ('source_revision', 'scope_hash'):
        if not policy.get(key) or record.get(key) != policy[key]:
            return False
    return True


def _finding_scope(record, finding, policy):
    if not _scope(record, policy):
        return False
    context = finding.get('context')
    if isinstance(context, dict) and context.get('schema_version') == 1:
        digest = finding.get('normalized_result_hash')
        return bool(isinstance(digest, str) and re.fullmatch('[a-f0-9]{64}', digest)
                    and record.get('normalized_result_hash') == digest)
    return True

def _exception(record, finding, policy, now):
    expires = _time(record.get('expires_at'))
    return bool(
        record.get('finding_id') == finding.get('finding_id') and record.get('owner') and record.get('reason') and expires and (expires > now) and _finding_scope(record, finding, policy) and _trusted(record, policy, 'risk-acceptance', ('security-owner', 'project-owner')),
    )

def apply_reviews(findings, reviews, *, policy):
    """Apply scoped decisions only when their complete record is trusted externally."""
    result = copy.deepcopy(findings)
    for finding in result:
        for review in reviews or []:
            if review.get('finding_id') != finding.get('finding_id') or not review.get('evidence_refs') or (not _finding_scope(review, finding, policy)):
                continue
            decision = review.get('decision')
            if decision in VERIFIED and _trusted(review, policy, 'finding-validation', ('independent-reviewer',)):
                finding['validation'] = decision
            elif decision == 'refuted' and _trusted(review, policy, 'finding-refutation', ('security-reviewer',)):
                finding['validation'] = 'refuted'
            else:
                continue
            if review.get('severity') in {'Critical', 'High', 'Medium', 'Low', 'Info'}:
                order = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}
                downgrade = finding.get('severity') in {'Critical', 'High'} and order[review['severity']] < order[finding['severity']]
                if not downgrade or _trusted(review, policy, 'finding-validation', ('independent-reviewer', 'security-reviewer')):
                    finding['severity'] = review['severity']
            finding['review_ref'] = review['id']
            finding.setdefault('observations', []).append(
                {
                    'type': 'trusted-human-review',
                    'review_ref': review['id'],
                    'decision': decision,
                    'evidence_refs': review['evidence_refs'],
                },
            )
            break
    return result

def evaluate(checks, findings, *, reviews=None, exceptions=None, policy=None, now=None) -> dict:
    policy = policy or {}
    reviews = reviews or []
    exceptions = exceptions or []
    now = _time(now) or dt.datetime.now(dt.timezone.utc)
    findings = apply_reviews(findings, reviews, policy=policy)
    blockers = []
    incomplete = []
    applied = []
    check_ids = set()
    if not checks:
        incomplete.append('No checks were executed')
    profile = policy.get('profile')
    minimum = PROFILE_REQUIREMENTS.get(profile, ())
    for check in checks:
        cid = check.get('id', 'unknown')
        check_ids.add(cid)
        required = check.get('required', True) or cid in minimum
        if not required:
            continue
        status = check.get('status', 'unknown')
        cov = check.get('coverage') or {}
        if status != 'complete':
            if status == 'not_applicable' and check.get('reason') and check.get('evidence_refs') and _trusted(check, policy, 'not-applicable', ('independent-reviewer',)):
                continue
            incomplete.append('Required check ' + cid + ' is ' + status)
            continue
        if check.get('errors'):
            incomplete.append('Required check ' + cid + ' has execution errors')
        eligible = cov.get('eligible')
        scanned = cov.get('scanned')
        if type(eligible) is not int or eligible <= 0:
            incomplete.append('Required check ' + cid + ' eligible scope must be a positive integer')
        if type(scanned) is not int or scanned <= 0:
            incomplete.append('Required check ' + cid + ' completed scope must be a positive integer')
        if type(eligible) is int and type(scanned) is int and scanned != eligible:
            incomplete.append('Required check ' + cid + ' completed scope differs from eligible scope')
        if cov.get('complete') is False or cov.get('missing') or cov.get('parse_errors'):
            incomplete.append('Required check ' + cid + ' coverage is incomplete')
        if profile in {'release', 'static-release', 'source-review'} and cov.get('scope') in {'diff', 'partial', 'changed'}:
            incomplete.append('Full profile ' + cid + ' used partial scope')
    for missing in sorted(set(minimum) - check_ids):
        incomplete.append('Required check ' + missing + ' was not executed')
    for f in findings:
        fid = f.get('finding_id', 'unknown')
        severity = f.get('severity')
        validation = f.get('validation', 'undetermined')
        if f.get('lifecycle') in CLOSED:
            continue
        if validation == 'refuted':
            review = next(
                (r for r in reviews if r.get('finding_id') == fid and r.get('decision') == 'refuted' and r.get('evidence_refs') and _finding_scope(r, f, policy) and _trusted(r, policy, 'finding-refutation', ('security-reviewer',))),
                None,
            )
            if review:
                continue
            incomplete.append('Finding ' + fid + ' refutation requires independent approval')
            continue
        if severity not in {'Critical', 'High', 'Medium', 'Low', 'Info'}:
            incomplete.append('Finding ' + fid + ' severity is unclassified')
        if severity in {'Critical', 'High'} | set(policy.get('block_severities', [])):
            if validation in VERIFIED:
                ex = next((e for e in exceptions if _exception(e, f, policy, now)), None)
                if ex:
                    applied.append(ex['id'])
                else:
                    blockers.append(fid)
            else:
                incomplete.append('Finding ' + fid + ' awaits validation')
        if f.get('review_required') and (not any(
            (r.get('finding_id') == fid and _finding_scope(r, f, policy) and _trusted(r, policy, 'finding-review', ('independent-reviewer',)) for r in reviews),
        )):
            incomplete.append('Finding ' + fid + ' review is pending')
    required_review_ids = set(policy.get('required_reviews', []))
    for missing in sorted(required_review_ids - {r.get('id') for r in reviews}):
        incomplete.append('Required review ' + missing + ' was not supplied')
    for ex in exceptions:
        target = next(
            (f for f in findings if f.get('finding_id') == ex.get('finding_id') and f.get('lifecycle') not in CLOSED),
            None,
        )
        if target is not None and (not _exception(ex, target, policy, now)):
            incomplete.append('Exception ' + str(ex.get('id', 'unknown')) + ' is expired, out of scope, or untrusted')
    for review in reviews:
        if not review.get('required', False) and review.get('id') not in required_review_ids:
            continue
        if review.get('status') != 'complete' or not review.get('evidence_refs') or (not _scope(review, policy)) or (not _trusted(review, policy, 'manual-review', ('independent-reviewer',))):
            incomplete.append('Required review ' + str(review.get('id', 'unknown')) + ' is pending or untrusted')
    if policy.get('require_trusted_evidence') or profile == 'release':
        evidence = policy.get('release_evidence') or {}
        if not (evidence.get('clean_checkout') is True and evidence.get('artifact_digest') and (evidence.get('source_revision') == policy.get('source_revision')) and _trusted(evidence, policy, 'release-evidence', ('protected-ci',))):
            incomplete.append('Protected CI checkout and artifact evidence are unverified')
    # Protected organization policy may narrow requirements. Project-controlled policy never reaches this API.
    for item in policy.get('forbidden_conditions', []):
        if item:
            blockers.append(str(item))
    incomplete = list(dict.fromkeys(incomplete))
    blockers = list(dict.fromkeys(blockers))
    applied = list(dict.fromkeys(applied))
    status = 'BLOCK' if blockers else 'INCOMPLETE' if incomplete else 'PASS_WITH_EXCEPTION' if applied else 'PASS'
    return {
        'status': status,
        'exit_code': {'BLOCK': 1, 'INCOMPLETE': 2, 'PASS_WITH_EXCEPTION': 3, 'PASS': 0}[status],
        'blockers': blockers,
        'incomplete': incomplete,
        'exceptions_applied': applied,
        'coverage': {'complete': not incomplete},
        'profile': profile,
        'evidence_level': 'official' if not incomplete and policy.get('require_trusted_evidence') else 'local',
    }
