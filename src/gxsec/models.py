"""Versioned dictionary factories; no engine result implies verification."""
import hashlib
import json
import re
from pathlib import PurePosixPath
from . import SCHEMA_VERSION
from .redaction import redact
SEVERITIES = ('Critical', 'High', 'Medium', 'Low', 'Info')
VALIDATIONS = ('candidate', 'source-verified', 'runtime-verified', 'refuted', 'undetermined')
CHECK_STATUSES = ('complete', 'degraded', 'partial', 'failed', 'skipped', 'unsupported', 'cancelled', 'incomplete', 'not_applicable')

def content_hash(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str).encode('utf-8'),
    ).hexdigest(
    )

def fingerprint(*, category, rule, path='', snippet='', symbol='', module='', identity=None):
    """Use a semantic symbol when known and a conservative full path otherwise."""
    parent = str(PurePosixPath(str(path).replace('\\', '/')).parent)
    anchor = re.sub('\\s+', '', str(snippet))
    return content_hash(
        {
            'category': category,
            'rule': rule,
            'module': module or parent,
            'symbol': symbol or str(path).replace('\\', '/'),
            'anchor': anchor,
            'identity': identity,
        },
    )

def make_finding(*, category, rule, path='', line=1, snippet='', severity=None, validation='candidate', title=None, description='', symbol='', module='', identity=None, **extra):
    fp = fingerprint(
        category=category,
        rule=rule,
        path=path,
        snippet=snippet,
        symbol=symbol,
        module=module,
        identity=identity,
    )
    result = {
        'schema_version': SCHEMA_VERSION,
        'finding_id': 'GXSEC-' + fp[:20],
        'fingerprint': fp,
        'semantic_fingerprint': fingerprint(category=category,rule=rule,path=path,snippet=snippet,symbol=symbol or '__unknown_symbol__',module=module,identity=identity),
        'semantic_rule_id': rule,
        'rule_id': rule,
        'category': category,
        'severity': severity if severity in SEVERITIES else None,
        'validation': validation if validation in VALIDATIONS else 'undetermined',
        'lifecycle': 'open',
        'locations': [{
            'path': str(path).replace('\\', '/'),
            'line': max(1, int(line or 1)),
            'symbol': symbol,
            'module': module,
        }],
        'title': title or rule,
        'description': description,
        'snippet': snippet,
        'observations': [],
        'evidence_refs': [],
        'remediation': {'guidance': 'Review the affected flow, apply the rule-specific fix, and rerun the same check.'},
        'confidence': {'level': 'low', 'reason': 'Engine candidate requires contextual review.'},
    }
    result.update(extra)
    return redact(result)

def make_check(check_id, *, required=True, status='incomplete', **extra):
    result = {
        'id': check_id,
        'status': status,
        'required': required,
        'findings': [],
        'errors': [],
        'coverage': {'eligible': 0, 'scanned': 0, 'scope': 'full', 'files': []},
        'engine': {},
    }
    result.update(extra)
    return result

def validate_run(run):
    """Small runtime guard; JSON schemas also describe exchange artifacts."""
    if not isinstance(run, dict) or run.get('schema_version') != SCHEMA_VERSION:
        raise ValueError('Unsupported result schema_version')
    for key in ('run_id', 'project_id', 'profile', 'source', 'checks', 'findings'):
        if key not in run:
            raise ValueError('Run is missing ' + key)
    if not isinstance(run['checks'], list) or not isinstance(run['findings'], list):
        raise ValueError('Run checks and findings must be arrays')
    if not re.fullmatch('[A-Za-z0-9_.-]{1,128}', str(run['run_id'])):
        raise ValueError('Invalid run_id')
    for f in run['findings']:
        if not all((f.get(k) for k in ('finding_id', 'fingerprint', 'validation', 'lifecycle'))):
            raise ValueError('Invalid finding identity/state')
    return run
