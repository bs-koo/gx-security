"""Untrusted project defaults may add requirements, never remove them."""
import copy
from pathlib import Path
import yaml
STATIC_REQUIRED = ('sast', 'sca', 'secrets', 'framework')
RELEASE_REQUIRED = STATIC_REQUIRED + ('readiness', 'auth', 'authorization', 'dast', 'manual-review')
PROFILE_REQUIREMENTS = {
    'check': STATIC_REQUIRED,
    'static-release': STATIC_REQUIRED,
    'source-review': STATIC_REQUIRED,
    'release': RELEASE_REQUIRED,
}

def default_config(source: Path) -> dict:
    source = Path(source).resolve()
    return {
        'schema_version': 1,
        'project': {
            'id': source.name or 'project',
            'name': source.name or 'project',
            'source': str(source),
            'modules': [],
        },
        'profiles': {p: {
            'required_checks': list(r),
            'scope': 'diff' if p == 'check' else 'full',
            'require_reviews': True,
            'require_trusted_evidence': p == 'release',
        } for p, r in PROFILE_REQUIREMENTS.items()},
        'tools': {
            'semgrep': {'command': 'semgrep', 'expected_version': '1.172.0', 'timeout_seconds': 300},
            'osv': {
                'command': 'osv-scanner',
                'expected_version': '2.7.0',
                'expected_major': 2,
                'offline_db': None,
                'max_db_age_hours': 72,
                'timeout_seconds': 300,
            },
            'gitleaks': {'command': 'gitleaks', 'expected_version': '8.30.1', 'expected_major': 8, 'timeout_seconds': 300},
        },
        'target': {},
        'auth': {},
        'discovery': {},
        'budgets': {'max_duration_seconds': 1200, 'max_requests': 500, 'requests_per_second': 2, 'concurrency': 2},
        'data_mode': 'local-only',
        'sca': {},
        'exclusions': [],
    }

def _merge(base, custom):
    for k, v in custom.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = copy.deepcopy(v)
    return base

def load_config(path: Path) -> dict:
    path = Path(path).resolve()
    with path.open(encoding='utf-8-sig') as handle:
        raw = yaml.safe_load(handle)
    if not isinstance(raw, dict):
        raise ValueError('Project config must be an object')
    if raw.get('schema_version', 1) != 1:
        raise ValueError('Unsupported project schema_version')
    if raw.get('data_mode', 'local-only') != 'local-only':
        raise ValueError('Project config cannot authorize external data transfer')
    forbidden = {'policy', 'trusted_approvals', 'approvals', 'exceptions', 'trusted_scope', 'trusted_evidence', 'organization_policy', 'reviews', 'framework_baseline', 'framework_baselines', 'framework_policy', '_trusted_policy', '_credentials', '_state_dir', '_inventory', '_scan_scope', '_sca_runtime', '_source_boundary', '_snapshot_object', '_snapshot_provenance'}
    if forbidden.intersection(raw):
        raise ValueError('Trust and approvals must come from an independent protected policy input')
    if not isinstance(raw.get('project', {}), dict):
        raise ValueError('project must be an object')
    src = Path(raw.get('project', {}).get('source', path.parent))
    if not src.is_absolute():
        src = path.parent / src
    result = _merge(default_config(src), raw)
    result['project']['source'] = str(src.resolve())
    if not isinstance(result['profiles'], dict) or not isinstance(result['tools'], dict):
        raise ValueError('profiles and tools must be objects')
    for profile, required in PROFILE_REQUIREMENTS.items():
        item = result['profiles'].setdefault(profile, {})
        requested = item.get('required_checks', item.get('required', []))
        if not isinstance(requested, list):
            raise ValueError('required_checks must be an array')
        item['required_checks'] = list(dict.fromkeys([*required, *requested]))
        if profile != 'check':
            item['scope'] = 'full'
        if profile == 'release':
            item['require_trusted_evidence'] = True
    for tool, version in [('semgrep', '1.172.0'), ('osv', '2.7.0'), ('gitleaks', '8.30.1')]:
        if not isinstance(result['tools'][tool], dict):
            raise ValueError('Tool options must be objects')
        command = result['tools'][tool].get('command')
        allowed = {'semgrep': 'semgrep', 'osv': 'osv-scanner', 'gitleaks': 'gitleaks'}[tool]
        import re
        if not isinstance(command, str) or (command != allowed and (not re.fullmatch('gxsec-(?:missing|nonexistent)-[A-Za-z0-9_-]+', command))):
            raise ValueError('Project config cannot choose an arbitrary executable')
        if result['tools'][tool].get('expected_version') != version:
            raise ValueError('Project config cannot replace the protected engine version pin')
    result['tools']['osv']['max_db_age_hours'] = min(72, float(result['tools']['osv'].get('max_db_age_hours', 72)))
    if result['tools']['osv']['max_db_age_hours'] <= 0:
        raise ValueError('DB freshness limit must be positive')
    return result
