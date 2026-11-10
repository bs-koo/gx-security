"""Pinned static-engine adapters. No builds, tool updates, or online scans."""
import datetime as dt
import math
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import parse_qs, urlsplit
import yaml
from .config import PROFILE_REQUIREMENTS
from .models import content_hash, make_check, make_finding
from .redaction import redact
from .source import EXCLUDED_DIRS, collect_source, trusted_runtime_tool, runtime_environment, reject_reparse_path, selected_paths, exclusion_contract
from .policy import _trusted
from .snapshot import verified_snapshot
from .contextual import contextualize_findings
from .triage import enrich_framework_findings
from .diagnostics import MAX_JSON_BYTES, exception_diagnostic, process_failure, semgrep_diagnostics
from .execution import BudgetExceeded, checkpoint, phase, timeout_for
from .processes import bounded_run as _process

def _plugin_root():
    candidates = []
    if os.environ.get('GXSEC_PLUGIN_ROOT'):
        candidates.append(Path(os.environ['GXSEC_PLUGIN_ROOT']).expanduser())
    candidates.extend([Path(__file__).resolve().parent / '_assets', Path(__file__).resolve().parents[2]])
    for candidate in candidates:
        candidate = candidate.resolve()
        if (candidate / 'skills').is_dir() and (candidate / 'tools').is_dir() and (candidate / 'scan_all.py').is_file():
            return candidate
    return Path(__file__).resolve().parents[2]
ROOT = _plugin_root()
KNOWN_COMMANDS = {
    'semgrep': 'semgrep',
    'osv': 'osv-scanner',
    'gitleaks': 'gitleaks',
    'trivy': 'trivy',
    'codeql': 'codeql',
    'nuclei': 'nuclei',
}
PINS = {'semgrep': '1.172.0', 'osv': '2.7.0', 'gitleaks': '8.30.1'}
SAST_SUFFIXES = {'.java', '.jsp', '.jspx', '.xml', '.yml', '.yaml', '.properties', '.js', '.jsx', '.ts', '.tsx', '.vue', '.html', '.htm', '.py', '.kt', '.kts'}
LOCK_NAMES = {'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock', 'uv.lock', 'Pipfile.lock', 'requirements.txt', 'go.sum', 'Cargo.lock', 'Gemfile.lock', 'composer.lock', 'gradle.lockfile', 'packages.lock.json'}

def _env(extra=None):
    env = runtime_environment()
    if extra:
        env.update({key: value for key, value in extra.items() if key in {'OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY','GXSEC_NO_SEMGREP'}})
    return env

def _run(cmd, *, cwd, timeout=300, extra_env=None):
    with tempfile.TemporaryDirectory(prefix='gxsec-home-') as home:
        environment = _env(extra_env)
        environment.update({'HOME': home, 'USERPROFILE': home, 'XDG_CACHE_HOME': str(Path(home) / 'cache')})
        return _process(
            [str(x) for x in cmd], cwd=str(cwd),
            timeout=timeout_for(max(1, min(float(timeout), 1200))),
            shell=False, env=environment,
        )

def _command(name, options, source):
    command = options.get('command', KNOWN_COMMANDS[name])
    # An untrusted repository cannot select a program. Protected packaging controls PATH.
    if not isinstance(command, str) or (command != KNOWN_COMMANDS[name] and (not re.fullmatch('gxsec-(?:missing|nonexistent)-[A-Za-z0-9_-]+', command))):
        raise ValueError('Project config cannot choose an arbitrary executable for ' + name)
    if command != KNOWN_COMMANDS[name]:
        raise FileNotFoundError('Requested engine is unavailable')
    return trusted_runtime_tool(name, source)

def _probe(name, options, source, check, *, trust_source=None):
    check['engine'] = {'name': name, 'expected_version': PINS.get(name), 'version': None, 'available': False}
    try:
        provenance = _command(name, options, trust_source or source)
        command = provenance['executable']
        check['engine'].update({'sha256': provenance['sha256'], 'runtime_manifest_hash': provenance['manifest_hash']})
        if not command:
            raise FileNotFoundError(KNOWN_COMMANDS[name] + ' is unavailable')
        result = _run([command, '--version'], cwd=source, timeout=15)
        if result.returncode != 0:
            raise ValueError('Version probe failed')
        match = re.search('\\b(\\d+\\.\\d+\\.\\d+)(?:[-+][\\w.-]+)?', result.stdout + ' ' + result.stderr)
        if not match:
            raise ValueError('Engine version could not be identified')
        version = match.group(1)
        check['engine'].update({'version': version, 'available': True, 'executable': str(command)})
        if name in PINS and version != PINS[name]:
            raise ValueError('Engine version mismatch; expected ' + PINS[name] + ', got ' + version)
        return command
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        check['errors'].append({'type': 'engine_unavailable', 'message': str(exc)})
        return None


def probe_engine(name, options, source):
    check = make_check(name)
    if _probe(name, options, Path(source).resolve(), check):
        check['status'] = 'complete'
        check['coverage'] = {'eligible': 1, 'scanned': 1, 'scope': 'full'}
    return redact(check)


def _json_result(result, check, expected=dict):
    if result.returncode not in (0, 1):
        check['errors'].append(process_failure(result))
        check['coverage']['partial'] = True
    try:
        if not isinstance(result.stdout, (str, bytes)) or len(result.stdout) > MAX_JSON_BYTES:
            raise ValueError('Engine JSON output exceeds its bound')
        if isinstance(result.stdout, str) and len(result.stdout.encode('utf-8')) > MAX_JSON_BYTES:
            raise ValueError('Engine JSON output exceeds its bound')
        data = json.loads(result.stdout)
        if not isinstance(data, expected):
            raise ValueError('Unexpected JSON shape')
        return data
    except (ValueError, TypeError, RecursionError) as exc:
        check['errors'].append(exception_diagnostic('malformed_output', exc))
        return None

def _path(path, source):
    p = Path(str(path))
    if p.is_absolute():
        try:
            return p.resolve().relative_to(source.resolve()).as_posix()
        except ValueError:
            return p.as_posix()
    return p.as_posix().removeprefix('./')

def _severity(value):
    if value is None:
        return None
    value = str(value).strip()
    canonical = {
        'critical': 'Critical',
        'high': 'High',
        'medium': 'Medium',
        'moderate': 'Medium',
        'low': 'Low',
        'info': 'Info',
        'informational': 'Info',
    }
    if value.lower() in canonical:
        return canonical[value.lower()]
    try:
        score = float(value)
        if not math.isfinite(score) or not 0 <= score <= 10:
            return None
        return 'Critical' if score >= 9 else 'High' if score >= 7 else 'Medium' if score >= 4 else 'Low' if score > 0 else 'Info'
    except ValueError:
        return None

def _fallback(source, check, *, trust_source=None):
    if not (ROOT / 'scan_all.py').is_file():
        return []
    try:
        python = trusted_runtime_tool('python', trust_source or source)['executable']
        result = _run(
            [python, ROOT / 'scan_all.py', source, '--json'],
            cwd=ROOT,
            timeout=180,
            extra_env={'GXSEC_NO_SEMGREP': '1'},
        )
        data = json.loads(result.stdout)
        check['engine']['fallback'] = {
            'name': 'legacy-regex',
            'execution_status': data.get('execution_status', 'unknown'),
            'coverage': data.get('coverage'),
            'reason': 'Pinned Semgrep unavailable; exploratory candidates only',
        }
        candidates = []
        for row in data.get('by_skill', data.get('results', [])):
            if not isinstance(row, dict):
                continue
            for item in row.get('candidates', []):
                candidates.append(
                    make_finding(
                        category=row.get('skill', 'legacy'),
                        rule=item.get('rule_id', 'legacy.unknown'),
                        path=_path(item.get('file', ''), source),
                        line=item.get('line', 1),
                        snippet=item.get('snippet', ''),
                        severity=_severity(item.get('severity')),
                        validation='candidate',
                        check_id='sast',
                        observations=[{'engine': 'legacy-regex', 'raw_confidence': item.get('confidence')}],
                    ),
                )
        return candidates
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired) as exc:
        check['errors'].append({'type': 'fallback_failed', 'message': str(exc)})
        return []


def _source_slice(source, item, cache):
    """Read bounded local evidence; engine-provided source text is not authoritative."""
    path = Path(str(item.get('path', '')))
    if not path.is_absolute():
        path = source / path
    path = reject_reparse_path(path).resolve(strict=True)
    path.relative_to(source.resolve())
    if path not in cache:
        with path.open('rb') as handle:
            raw = handle.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError('Source evidence slice exceeds the bounded reader size: ' + str(path))
        for encoding in ('utf-8-sig', 'cp949', 'euc-kr'):
            try:
                text = raw.decode(encoding)
                break
            except UnicodeDecodeError:
                continue
        else:
            raise ValueError('Source evidence encoding is unsupported: ' + str(path))
        cache[path] = (text.splitlines(), encoding, hashlib.sha256(raw).hexdigest())
    lines, encoding, file_hash = cache[path]
    start = int(item.get('start', {}).get('line', 0))
    end = int(item.get('end', {}).get('line', start))
    if start < 1 or end < start or end > len(lines):
        raise ValueError('Engine result points outside the source line range')
    snippet = '\n'.join(lines[start - 1:min(end, start + 9)])[:6000]
    context = '\n'.join(lines[max(0, start - 4):min(len(lines), end + 3)])
    prefix = '\n'.join(lines[:start])
    classes = list(re.finditer(r'\b(?:class|interface|enum|record)\s+([A-Za-z_$]\w*)', prefix))
    methods = list(re.finditer(r'(?m)^\s*(?:(?:public|private|protected|static|final|async|export)\s+)*(?:[\w.<>\[\]?]+\s+)?([A-Za-z_$]\w*)\s*\([^;{}]*\)\s*(?:throws[^{]+)?\{', prefix))
    methods = [match for match in methods if match.group(1) not in {'if', 'for', 'while', 'switch', 'catch', 'synchronized'}]
    symbol = ('::'.join([classes[-1].group(1) if classes else '', methods[-1].group(1) if methods else ''])).strip(':')
    return snippet, re.sub(r'\s+', '', context), symbol, encoding, file_hash


SAST_CATEGORIES = {
    'detecting-auth-session-weaknesses': 'auth-session',
    'detecting-broken-access-control': 'access-control',
    'detecting-csrf-vulnerabilities': 'csrf',
    'detecting-file-upload-vulnerabilities': 'file-upload',
    'detecting-path-traversal': 'path-traversal',
    'detecting-sensitive-data-exposure': 'sensitive-data-exposure',
    'detecting-sql-injection': 'sql-injection',
    'detecting-ssrf-and-open-redirect': 'ssrf-and-open-redirect',
    'detecting-xss-vulnerabilities': 'xss',
}


def _rule_guidance(rule_id, catalog):
    trusted = catalog.get(rule_id) or {}
    message = trusted.get('message')
    if not isinstance(message, str) or not message.strip():
        message = 'Static rule candidate requires review of the recorded source location.'
    sentences = re.split(r'(?<=[.!?])\s+', message.strip())
    title = sentences[0] if trusted else rule_id
    title = title if len(title) <= 180 else title[:177] + '...'
    guidance = ' '.join(sentences[1:]) or message
    return title, message, guidance, trusted.get('metadata') or {}, trusted.get('category', 'sast')

def _sast(source, config, inventory, profile):
    check = make_check('sast')
    options = config.get('tools', {}).get('semgrep', {})
    findings = []
    eligible = [p for p in inventory['files'] if Path(p).suffix.lower() in SAST_SUFFIXES]
    check['coverage'].update(
        {
            'eligible': len(eligible),
            'files': eligible,
            'scope_hash': inventory['scope_hash'],
            'exclusions': inventory['exclusions'],
        },
    )
    rules = sorted((ROOT / 'skills').glob('detecting-*/rules/*.y*ml'))
    rule_docs = []
    rule_ids = []
    rule_catalog = {}
    rule_languages = set()
    for path in rules:
        try:
            doc = yaml.safe_load(path.read_text(encoding='utf-8-sig'))
            for rule in doc['rules']:
                rule_ids.append(rule['id'])
                rule_catalog[rule['id']] = {'message': rule.get('message'), 'metadata': rule.get('metadata') or {}, 'category': SAST_CATEGORIES.get(path.parent.parent.name, 'sast')}
                rule_languages.update(value for value in rule.get('languages', []) if isinstance(value, str))
            rule_docs.append(
                {'path': path.relative_to(ROOT).as_posix(), 'hash': hashlib.sha256(path.read_bytes()).hexdigest()},
            )
        except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as exc:
            check['errors'].append({'type': 'rule_load_failed', 'path': str(path), 'message': str(exc)})
    command = _probe('semgrep', options, source, check, trust_source=config.get('_source_boundary', source))
    check['engine'].update(
        {
            'rules_hash': content_hash(rule_docs),
            'rule_files': rule_docs,
            'rule_ids': rule_ids,
            'asset_root': str(ROOT),
            'asset_mode': 'bundled' if ROOT.name == '_assets' else 'checkout-or-runtime',
            'limitations': ['Semgrep CE does not establish complete cross-file data flow or full JSP coverage.'],
        },
    )
    if not rules or not rule_ids:
        check['errors'].append({'type': 'empty_rules', 'message': 'No organization rules were loaded'})
    if command and eligible and rules:
        # Pinned Semgrep's own defaults and repository ignore files must not
        # silently narrow the byte-verified inventory. Unsupported flags fail
        # closed below; never retry with weaker target selection.
        args = [command, 'scan', '--json', '--quiet', '--metrics=off', '--disable-version-check', '--disable-nosem', '--no-git-ignore', '--x-ignore-semgrepignore-files', '--no-rewrite-rule-ids', '--strict']
        for path in rules:
            args += ['--config', str(path)]
        for excluded in sorted(EXCLUDED_DIRS):
            args += ['--exclude', excluded]
        args += ['--', str(source)]
        try:
            result = _run(args, cwd=ROOT, timeout=options.get('timeout_seconds', 300))
            data = _json_result(result, check)
            if data is not None:
                if isinstance(data.get('errors'), list):
                    check['errors'] += semgrep_diagnostics(data['errors'], source, inventory['files'])
                else:
                    check['errors'].append({'type': 'execution_metadata_missing'})
                paths = data.get('paths')
                scanned_paths = paths.get('scanned') if isinstance(paths, dict) else None
                if not isinstance(scanned_paths, list):
                    check['errors'].append({'type': 'coverage_metadata_missing'})
                    check['coverage']['partial'] = True
                    scanned_paths = []
                if not isinstance(data.get('results'), list):
                    raise ValueError('Semgrep result metadata missing')
                scanned = [_path(p, source) for p in scanned_paths]
                check['coverage'].update(
                    {
                        'scanned': len(set(scanned) & set(eligible)),
                        'scanned_files': scanned,
                        'missing': sorted(set(eligible) - set(scanned)),
                    },
                )
                kotlin_missing = [path for path in check['coverage']['missing']
                                  if Path(path).suffix.lower() in {'.kt', '.kts'}]
                if kotlin_missing and not {'kotlin', 'kt'} & rule_languages:
                    check['errors'].append({'type': 'rule_coverage_unavailable', 'language': 'kotlin',
                                            'reason': 'no_language_specific_rules', 'files': kotlin_missing})
                cache = {}
                occurrences = {}
                local_key = _local_hmac_key(source, config)
                check['engine']['fingerprint_key_id'] = hashlib.sha256(local_key).hexdigest() if local_key else None
                for item in sorted(data['results'], key=lambda result: (str(result.get('path', '')), result.get('start', {}).get('line', 0), result.get('check_id', ''))):
                    extra = item.get('extra') or {}
                    try:
                        snippet, context, symbol, encoding, observed_file_hash = _source_slice(source, item, cache)
                    except (OSError, ValueError) as exc:
                        check['errors'].append(exception_diagnostic('source_evidence_unavailable', exc))
                        continue
                    relative = _path(item.get('path', ''), source)
                    rule = item.get('check_id', 'unknown')
                    title, description, guidance, metadata, category = _rule_guidance(rule, rule_catalog)
                    context_hmac = hmac.new(local_key, context.encode('utf-8'), hashlib.sha256).hexdigest()
                    occurrence_key = (relative, rule, context_hmac)
                    occurrence = occurrences.get(occurrence_key, 0)
                    occurrences[occurrence_key] = occurrence + 1
                    finding = make_finding(
                        category=category,
                        rule=rule,
                        path=relative,
                        line=item.get('start', {}).get('line', 1),
                        snippet=redact(snippet),
                        identity={'context_hmac': context_hmac, 'occurrence': occurrence},
                        severity=_severity(metadata.get('security-severity', metadata.get('severity'))),
                        title=title,
                        description=description,
                        remediation={'guidance': guidance},
                        cwe=metadata.get('cwe'),
                        stack=metadata.get('stack'),
                        owasp=metadata.get('owasp'),
                        check_id='sast',
                        review_required=True,
                        observations=[{'engine': 'semgrep', 'engine_severity': extra.get('severity') if extra.get('severity') in {'ERROR','WARNING','INFO'} else 'UNKNOWN', 'source_encoding': encoding, 'source_evidence': 'bounded-local-slice'}],
                    )
                    finding['locations'][0]['symbol'] = symbol
                    finding['file_hash'] = observed_file_hash
                    findings.append(finding)
        except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
            check['errors'].append(exception_diagnostic('sast_failed', exc))
    elif command and (not eligible):
        check['errors'].append({'type': 'empty_scope', 'message': 'No supported SAST source files'})
    elif not command and options.get('fallback', True):
        findings = _fallback(source, check, trust_source=config.get('_source_boundary', source))
    check['status'] = 'complete' if not check['errors'] and check['coverage']['eligible'] > 0 and (check['coverage']['scanned'] >= check['coverage']['eligible']) else 'incomplete'
    check['findings'] = [f['finding_id'] for f in findings]
    return (check, findings)

def _parse_time(value):
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return parsed.replace(tzinfo=dt.timezone.utc) if parsed.tzinfo is None else parsed
    except (ValueError, TypeError):
        return None


def _osv_matching_coverage(check, stderr, database, approved_hashes):
    """Parsing a dependency is separate from running its offline advisory match."""
    loaded = []
    unapproved = False
    for ecosystem, raw_path in re.findall(r'(?m)^Loaded (.+?) local db from (.+?)\s*$', stderr):
        path = Path(os.path.abspath(raw_path.strip()))
        try:
            relative = path.relative_to(database).as_posix()
        except ValueError:
            unapproved = True
            continue
        ecosystem = ecosystem.strip()
        normalized = ecosystem.split(':', 1)[0]
        canonical = 'osv-scalibr/' + normalized + '/all.zip'
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ._-]*', normalized) or relative != canonical or relative not in approved_hashes:
            unapproved = True
            continue
        loaded.append({'ecosystem': ecosystem, 'path': relative, 'sha256': approved_hashes[relative]})
    loaded.sort(key=lambda entry: (entry['ecosystem'], entry['path'], entry['sha256']))
    loaded_ecosystems = {entry['ecosystem'] for entry in loaded}
    unmatched = []
    for package in check['coverage']['packages']:
        ecosystem = package.get('ecosystem')
        origin = package.get('source_origin')
        reason = None
        if origin == 'LOCAL':
            reason = 'local-package-advisory-matching-skipped'
        elif ecosystem == 'npm' and origin != 'PUBLIC_REGISTRY':
            reason = 'npm-registry-origin-unverified'
        elif origin not in {'UNSPECIFIED', 'PUBLIC_REGISTRY'}:
            reason = 'unsupported-package-origin'
        elif not isinstance(ecosystem, str) or not ({ecosystem, ecosystem.split(':', 1)[0]} & loaded_ecosystems):
            reason = 'approved-ecosystem-database-load-unverified'
        if reason:
            unmatched.append({'package': package, 'reason': reason})
    matcher_failed = bool(re.search(r'(?im)^(?:Error during extraction:|could not load db for .+ ecosystem:)', stderr))
    complete = bool(check['coverage']['packages']) and not unmatched and not unapproved and not matcher_failed
    check['coverage']['matching'] = {'complete': complete, 'loaded_databases': loaded, 'unmatched_packages': unmatched}
    check['engine']['database']['loaded'] = loaded
    check['engine']['database']['cache_layout'] = 'osv-scalibr/<ecosystem>/all.zip'
    if not complete:
        check['errors'].append({'type': 'advisory_matching_incomplete', 'message': 'Offline advisory matching did not cover every parsed package with an approved ecosystem database'})

def _sca(source, config, inventory, profile):
    check = make_check('sca')
    findings = []
    options = config.get('tools', {}).get('osv', {})
    inputs = [p for p in inventory['files'] if Path(p).name in LOCK_NAMES or Path(p).name.endswith(('.cdx.json', '.spdx.json', '.spdx', '.bom.json'))]
    check['coverage'].update(
        {'eligible': len(inputs), 'files': inputs, 'scope_hash': inventory['scope_hash'], 'packages': []},
    )
    command = _probe('osv', options, source, check, trust_source=config.get('_source_boundary', source))
    trusted = config.get('_trusted_policy') or {}
    trusted_sca = trusted.get('sca') or {}
    approved_db = config.get('_sca_runtime') or trusted_sca
    db = None
    metadata = {}
    db_files = []
    actual_hashes = {}
    db_usable = False
    if approved_db.get('offline_db') and approved_db.get('db_manifest_sha256'):
        try:
            db = reject_reparse_path(approved_db['offline_db']).resolve(strict=True)
            if db.is_relative_to(Path(config.get('_source_boundary', source)).resolve()):
                raise ValueError('Advisory database must be outside inspected source')
            manifest_path = reject_reparse_path(db / 'snapshot.json')
            manifest_bytes = manifest_path.read_bytes()
            if hashlib.sha256(manifest_bytes).hexdigest() != approved_db['db_manifest_sha256']:
                raise ValueError('Offline database manifest hash mismatch')
            metadata = json.loads(manifest_bytes.decode('utf-8-sig'))
            db_files = sorted(db.rglob('*.zip'))
            for archive in db_files:
                reject_reparse_path(archive)
            actual_hashes = {p.relative_to(db).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in db_files}
            if metadata.get('schema_version') != 1 or not metadata.get('files') or metadata.get('files') != actual_hashes:
                raise ValueError('Offline database file hash mismatch')
            db_usable = True
        except (OSError, ValueError, AttributeError) as exc:
            check['errors'].append({'type': 'database_provenance_unverified', 'message': str(exc)})
    else:
        check['errors'].append({'type': 'database_provenance_unverified', 'message': 'Independent policy or explicit runtime input must approve database location and manifest hash'})
    generated = _parse_time(metadata.get('generated_at'))
    # Project timestamps are diagnostic only; they cannot authorize freshness.
    diagnostic_generated = generated or _parse_time(options.get('db_generated_at'))
    now = dt.datetime.now(dt.timezone.utc)
    max_age = min(72, float(options.get('max_db_age_hours', 72)))
    check['engine']['database'] = {
        'path': str(db) if db else None,
        'generated_at': metadata.get('generated_at'),
        'advisory_as_of': metadata.get('advisory_as_of'),
        'max_age_hours': max_age,
        'hash': content_hash(actual_hashes) if db_files else None,
        'manifest_hash': content_hash(metadata) if metadata else None,
    }
    if not db_files:
        check['errors'].append(
            {
                'type': 'missing_database',
                'message': 'OSV offline advisory snapshot is not installed; runtime download is disabled',
            },
        )
    if not generated:
        check['errors'].append(
            {'type': 'unknown_database_age', 'message': 'OSV DB generated_at evidence is missing'},
        )
    if diagnostic_generated and ((now - diagnostic_generated).total_seconds() > max_age * 3600 or diagnostic_generated > now + dt.timedelta(minutes=5)):
        check['errors'].append(
            {'type': 'stale_database', 'message': 'OSV offline DB is stale or has an invalid future timestamp'},
        )
    if not inputs:
        check['errors'].append(
            {
                'type': 'unresolved_dependencies',
                'message': 'No resolved lockfile/SBOM dependency inputs; declarations alone are insufficient',
            },
        )
    provenance = trusted_sca.get('provenance') or {}
    revision = inventory.get('revision') or inventory['hash']
    expected = {x['path']: x['hash'] for x in inventory['inventory'] if x['path'] in inputs}
    module_paths = {m['path'] for m in inventory.get('modules', [])} or {'.'}
    if not _trusted(provenance, trusted, 'dependency-provenance', ('protected-ci',)) or provenance.get('source_revision') != revision or provenance.get('scope_hash') != inventory.get('scope_hash') or provenance.get('input_hashes') != expected or provenance.get('runtime_complete') is not True or not provenance.get('artifact_digest') or not module_paths <= set(provenance.get('modules', [])):
        check['errors'].append(
            {
                'type': 'dependency_provenance_unverified',
                'message': 'Resolved inputs require matching revision, file hashes, all modules, and runtime/transitive coverage evidence',
            },
        )
    if profile == 'release':
        trusted = config.get('_trusted_policy', {})
        evidence = trusted.get('release_evidence', {})
        if not provenance.get('artifact_digest') or provenance.get('artifact_digest') != evidence.get('artifact_digest') or evidence.get('source_revision') != revision:
            check['errors'].append(
                {
                    'type': 'artifact_provenance_unverified',
                    'message': 'Release SCA requires independently trusted artifact-linked dependency inputs',
                },
            )
    if command and inputs and db_files and db_usable:
        with tempfile.TemporaryDirectory(prefix='gxsec-osv-') as temp:
            clean_config = Path(temp) / 'osv-scanner.toml'
            clean_config.write_text('', encoding='utf-8')
            args = [command, 'scan', 'source', '--offline', '--format=json', '--all-packages', '--config', str(clean_config)]
            for path in inputs:
                args += ['--lockfile', str(source / path)] if not Path(path).name.endswith(('.cdx.json', '.spdx.json', '.spdx', '.bom.json')) else ['--sbom', str(source / path)]
            try:
                db_inventory = {'files': sorted(actual_hashes), 'hash': content_hash(actual_hashes),
                    'inventory': [{'path': path, 'hash': digest} for path, digest in actual_hashes.items()]}
                with verified_snapshot(db, db_inventory, include_history=False) as database_snapshot:
                    database_input = database_snapshot.path
                    check['engine']['database']['snapshot'] = database_snapshot.provenance
                    result = _run(
                        args,
                        cwd=Path(temp),
                        timeout=options.get('timeout_seconds', 300),
                        extra_env={'OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY': str(database_input)},
                    )
                    if not database_snapshot.verify():
                        raise ValueError('Private advisory database bytes changed during scanning')
                data = _json_result(result, check)
                if data is not None:
                    if not isinstance(data.get('results'), list):
                        raise ValueError('OSV JSON results missing')
                    scanned = set()
                    unidentified = []
                    for group in data['results']:
                        origin = group.get('source') or {}
                        origin_path = _path(origin.get('path', ''), source)
                        scanned.add(origin_path)
                        for package in group.get('packages', []):
                            raw_package = package.get('package', {})
                            p = {key: raw_package.get(key) for key in ('name', 'version', 'ecosystem', 'purl')}
                            purl = p.get('purl')
                            try:
                                package_origin = parse_qs(urlsplit(purl).query).get('source', ['UNSPECIFIED'])[0] if isinstance(purl, str) else 'UNSPECIFIED'
                            except ValueError:
                                package_origin = 'UNVERIFIED'
                            p['source_origin'] = package_origin
                            check['coverage']['packages'].append(p)
                            if not all(isinstance(p.get(key), str) and p[key] for key in ('name','version','ecosystem')):
                                unidentified.append(p)
                            for vuln in package.get('vulnerabilities', []):
                                sev = _severity(vuln.get('database_specific', {}).get('severity'))
                                if sev is None:
                                    for s in vuln.get('severity', []):
                                        if isinstance(s, dict):
                                            sev = _severity(s.get('score')) or sev
                                findings.append(
                                    make_finding(
                                        category='dependencies',
                                        rule=vuln.get('id', 'unknown-advisory'),
                                        path=origin_path,
                                        severity=sev,
                                        validation='candidate' if result.returncode not in (0, 1) else 'source-verified',
                                        identity={
                                            'name': p.get('name'),
                                            'version': p.get('version'),
                                            'ecosystem': p.get('ecosystem'),
                                            'advisory': vuln.get('id'),
                                        },
                                        title=vuln.get('summary', vuln.get('id')),
                                        description='Dependency advisory match requires review of the identified package and advisory.',
                                        check_id='sca',
                                        observations=[{'engine': 'osv', 'package': p, 'aliases': vuln.get('aliases', []), 'source': {'path': origin_path, 'type': origin.get('type')}}],
                                    ),
                                )
                    check['coverage'].update(
                        {
                            'scanned': len(scanned & set(inputs)),
                            'scanned_files': sorted(scanned),
                            'missing': sorted(set(inputs) - scanned),
                            'unidentified_packages': unidentified,
                        },
                    )
                    if unidentified:
                        check['errors'].append(
                            {'type': 'unidentified_dependencies', 'message': 'Some dependencies lack exact identity/version'},
                        )
                    if not check['coverage']['packages']:
                        check['errors'].append(
                            {'type': 'empty_dependency_graph', 'message': 'OSV parsed zero packages; unresolved coverage'},
                        )
                    _osv_matching_coverage(check, result.stderr, database_input, actual_hashes)
            except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
                check['errors'].append(exception_diagnostic('sca_failed', exc))
    check['status'] = 'complete' if not check['errors'] and inputs and (check['coverage']['scanned'] == len(inputs)) else 'incomplete'
    check['findings'] = [f['finding_id'] for f in findings]
    return (check, findings)

def _local_hmac_key(source, config):
    base = Path(config.get('_state_dir') or source / '.gxsec')
    if base.is_symlink():
        raise ValueError('Local fingerprint state directory must not be a symlink')
    base.mkdir(parents=True, exist_ok=True)
    keyfile = base / 'fingerprint.key'
    if keyfile.is_symlink():
        raise ValueError('Local fingerprint key must not be a symlink')
    try:
        fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(secrets.token_bytes(32))
    except FileExistsError:
        pass
    key = keyfile.read_bytes()
    if len(key) != 32:
        raise ValueError('Local secret fingerprint key has invalid length')
    return key

def _secret_anchor(item, source):
    raw = str(item.get('Secret') or item.get('Match') or '')
    if raw and (not re.fullmatch('(?i)(?:\\[?redacted\\]?|\\*+)', raw)):
        return raw
    # The engine masks report values. A keyed source-line anchor distinguishes
    # separate findings and survives inserting lines above a current-tree secret.
    path = Path(str(item.get('File', '')))
    if not path.is_absolute():
        path = source / path
    try:
        path.resolve().relative_to(source.resolve())
        line = int(item.get('StartLine', 0))
        if line > 0:
            with path.open('r', encoding='utf-8', errors='replace') as handle:
                for number, text in enumerate(handle, 1):
                    if number == line:
                        return re.sub('\\s+', '', text)
    except (OSError, ValueError):
        pass
    # Historical/deleted files have no current source. Preserve distinct records
    # conservatively instead of falsely matching different secret locations.
    return json.dumps(
        {
            'path': str(item.get('File', '')),
            'commit': item.get('Commit'),
            'line': item.get('StartLine'),
            'fingerprint': item.get('Fingerprint'),
        },
        sort_keys=True,
    )

def _history_errors(history):
    """Forward fixed preparation metadata, never native Git output or paths."""
    if history.get('status') == 'complete':
        return []
    errors = history.get('errors')
    if not isinstance(errors, list):
        return []
    allowed = {
        'category': {'nonzero_exit', 'terminated_by_signal', 'memory_exhaustion_reported',
                     'resource_exhaustion_reported', 'storage_exhaustion_reported',
                     'permission_denied_reported', 'ownership_rejected_reported',
                     'invalid_repository_reported', 'invalid_engine_output', 'timeout',
                     'output_limit', 'memory_exhaustion', 'storage_exhaustion',
                     'resource_unavailable', 'permission_denied', 'input_unavailable', 'io_error'},
        'stage': {'inventory', 'clone', 'independent-objects', 'object-format', 'commit-and-refs'},
        'evidence': {'stderr-marker', 'process-returncode'},
    }
    safe = []
    for error in errors[:100]:
        if not isinstance(error, dict) or error.get('type') != 'git_history_failed':
            continue
        item = {'type': 'git_history_failed'}
        for key, values in allowed.items():
            if isinstance(error.get(key), str) and error[key] in values:
                item[key] = error[key]
        for key, minimum, maximum in (('returncode', -(2 ** 31), 2 ** 32 - 1), ('signal', 1, 64)):
            value = error.get(key)
            if type(value) is int and minimum <= value <= maximum:
                item[key] = value
        safe.append(item)
    return safe


def _gitleaks_scope_config(inventory):
    """Generate trusted rules from the collector's literal directory contract."""
    contract = inventory.get('exclusion_contract', {})
    if not isinstance(contract, dict):
        raise ValueError('Invalid source exclusion contract')
    case_sensitive = contract.get('case_sensitive_paths', True)
    if type(case_sensitive) is not bool:
        raise ValueError('Invalid source path comparison contract')
    with selected_paths(contract.get('selected_directory_paths', [])):
        paths = exclusion_contract()['selected_directory_paths']
    scope = {'version': 1, 'selected_directory_paths': paths,
             'case_sensitive_paths': case_sensitive}
    document = '[extend]\nuseDefault = true\n'
    if paths:
        # Go/RE2 literal escaping, followed separately by TOML string escaping.
        # A trailing slash excludes descendants, never a same-named regular file.
        expressions = ['^' + ''.join('\\' + char if char in '\\.+*?()|[]{}^$' else char
                                    for char in path) + '/' for path in paths]
        quoted = [json.dumps(value, ensure_ascii=False).replace('\x7f', '\\u007f')
                  for value in expressions]
        document += ('\n[[allowlists]]\ndescription = "gxsec operator-selected directory exclusions"\n'
                     'condition = "OR"\npaths = [' + ', '.join(quoted) + ']\n')
    return document.encode('utf-8'), scope


def _secrets(source, config, inventory, profile):
    check = make_check('secrets')
    findings = []
    options = config.get('tools', {}).get('gitleaks', {})
    history = config.get('_snapshot_provenance', {}).get('history', {})
    history_required = history.get('required')
    check['errors'].extend(_history_errors(history))
    modes = ['dir', 'git'] if history_required or inventory.get('git') or (source / '.git').exists() else ['dir']
    check['coverage'].update(
        {
            'eligible': len(modes),
            'scanned': 0,
            'files': inventory['files'],
            'modes': modes,
            'scope_hash': inventory['scope_hash'],
            'history_complete': False,
        },
    )
    if 'git' not in modes and profile != 'check':
        check['errors'].append({'type': 'missing_history', 'message': 'Required git history is unavailable'})
    if inventory.get('shallow') and profile != 'check':
        check['errors'].append(
            {'type': 'shallow_history', 'message': 'Shallow clone cannot establish required full git history'},
        )
    try:
        rules, history_scope = _gitleaks_scope_config(inventory)
    except (TypeError, ValueError):
        check['errors'].append({'type': 'invalid_history_scope',
                                'message': 'Selected Git-history directory scope could not be validated.'})
        return check, findings
    check['coverage'].update(history_scope=history_scope, history_scope_hash=content_hash(history_scope))
    if history_scope['selected_directory_paths'] and not history_scope['case_sensitive_paths']:
        # RE2 case folding can exclude more Unicode paths than Windows normcase.
        # Require the packaged Linux runtime instead of widening the approved scope.
        check['errors'].append({'type': 'unsupported_history_scope',
            'message': 'Case-insensitive selected directories require the packaged Linux scanner runtime.'})
        return check, findings
    command = _probe('gitleaks', options, source, check, trust_source=config.get('_source_boundary', source))
    check['engine']['rules_hash'] = hashlib.sha256(rules).hexdigest()
    if command:
        try:
            key = _local_hmac_key(source, config)
        except (OSError, ValueError) as exc:
            check['errors'].append({'type': 'fingerprint_key_failed', 'message': str(exc)})
            key = None
        with tempfile.TemporaryDirectory(prefix='gxsec-gitleaks-') as temp:
            cfg = Path(temp) / 'gitleaks.toml'
            cfg.write_bytes(rules)
            ignore = Path(temp) / 'ignore'
            ignore.write_text('', encoding='utf-8')
            for mode in modes:
                if mode == 'git':
                    try:
                        trusted_runtime_tool('git', config.get('_source_boundary', source))
                        if config.get('_snapshot_provenance', {}).get('history', {}).get('status') != 'complete':
                            raise ValueError('Private Git history snapshot is incomplete')
                    except (ValueError, OSError) as exc:
                        check['errors'].append({'type': 'git_runtime_unverified', 'message': str(exc)})
                        continue
                report = Path(temp) / (mode + '.json')
                args = [command, mode, str(source), '--no-banner', '--no-color', '--redact=100', '--ignore-gitleaks-allow', '--config', str(cfg), '--gitleaks-ignore-path', str(ignore), '--report-format', 'json', '--report-path', str(report), '--exit-code', '1']
                if mode == 'git':
                    args += ['--log-opts=--all --full-history --no-show-signature --no-ext-diff --no-textconv']
                try:
                    output = _run(args, cwd=Path(temp), timeout=options.get('timeout_seconds', 300))
                    if output.returncode not in (0, 1):
                        check['errors'].append({**process_failure(output), 'mode': mode})
                        check['coverage']['partial'] = True
                    # Empty/missing report is not evidence of a clean scan.
                    if not report.is_file():
                        raise ValueError('Gitleaks did not produce a JSON report')
                    with report.open('rb') as handle:
                        raw_report = handle.read(MAX_JSON_BYTES + 1)
                    if len(raw_report) > MAX_JSON_BYTES:
                        raise ValueError('Gitleaks JSON report exceeds its bound')
                    data = json.loads(raw_report.decode('utf-8-sig'))
                    if not isinstance(data, list):
                        raise ValueError('Gitleaks JSON report must be an array')
                    for item in data:
                        path = _path(item.get('File', ''), source)
                        rule = item.get('RuleID', 'unknown-secret')
                        # Raw values are never retained. Keyed local identity prevents offline secret guessing.
                        raw = _secret_anchor({**item, 'File': path}, source)
                        identity = hmac.new(key, raw.encode(), hashlib.sha256).hexdigest() if key and raw else None
                        f = make_finding(
                            category='secrets',
                            rule=rule,
                            path=path,
                            line=item.get('StartLine', 1),
                            snippet='[REDACTED]',
                            severity='High',
                            validation='candidate',
                            identity=identity,
                            title='Potential exposed secret: ' + rule,
                            description='Potential secret requires review; active key validation is disabled.',
                            check_id='secrets',
                            observations=[{'engine': 'gitleaks', 'mode': mode, 'commit': item.get('Commit'), 'line': item.get('StartLine')}],
                        )
                        findings.append(f)
                    if output.returncode in (0, 1):
                        check['coverage']['scanned'] += 1
                        if mode == 'git':
                            check['coverage']['history_complete'] = not inventory.get('shallow')
                except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
                    check['errors'].append({**exception_diagnostic('secret_scan_failed', exc), 'mode': mode})
    merged = {}
    for f in findings:
        fp = f['fingerprint']
        if fp in merged:
            merged[fp]['observations'] += f['observations']
        else:
            merged[fp] = f
    findings = list(merged.values())
    check['status'] = 'complete' if not check['errors'] and check['coverage']['scanned'] == len(modes) and inventory['files'] else 'incomplete'
    check['findings'] = [f['finding_id'] for f in findings]
    return (check, findings)

def _run_snapshot_checks(source, config, inventory, profile):
    from .framework import run_framework_check
    from . import contextual, triage, framework as framework_analyzer
    source = Path(source).resolve()
    if profile not in PROFILE_REQUIREMENTS:
        raise ValueError('Unsupported profile ' + str(profile))
    checks = []
    findings = []
    context_rules_hash = content_hash({'contextual': hashlib.sha256(Path(contextual.__file__).read_bytes()).hexdigest(),
                                       'triage': hashlib.sha256(Path(triage.__file__).read_bytes()).hexdigest()})
    framework_rules_hash = hashlib.sha256(Path(framework_analyzer.__file__).read_bytes()).hexdigest()
    for check_id, runner in (('sast', _sast), ('sca', _sca), ('secrets', _secrets), ('framework', run_framework_check)):
        try:
            with phase('engine-' + check_id):
                if not config['_snapshot_object'].verify():
                    raise ValueError('Private static snapshot bytes changed before engine execution')
                check, items = runner(source, config, inventory, profile)
        except BudgetExceeded as exc:
            check, items = make_check(check_id, errors=[exc.diagnostic]), []
        except Exception as exc:
            check = make_check(
                check_id,
                errors=[exception_diagnostic('adapter_error', exc)],
            )
            items = []
        if inventory.get('errors'):
            check['errors'] += inventory['errors']
            check['status'] = 'incomplete'
        check['required'] = True
        if check_id in {'sast', 'framework'}:
            check['engine']['context_rules_hash'] = context_rules_hash
        if check_id == 'framework':
            check['engine']['implementation_hash'] = framework_rules_hash
        if profile == 'check':
            check['coverage']['requested_scope'] = 'diff'
            check['coverage']['strategy'] = 'Full-source rescan; changed-file module narrowing is not implemented.'
            check['coverage']['requested_changed_files'] = list(config.get('_scan_scope', {}).get('changed_files', []))
        check['coverage']['scope'] = 'full'
        framework_model = check.get('framework') or {}
        framework_identity = {key: framework_model.get(key) for key in ('family', 'variant')}
        framework_identity['modules'] = [{key: module.get(key) for key in ('path', 'variant', 'signals')}
                                         for module in framework_model.get('modules', []) if isinstance(module, dict)]
        check['coverage']['signature'] = content_hash({'id': check['id'], 'files': sorted(check['coverage'].get('files', [])), 'exclusions': inventory.get('exclusions', []), 'capabilities': check['engine'].get('limitations', []), 'rules_hash': check['engine'].get('rules_hash'), 'rule_ids': check['engine'].get('rule_ids', []),
            'framework_model': framework_identity if check_id == 'framework' else None})
        checks.append(redact(check))
        findings.extend(redact(items))
    from .optional import ENGINES, run_optional_checks
    try:
        with phase('engine-optional'):
            optional_checks, optional_findings = run_optional_checks(source, config, profile)
    except BudgetExceeded as exc:
        requested = config.get('tools') or {}
        trusted = (config.get('_trusted_policy') or {}).get('optional') or {}
        optional_checks = [make_check(name, errors=[exc.diagnostic]) for name in ENGINES
            if (requested.get(name) or {}).get('enabled') or (trusted.get(name) or {}).get('enabled')
            or (trusted.get(name) or {}).get('required')]
        optional_findings = []
    checks.extend(optional_checks)
    findings.extend(optional_findings)
    try:
        checkpoint()
        if not config['_snapshot_object'].verify():
            raise ValueError('Private snapshot changed before contextual review')
        findings = contextualize_findings(source, inventory, findings)
        findings = enrich_framework_findings(findings, inventory)
    except (OSError, ValueError, RuntimeError, TypeError) as exc:
        framework = next(c for c in checks if c['id'] == 'framework')
        framework['status'] = 'incomplete'
        framework['errors'].append({'type': 'context_analysis_failed',
            'message': 'Source context could not be completed; candidates remain unvalidated.'})
        if isinstance(exc, BudgetExceeded):
            framework['errors'].append(exc.diagnostic)
    initial_hashes = {row['path']: row['hash'] for row in inventory.get('inventory', [])}
    contracts = {check['id']: content_hash({'engine': check.get('engine', {}),
        'coverage_signature': check.get('coverage', {}).get('signature')}) for check in checks}
    for finding in findings:
        location = (finding.get('locations') or [{}])[0].get('path')
        finding['file_hash'] = finding.get('file_hash') or initial_hashes.get(location)
        finding['expected_file_hash'] = initial_hashes.get(location)
        finding['analysis_contract_hash'] = contracts.get(finding.get('check_id'))
        finding['normalized_result_hash'] = content_hash({key: value for key, value in finding.items() if key != 'normalized_result_hash'})
    return (checks, findings)


def run_static_checks(source: Path, config: dict, profile: str) -> tuple[list, list]:
    original = reject_reparse_path(source).resolve(strict=True)
    if profile not in PROFILE_REQUIREMENTS:
        raise ValueError('Unsupported profile ' + str(profile))
    inventory = copy.deepcopy(config['_inventory']) if '_inventory' in config else collect_source(original)
    runtime = dict(config)
    runtime['_source_boundary'] = original
    runtime['_inventory'] = inventory
    runtime['_state_dir'] = config.get('_state_dir') or original / '.gxsec'
    try:
        with verified_snapshot(original, inventory) as snapshot:
            runtime['_snapshot_object'] = snapshot
            runtime['_snapshot_provenance'] = snapshot.provenance
            checks, findings = _run_snapshot_checks(snapshot.path, runtime, inventory, profile)
            budget_error = None
            try:
                stable = snapshot.verify()
            except BudgetExceeded as exc:
                stable, budget_error = False, exc.diagnostic
                snapshot.provenance['stable_after_scan'] = False
                snapshot.provenance['verification_incomplete'] = True
            for check in checks:
                check['snapshot'] = copy.deepcopy(snapshot.provenance)
                if not stable:
                    check['status'] = 'incomplete'
                    check['errors'].append(budget_error or {'type': 'snapshot_changed', 'message': 'Private static input bytes changed during scanning'})
            return checks, findings
    except (OSError, ValueError, RuntimeError) as exc:
        provenance = {'copy_verified': False, 'stable_after_scan': False, 'digest': None, 'source_hash': inventory.get('hash')}
        error = exc.diagnostic if isinstance(exc, BudgetExceeded) else {'type': 'snapshot_invalid', 'message': str(exc)}
        return [make_check(name, snapshot=provenance, errors=[dict(error)]) for name in ('sast','sca','secrets','framework')], []
