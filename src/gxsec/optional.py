"""Optional native scanners with protected evidence and confined execution.

Project configuration requests checks. Only independently supplied policy can
approve an evidence artifact or a runner plan. Native output is data, and never
establishes its own provenance, successful execution, or coverage denominator.
"""
from __future__ import annotations

from datetime import datetime, timezone
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import subprocess
import tempfile
import threading
import time
from urllib.parse import unquote, urlsplit

import yaml

from .models import content_hash, make_check, make_finding
from .policy import _trusted
from .redaction import redact
from .source import collect_source, full_source_scope_hash, reject_reparse_path, runtime_environment
from .transport import BoundedTransport, TransportError, parse_url

ENGINES = ('trivy', 'codeql', 'nuclei')
MAX_REPORT_BYTES = 16 * 1024 * 1024


class OptionalEvidenceError(ValueError):
    """A controlled diagnostic safe to expose in a normalized check."""


def _require(condition, message):
    if not condition:
        raise OptionalEvidenceError(message)



def source_identity(inventory, origin_source):
    """Describe original identity without altering its approved scanner record."""
    return {'origin_source': str(Path(origin_source).absolute()), 'source_revision': inventory.get('revision'),
            'source_hash': inventory.get('hash'), 'scope_hash': inventory.get('scope_hash'),
            'exclusion_contract': copy.deepcopy(inventory.get('exclusion_contract')),
            'file_hashes': {row['path']: row['hash'] for row in inventory.get('inventory', [])}}


def execution_inventory(source, identity=None):
    """Rebind an immutable relocation only after exact path and byte verification."""
    source = Path(source).resolve()
    origin = Path(identity['origin_source']).absolute() if identity else source
    actual = collect_source(source, git_boundary=origin) if identity else collect_source(source)
    _require(not actual.get('errors'), 'Execution source inventory failed')
    if identity is None:
        return actual, actual
    file_hashes = {row['path']: row['hash'] for row in actual.get('inventory', [])}
    _require(file_hashes == identity.get('file_hashes') and actual.get('hash') == identity.get('source_hash'),
             'Relocated source bytes or paths differ from approved original identity')
    if 'exclusion_contract' in identity:
        _require(identity['exclusion_contract'] == actual['exclusion_contract'],
                 'Relocated source exclusion contract differs from the current runtime')
    modules = {module['path']: module['manifests'] for module in actual.get('modules', [])}
    derived_scope = full_source_scope_hash(origin, modules)
    _require(derived_scope == identity.get('scope_hash'), 'Relocated source scope does not derive from its approved original path')
    rebound = {**actual, 'revision': identity.get('source_revision'), 'scope_hash': derived_scope}
    return rebound, actual

def _fresh(record, name):
    try:
        expires = datetime.fromisoformat(record.get('expires_at', '').replace('Z', '+00:00'))
        valid = expires.tzinfo is not None and expires > datetime.now(timezone.utc)
    except (TypeError, ValueError, AttributeError):
        valid = False
    _require(valid, name + ' is expired or lacks a timezone-aware expiry')


def _sha256(path):
    value = hashlib.sha256()
    size = 0
    with path.open('rb') as handle:
        _require(stat.S_ISREG(os.fstat(handle.fileno()).st_mode), 'Protected input is not a regular file')
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            size += len(chunk)
            _require(size <= 4 * 1024 ** 3, 'Protected input exceeds its hashing quota')
            value.update(chunk)
    return value.hexdigest()


def _external_path(value, source, *, directory=False, maximum=4 * 1024 ** 3):
    _require(isinstance(value, str) and bool(value), 'An absolute protected input path is required')
    raw = reject_reparse_path(value)
    _require(raw.is_absolute() and not raw.is_symlink(), 'Protected inputs must be absolute, regular paths')
    path = raw.resolve()
    _require(not path.is_relative_to(source), 'Protected inputs must be outside inspected source')
    _require(path.is_dir() if directory else path.is_file(), 'Protected input does not exist')
    if not directory:
        _require(path.stat().st_size <= maximum, 'Protected input exceeds its size limit')
    return path


def _file(record, source, *, maximum=4 * 1024 ** 3):
    _require(isinstance(record, dict), 'Protected file manifest is missing')
    path = _external_path(record.get('path'), source, maximum=maximum)
    _require(re.fullmatch(r'[0-9a-f]{64}', str(record.get('sha256', ''))) is not None
             and _sha256(path) == record['sha256'], 'Protected input digest mismatch')
    return path


def _read_file(record, source, *, maximum=MAX_REPORT_BYTES):
    """Hash and consume the same immutable byte string, never reopen by path."""
    _require(isinstance(record, dict), 'Protected file manifest is missing')
    path = _external_path(record.get('path'), source, maximum=maximum)
    with path.open('rb') as handle:
        _require(stat.S_ISREG(os.fstat(handle.fileno()).st_mode), 'Protected input is not a regular file')
        data = handle.read(maximum + 1)
    _require(len(data) <= maximum and hashlib.sha256(data).hexdigest() == record.get('sha256'),
             'Protected input bytes differ from their approved digest')
    return data


def _snapshot_file(record, source, destination, budget):
    """Copy and hash one open input; only verified bytes enter private scratch."""
    path = _external_path(record.get('path'), source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    with path.open('rb') as original, destination.open('xb') as copied:
        metadata = os.fstat(original.fileno())
        _require(stat.S_ISREG(metadata.st_mode), 'Snapshot input is not a regular file')
        for block in iter(lambda: original.read(1024 * 1024), b''):
            _require(len(block) <= budget['remaining'], 'Approved private snapshot disk quota exceeded')
            budget['remaining'] -= len(block)
            digest.update(block)
            copied.write(block)
    _require(digest.hexdigest() == record.get('sha256'), 'Input changed before its verified snapshot')
    destination.chmod(stat.S_IMODE(metadata.st_mode))
    return destination


def _snapshot_tree(record, source, destination, budget):
    directory = _external_path(record.get('path'), source, directory=True)
    files = record.get('files')
    _require(isinstance(files, dict) and files and content_hash(files) == record.get('sha256'), 'Snapshot manifest digest mismatch')
    actual = {p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file()}
    _require(actual == set(files), 'Snapshot directory has unapproved files')
    destination.mkdir()
    for name, expected in files.items():
        name = _relative(name)
        _snapshot_file({'path': str(directory / name), 'sha256': expected}, source, destination / name, budget)
    return destination


def _runtime(runtime, engine, source):
    directory = _tree(runtime, source)
    entrypoint = _relative(runtime.get('entrypoint'))
    _require(runtime['files'].get(entrypoint) == engine['digest'][7:], 'Complete runtime manifest does not bind the scanner entrypoint')
    if engine.get('executable'):
        _require(Path(engine['executable']).resolve() == (directory / entrypoint).resolve(), 'Scanner executable is outside its complete runtime bundle')
    return directory / entrypoint


def _host_limits(record):
    limits = record.get('limits')
    maxima = {'cpu_seconds': 1200, 'memory_bytes': 16 * 1024 ** 3, 'disk_bytes': 32 * 1024 ** 3,
              'pids': 64, 'output_bytes': MAX_REPORT_BYTES}
    _require(isinstance(limits, dict) and all(type(limits.get(k)) is int and 1 <= limits[k] <= maximum
             for k, maximum in maxima.items()) and record.get('limits_enforced') is True
             and record.get('resource_evidence_refs'), 'Numeric enforced CPU, memory, disk, process and output host quotas are required')
    return limits


def _bounded_process(command, *, cwd, environment, timeout, maximum, reports=()):
    """Drain pipes with a shared hard memory cap and kill on quota/deadline failure.

    File quotas are independently enforced by the approved host; monitoring adds
    prompt failure detection, and does not claim to implement a kernel disk quota.
    """
    _require(type(maximum) is int and 1 <= maximum <= MAX_REPORT_BYTES, 'Invalid streaming output quota')
    deadline = time.monotonic() + timeout
    process = subprocess.Popen([str(x) for x in command], cwd=cwd, env=environment, shell=False,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=os.name != 'nt')
    lock, overflow = threading.Lock(), threading.Event()
    buffers, total = [bytearray(), bytearray()], [0]

    def stop():
        if process.poll() is None:
            if os.name != 'nt':
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                    return
                except ProcessLookupError:
                    return
            process.kill()

    def drain(stream, index):
        try:
            while True:
                block = stream.read(min(65536, maximum + 1))
                if not block:
                    break
                with lock:
                    total[0] += len(block)
                    if total[0] > maximum:
                        overflow.set()
                        stop()
                        break
                    buffers[index].extend(block)
        except (OSError, ValueError):
            overflow.set()
            stop()

    threads = [threading.Thread(target=drain, args=(stream, index), daemon=True)
               for index, stream in enumerate((process.stdout, process.stderr))]
    for thread in threads:
        thread.start()
    try:
        while process.poll() is None:
            if overflow.is_set() or any(p.exists() and p.stat().st_size > maximum for p in reports):
                overflow.set()
                stop()
                break
            _require(time.monotonic() < deadline, 'Optional subprocess deadline expired')
            try:
                process.wait(timeout=min(0.05, max(0.001, deadline - time.monotonic())))
            except subprocess.TimeoutExpired:
                pass
        process.wait(timeout=1)
        for thread in threads:
            thread.join(timeout=1)
        _require(not any(t.is_alive() for t in threads) and not overflow.is_set()
                 and all(not p.exists() or p.stat().st_size <= maximum for p in reports), 'Optional subprocess exceeded its streaming/report output quota')
        _require(process.returncode == 0, 'Optional subprocess failed')
        return subprocess.CompletedProcess(command, process.returncode,
            *(bytes(b).decode('utf-8', errors='replace') for b in buffers))
    finally:
        stop()
        for index, stream in enumerate((process.stdout, process.stderr)):
            if not threads[index].is_alive():
                stream.close()


def _relative(value):
    _require(isinstance(value, str) and value and '\\' not in value and '\x00' not in value,
             'Native result path is invalid')
    path = PurePosixPath(value)
    _require(not path.is_absolute() and '..' not in path.parts and ':' not in value,
             'Native result path escapes approved source')
    return path.as_posix().removeprefix('./')


def _tree(record, source):
    _require(isinstance(record, dict), 'Protected directory manifest is missing')
    directory = _external_path(record.get('path'), source, directory=True)
    files = record.get('files')
    _require(isinstance(files, dict) and files and content_hash(files) == record.get('sha256'),
             'Protected directory manifest digest mismatch')
    actual = {}
    for path in directory.rglob('*'):
        _require(not path.is_symlink() and path.resolve().is_relative_to(directory), 'Protected directory contains a symlink or escaped junction')
        if path.is_file():
            actual[path.relative_to(directory).as_posix()] = _sha256(path)
    _require(actual == files, 'Protected directory contents differ from approved manifest')
    return directory


def _scoped(record, policy, inventory):
    _require(record.get('source_revision') == inventory.get('revision') == policy.get('source_revision')
             and record.get('source_hash') == inventory.get('hash')
             and record.get('scope_hash') == inventory.get('scope_hash') == policy.get('scope_hash'),
             'Scanner evidence does not match the exact source revision, contents and scope')


def _coverage(record, *, expected=None):
    coverage = record.get('coverage')
    _require(isinstance(coverage, dict), 'Native scanner execution coverage is missing')
    eligible, scanned = coverage.get('eligible'), coverage.get('scanned')
    _require(isinstance(eligible, list) and eligible and all(isinstance(x, str) and x for x in eligible)
             and len(eligible) == len(set(eligible)), 'A nonempty, exact eligible scope is required')
    _require(isinstance(scanned, list) and all(isinstance(x, str) for x in scanned)
             and len(scanned) == len(set(scanned)) and set(scanned) == set(eligible)
             and coverage.get('complete') is True and not coverage.get('errors')
             and not coverage.get('missing') and not coverage.get('parse_errors'),
             'Scanner has missing, failed or unestablished execution coverage')
    if expected is not None:
        _require(set(eligible) == set(expected), 'Scanner scope differs from approved inputs')
    return eligible


def _confinement(record, policy, source, engine, scope, *, runner=None):
    _require(isinstance(record, dict) and _trusted(record, policy, 'network-confinement', ('protected-ci', 'security-owner')),
             'Independent process and network confinement approval is required')
    _fresh(record, 'Confinement approval')
    _host_limits(record)
    _require(record.get('status') == 'verified' and record.get('source_revision') == policy.get('source_revision')
             and record.get('scope_hash') == policy.get('scope_hash') and record.get('scope') == scope
             and record.get('engine_digest') == engine['digest'] and record.get('process_tree') is True
             and record.get('filesystem') == 'source-read-only' and record.get('firewall_evidence_refs'),
             'Confinement does not attest the exact process tree, source and engine')
    network = 'exact-scope' if engine['name'] == 'nuclei' else 'deny-all'
    _require(record.get('network') == network, 'Required engine network confinement is unavailable')
    if network == 'exact-scope':
        _require(record.get('broker_evidence_refs'), 'Nuclei requires an exact-route broker attestation')
    if runner:
        _require(record.get('runner_digest') == runner['sha256'], 'Confinement runner digest mismatch')


def _templates(records, source, policy):
    _require(isinstance(records, list) and records, 'Reviewed exact Nuclei template files are required')
    ids = []
    for record in records:
        text = _read_file(record, source, maximum=1024 * 1024).decode('utf-8-sig')
        template = yaml.safe_load(text)
        signature = record.get('signature_verification') or {}
        certificate = signature.get('certificate') or {}
        _require(record.get('reviewed') is True
                 and _trusted(signature, policy, 'template-signature', ('protected-ci', 'security-owner'))
                 and signature.get('status') == 'verified' and signature.get('template_sha256') == record['sha256']
                 and signature.get('verification_evidence_refs') and signature.get('signer_id')
                 and (policy.get('template_signers') or {}).get(signature['signer_id']) == certificate.get('sha256'),
                 'Independent template signature verification and an approved exact signer certificate are required')
        _fresh(signature, 'Template signature verification')
        _read_file(certificate, source, maximum=64 * 1024)
        _require(isinstance(template, dict) and set(template) <= {'id', 'info', 'http'}
                 and template.get('id') == record.get('id') and re.fullmatch(r'[A-Za-z0-9_-]+', str(record.get('id', ''))),
                 'Only reviewed HTTP template IDs are supported')
        requests = template.get('http')
        _require(isinstance(requests, list) and len(requests) == 1, 'Nuclei template must make one bounded request')
        request = requests[0]
        _require(isinstance(request, dict) and set(request) <= {'method', 'path', 'matchers', 'matchers-condition', 'redirects'}
                 and request.get('method') in {'GET', 'HEAD'} and request.get('path') == ['{{BaseURL}}']
                 and request.get('redirects', False) is False, 'Nuclei supports exact-URL GET/HEAD without redirects or fuzzing')
        matchers = request.get('matchers')
        _require(isinstance(matchers, list) and matchers, 'Nuclei template matchers are missing')
        for matcher in matchers:
            _require(isinstance(matcher, dict) and matcher.get('type') in {'status', 'word', 'regex'}
                     and set(matcher) <= {'type', 'status', 'words', 'regex', 'condition', 'part', 'negative', 'case-insensitive', 'name'}
                     and '{{' not in json.dumps(matcher), 'Nuclei matcher has unsupported execution or interpolation')
        ids.append(record['id'])
    _require(len(ids) == len(set(ids)), 'Nuclei template IDs must be unique')
    return ids


def _inputs(record, policy, source, inventory):
    engine, inputs = record['engine']['name'], record.get('inputs')
    _require(isinstance(inputs, dict), 'Engine inputs manifest is missing')
    if engine == 'trivy':
        db = inputs.get('database')
        _tree(db, source)
        _fresh(db, 'Offline Trivy database')
        _require({'db/trivy.db', 'db/metadata.json'} <= set(db['files']), 'Trivy vulnerability database files are missing')
        target = inputs.get('target') or {}
        if target.get('kind') == 'filesystem':
            eligible = _coverage(record)
            _require(all(_relative(path) in inventory['files'] for path in eligible), 'Trivy file scope is not present in source')
        elif target.get('kind') == 'image-archive':
            _file(target, source)
            _coverage(record, expected=['image-sha256:' + target['sha256']])
        else:
            raise OptionalEvidenceError('Trivy requires source filesystem or a digest-locked local image archive')
    elif engine == 'codeql':
        _runtime(inputs.get('runtime'), record['engine'], source)
        rights = inputs.get('use_rights') or {}
        _require(_trusted(rights, policy, 'engine-use-rights', ('protected-ci', 'license-owner'))
                 and rights.get('permitted') is True and rights.get('basis') and rights.get('evidence_refs')
                 and rights.get('source_revision') == policy.get('source_revision')
                 and rights.get('scope_hash') == policy.get('scope_hash'), 'CodeQL explicit license/use-rights approval is required')
        _fresh(rights, 'CodeQL use-rights approval')
        db = inputs.get('database') or {}
        path = _tree(db, source)
        _require(db.get('prebuilt') is True and db.get('source_revision') == inventory['revision']
                 and 'codeql-database.yml' in db['files'], 'CodeQL requires an exact-revision prebuilt database')
        metadata = yaml.safe_load(_read_file({'path': str(path / 'codeql-database.yml'),
            'sha256': db['files']['codeql-database.yml']}, source).decode('utf-8-sig'))
        _require(isinstance(metadata, dict) and metadata.get('finalised') is True, 'CodeQL database is not finalized')
        queries = inputs.get('queries') or {}
        _tree(queries, source)
        _require(_relative(queries.get('suite')) in queries['files'] and queries['suite'].endswith('.qls'),
                 'A reviewed local CodeQL query suite is required')
        rule_ids = queries.get('rule_ids')
        _require(isinstance(rule_ids, list) and rule_ids and all(isinstance(r, str) and r for r in rule_ids)
                 and len(rule_ids) == len(set(rule_ids)), 'Expected CodeQL query rule IDs must be declared')
        packs = inputs.get('query_packs')
        pack_root = _tree(packs, source)
        _require(not any(PurePosixPath(p).name == '.codeqlmanifest.json' for p in packs['files']),
                 'CodeQL pack bundles must use explicit local directories without redirecting bundle manifests')
        resolved = {}
        for name in packs['files']:
            if PurePosixPath(name).name == 'qlpack.yml':
                _require(len(PurePosixPath(name).parts) == 2, 'Resolved CodeQL packs must be immediate approved subdirectories')
                metadata = yaml.safe_load(_read_file({'path': str(pack_root / name), 'sha256': packs['files'][name]}, source).decode('utf-8-sig'))
                _require(isinstance(metadata, dict) and isinstance(metadata.get('name'), str) and metadata.get('version')
                         and metadata['name'] not in resolved, 'Resolved CodeQL pack identity is missing or duplicated')
                resolved[metadata['name']] = {'version': str(metadata['version'])}
        _require(resolved and resolved == packs.get('resolved'), 'Actual local CodeQL pack metadata differs from approved resolution')
        lockfile = _relative(queries.get('lockfile'))
        _require(lockfile in queries['files'], 'CodeQL pack lockfile is missing from the query manifest')
        lock = yaml.safe_load(_read_file({'path': str(Path(queries['path']) / lockfile), 'sha256': queries['files'][lockfile]}, source).decode('utf-8-sig'))
        dependencies = lock.get('dependencies') if isinstance(lock, dict) else None
        _require(isinstance(dependencies, dict) and dependencies == packs.get('resolved'), 'Resolved CodeQL packs do not match their approved lockfile')
        suite = yaml.safe_load(_read_file({'path': str(Path(queries['path']) / queries['suite']), 'sha256': queries['files'][queries['suite']]}, source).decode('utf-8-sig'))
        _require(isinstance(suite, list) and suite and all(isinstance(q, dict) and set(q) == {'query'}
                 and _relative(q['query']) in queries['files'] and q['query'].endswith('.ql') for q in suite),
                 'CodeQL suite must enumerate only approved local query files')
        _require(all(_relative(path) in inventory['files'] for path in _coverage(record)), 'CodeQL file scope is not present in source')
    else:
        ids = _templates(inputs.get('templates'), source, policy)
        target = inputs.get('target') or {}
        BoundedTransport(target.get('origin'), paths=target.get('paths'), allowed_ips=target.get('allowed_ips'))
        _require(not target['origin'].endswith('/'), 'Nuclei origin must omit its trailing slash')
        expected = [tid + '@' + target['origin'] + path for tid in ids for path in target['paths']]
        _coverage(record, expected=expected)
        _confinement(record.get('confinement'), policy, source, record['engine'], target)


def _severity(value):
    text = str(value).lower()
    canonical = {'critical': 'Critical', 'high': 'High', 'medium': 'Medium', 'moderate': 'Medium', 'low': 'Low', 'info': 'Info', 'note': 'Info'}
    if text in canonical:
        return canonical[text]
    try:
        score = float(value)
        _require(0 <= score <= 10, 'Security severity score is invalid')
        return 'Critical' if score >= 9 else 'High' if score >= 7 else 'Medium' if score >= 4 else 'Low' if score > 0 else 'Info'
    except (TypeError, ValueError):
        return None


def _native_path(value, source, scope, *, original_source=None):
    _require(isinstance(value, str), 'Native result location is missing')
    if value.startswith('file:'):
        parsed = urlsplit(value)
        _require(not parsed.netloc, 'Native file URI has an unsupported host')
        value = unquote(parsed.path)
    else:
        value = unquote(value)
    path = Path(value)
    if path.is_absolute():
        lexical = Path(os.path.abspath(path))
        roots = [Path(source).absolute()] + ([Path(original_source).absolute()] if original_source else [])
        matched = next((root for root in roots if lexical.is_relative_to(root)), None)
        _require(matched is not None, 'Native result is outside approved source')
        value = lexical.relative_to(matched).as_posix()
    value = _relative(value)
    _require(value in scope, 'Native result is outside approved file scope')
    return value


def _trivy(report, record, source, *, original_source=None):
    _require(isinstance(report, dict) and report.get('SchemaVersion') == 2
             and isinstance(report.get('ArtifactName'), str) and report['ArtifactName']
             and isinstance(report.get('Metadata'), dict) and isinstance(report.get('Results'), list),
             'Trivy native JSON schema or execution metadata is malformed')
    image = record['inputs']['target']['kind'] == 'image-archive'
    _require(report.get('ArtifactType') == ('container_image' if image else 'filesystem'), 'Trivy artifact type differs from approved input')
    findings = []
    scope = record['coverage']['eligible']
    for result in report['Results']:
        _require(isinstance(result, dict) and isinstance(result.get('Target'), str)
                 and result.get('Class') in {'lang-pkgs', 'os-pkgs'}, 'Trivy native package result is malformed or unsupported')
        path = record['coverage']['eligible'][0] if image else _native_path(result['Target'], source, scope, original_source=original_source)
        vulnerabilities = result.get('Vulnerabilities', [])
        _require(isinstance(vulnerabilities, list), 'Trivy native vulnerabilities list is malformed')
        for item in vulnerabilities:
            _require(isinstance(item, dict) and item.get('VulnerabilityID') and item.get('PkgName'), 'Trivy vulnerability identity is missing')
            findings.append(make_finding(category='sca', rule='trivy.' + item['VulnerabilityID'], path=path,
                severity=_severity(item.get('Severity')), title='trivy.' + item['VulnerabilityID'],
                description='Review the identified dependency advisory and affected package.',
                identity={'package': item['PkgName'], 'version': item.get('InstalledVersion')}, check_id='trivy',
                observations=[{'engine': 'trivy', 'package': item['PkgName'], 'installed_version': item.get('InstalledVersion'),
                               'fixed_version': item.get('FixedVersion')}], evidence_refs=[record['id']]))
    return findings


def _codeql(report, record, source, *, original_source=None):
    _require(isinstance(report, dict) and report.get('version') == '2.1.0'
             and isinstance(report.get('runs'), list) and report['runs'], 'CodeQL SARIF runs or version is missing')
    findings, observed_rules = [], set()
    for run in report['runs']:
        _require(isinstance(run, dict), 'CodeQL SARIF run is malformed')
        driver = (run.get('tool') or {}).get('driver') or {}
        _require(driver.get('name') == 'CodeQL' and driver.get('semanticVersion', driver.get('version')) == record['engine']['version'],
                 'CodeQL native tool provenance differs from approval')
        invocations = run.get('invocations')
        _require(isinstance(invocations, list) and invocations and all(isinstance(i, dict)
                 and i.get('executionSuccessful') is True and not any(n.get('level') == 'error' for n in i.get('toolExecutionNotifications', []))
                 for i in invocations), 'CodeQL SARIF invocation failed or lacks success metadata')
        _require(isinstance(run.get('results'), list) and isinstance(driver.get('rules', []), list), 'CodeQL native results are malformed')
        extensions = (run.get('tool') or {}).get('extensions', [])
        _require(isinstance(extensions, list) and all(isinstance(c, dict) and isinstance(c.get('rules', []), list) for c in extensions),
                 'CodeQL native query extensions are malformed')
        rules = {r['id']: r for c in [driver, *extensions] for r in c.get('rules', []) if isinstance(r, dict) and r.get('id')}
        observed_rules.update(rules)
        for result in run['results']:
            _require(isinstance(result, dict) and result.get('ruleId') and isinstance(result.get('message'), dict)
                     and isinstance(result.get('locations'), list) and result['locations'], 'CodeQL native finding is missing its identity or location')
            rule = result['ruleId']
            _require(rule in rules, 'CodeQL finding rule metadata is missing')
            severity = _severity((rules.get(rule, {}).get('properties') or {}).get('security-severity'))
            for location in result['locations']:
                physical = location.get('physicalLocation') or {}
                artifact = physical.get('artifactLocation') or {}
                path = _native_path(artifact.get('uri'), source, record['coverage']['eligible'], original_source=original_source)
                region = physical.get('region') or {}
                findings.append(make_finding(category='sast', rule='codeql.' + rule, path=path,
                    line=region.get('startLine', 1), snippet=(region.get('snippet') or {}).get('text', ''),
                    severity=severity, title='codeql.' + rule,
                    description='Review the recorded rule and source location in the protected native evidence.',
                    check_id='codeql', observations=[{'engine': 'codeql', 'rule': rule}], evidence_refs=[record['id']]))
    _require(observed_rules == set(record['inputs']['queries']['rule_ids']), 'CodeQL did not execute the approved query rule scope')
    return findings


def _nuclei(report, record, source):
    _require(isinstance(report, str), 'Nuclei JSONL report must be text')
    findings = []
    for text in report.splitlines():
        if not text.strip():
            continue
        row = json.loads(text)
        _require(isinstance(row, dict) and row.get('type') == 'http' and isinstance(row.get('info'), dict), 'Nuclei native HTTP result is malformed')
        url = row.get('matched-at')
        parsed, origin, path = parse_url(url)
        target = record['inputs']['target']
        _require(origin == parse_url(target['origin'])[1] and not parsed.query
                 and url == target['origin'] + path and row.get('template-id', '') + '@' + url in record['coverage']['eligible'],
                 'Nuclei finding is outside approved URL/template scope')
        finding = make_finding(category='dast', rule='nuclei.' + row['template-id'], path=url,
            severity=_severity(row['info'].get('severity')), title='nuclei.' + row['template-id'],
            description='Review the approved template and recorded URL in protected native evidence.',
            check_id='nuclei', identity={'template': row['template-id'], 'url': url},
            observations=[{'engine': 'nuclei', 'template_id': row['template-id']}], evidence_refs=[record['id']])
        finding['locations'] = [{'url': url}]
        findings.append(finding)
    return findings


def parse_native(report, record, source, *, original_source=None):
    """Normalize bounded engine-native output, discarding all request/response data."""
    name = record['engine']['name']
    if name != 'nuclei' and isinstance(report, str):
        report = json.loads(report)
    arguments = {'original_source': original_source} if name != 'nuclei' else {}
    return redact({'trivy': _trivy, 'codeql': _codeql, 'nuclei': _nuclei}[name](report, record, source, **arguments))


def _record(record, policy, source, inventory, name, *, plan=False):
    _require(isinstance(record, dict), 'Protected scanner evidence or plan is missing')
    kind, roles = ('scanner-plan', ('protected-ci', 'security-owner')) if plan else ('scanner-evidence', ('protected-ci',))
    _require(_trusted(record, policy, kind, roles), 'Independent ' + kind + ' approval is missing')
    _fresh(record, 'Scanner approval')
    _scoped(record, policy, inventory)
    engine = record.get('engine')
    _require(isinstance(engine, dict) and engine.get('name') == name
             and isinstance(engine.get('version'), str) and re.fullmatch(r'\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?', engine['version'])
             and re.fullmatch(r'sha256:[0-9a-f]{64}', str(engine.get('digest', ''))), 'Pinned scanner version and digest are required')
    _coverage(record)
    _inputs(record, policy, source, inventory)
    if plan:
        _runtime(record['inputs'].get('runtime'), record['engine'], source)
        runner = record.get('runner') or {}
        _runtime(runner.get('runtime'), {'digest': 'sha256:' + runner.get('sha256', ''), 'executable': runner.get('path')}, source)
        expected = {'engine': record['inputs']['runtime']['sha256'], 'runner': runner['runtime']['sha256']}
        if name == 'codeql':
            expected['query_packs'] = record['inputs']['query_packs']['sha256']
        _require((record.get('confinement') or {}).get('runtime_digests') == expected,
                 'Confinement does not bind complete engine, runner and resolved query pack bundles')


def _snapshot_plan(record, source, directory, budget):
    """Materialize only approved bytes; scanners receive private snapshot paths."""
    result = copy.deepcopy(record)
    inputs = result['inputs']
    runtime = _snapshot_tree(inputs['runtime'], source, directory / 'engine-runtime', budget)
    inputs['runtime']['path'] = str(runtime)
    result['engine']['executable'] = str(runtime / inputs['runtime']['entrypoint'])
    for name in ('database', 'queries', 'query_packs'):
        if inputs.get(name):
            inputs[name]['path'] = str(_snapshot_tree(inputs[name], source, directory / name, budget))
    target = inputs.get('target') or {}
    if target.get('kind') == 'image-archive':
        target['path'] = str(_snapshot_file(target, source, directory / 'image-archive.tar', budget))
    for index, template in enumerate(inputs.get('templates', [])):
        template['path'] = str(_snapshot_file(template, source, directory / ('template-' + str(index) + '.yaml'), budget))
        certificate = template['signature_verification']['certificate']
        certificate['path'] = str(_snapshot_file(certificate, source, directory / ('signer-' + str(index) + '.crt'), budget))
    return result


def _execute(record, policy, source, *, trust_source=None, inventory=None):
    trust_source = Path(trust_source or source).absolute()
    runner = record.get('runner')
    _confinement(record.get('confinement'), policy, trust_source, record['engine'], record['inputs'].get('target', {}), runner=runner)
    limits = _host_limits(record['confinement'])
    timeout = record.get('timeout_seconds', 300)
    _require(type(timeout) in {int, float} and 1 <= timeout <= 1200, 'Scanner timeout must be bounded to 1..1200 seconds')
    plan = {**record, 'source': str(source), 'source_identity': source_identity(inventory, trust_source), 'approval_context': {
        'source_revision': policy.get('source_revision'), 'scope_hash': policy.get('scope_hash'),
        'trusted_approvals': policy.get('trusted_approvals', []), 'template_signers': policy.get('template_signers', {})}}
    environment = runtime_environment()
    with tempfile.TemporaryDirectory(prefix='gxsec-optional-') as directory:
        runtime = _snapshot_tree(runner['runtime'], trust_source, Path(directory) / 'runner-runtime', {'remaining': limits['disk_bytes']})
        runner_path = runtime / runner['runtime']['entrypoint']
        environment.update(HOME=directory, USERPROFILE=directory, XDG_CACHE_HOME=directory)
        plan_path, result_path = Path(directory) / 'plan.json', Path(directory) / 'result.json'
        plan_path.write_text(json.dumps(plan, ensure_ascii=False), encoding='utf-8')
        _bounded_process([str(runner_path), '--gxsec-plan', str(plan_path), '--gxsec-result', str(result_path)],
            cwd=directory, environment=environment, timeout=timeout, maximum=limits['output_bytes'], reports=[result_path])
        with result_path.open('rb') as handle:
            data = handle.read(limits['output_bytes'] + 1)
        _require(len(data) <= limits['output_bytes'], 'Confined scanner result exceeded its quota')
        result = json.loads(data.decode('utf-8-sig'))
    _require(isinstance(result, dict) and result.get('plan_digest') == content_hash(plan)
             and result.get('engine') == record['engine'] and result.get('execution_status') == 'complete'
             and result.get('source_revision') == record['source_revision']
             and result.get('source_hash') == record['source_hash'] and result.get('scope_hash') == record['scope_hash']
             and result.get('confinement_record_id') == record['confinement']['id']
             and result.get('coverage') == record['coverage'], 'Confined scanner result does not match approved plan and coverage')
    return result.get('native_report')


def run_optional_checks(source: Path, config: dict, profile: str) -> tuple[list, list]:
    """Run selected engines from trusted artifacts or protected confined plans."""
    policy = config.get('_trusted_policy') or {}
    trusted = policy.get('optional') or {}
    tools = config.get('tools') or {}
    selected = [name for name in ENGINES if (tools.get(name) or {}).get('enabled')
                or (trusted.get(name) or {}).get('enabled') or (trusted.get(name) or {}).get('required')]
    if not selected:
        return [], []
    source = Path(source).resolve()
    trust_source = Path(config.get('_source_boundary', source)).absolute()
    identity = source_identity(config['_inventory'], trust_source) if config.get('_inventory') else None
    inventory, actual_before = execution_inventory(source, identity) if any((trusted.get(n) or {}).get('evidence') or (trusted.get(n) or {}).get('plan') for n in selected) else (None, None)
    checks, findings = [], []
    for name in selected:
        options, org = tools.get(name) or {}, trusted.get(name) or {}
        record = org.get('evidence') or org.get('plan')
        check = make_check(name, required=bool(options.get('required') or org.get('required')))
        checks.append(check)
        if not record:
            check.update(status='unsupported', errors=[{'type': 'missing_prerequisites', 'message': 'Protected scanner evidence or confined runner plan is required'}])
            continue
        try:
            _require(not inventory.get('errors'), 'Source inventory contains unreadable files')
            plan = not bool(org.get('evidence'))
            if config.get('_snapshot_object'):
                _require(config['_snapshot_object'].verify(), 'Private static snapshot changed before optional scanning')
            _record(record, policy, trust_source, inventory, name, plan=plan)
            if plan:
                native = _execute(record, policy, source, trust_source=trust_source, inventory=inventory)
            else:
                _require(record.get('execution_status') == 'complete', 'Native scanner did not complete successfully')
                native = _read_file(record.get('artifact'), trust_source, maximum=MAX_REPORT_BYTES).decode('utf-8-sig')
            items = parse_native(native, record, source, original_source=trust_source)
            eligible = record['coverage']['eligible']
            check.update(status='complete', findings=[f['finding_id'] for f in items],
                coverage={'eligible': len(eligible), 'scanned': len(eligible), 'complete': True, 'scope': 'full',
                          'files': eligible, 'scanned_files': eligible, 'scope_hash': inventory['scope_hash']},
                engine=record['engine'], evidence_refs=[record['id']],
                limitations=['Native results are candidates; protected-host execution and coverage attestations are trusted.'])
            hashes = {row['path']: row['hash'] for row in actual_before.get('inventory', [])}
            for finding in items:
                location = (finding.get('locations') or [{}])[0].get('path')
                finding['file_hash'] = hashes.get(location)
                finding['expected_file_hash'] = hashes.get(location)
                finding['normalized_result_hash'] = content_hash({key: value for key, value in finding.items() if key != 'normalized_result_hash'})
            findings.extend(items)
        except (ValueError, TypeError, KeyError, AttributeError, OSError, subprocess.SubprocessError, yaml.YAMLError, TransportError) as error:
            # Exception text from parsers/OS may contain evidence values or credentials.
            message = str(error) if isinstance(error, OptionalEvidenceError) else 'Native scanner evidence, inputs or execution could not be validated'
            check['errors'].append({'type': 'optional_engine_incomplete', 'message': message})
    after = collect_source(source, git_boundary=trust_source) if inventory else None
    snapshot_stable = config['_snapshot_object'].verify() if config.get('_snapshot_object') else True
    if not snapshot_stable or (after and (after.get('hash') != actual_before.get('hash') or after.get('scope_hash') != actual_before.get('scope_hash') or {row['path']: row['hash'] for row in after.get('inventory', [])} != {row['path']: row['hash'] for row in actual_before.get('inventory', [])} or after.get('errors'))):
        for check in checks:
            check['status'] = 'incomplete'
            check['findings'] = []
            check['errors'].append({'type': 'source_changed', 'message': 'Source changed during optional evidence validation'})
        findings = []
    return redact(checks), redact(findings)
