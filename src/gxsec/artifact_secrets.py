"""Inspect approved ZIP-format deployment artifacts without extracting members."""
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import tempfile
from zipfile import BadZipFile, ZIP_DEFLATED, ZIP_STORED, ZipFile
import zlib

import yaml

from .execution import BudgetExceeded, checkpoint
from .models import content_hash, make_check, make_finding
from .optional import _snapshot_file
from .policy import _trusted
from .settings_data import SettingsLoader

CHECK_ID = 'artifact-secrets'
ARCHIVES = {'.war', '.jar', '.zip'}
TEXT_CONFIGS = {'.yaml', '.yml', '.properties'}
MAX_ARCHIVE_BYTES = 256 * 1024**2
MAX_NESTED_BYTES = 64 * 1024**2
MAX_PARSED_BYTES = 512 * 1024**2
MAX_CONFIG_BYTES = 512 * 1024
MAX_DIRECTORY_BYTES = 8 * 1024**2
MAX_ENTRIES = 20000
MAX_DEPTH = 2
MAX_FINDINGS = 500
EOCD = struct.Struct('<4s4H2LH')
LIMITATIONS = [
    'Checks packaged dotenv files and selected AES, database and configuration-decryption keys.',
    'Does not inspect compiled classes, arbitrary credential formats or ZIP64/multi-disk archives.',
    'Only ordinal member locations and fixed diagnostic labels are shared.',
]
RULES = {
    'artifact-dotenv-bundled': ('Medium', 'Review packaged dotenv configuration and supply operational settings at runtime.'),
    'artifact-sensitive-literal': ('High', 'Remove the literal from the deployment artifact and use a protected runtime reference.'),
}
ASSIGNMENT = re.compile(r'^\s*(?:export\s+)?([A-Za-z0-9_.-]+)\s*(?:=|:)\s*(.*)$')
REF = re.compile(r'\$\{([A-Za-z0-9_.-]+)(?::(.*))?\}', re.S)


def _secret_kind(name):
    name = re.sub('[^a-z0-9]', '', name.casefold())
    if re.fullmatch(r'cryptoaeskey(?:s?v\d+)?|aesencryptionkey|piiencryptionkey', name):
        return 'aes-key'
    if name in {'cryptohashsalt', 'jasyptencryptorpassword'}:
        return 'configuration-secret'
    if name in {'dbpassword', 'dbpasswd', 'databasepassword', 'datasourcepassword', 'springdatasourcepassword',
                'postgrespassword', 'mysqlpassword', 'mariadbpassword'}:
        return 'database-password'
    return None


def _literal(value):
    value = value.strip()
    if value and value[0] in {'"', "'"}:
        end = value.rfind(value[0])
        if end > 0 and (not value[end + 1:].strip() or value[end + 1:].lstrip().startswith('#')):
            value = value[1:end]
    value = re.split(r'\s+#', value, maxsplit=1)[0].strip()
    reference = REF.fullmatch(value)
    if reference:
        # A literal fallback is still present in the deployment artifact.
        value = (reference[2] or '').strip()
    if value.startswith('ENC(') and value.endswith(')'):
        return False
    if not value or value in {'null', '~'} or value.startswith('#'):
        return False
    return True


def _yaml_secrets(node, parents=()):
    if isinstance(node, dict):
        for key, value in node.items():
            parts = (*parents, key)
            kind = (_secret_kind(key) or _secret_kind('.'.join(parts[-3:]))
                    or _secret_kind('.'.join(parts[-4:])))
            if kind and isinstance(value, str) and _literal(value):
                yield kind, 1  # YAML findings identify config members, not values or snippets.
            if isinstance(value, (dict, list)):
                yield from _yaml_secrets(value, parts)
    elif isinstance(node, list):
        for item in node:
            yield from _yaml_secrets(item, parents)


def _config_secrets(text, suffix):
    if suffix in {'.yml', '.yaml'}:
        for doc in yaml.load_all(text, Loader=SettingsLoader):
            yield from _yaml_secrets(doc)
        return
    # Java property continuations preserve the logical assignment on one line.
    if suffix == '.properties':
        text = re.sub(r'(?<!\\)\\\r?\n[ \t]*', '', text)
    for line, value in enumerate(text.splitlines(), 1):
        match = ASSIGNMENT.match(value)
        if match and (kind := _secret_kind(match[1])) and _literal(match[2]):
            yield kind, line


def _directory_count(file):
    # Bound central-directory allocation before constructing ZipFile.
    size = file.seek(0, 2)
    tail = min(size, 65535 + EOCD.size)
    file.seek(-tail, 2)
    data = file.read(tail)
    offset = data.rfind(b'PK\x05\x06')
    if offset < 0 or offset + EOCD.size > len(data):
        raise ValueError('Missing archive directory')
    _, disk, directory_disk, disk_count, count, length, start, comment = EOCD.unpack_from(data, offset)
    if (disk or directory_disk or disk_count != count or count > MAX_ENTRIES or length > MAX_DIRECTORY_BYTES
            or offset + EOCD.size + comment != len(data) or start + length != size - tail + offset):
        raise ValueError('Unsupported archive directory')
    return count


def _member_name(info):
    name = info.orig_filename.rstrip('/')
    mode = stat.S_IFMT(info.external_attr >> 16)
    if (not name or '\\' in name or ':' in name or any(ord(char) < 32 or ord(char) == 127 for char in name)
            or any(part in {'', '.', '..'} for part in name.split('/'))
            or mode not in {0, stat.S_IFREG, stat.S_IFDIR} or info.flag_bits & 1
            or (mode == stat.S_IFDIR and not info.is_dir())):
        raise ValueError('Unsupported archive member')
    return PurePosixPath(name)


def _dotenv(name):
    return name == '.env' or name.startswith('.env.') or name.endswith('.env')


def _copy_member(archive, info, target, maximum, budget):
    if info.file_size > maximum or info.file_size > budget['bytes'] or info.compress_type not in {ZIP_STORED, ZIP_DEFLATED}:
        raise ValueError('Unsupported archive member size or method')
    with archive.open(info) as member:
        size = 0
        while block := member.read(256 * 1024):
            checkpoint()
            size += len(block)
            budget['bytes'] -= len(block)
            if size > maximum or budget['bytes'] < 0:
                raise ValueError('Archive reading budget exceeded')
            target.write(block)
        if size != info.file_size:
            raise ValueError('Archive member is incomplete')
    target.seek(0)


def _finding(rule, path, line=1, kind=None):
    severity, guidance = RULES[rule]
    return make_finding(category='artifact-secret', rule=rule, path=path, line=line, identity=kind,
                        title=guidance, severity=severity, check_id=CHECK_ID, review_required=True,
                        evidence_type=kind, remediation={'guidance': guidance})


def _scan(file, check, findings, budget, prefix='artifact', depth=0):
    count = _directory_count(file)
    with ZipFile(file, 'r') as archive:
        infos = archive.infolist()
        if len(infos) != count or count > budget['entries']:
            raise ValueError('Archive member limit or directory mismatch')
        if depth == 0 and all(info.is_dir() for info in infos):
            raise ValueError('Deployment archive has no files')
        budget['entries'] -= count
        seen = set()
        for position, info in enumerate(infos, 1):
            checkpoint()
            path = _member_name(info)
            canonical = path.as_posix().casefold()
            if canonical in seen:
                raise ValueError('Ambiguous archive directory')
            seen.add(canonical)
            if info.is_dir():
                continue
            name = path.name.casefold()
            suffix = path.suffix.casefold()
            dotenv = _dotenv(name)
            if suffix not in ARCHIVES | TEXT_CONFIGS and not dotenv:
                continue
            locator = f'{prefix}/member-{position}'
            nested = suffix in ARCHIVES
            if nested and depth >= MAX_DEPTH:
                raise ValueError('Nested archive depth limit')
            check['coverage']['eligible'] += 1
            with tempfile.SpooledTemporaryFile(max_size=1024**2, mode='w+b') as member:
                _copy_member(archive, info, member, MAX_NESTED_BYTES if nested else MAX_CONFIG_BYTES, budget)
                if nested:
                    _scan(member, check, findings, budget, locator, depth + 1)
                else:
                    encoding = 'iso-8859-1' if suffix == '.properties' else 'utf-8-sig'
                    text = member.read().decode(encoding)
                    if dotenv and not name.endswith(('.example', '.sample', '.template')):
                        findings.append(_finding('artifact-dotenv-bundled', locator))
                    detected = set()
                    for kind, line in _config_secrets(text, '' if dotenv else suffix):
                        if kind not in detected:
                            findings.append(_finding('artifact-sensitive-literal', locator, line, kind))
                            detected.add(kind)
                    if len(findings) > MAX_FINDINGS:
                        raise ValueError('Archive finding limit exceeded')
            check['coverage']['scanned'] += 1


def run_artifact_secret_check(source, inventory, trusted, profile):
    if 'artifact_secrets' not in trusted:
        return None, []
    record = trusted['artifact_secrets']
    check = make_check(CHECK_ID, engine={'name': 'gxsec-deployment-secret-inspection', 'version': 1,
                       'rules_hash': content_hash(RULES), 'rule_ids': sorted(RULES), 'limitations': LIMITATIONS})
    check['coverage'].update(eligible=1, scanned=0)
    if (not isinstance(record, dict) or not inventory.get('revision')
            or record.get('source_revision') != inventory['revision']
            or not _trusted(record, trusted, 'artifact-secret-scan', ('protected-ci',))):
        check['errors'].append({'type': 'artifact_approval_unverified'})
        return check, []
    artifact = record.get('artifact')
    digest = artifact.get('sha256') if isinstance(artifact, dict) else None
    if not isinstance(digest, str) or not re.fullmatch(r'[a-f0-9]{64}', digest):
        check['errors'].append({'type': 'artifact_digest_invalid'})
        return check, []
    if profile == 'release':
        release = trusted.get('release_evidence')
        expected = release.get('artifact_digest') if isinstance(release, dict) else None
        if expected != digest and expected != f'sha256:{digest}':
            check['errors'].append({'type': 'artifact_release_digest_mismatch'})
            return check, []
    check['coverage']['artifact_digest'] = digest
    findings = []
    budget = {'bytes': MAX_PARSED_BYTES, 'entries': MAX_ENTRIES}
    try:
        with tempfile.TemporaryDirectory(prefix='gxsec-approved-artifact-') as directory:
            copy = _snapshot_file(artifact, source, Path(directory) / 'artifact.zip', {'remaining': MAX_ARCHIVE_BYTES})
            with copy.open('rb') as file:
                _scan(file, check, findings, budget)
        check['coverage']['scanned'] += 1
        check['status'] = 'complete'
    except BudgetExceeded as exc:
        check['errors'].append(exc.diagnostic)
    except (OSError, RuntimeError, ValueError, BadZipFile, zlib.error, yaml.YAMLError):
        check['errors'].append({'type': 'artifact_scan_unverified'})
    check['findings'] = [item['finding_id'] for item in findings]
    return check, findings
