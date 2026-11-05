#!/usr/bin/env python3
"""Reference optional scanner runner for an already confined protected host.

The launcher must provide a process-tree deadline, read-only source, and the
approved deny-all or exact-route network lease. This script does not install a
firewall or grant itself an approval. Install it and its gxsec dependency outside
the inspected source; approve the complete deployed launcher/runtime digest.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

from gxsec.models import content_hash
from gxsec.optional import (MAX_REPORT_BYTES, _bounded_process, _confinement, _host_limits, _read_file,
                            _record, _require, _snapshot_plan, parse_native, execution_inventory)
from gxsec.redaction import redact
from gxsec.source import collect_source, runtime_environment


def _child(command, directory, environment, deadline, *, maximum=MAX_REPORT_BYTES, reports=()):
    remaining = deadline - time.monotonic()
    _require(remaining > 0, 'Optional scanner deadline expired')
    result = _bounded_process(command, cwd=directory, environment=environment,
                              timeout=remaining, maximum=maximum, reports=reports)
    return result.stdout, result.stderr


def _report(path, maximum):
    _require(path.is_file() and not path.is_symlink(), 'Optional scanner produced no native report')
    with path.open('rb') as handle:
        data = handle.read(maximum + 1)
    _require(len(data) <= maximum, 'Optional native report exceeded its quota')
    return data.decode('utf-8-sig')


def _version(engine, directory, environment, deadline, maximum):
    executable, name = engine['executable'], engine['name']
    args = ['version', '--format=json'] if name == 'codeql' else ['-version'] if name == 'nuclei' else ['--version']
    out, err = _child([executable, *args], directory, environment, deadline, maximum=maximum)
    if name == 'codeql':
        version = json.loads(out).get('version')
    else:
        match = re.search(r'(?<!\d)(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)\b', out + ' ' + err)
        version = match.group(1) if match else None
    _require(version == engine['version'], 'Optional scanner version differs from protected pin')


def _trivy(plan, directory, environment, deadline):
    inputs = plan['inputs']
    database = Path(inputs['database']['path'])
    quota = plan['confinement']['limits']['output_bytes']
    config, ignore = Path(directory) / 'trivy.yaml', Path(directory) / 'empty.trivyignore'
    config.write_text('{}\n', encoding='utf-8')
    ignore.write_text('', encoding='utf-8')
    target = inputs['target']
    targets = [target['path']] if target['kind'] == 'image-archive' else [str(Path(plan['source']) / p) for p in plan['coverage']['eligible']]
    reports = []
    for index, path in enumerate(targets):
        report = Path(directory) / ('trivy-' + str(index) + '.json')
        command = [plan['engine']['executable'], 'image' if target['kind'] == 'image-archive' else 'filesystem',
            '--config', str(config), '--ignorefile', str(ignore), '--cache-dir', str(database),
            '--format', 'json', '--scanners', 'vuln', '--offline-scan', '--skip-db-update',
            '--skip-java-db-update', '--skip-version-check', '--disable-telemetry', '--exit-code', '0', '--output', str(report)]
        command += ['--input', path] if target['kind'] == 'image-archive' else ['--', path]
        _child(command, directory, environment, deadline, maximum=quota, reports=[report])
        native = json.loads(_report(report, quota))
        # Validate every individual report before merging its native result rows.
        single = {**plan, 'coverage': {**plan['coverage'], 'eligible': [plan['coverage']['eligible'][index]]}} if target['kind'] != 'image-archive' else plan
        parse_native(native, single, Path(plan['source']), original_source=Path((plan.get('source_identity') or {}).get('origin_source', plan['source'])))
        reports.append(native)
    combined = {**reports[0], 'Results': [row for report in reports for row in report['Results']]}
    return combined


def _codeql(plan, directory, environment, deadline):
    database, queries = plan['inputs']['database'], plan['inputs']['queries']
    working = Path(database['path'])
    limits = plan['confinement']['limits']
    output = Path(directory) / 'codeql.sarif'
    command = [plan['engine']['executable'], 'database', 'analyze', '--format=sarifv2.1.0',
        '--output=' + str(output), '--no-download', '--threads=1', '--ram=' + str(min(1024, max(1, limits['memory_bytes'] // (1024 ** 2)))), '--rerun',
        '--max-disk-cache=' + str(min(256, max(1, limits['disk_bytes'] // (1024 ** 2)))),
        '--search-path=' + plan['inputs']['query_packs']['path'], '--additional-packs=' + queries['path'],
        '--no-default-compilation-cache', '--compilation-cache=' + str(Path(directory) / 'query-cache'),
        '--no-database-extension-packs', '--no-database-threat-models', '--no-sarif-add-file-contents',
        '--no-sarif-add-snippets', '--sarif-include-query-help=never', '--', str(working),
        str(Path(queries['path']) / queries['suite'])]
    _child(command, directory, environment, deadline, maximum=limits['output_bytes'], reports=[output])
    return json.loads(_report(output, limits['output_bytes']))


def _nuclei(plan, directory, environment, deadline):
    config = Path(directory) / 'nuclei.yaml'
    config.write_text('{}\n', encoding='utf-8')
    environment = {**environment, **{'DISABLE_NUCLEI_TEMPLATES_' + provider + '_DOWNLOAD': 'true'
        for provider in ('PUBLIC', 'GITHUB', 'GITLAB', 'AWS', 'AZURE')}}
    rows = []
    target = plan['inputs']['target']
    for template in plan['inputs']['templates']:
        certificate = template['signature_verification']['certificate']
        scoped_environment = {**environment, 'NUCLEI_USER_CERTIFICATE': _read_file(certificate, Path(plan['source']), maximum=64 * 1024).decode('ascii')}
        for path in target['paths']:
            output = Path(directory) / 'nuclei.jsonl'
            output.unlink(missing_ok=True)
            command = [plan['engine']['executable'], '-config', str(config), '-target', target['origin'] + path,
                '-templates', template['path'], '-type', 'http', '-dut', '-duc', '-ni', '-dr', '-no-httpx',
                '-no-stdin', '-omit-raw', '-omit-template', '-jsonl', '-output', str(output), '-stats-json',
                '-stats-interval', '1', '-rate-limit', '1', '-concurrency', '1', '-bulk-size', '1',
                '-retries', '0', '-timeout', '10', '-response-size-read', '1048576', '-disable-clustering']
            quota = plan['confinement']['limits']['output_bytes']
            stdout, stderr = _child(command, directory, scoped_environment, deadline, maximum=quota, reports=[output])
            stats = []
            for line in (stdout + '\n' + stderr).splitlines():
                try:
                    row = json.loads(line)
                    if isinstance(row, dict) and 'templates' in row:
                        stats.append(row)
                except ValueError:
                    pass
            _require(stats and all(str(stats[-1].get(key)) == '1' for key in ('templates', 'hosts', 'requests', 'total'))
                     and str(stats[-1].get('errors')) == '0'
                     and str(stats[-1].get('percent')) in {'100', '100.0'},
                     'Nuclei did not attest a completed signed-template request with zero errors')
            rows.extend(_report(output, quota).splitlines())
    return '\n'.join(rows)


def execute_plan(plan):
    """Execute only the three fixed, approved scanner command families."""
    _require(isinstance(plan, dict), 'Optional scanner plan must be an object')
    source = Path(plan.get('source', '')).resolve()
    _require(source.is_dir(), 'Optional scanner source directory is missing')
    record = {key: value for key, value in plan.items() if key not in {'source', 'approval_context', 'source_identity'}}
    policy = plan.get('approval_context') or {}
    name = (record.get('engine') or {}).get('name')
    _require(name in {'trivy', 'codeql', 'nuclei'}, 'Optional scanner engine is unsupported')
    identity = plan.get('source_identity')
    trust_source = Path(identity['origin_source']).absolute() if identity else source
    inventory, actual_before = execution_inventory(source, identity)
    _require(inventory.get('hash') == record.get('source_hash') and inventory.get('scope_hash') == record.get('scope_hash'),
             'Optional scanner source contents or scope differ from approved revision evidence')
    inventory['revision'] = record.get('source_revision')
    _record(record, policy, trust_source, inventory, name, plan=True)
    _confinement(record.get('confinement'), policy, trust_source, record['engine'], record['inputs'].get('target', {}), runner=record.get('runner'))
    limits = _host_limits(record['confinement'])
    timeout = record.get('timeout_seconds', 300)
    _require(type(timeout) in {int, float} and 1 <= timeout <= 1200, 'Optional scanner timeout is unbounded')
    deadline = time.monotonic() + timeout
    with tempfile.TemporaryDirectory(prefix='gxsec-optional-child-') as directory:
        execution = _snapshot_plan(record, trust_source, Path(directory), {'remaining': limits['disk_bytes']})
        execution['source'] = str(source)
        if identity:
            execution['source_identity'] = identity
        environment = runtime_environment()
        environment['PATH'] = str(Path(execution['engine']['executable']).parent)
        environment.update(HOME=directory, USERPROFILE=directory, XDG_CONFIG_HOME=directory,
                           XDG_CACHE_HOME=directory, NO_COLOR='1', GIT_CONFIG_NOSYSTEM='1',
                           GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT='0')
        _version(execution['engine'], directory, environment, deadline, limits['output_bytes'])
        native = {'trivy': _trivy, 'codeql': _codeql, 'nuclei': _nuclei}[name](execution, directory, environment, deadline)
        # Redact the structured native artifact before it leaves confined scratch.
        # JSONL must be decoded first so masking cannot corrupt the wire format.
        if name == 'nuclei':
            safe = []
            for text in native.splitlines():
                if not text.strip():
                    continue
                row = json.loads(text)
                _require(isinstance(row, dict) and isinstance(row.get('info'), dict), 'Nuclei native result is malformed')
                item = {key: row[key] for key in ('template-id', 'type', 'matched-at') if key in row}
                item['info'] = {key: row['info'][key] for key in ('name', 'severity') if key in row['info']}
                safe.append(json.dumps(redact(item), ensure_ascii=False))
            native = '\n'.join(safe)
        else:
            native = redact(native)
        parse_native(native, record, source, original_source=trust_source)
    after = collect_source(source, git_boundary=trust_source)
    _require(not after.get('errors') and all(after.get(key) == actual_before.get(key) for key in ('hash', 'scope_hash'))
             and {row['path']: row['hash'] for row in after.get('inventory', [])} == {row['path']: row['hash'] for row in actual_before.get('inventory', [])},
             'Optional scanner source changed during execution')
    return {'execution_status': 'complete', 'plan_digest': content_hash(plan), 'engine': record['engine'],
        'source_revision': record['source_revision'], 'source_hash': record['source_hash'], 'scope_hash': record['scope_hash'],
        'coverage': record['coverage'], 'confinement_record_id': record['confinement']['id'], 'native_report': native}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gxsec-plan', required=True, type=Path)
    parser.add_argument('--gxsec-result', required=True, type=Path)
    args = parser.parse_args()
    try:
        with args.gxsec_plan.open('rb') as handle:
            data = handle.read(MAX_REPORT_BYTES + 1)
        _require(len(data) <= MAX_REPORT_BYTES, 'Optional scanner plan is too large')
        plan = json.loads(data.decode('utf-8-sig'))
        output = args.gxsec_result.resolve()
        _require(not output.is_relative_to(Path(plan.get('source', '')).resolve()), 'Optional result must be outside source')
        result = execute_plan(plan)
        data = json.dumps(result, ensure_ascii=False).encode('utf-8')
        _require(len(data) <= plan['confinement']['limits']['output_bytes'], 'Optional result envelope exceeds its output quota')
        output.write_bytes(data)
        return 0
    except (ValueError, TypeError, KeyError, OSError, RuntimeError, subprocess.SubprocessError):
        # Never export scanner stderr, credentials, or the arbitrary input value.
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
