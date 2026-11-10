"""Bounded engine failure metadata; native prose is never report content."""
import errno
from pathlib import Path, PureWindowsPath
import subprocess

from .source import reject_reparse_path


MAX_DIAGNOSTICS = 100
MAX_JSON_BYTES = 16 * 1024 * 1024


class OutputLimitExceeded(ValueError):
    """A native process exceeded the bounded stdout/stderr capture contract."""


_SEMGREP_TYPES = frozenset({
    'PartialParsing', 'ParseError', 'LexicalError', 'Timeout', 'OutOfMemory',
    'StackOverflow', 'FatalError', 'MatchingError', 'SemgrepError', 'SemgrepCoreError',
    'InvalidRuleSchemaError', 'RuleParseError', 'PatternParseError', 'UnknownLanguageError',
    'TooManyMatches', 'AstBuilderError', 'InternalError', 'InvalidYaml', 'MissingPlugin',
})


def _inventory_path(value, source, files):
    if not isinstance(value, str) or not value or len(value) > 4096 or any(ord(c) < 32 for c in value):
        return None
    path = Path(value)
    if PureWindowsPath(value).is_absolute() and not path.is_absolute():
        return None
    try:
        root = Path(source).resolve()
        resolved = reject_reparse_path(path if path.is_absolute() else root / path).resolve(strict=True)
        relative = resolved.relative_to(root).as_posix()
        return relative if relative in files and resolved.is_file() else None
    except (OSError, ValueError, RuntimeError):
        return None


def semgrep_diagnostics(items, source, files):
    result = []
    files = set(files)
    for item in items[:MAX_DIAGNOSTICS]:
        item = item if isinstance(item, dict) else {}
        kind = item.get('type')
        kind = kind if isinstance(kind, str) and kind in _SEMGREP_TYPES else 'unclassified'
        diagnostic = {'type': 'semgrep_diagnostic', 'error_type': kind}
        code = item.get('code')
        if type(code) is int and 0 <= code <= 255:
            diagnostic['code'] = code
        if kind in {'Timeout', 'OutOfMemory', 'StackOverflow'}:
            diagnostic['category'] = {'Timeout': 'timeout_reported', 'OutOfMemory': 'memory_exhaustion_reported',
                                      'StackOverflow': 'stack_exhaustion_reported'}[kind]
            diagnostic['evidence'] = 'engine-diagnostic'
        spans = item.get('spans')
        locations = [item, *(spans[:4] if isinstance(spans, list) else [])]
        for location in locations:
            if not isinstance(location, dict):
                continue
            path = _inventory_path(location.get('path', location.get('file')), source, files)
            if path is None:
                continue
            diagnostic['path'] = path
            start = location.get('start')
            line = start.get('line') if isinstance(start, dict) else None
            if type(line) is int and 1 <= line <= 10 ** 9:
                diagnostic['line'] = line
            break
        result.append(diagnostic)
    if len(items) > MAX_DIAGNOSTICS:
        result.append({'type': 'diagnostics_truncated', 'omitted': len(items) - MAX_DIAGNOSTICS})
    return result


def process_failure(result):
    diagnostic = {'type': 'engine_failed', 'category': 'nonzero_exit',
                  'message': 'Engine execution failed; raw diagnostics omitted'}
    code = result.returncode
    if type(code) is int and -(2 ** 31) <= code < 2 ** 32:
        diagnostic['returncode'] = code
        if -64 <= code < 0:
            diagnostic.update(category='terminated_by_signal', signal=-code, evidence='process-returncode')
    # Text is a bounded classification hint, never proof of the root cause.
    stderr = result.stderr
    if isinstance(stderr, bytes):
        stderr = stderr[:65536].decode('utf-8', errors='replace')
    text = stderr[:65536].lower() if isinstance(stderr, str) else ''
    if diagnostic['category'] == 'nonzero_exit':
        for markers, category in (
            (('out of memory', 'cannot allocate memory', 'memoryerror'), 'memory_exhaustion_reported'),
            (('resource temporarily unavailable', 'pthread_create', "can't start new thread"), 'resource_exhaustion_reported'),
            (('no space left on device',), 'storage_exhaustion_reported'),
            (('permission denied',), 'permission_denied_reported'),
        ):
            if any(marker in text for marker in markers):
                diagnostic.update(category=category, evidence='stderr-marker')
                break
    return diagnostic


def exception_diagnostic(kind, exc):
    category = 'invalid_engine_output'
    if isinstance(exc, subprocess.TimeoutExpired):
        category = 'timeout'
    elif isinstance(exc, OutputLimitExceeded):
        category = 'output_limit'
    elif isinstance(exc, OSError):
        category = {errno.ENOMEM: 'memory_exhaustion', errno.ENOSPC: 'storage_exhaustion',
                    errno.EAGAIN: 'resource_unavailable', errno.EACCES: 'permission_denied',
                    errno.ENOENT: 'input_unavailable'}.get(exc.errno, 'io_error')
    return {'type': kind, 'category': category,
            'message': 'Engine processing could not complete; raw exception details omitted'}
