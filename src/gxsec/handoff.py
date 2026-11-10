"""Non-authoritative host path hints for resuming a saved run from its report."""
import base64
import json
import os
from pathlib import Path


def execution_context(args, source, state_dir, *, environment=None):
    environment = os.environ if environment is None else environment
    context = {'runner': 'native', 'source': str(source), 'state_dir': str(state_dir),
               'authority': 'report-hint-only'}
    for key in ('config', 'policy', 'review_records'):
        value = getattr(args, key, None)
        if value:
            context[key] = str(Path(value).resolve())
    raw = environment.get('GXSEC_REPORT_CONTEXT_B64', '')
    allowed = {'runner', 'source', 'state_dir', 'output', 'policy', 'database', 'review_records', 'launcher', 'image'}
    if not isinstance(raw, str) or not raw or len(raw) > 32768:
        return context
    try:
        hint = json.loads(base64.b64decode(raw, validate=True).decode('utf-8'))
        if (not isinstance(hint, dict) or set(hint) - allowed
                or hint.get('runner') != 'powershell-docker'
                or not {'source', 'state_dir', 'output'} <= set(hint)
                or any(not isinstance(v, str) or not v or len(v) > 4096
                       or any(ord(ch) < 32 for ch in v) for v in hint.values())):
            return context
        return {**hint, 'authority': 'report-hint-only'}
    except (ValueError, UnicodeError):
        return context
