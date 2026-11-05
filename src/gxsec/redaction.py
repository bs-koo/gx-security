"""Secret masking shared by snapshots, errors, and exports."""
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
MASK = '[REDACTED]'
OMITTED = '[OMITTED: raw evidence remains local]'
_RAW_FIELDS = {'snippet','source_slice','raw','raw_output','details','stdout','stderr','response_body','request_body','traceback','diagnostic','diagnostics'}
_XML_SECRET = re.compile(r'(?is)(<(?:password|secret|token|api[_-]?key)[^>]*>).*?(</(?:password|secret|token|api[_-]?key)\s*>)')
_EXACT = re.compile(
    '(?i)^(?:authorization|proxy-authorization|cookie|set-cookie|password|passwd|pwd|secret|client_secret|api_key|apikey|access_token|refresh_token|id_token|token|private_key|session|sessionid|secretvalue|match)$',
)
_SENSITIVE_IDENTIFIER = re.compile(
    '(?i)(?:password|passwd|pwd|secret(?:key|value)?|token|apikey|privatekey|cookie(?:value)?|credential|authorization|sessionid)$',
)
_SAFE_REFERENCE = re.compile('(?i)(?:_ref|_path|_field|_name|_count|_budget|_location|_type|_id|Path|Field|Name|Ref)$')
_PEM = re.compile(
    '-----BEGIN (?:[A-Z ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)',
    re.S,
)
_INLINE = re.compile(
    '(?im)((?:["\']?)(?P<key>[A-Za-z_$][A-Za-z0-9_$.-]*)(?:["\']?)\\s*[=:]\\s*)(?P<value>["\'][^"\'\\r\\n]*["\']|(?:Bearer|Basic)\\s+[^\\s,;]+|[^\\s,;&<>{}\\[\\]"\']+)',
)
_TOKEN = re.compile(
    '\\b(?:AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+)\\b',
)
_URL = re.compile('https?://[^\\s<>"\\\']+')

def _sensitive_key(key):
    key = str(key)
    if _SAFE_REFERENCE.search(key):
        return False
    normalized = re.sub('[^A-Za-z0-9]', '', key)
    return bool(_EXACT.match(key) or _SENSITIVE_IDENTIFIER.search(normalized))

def _url(match):
    text = match.group(0)
    try:
        p = urlsplit(text)
        host = p.hostname or ''
        if ':' in host:
            host = '[' + host + ']'
        if p.port:
            host += ':' + str(p.port)
        if p.username is not None:
            host = MASK + '@' + host
        q = [(k, MASK if _sensitive_key(k) else v) for k, v in parse_qsl(p.query, keep_blank_values=True)]
        query = urlencode(q).replace('%5BREDACTED%5D', MASK)
        fragment = p.fragment
        if '=' in fragment:
            fragment = urlencode([(k, MASK if _sensitive_key(k) else v) for k, v in parse_qsl(fragment, keep_blank_values=True)]).replace('%5BREDACTED%5D', MASK)
        return urlunsplit((p.scheme, host, p.path, query, fragment))
    except (ValueError, TypeError):
        return MASK

def _redact(value, known):
    if isinstance(value, dict):
        return {str(k): OMITTED if str(k).lower() in _RAW_FIELDS else MASK if _sensitive_key(k) else _redact(v, known) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_redact(v, known) for v in value]
    if isinstance(value, str):
        for secret in known:
            value = value.replace(secret, MASK)
        value = _PEM.sub(MASK, value)
        value = _XML_SECRET.sub(lambda m: m.group(1) + MASK + m.group(2), value)
        value = _URL.sub(_url, value)
        value = _INLINE.sub(lambda m: m.group(1) + MASK if _sensitive_key(m.group('key')) else m.group(0), value)
        return _TOKEN.sub(MASK, value)
    return value

def redact(value):
    """Return a recursively masked copy, including known literals in adjacent errors."""
    known = set()

    def collect(item):
        if isinstance(item, dict):
            for key, child in item.items():
                if _sensitive_key(key) and isinstance(child, str) and (len(child) >= 4) and (child != MASK):
                    known.add(child)
                    if child.lower().startswith(('bearer ', 'basic ')):
                        known.add(child.split(' ', 1)[1])
                collect(child)
        elif isinstance(item, (list, tuple, set)):
            for child in item:
                collect(child)
    collect(value)
    return _redact(value, sorted(known, key=len, reverse=True))
