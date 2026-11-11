"""Secret-safe legacy output, with a conservative standalone fallback."""
import importlib.util
from pathlib import Path
import re

MASK = "[REDACTED]"
_SENSITIVE = re.compile(r"(?i)(?:password|passwd|pwd|secret(?:key|value)?|token|apikey|credential|authorization|cookie)$")
_REFERENCE = re.compile(r"(?i)(?:_id|_count|_path|_field|_name|_ref|_type|_location|_budget)$")
_ASSIGNMENT = re.compile(r'''(?im)(["']?([A-Za-z_$][\w$.-]*)["']?\s*[=:]\s*)(["'][^"'\r\n]*["']|(?:Bearer|Basic)\s+[^\s,;]+|[^\s,;&<>{}\[\]"']+)''')
_TOKEN = re.compile(r"\b(?:AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|eyJ[\w-]+\.[\w-]+\.[\w-]+)\b")
_RESPONSE_EXCERPTS = {"response_snippet", "marker_found"}


def _sensitive(key):
    return not _REFERENCE.search(str(key)) and bool(_SENSITIVE.search(re.sub(r"[^A-Za-z0-9]", "", str(key))))


def _shared_redactor():
    root = Path(__file__).resolve().parents[1]
    paths = [root / "src" / "gxsec" / "redaction.py"]
    if root.name == "_assets" and root.parent.name == "gxsec":
        paths.append(root.parent / "redaction.py")
    for path in paths:
        if path.is_file():
            spec = importlib.util.spec_from_file_location("_gxsec_legacy_redaction", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module.redact
    return None


_SHARED = _shared_redactor()


def redact(value):
    """Mask source snippets and diagnostic echoes without changing locations."""
    known = set()

    def collect(item):
        if isinstance(item, dict):
            for key, child in item.items():
                if _sensitive(key) and isinstance(child, str) and len(child) >= 4:
                    known.add(child)
                collect(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                collect(child)
        elif isinstance(item, str):
            for match in _ASSIGNMENT.finditer(item):
                literal = match.group(3).strip("\"'")
                if _sensitive(match.group(2)) and len(literal) >= 4 and not literal.startswith(("${", MASK)):
                    known.add(literal)
    collect(value)
    safe = _SHARED(value) if _SHARED else value

    def restore_counts(original, cleaned):
        if isinstance(original, dict) and isinstance(cleaned, dict):
            for field, child in original.items():
                if field == "rule_summary" and isinstance(child, dict):
                    cleaned[field] = {str(rule): count if type(count) is int else MASK for rule, count in child.items()}
                elif field in cleaned:
                    restore_counts(child, cleaned[field])
        elif isinstance(original, (list, tuple)) and isinstance(cleaned, list):
            for child, cleaned_child in zip(original, cleaned):
                restore_counts(child, cleaned_child)
    if _SHARED:
        restore_counts(value, safe)

    def mask(item, key=None):
        if isinstance(item, dict):
            result = {str(k): (MASK if str(k).lower() in _RESPONSE_EXCERPTS
                              else v if key == "rule_summary" and isinstance(v, int)
                              else MASK if _sensitive(k) else mask(v, str(k))) for k, v in item.items()}
            # Literal secrecy cannot be inferred from its spelling or rule.
            # Source consumers use the retained file/line to inspect context.
            if "snippet" in result:
                result["snippet"] = MASK
            return result
        if isinstance(item, (list, tuple)):
            return [mask(child, key) for child in item]
        if isinstance(item, str):
            for literal in sorted(known, key=len, reverse=True):
                item = item.replace(literal, MASK)
            item = _ASSIGNMENT.sub(lambda m: m.group(1) + MASK if _sensitive(m.group(2)) else m.group(0), item)
            item = _TOKEN.sub(MASK, item)
            if key in {"error", "errors", "message", "detail", "stderr"}:
                # Arbitrary diagnostic prose can echo an unlabelled secret.
                # Structured error type, engine, return code and path survive.
                return MASK
            if _SHARED is None and key in {"snippet", "error", "errors", "message", "detail", "stderr"}:
                return MASK
        return item
    return mask(safe)


def scanner_diagnostic(error):
    """Export only structured engine error identity and source positions."""
    result = {"engine": "semgrep", "type": "engine_error"}
    if not isinstance(error, dict):
        return result
    if isinstance(error.get("type"), str):
        result["type"] = error["type"]
    if type(error.get("code")) is int:
        result["code"] = error["code"]
    for field in ("path", "file"):
        if isinstance(error.get(field), str):
            result[field] = error[field]
    locations = []
    for span in error.get("spans", []) if isinstance(error.get("spans", []), list) else []:
        if not isinstance(span, dict):
            continue
        location = {field: span[field] for field in ("path", "file") if isinstance(span.get(field), str)}
        for field in ("start", "end"):
            position = span.get(field)
            if isinstance(position, dict):
                location[field] = {name: position[name] for name in ("line", "col", "offset") if type(position.get(name)) is int}
        if location:
            locations.append(location)
    if locations:
        result["locations"] = locations
    return result
