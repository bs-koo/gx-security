"""Execution diagnostics shared by the legacy scanners.

Candidate generation is deliberately separate from completion: regex fallback
can still supply useful candidates when Semgrep is unavailable or fails.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
from tools.redaction import redact, scanner_diagnostic


class ScannerContract:
    def __init__(self):
        self.reset()

    def reset(self):
        self.errors = []
        self.semgrep = None
        self.files = set()
        self.ignored = []

    def record_file(self, path):
        self.files.add(str(path))

    def record_ignored(self, path, reason, *, line=None):
        item = {"path": str(path), "reason": reason}
        if line is not None:
            item["line"] = line
        if item not in self.ignored:
            self.ignored.append(item)

    def record_read_error(self, path):
        self.record_ignored(path, "read_error")
        self.errors.append({"engine": "grep-fallback", "type": "read_error", "path": str(path)})

    def filter_dirs(self, root, dirs, excluded):
        for name in dirs:
            if name in excluded:
                self.record_ignored(os.path.join(root, name), "excluded_directory")
        return [name for name in dirs if name not in excluded]

    def run_semgrep(self, cmd, **kwargs):
        # JSON omits skipped paths unless verbose mode is enabled. Keep
        # diagnostics on stderr, and disable optional network telemetry.
        cmd = [cmd[0], "--verbose", "--metrics=off", "--disable-version-check"] + [
            arg for arg in cmd[1:] if arg != "--quiet"]
        configs = [cmd[i + 1] for i, item in enumerate(cmd[:-1]) if item == "--config"]
        hashes = {}
        for config in configs:
            try:
                hashes[config] = hashlib.sha256(Path(config).read_bytes()).hexdigest()
            except OSError:
                hashes[config] = None
        self.semgrep = {"available": True, "version": None, "returncode": None,
                        "rule_configs": configs, "rule_hashes": hashes,
                        "coverage": {"parsed_files": [], "parsed_file_count": 0, "ignored_files": []}}
        try:
            out = subprocess.run(cmd, **kwargs)
        except (subprocess.TimeoutExpired, OSError) as exc:
            kind = "timeout" if isinstance(exc, subprocess.TimeoutExpired) else "execution_error"
            self.errors.append({"engine": "semgrep", "type": kind})
            raise
        self.semgrep["returncode"] = out.returncode
        try:
            data = json.loads(out.stdout)
            if not isinstance(data, dict) or not isinstance(data.get("results"), list):
                raise ValueError("expected Semgrep results array")
            if not isinstance(data.get("errors", []), list):
                raise ValueError("invalid Semgrep errors")
            for finding in data["results"]:
                if (not isinstance(finding, dict) or not isinstance(finding.get("path"), str)
                        or not isinstance(finding.get("check_id"), str)
                        or not isinstance(finding.get("start"), dict)
                        or type(finding["start"].get("line")) is not int
                        or finding["start"]["line"] < 1
                        or not isinstance(finding.get("extra", {}), dict)):
                    raise ValueError("invalid Semgrep finding")
                extra = finding.get("extra", {})
                if (not isinstance(extra.get("metadata", {}), dict)
                        or not isinstance(extra.get("lines", "") or "", str)):
                    raise ValueError("invalid Semgrep finding context")
        except (ValueError, TypeError) as exc:
            self.errors.append({"engine": "semgrep", "type": "invalid_json", "message": str(exc)})
            raise OSError("semgrep returned invalid JSON") from exc
        self.semgrep["version"] = data.get("version")
        if not isinstance(data.get("version"), str) or not data["version"].strip():
            self.errors.append({"engine": "semgrep", "type": "version_missing"})
        paths = data.get("paths", {})
        if not isinstance(paths, dict) or not isinstance(paths.get("scanned"), list):
            self.errors.append({"engine": "semgrep", "type": "coverage_missing"})
            paths = {}
        scanned = paths.get("scanned", [])
        ignored = paths.get("skipped", [])
        if any(not isinstance(path, str) or not path.strip() for path in scanned):
            self.errors.append({"engine": "semgrep", "type": "invalid_scanned_paths"})
            scanned = [path for path in scanned if isinstance(path, str) and path.strip()]
        if not isinstance(ignored, list):
            ignored = []
            self.errors.append({"engine": "semgrep", "type": "invalid_skipped_paths"})
        elif any(not isinstance(item, dict)
                 or not isinstance(item.get("path"), str) or not item["path"].strip()
                 or not isinstance(item.get("reason"), str) or not item["reason"].strip() for item in ignored):
            self.errors.append({"engine": "semgrep", "type": "invalid_skipped_paths"})
            ignored = []
        self.semgrep["coverage"] = {"parsed_files": scanned, "parsed_file_count": len(scanned),
                                     "ignored_files": ignored}
        if not scanned:
            self.errors.append({"engine": "semgrep", "type": "no_parsed_files"})
        for error in data.get("errors", []):
            self.errors.append(scanner_diagnostic(error))
        if out.returncode not in (0, 1):
            # Do not embed stderr: it may contain source code or credentials.
            self.errors.append({"engine": "semgrep", "type": "nonzero_exit", "returncode": out.returncode})
        return out

    def enrich(self, result):
        fallback = result["engine"] == "grep-fallback"
        if fallback:
            coverage = {"parsed_files": sorted(self.files), "parsed_file_count": len(self.files),
                        "ignored_files": self.ignored, "partial": True}
        else:
            coverage = dict((self.semgrep or {}).get("coverage", {}))
            coverage["partial"] = bool(self.errors)
        errors = list(self.errors)
        if not coverage.get("parsed_file_count") and not any(e.get("type") == "no_parsed_files" for e in errors):
            errors.append({"engine": result["engine"], "type": "no_parsed_files"})
        result["coverage"] = coverage
        result["errors"] = errors
        result["execution_status"] = "incomplete" if errors else ("degraded" if fallback else "complete")
        result["engine_metadata"] = {"semgrep": self.semgrep or {
            "available": False, "version": None,
            "reason": "disabled" if os.environ.get("GXSEC_NO_SEMGREP") else "not_found"}}
        if fallback:
            result["engine_metadata"]["grep-fallback"] = {"precision": "limited", "coverage": coverage}
        safe = redact(result)
        result.clear()
        result.update(safe)
        return result


def result_exit_code(result):
    # Preserve exploratory legacy CLI use; release aggregation rejects degraded.
    return 2 if result.get("execution_status") == "incomplete" or result.get("errors") else 0


def completion_proven(result):
    """A legacy status label alone is insufficient evidence of completion."""
    if (result.get("execution_status") != "complete" or result.get("errors")
            or result.get("error") or result.get("engine") != "semgrep"):
        return False
    coverage = result.get("coverage")
    metadata = result.get("engine_metadata")
    if not isinstance(coverage, dict) or not isinstance(metadata, dict):
        return False
    engine = metadata.get("semgrep")
    if not isinstance(engine, dict):
        return False
    parsed = coverage.get("parsed_files")
    if (not isinstance(parsed, list) or not parsed
            or any(not isinstance(path, str) or not path.strip() for path in parsed)):
        return False
    return (type(coverage.get("parsed_file_count")) is int
            and coverage["parsed_file_count"] > 0
            and coverage["parsed_file_count"] == len(parsed)
            and isinstance(engine.get("version"), str) and bool(engine["version"].strip()))
