#!/usr/bin/env python3
"""Record executable provenance at trusted bundle build time, never during a scan."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def record(output):
    commands = {"semgrep": ("semgrep", "--version"), "osv": ("osv-scanner", "--version"),
                "gitleaks": ("gitleaks", "version"), "git": ("git", "--version"), "python": ("python", "--version")}
    entries = {}
    with tempfile.TemporaryDirectory(prefix="gxsec-build-version-") as home:
        env = {"PATH": os.environ.get("PATH", ""), "HOME": home, "PYTHONIOENCODING": "utf-8",
               "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}
        for name, (command, flag) in commands.items():
            executable = shutil.which(command)
            if not executable:
                raise RuntimeError("Missing bundle executable: " + name)
            executable = Path(executable).resolve(strict=True)
            result = subprocess.run([str(executable), flag], env=env, text=True, capture_output=True,
                                    encoding="utf-8", errors="replace", timeout=30, check=True)
            entries[name] = {"executable": str(executable), "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                             "version": result.stdout.strip()}
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({"schema_version": 1, "tools": entries}, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    record(parser.parse_args().output)
