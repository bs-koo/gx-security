#!/usr/bin/env python3
"""Install the exact Linux binaries from a reviewed lock, verifying before extract."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import platform
import tarfile
import urllib.request


def install(lock_path: Path, output: Path):
    if platform.system() != "Linux" or platform.machine().lower() not in ("x86_64", "amd64"):
        raise RuntimeError("This lock is linux/amd64. Use Docker/WSL or a reviewed platform-specific lock.")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    output.mkdir(parents=True, exist_ok=True)
    for name in ("osv", "gitleaks"):
        item = lock["engines"][name]
        with urllib.request.urlopen(item["url"], timeout=120) as response:
            raw = response.read(200 * 1024 * 1024 + 1)
        if len(raw) > 200 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise RuntimeError("Download hash/size validation failed for " + name)
        if name == "gitleaks":
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
                member = archive.getmember("gitleaks")
                if not member.isfile() or member.size > 100 * 1024 * 1024:
                    raise RuntimeError("Unexpected archive member")
                stream = archive.extractfile(member)
                if stream is None:
                    raise RuntimeError("Missing binary in archive")
                binary = stream.read()
        else:
            binary = raw
        destination = output / ("osv-scanner" if name == "osv" else "gitleaks")
        destination.write_bytes(binary)
        destination.chmod(0o755)
        print(name + " " + item["version"] + " verified")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=Path(__file__).resolve().parents[1] / "runtime" / "engines.lock.json")
    parser.add_argument("--output", type=Path, default=Path("/usr/local/bin"))
    args = parser.parse_args()
    install(args.lock, args.output)
