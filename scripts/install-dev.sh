#!/usr/bin/env bash
set -euo pipefail
python -m pip install -r "$(dirname "$0")/../requirements-dev.txt"
semgrep --version
echo "[gx-security] 개발 의존성 설치 완료 — 정적 엔진: semgrep"
