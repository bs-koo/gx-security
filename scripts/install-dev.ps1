$ErrorActionPreference = "Stop"
python -m pip install -r "$PSScriptRoot/../requirements-dev.txt"
semgrep --version
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "[gx-security] 개발 의존성 설치 완료 — 정적 엔진: semgrep"
