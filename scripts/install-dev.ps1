$ErrorActionPreference = "Stop"
python -c "import sys; assert sys.version_info >= (3,10), 'Python 3.10+ required'"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python -m pip install -r "$PSScriptRoot/../requirements-dev.txt"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
semgrep --version
if ($LASTEXITCODE -ne 0) {
    Write-Host "[gx-security] 호스트 정밀 엔진 미가용. 고정 Linux Docker/WSL 경로를 사용하세요."
    exit $LASTEXITCODE
}
Write-Host "[gx-security] 개발 의존성 설치 완료. OSV/Gitleaks와 DB는 doctor/고정 bundle에서 별도 확인합니다."
