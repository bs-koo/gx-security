param(
    [Parameter(Mandatory=$true)][string]$Source,
    [string]$Action='release',
    [string]$Profile,
    [string]$Image='gx-security:0.10.1',
    [string]$Output,
    [string]$FindingId,
    [string]$Base,
    [string]$RunId,
    [string]$SessionId,
    [string]$Record,
    [switch]$Json
)
$ErrorActionPreference='Stop'

function Stop-Preparation([string]$Reason, [string]$Detail, [string]$NextAction) {
    if ($Json) {
        [ordered]@{status='INCOMPLETE';phase='preparation';reason=$Reason;detail=$Detail;next_action=$NextAction} |
            ConvertTo-Json -Compress
    }
    else {
        Write-Output "Preparation incomplete: $Detail"
        Write-Output $NextAction
    }
    exit 2
}

function Test-ReparseComponents([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $attributes = (Get-Item -LiteralPath $current -Force).Attributes
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $true }
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ($parent -eq $current) { break }
        $current = $parent
    }
    return $false
}

function ConvertTo-ProcessArgument([string]$Value) {
    # ProcessStartInfo on Windows PowerShell has no ArgumentList property.
    # Quote argv for CreateProcess; no command shell interprets this string.
    $quoted = New-Object Text.StringBuilder
    [void]$quoted.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') { $slashes++; continue }
        if ($character -eq '"') {
            [void]$quoted.Append(('\' * ($slashes * 2 + 1)))
            [void]$quoted.Append('"')
        }
        else {
            [void]$quoted.Append(('\' * $slashes))
            [void]$quoted.Append($character)
        }
        $slashes = 0
    }
    [void]$quoted.Append(('\' * ($slashes * 2)))
    [void]$quoted.Append('"')
    return $quoted.ToString()
}

function Invoke-DockerProbe([string]$Executable, [string[]]$ProbeArguments) {
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $Executable
    $start.Arguments = (($ProbeArguments | ForEach-Object { ConvertTo-ProcessArgument $_ }) -join ' ')
    $start.WorkingDirectory = $PSScriptRoot
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    try {
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(7000)) {
            try { $process.Kill() } catch {}
            [void]$process.WaitForExit(1000)
            return @{TimedOut=$true;Code=-1;Text=''}
        }
        if (-not $stdout.Wait(500) -or -not $stderr.Wait(500)) {
            return @{TimedOut=$true;Code=-1;Text=''}
        }
        return @{TimedOut=$false;Code=$process.ExitCode;Text=$stdout.Result.Trim()}
    }
    catch { return @{TimedOut=$false;Code=-1;Text=''} }
    finally { $process.Dispose() }
}

$Action = $Action.ToLowerInvariant()
$Profile = ([string]$Profile).ToLowerInvariant()
$forwardProfile = $Action -ne 'retest' -or $PSBoundParameters.ContainsKey('Profile')
if (-not $PSBoundParameters.ContainsKey('Profile')) {
    if ($Action -eq 'check') { $Profile = 'check' }
    elseif ($Action -ne 'retest') { $Profile = 'static-release' }
}
$validArguments = $Action -in @('doctor','check','release','retest','discuss') -and
    (-not $forwardProfile -or $Profile -in @('check','static-release','release')) -and
    $Image -match '^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}$'
if ($Action -eq 'retest') {
    $validArguments = $validArguments -and $FindingId -match '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
}
elseif ($Action -eq 'discuss') {
    $validArguments = $validArguments -and $PSBoundParameters.ContainsKey('RunId') -and
        -not $PSBoundParameters.ContainsKey('FindingId') -and -not $PSBoundParameters.ContainsKey('Profile')
}
elseif ($PSBoundParameters.ContainsKey('FindingId') -or $PSBoundParameters.ContainsKey('RunId')) { $validArguments = $false }
if ($PSBoundParameters.ContainsKey('RunId') -and $RunId -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$') {
    $validArguments = $false
}
if ($PSBoundParameters.ContainsKey('Base') -and ($Action -ne 'check' -or $Base -notmatch '^[^-\s][^\s]*$')) {
    $validArguments = $false
}
if ($PSBoundParameters.ContainsKey('SessionId') -and
        ($Action -ne 'discuss' -or $SessionId -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')) {
    $validArguments = $false
}
if ($PSBoundParameters.ContainsKey('Record') -and
        ($Action -ne 'discuss' -or -not $PSBoundParameters.ContainsKey('SessionId'))) {
    $validArguments = $false
}
if (-not $validArguments) {
    Stop-Preparation 'invalid_arguments' 'The action or its arguments are invalid.' 'Use FindingId for retest, RunId for retest/discuss, Base for check, and SessionId/Record for discuss.'
}

try {
    $sourcePath = Resolve-Path -LiteralPath $Source
    if ($sourcePath.Provider.Name -ne 'FileSystem' -or -not (Test-Path -LiteralPath $sourcePath.Path -PathType Container) -or
            (Test-ReparseComponents $sourcePath.Path)) { throw 'Invalid source directory' }
    $resolvedSource = $sourcePath.Path
}
catch { Stop-Preparation 'invalid_source' 'The source must be an existing local directory without reparse entries.' 'Select the intended project directory.' }

if (-not $Output) { $Output = Join-Path $resolvedSource '.gxsec-container' }
try {
    $resolvedOutput = [IO.Path]::GetFullPath($Output)
    if ((Test-Path -LiteralPath $resolvedOutput -PathType Leaf) -or (Test-ReparseComponents $resolvedOutput)) {
        throw 'Invalid output directory'
    }
}
catch { Stop-Preparation 'invalid_output' 'The output must be a directory path without reparse entries.' 'Select a separate results directory.' }
if ($Action -eq 'retest') {
    $previousDatabase = Join-Path $resolvedOutput 'state/state.sqlite3'
    if (-not (Test-Path -LiteralPath $previousDatabase -PathType Leaf) -or (Test-ReparseComponents $previousDatabase)) {
        Stop-Preparation 'previous_state_unavailable' 'Retest requires the original saved state.' 'Select the results directory from the previous Docker run; do not create a replacement store.'
    }
}
if ($Action -eq 'discuss') {
    $previousDatabase = Join-Path $resolvedOutput 'state/state.sqlite3'
    $previousRun = Join-Path $resolvedOutput ("state/runs/$RunId.json")
    if (-not (Test-Path -LiteralPath $previousDatabase -PathType Leaf) -or
            -not (Test-Path -LiteralPath $previousRun -PathType Leaf) -or
            (Test-ReparseComponents $previousDatabase) -or (Test-ReparseComponents $previousRun)) {
        Stop-Preparation 'previous_state_unavailable' 'Discussion requires the original saved run and state.' 'Select the results directory and run ID from the previous Docker run; do not create a replacement store.'
    }
}

if ($PSBoundParameters.ContainsKey('Record')) {
    try {
        $resolvedRecord = [IO.Path]::GetFullPath($Record)
        if ($resolvedRecord.Contains(',') -or -not (Test-Path -LiteralPath $resolvedRecord -PathType Leaf) -or
                (Test-ReparseComponents $resolvedRecord)) { throw 'Invalid record file' }
    }
    catch { Stop-Preparation 'invalid_record' 'The discussion record must be an existing file without reparse entries or mount separators.' 'Select the local JSON record file; never put its contents in command arguments.' }
}

$docker = Get-Command docker.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $docker) {
    Stop-Preparation 'docker_cli_unavailable' 'Docker is not available on this computer.' 'Prepare Docker once, or select an already verified native runtime.'
}
$dockerPath = [IO.Path]::GetFullPath($docker.Source)
$sourcePrefix = $resolvedSource.TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
if ($dockerPath.StartsWith($sourcePrefix, [StringComparison]::OrdinalIgnoreCase) -or (Test-ReparseComponents $dockerPath)) {
    Stop-Preparation 'untrusted_docker_location' 'The Docker executable resolves inside the inspected project or through a reparse entry.' 'Use the installed Docker application outside the project.'
}
$daemon = Invoke-DockerProbe $dockerPath @('info','--format','{{.OSType}}')
if ($daemon.TimedOut) {
    Stop-Preparation 'docker_probe_timeout' 'Docker preparation did not respond within the time limit.' 'Start Docker and retry the same request.'
}
if ($daemon.Code -ne 0) {
    Stop-Preparation 'docker_unavailable' 'The Docker service is not ready.' 'Start Docker and retry the same request.'
}
if ($daemon.Text -ne 'linux') {
    Stop-Preparation 'docker_linux_required' 'This runtime requires Linux containers.' 'Select the Linux container engine in Docker.'
}
$localImage = Invoke-DockerProbe $dockerPath @('image','inspect',$Image,'--format','{{.Id}}|{{.Os}}')
if ($localImage.TimedOut) {
    Stop-Preparation 'docker_probe_timeout' 'The local image check did not respond within the time limit.' 'Check Docker and retry the same request.'
}
if ($localImage.Code -ne 0) {
    Stop-Preparation 'image_unavailable' 'The selected runtime image is not available locally.' 'Prepare the fixed runtime image once; this command does not download it.'
}
$imageParts = $localImage.Text.Split('|')
if ($imageParts.Count -ne 2 -or $imageParts[0] -notmatch '^sha256:[a-f0-9]{64}$') {
    Stop-Preparation 'image_unavailable' 'The local runtime image metadata could not be verified.' 'Prepare the fixed runtime image again.'
}
if ($imageParts[1] -ne 'linux') {
    Stop-Preparation 'image_linux_required' 'The selected local image is not a Linux image.' 'Use the fixed Linux runtime image.'
}

$dockerArguments = @('run','--rm','--pull','never','--network','none','--read-only','--cap-drop','ALL',
    '--security-opt','no-new-privileges','--tmpfs','/tmp:rw,nosuid,nodev,size=512m',
    '--mount',"type=bind,source=$resolvedSource,target=/workspace,readonly")
if ($Action -ne 'doctor') {
    try { if ($Action -ne 'discuss') { New-Item -ItemType Directory -Path $resolvedOutput -Force | Out-Null } }
    catch { Stop-Preparation 'invalid_output' 'The results directory could not be prepared.' 'Select a writable results directory.' }
    $dockerArguments += @('--mount',"type=bind,source=$resolvedOutput,target=/results")
}
if ($PSBoundParameters.ContainsKey('Record')) {
    $dockerArguments += @('--mount',"type=bind,source=$resolvedRecord,target=/discussion-input/record.json,readonly")
}
$dockerArguments += @($imageParts[0],$Action)
if ($Action -eq 'doctor') { $dockerArguments += @('--source','/workspace','--json') }
elseif ($Action -eq 'discuss') {
    $dockerArguments += @($RunId,'--source','/workspace','--state-dir','/results/state')
    if ($PSBoundParameters.ContainsKey('SessionId')) { $dockerArguments += @('--session-id',$SessionId) }
    if ($PSBoundParameters.ContainsKey('Record')) { $dockerArguments += @('--record','/discussion-input/record.json') }
    if ($Json) { $dockerArguments += @('--json') }
}
else {
    if ($Action -eq 'retest') { $dockerArguments += @($FindingId,'--source','/workspace') }
    else { $dockerArguments += @('/workspace') }
    if ($forwardProfile) { $dockerArguments += @('--profile',$Profile) }
    $dockerArguments += @('--state-dir','/results/state','--output','/results/report')
    if ($PSBoundParameters.ContainsKey('Base')) { $dockerArguments += @('--base',$Base) }
    if ($PSBoundParameters.ContainsKey('RunId')) { $dockerArguments += @('--run-id',$RunId) }
    if ($Json) { $dockerArguments += @('--json') }
}
& $dockerPath @dockerArguments
exit $LASTEXITCODE
