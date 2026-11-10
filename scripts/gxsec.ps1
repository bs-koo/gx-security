param(
    [Parameter(Mandatory=$true)][string]$Source,
    [string]$Action='release',
    [string]$Profile,
    [string]$Image='gx-security:0.10.3',
    [string]$Output,
    [string]$FindingId,
    [string]$Base,
    [string]$RunId,
    [string]$SessionId,
    [string]$Record,
    [string]$Policy,
    [string]$Database,
    [string]$ReviewRecords,
    [string]$ExpectedFramework,
    [string]$TemporarySize='512m',
    [ValidateRange(1,86400)][int]$MaxDurationSeconds=1200,
    [Parameter(HelpMessage='Working-tree file byte budget; Git history and advisory database copies are limited separately by TemporarySize.')]
    [ValidateRange(1,1099511627776)][long]$MaxInputBytes=4294967296,
    [string[]]$ExcludeSourcePath,
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

function Test-WithinPath([string]$Path, [string]$Root) {
    $normalizedPath = $Path.TrimEnd('\','/')
    $normalizedRoot = $Root.TrimEnd('\','/')
    $prefix = $normalizedRoot + [IO.Path]::DirectorySeparatorChar
    return $normalizedPath.Equals($normalizedRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $normalizedPath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}

function Read-PreviousTemporarySize([string]$RecordPath, [string]$ExpectedRunId,
        [string]$SourcePath, [string]$OutputPath) {
    $stream = $null
    $reader = $null
    try {
        $item = Get-Item -LiteralPath $RecordPath -Force -ErrorAction Stop
        if ($item.PSIsContainer -or (Test-ReparseComponents $RecordPath) -or
                ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Invalid saved context file' }
        $stream = [IO.File]::OpenRead($item.FullName)
        if ($stream.Length -le 0 -or $stream.Length -gt 16777216) { throw 'Saved context exceeds read limit' }
        $reader = New-Object IO.StreamReader($stream, [Text.Encoding]::UTF8, $true)
        $saved = $reader.ReadToEnd() | ConvertFrom-Json -ErrorAction Stop
        if ($saved -isnot [PSCustomObject] -or $saved.schema_version -ne 1 -or
                $saved.run_id -isnot [string] -or $saved.run_id -cnotmatch '^[A-Za-z0-9_.-]{1,128}\z' -or
                $saved.run_id -in @('.','..') -or ($ExpectedRunId -and $saved.run_id -cne $ExpectedRunId)) {
            throw 'Invalid saved run identity'
        }
        if (-not $saved.PSObject.Properties['execution_context']) { return '512m' }
        $context = $saved.execution_context
        if ($context -isnot [PSCustomObject]) { throw 'Invalid saved execution context' }
        if (-not $context.PSObject.Properties['temporary_size']) { return '512m' }
        $allowed = @('authority','runner','source','state_dir','output','policy','database',
                     'review_records','launcher','image','temporary_size')
        foreach ($property in $context.PSObject.Properties) {
            if ($allowed -cnotcontains $property.Name -or $property.Value -isnot [string] -or
                    -not $property.Value -or $property.Value.Length -gt 4096 -or
                    $property.Value -match '[\x00-\x1F]') { throw 'Invalid saved hint' }
        }
        if ($context.runner -cne 'powershell-docker' -or $context.authority -cne 'report-hint-only' -or
                $context.temporary_size -cnotin @('512m','1g','2g','4g')) { throw 'Invalid saved temporary size' }
        $originalPaths = @{source=$SourcePath;output=$OutputPath;state_dir=(Join-Path $OutputPath 'state')}
        foreach ($key in $originalPaths.Keys) {
            if (-not $context.PSObject.Properties[$key] -or -not [IO.Path]::IsPathRooted($context.$key)) {
                throw 'Missing original execution path'
            }
            $recorded = [IO.Path]::GetFullPath($context.$key)
            if (-not (Test-WithinPath $recorded $originalPaths[$key]) -or
                    -not (Test-WithinPath $originalPaths[$key] $recorded)) { throw 'Different original state' }
        }
        return $context.temporary_size
    }
    catch {
        Stop-Preparation 'previous_context_unavailable' 'The saved Docker resource hint could not be verified.' 'Use the original saved run, or explicitly select TemporarySize: 512m, 1g, 2g, or 4g.'
    }
    finally {
        if ($reader) { $reader.Dispose() }
        elseif ($stream) { $stream.Dispose() }
    }
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
$validArguments = $Action -in @('doctor','plan','check','release','retest','discuss') -and
    (-not $forwardProfile -or $Profile -in @('check','static-release','release')) -and
    $Image -match '^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}$' -and
    $TemporarySize -cin @('512m','1g','2g','4g')
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
if (($PSBoundParameters.ContainsKey('Policy') -and $Action -notin @('check','release','retest')) -or
        ($PSBoundParameters.ContainsKey('Database') -and -not $PSBoundParameters.ContainsKey('Policy')) -or
        ($PSBoundParameters.ContainsKey('ReviewRecords') -and -not $PSBoundParameters.ContainsKey('Policy')) -or
        ($PSBoundParameters.ContainsKey('ExpectedFramework') -and
            ($ExpectedFramework -cne 'SEF' -or $Action -notin @('check','release','retest')))) {
    $validArguments = $false
}
if (($PSBoundParameters.ContainsKey('MaxDurationSeconds') -and $Action -notin @('plan','check','release','retest')) -or
        ($PSBoundParameters.ContainsKey('MaxInputBytes') -and $Action -notin @('check','release','retest'))) {
    $validArguments = $false
}
if ($PSBoundParameters.ContainsKey('ExcludeSourcePath')) {
    if ($Action -notin @('plan','check','release','retest') -or
            $ExcludeSourcePath.Count -lt 1 -or $ExcludeSourcePath.Count -gt 64) { $validArguments = $false }
    foreach ($relativePath in $ExcludeSourcePath) {
        if (-not $relativePath -or $relativePath.Length -gt 512 -or
                $relativePath -match '^[/-]|[\\:*?\[\]\x00-\x1F]' -or
                @($relativePath.Split('/') | Where-Object { $_ -cin @('','.','..','.git') }).Count -gt 0) {
            $validArguments = $false
        }
    }
}
if (-not $validArguments) {
    Stop-Preparation 'invalid_arguments' 'The action or its arguments are invalid.' 'Use FindingId for retest, RunId for retest/discuss, Base for check, and SessionId/Record for discuss.'
}

try {
    $sourcePath = Resolve-Path -LiteralPath $Source
    if ($sourcePath.Provider.Name -ne 'FileSystem' -or -not (Test-Path -LiteralPath $sourcePath.Path -PathType Container) -or
            $sourcePath.Path.Contains(',') -or (Test-ReparseComponents $sourcePath.Path)) { throw 'Invalid source directory' }
    $resolvedSource = $sourcePath.Path
}
catch { Stop-Preparation 'invalid_source' 'The source must be an existing local directory without reparse entries.' 'Select the intended project directory.' }

if (-not $Output) { $Output = Join-Path $resolvedSource '.gxsec-container' }
try {
    $resolvedOutput = [IO.Path]::GetFullPath($Output)
    if ($resolvedOutput.Contains(',') -or (Test-WithinPath $resolvedSource $resolvedOutput) -or
            (Test-Path -LiteralPath $resolvedOutput -PathType Leaf) -or (Test-ReparseComponents $resolvedOutput)) {
        throw 'Invalid output directory'
    }
}
catch { Stop-Preparation 'invalid_output' 'The output must be a directory path without reparse entries.' 'Select a separate results directory.' }
if ($PSBoundParameters.ContainsKey('Policy')) {
    try {
        $resolvedPolicy = [IO.Path]::GetFullPath($Policy)
        if ($resolvedPolicy.Contains(',') -or -not (Test-Path -LiteralPath $resolvedPolicy -PathType Leaf) -or
                (Test-ReparseComponents $resolvedPolicy) -or (Test-WithinPath $resolvedPolicy $resolvedSource) -or
                (Test-WithinPath $resolvedPolicy $resolvedOutput)) { throw 'Invalid protected policy' }
    }
    catch { Stop-Preparation 'invalid_policy' 'The policy must be an existing file outside source and output, without reparse entries or mount separators.' 'Select the organization-controlled policy; the launcher does not authenticate its author.' }
}
if ($PSBoundParameters.ContainsKey('Database')) {
    try {
        $resolvedDatabase = [IO.Path]::GetFullPath($Database)
        if ($resolvedDatabase.Contains(',') -or -not (Test-Path -LiteralPath $resolvedDatabase -PathType Container) -or
                (Test-ReparseComponents $resolvedDatabase) -or (Test-WithinPath $resolvedDatabase $resolvedSource) -or
                (Test-WithinPath $resolvedSource $resolvedDatabase) -or (Test-WithinPath $resolvedDatabase $resolvedOutput) -or
                (Test-WithinPath $resolvedOutput $resolvedDatabase)) { throw 'Invalid approved database' }
    }
    catch { Stop-Preparation 'invalid_database' 'The database must be a separate existing directory without reparse entries or mount separators.' 'Select the approved snapshot outside source and output; set sca.offline_db to /advisories in the policy.' }
}
if ($PSBoundParameters.ContainsKey('ReviewRecords')) {
    try {
        $resolvedReviews = [IO.Path]::GetFullPath($ReviewRecords)
        if ($resolvedReviews.Contains(',') -or -not (Test-Path -LiteralPath $resolvedReviews -PathType Leaf) -or
                (Test-ReparseComponents $resolvedReviews) -or (Test-WithinPath $resolvedReviews $resolvedSource) -or
                (Test-WithinPath $resolvedReviews $resolvedOutput)) { throw 'Invalid review records' }
    }
    catch { Stop-Preparation 'invalid_review_records' 'Review records must be an existing file outside source and output, without reparse entries or mount separators.' 'Select the review records corresponding to the protected policy approvals.' }
}
if ($Action -eq 'retest') {
    $previousDatabase = Join-Path $resolvedOutput 'state/state.sqlite3'
    if (-not (Test-Path -LiteralPath $previousDatabase -PathType Leaf) -or (Test-ReparseComponents $previousDatabase)) {
        Stop-Preparation 'previous_state_unavailable' 'Retest requires the original saved state.' 'Select the results directory from the previous Docker run; do not create a replacement store.'
    }
    if (-not $PSBoundParameters.ContainsKey('TemporarySize')) {
        $resourceRecord = if ($RunId) { Join-Path $resolvedOutput ("state/runs/$RunId.json") }
                          else { Join-Path $resolvedOutput 'report/result.json' }
        $TemporarySize = Read-PreviousTemporarySize $resourceRecord $RunId $resolvedSource $resolvedOutput
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
    '--security-opt','no-new-privileges','--tmpfs',"/tmp:rw,nosuid,nodev,size=$TemporarySize",
    '--mount',"type=bind,source=$resolvedSource,target=/workspace,readonly")
if ($Action -notin @('doctor','plan')) {
    try { if ($Action -ne 'discuss') { New-Item -ItemType Directory -Path $resolvedOutput -Force | Out-Null } }
    catch { Stop-Preparation 'invalid_output' 'The results directory could not be prepared.' 'Select a writable results directory.' }
    $dockerArguments += @('--mount',"type=bind,source=$resolvedOutput,target=/results")
}
if ($PSBoundParameters.ContainsKey('Record')) {
    $dockerArguments += @('--mount',"type=bind,source=$resolvedRecord,target=/discussion-input/record.json,readonly")
}
if ($PSBoundParameters.ContainsKey('Policy')) {
    $dockerArguments += @('--mount',"type=bind,source=$resolvedPolicy,target=/trusted/policy.json,readonly")
}
if ($PSBoundParameters.ContainsKey('Database')) {
    $dockerArguments += @('--mount',"type=bind,source=$resolvedDatabase,target=/advisories,readonly")
}
if ($PSBoundParameters.ContainsKey('ReviewRecords')) {
    $dockerArguments += @('--mount',"type=bind,source=$resolvedReviews,target=/trusted/reviews.json,readonly")
}
if ($Action -in @('check','release','retest')) {
    $reportContext = @{runner='powershell-docker';source=$resolvedSource;output=$resolvedOutput;
        state_dir=(Join-Path $resolvedOutput 'state');launcher=$PSCommandPath;image=$imageParts[0];
        temporary_size=$TemporarySize}
    if ($PSBoundParameters.ContainsKey('Policy')) { $reportContext.policy = $resolvedPolicy }
    if ($PSBoundParameters.ContainsKey('Database')) { $reportContext.database = $resolvedDatabase }
    if ($PSBoundParameters.ContainsKey('ReviewRecords')) { $reportContext.review_records = $resolvedReviews }
    $reportContextEncoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($reportContext | ConvertTo-Json -Compress)))
    $dockerArguments += @('--env',"GXSEC_REPORT_CONTEXT_B64=$reportContextEncoded")
}
$dockerArguments += @($imageParts[0],$Action)
if ($Action -eq 'doctor') { $dockerArguments += @('--source','/workspace','--json') }
elseif ($Action -eq 'plan') {
    $planLimit = if ($PSBoundParameters.ContainsKey('MaxDurationSeconds')) { $MaxDurationSeconds } else { 30 }
    $dockerArguments += @('/workspace','--max-duration-seconds',[string]$planLimit)
    foreach ($relativePath in $ExcludeSourcePath) { $dockerArguments += @('--exclude-source-path',$relativePath) }
}
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
    if ($PSBoundParameters.ContainsKey('Policy')) { $dockerArguments += @('--policy','/trusted/policy.json') }
    if ($PSBoundParameters.ContainsKey('ReviewRecords')) { $dockerArguments += @('--review-records','/trusted/reviews.json') }
    if ($PSBoundParameters.ContainsKey('ExpectedFramework')) { $dockerArguments += @('--expected-framework',$ExpectedFramework) }
    if ($Action -ne 'retest' -or $PSBoundParameters.ContainsKey('MaxDurationSeconds')) {
        $dockerArguments += @('--max-duration-seconds',[string]$MaxDurationSeconds)
    }
    if ($Action -ne 'retest' -or $PSBoundParameters.ContainsKey('MaxInputBytes')) {
        $dockerArguments += @('--max-input-bytes',[string]$MaxInputBytes)
    }
    foreach ($relativePath in $ExcludeSourcePath) { $dockerArguments += @('--exclude-source-path',$relativePath) }
    if ($Json) { $dockerArguments += @('--json') }
}
& $dockerPath @dockerArguments
exit $LASTEXITCODE
