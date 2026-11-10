[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$BundleRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$SkillsDirectory = (Join-Path ([Environment]::GetFolderPath('UserProfile')) '.agents\skills')
)

$ErrorActionPreference = 'Stop'

function Get-PhysicalDirectory([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer) { throw "Not a directory: $Path" }
    $seen = @{}
    while ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        if ($seen.ContainsKey($item.FullName)) { throw "Directory link cycle: $Path" }
        $seen[$item.FullName] = $true
        $target = @($item.Target)[0]
        if (-not $target) { throw "Cannot resolve directory link: $Path" }
        if (-not [IO.Path]::IsPathRooted($target)) {
            $target = Join-Path $item.Parent.FullName $target
        }
        $item = Get-Item -LiteralPath $target -Force
        if (-not $item.PSIsContainer) { throw "Link target is not a directory: $Path" }
    }
    return $item.FullName.TrimEnd([IO.Path]::DirectorySeparatorChar)
}

$bundle = Get-PhysicalDirectory $BundleRoot
foreach ($relative in @('gxsec.py', 'scripts\gxsec.ps1', 'tools\dyn_session.py', '.claude-plugin\plugin.json', 'skills\gx-security\SKILL.md')) {
    if (-not (Test-Path -LiteralPath (Join-Path $bundle $relative) -PathType Leaf)) {
        throw "Incomplete bundle: missing $relative. Keep the complete trusted gx-security package."
    }
}
$destination = [IO.Path]::GetFullPath($SkillsDirectory)
if ((Test-Path -LiteralPath $destination) -and -not (Test-Path -LiteralPath $destination -PathType Container)) {
    throw "Skills directory is not a directory: $destination"
}

# Preflight every name before creating anything. Existing skills are never replaced.
$plan = @()
foreach ($skill in Get-ChildItem -LiteralPath (Join-Path $bundle 'skills') -Directory | Sort-Object Name) {
    $manifest = Join-Path $skill.FullName 'SKILL.md'
    if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { continue }
    if ($skill.Name -notmatch '^[a-z0-9][a-z0-9-]*$') { throw "Unsupported skill folder name: $($skill.Name)" }
    $source = Get-PhysicalDirectory $skill.FullName
    $bundlePrefix = $bundle + [IO.Path]::DirectorySeparatorChar
    if (-not $source.StartsWith($bundlePrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Skill target leaves the bundle: $($skill.Name)"
    }
    $link = Join-Path $destination $skill.Name
    $existing = Get-Item -LiteralPath $link -Force -ErrorAction SilentlyContinue
    $action = 'create'
    if ($null -ne $existing) {
        if (-not ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Existing skill will not be overwritten: $link"
        }
        $actual = Get-PhysicalDirectory $link
        if (-not $actual.Equals($source, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Existing skill points to another bundle and will not be overwritten: $link"
        }
        $action = 'already-linked'
    }
    $plan += [pscustomobject]@{ name = $skill.Name; path = $link; target = $source; action = $action }
}
if ($plan.Count -eq 0) { throw 'No skills found in the bundle.' }
if (-not $PSCmdlet.ShouldProcess($destination, "Register $($plan.Count) gx-security skill links; preserve the bundle")) {
    return
}

if (-not (Test-Path -LiteralPath $destination)) {
    [IO.Directory]::CreateDirectory($destination) | Out-Null
}
$created = @()
try {
    foreach ($entry in $plan) {
        if ($entry.action -eq 'already-linked') { continue }
        # Windows junctions need no Developer Mode or administrator symlink privilege.
        $kind = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { 'Junction' } else { 'SymbolicLink' }
        New-Item -ItemType $kind -Path $entry.path -Target $entry.target -ErrorAction Stop | Out-Null
        $created += $entry
    }
} catch {
    # Only remove links created by this invocation. Never traverse/delete a bundle.
    foreach ($entry in $created) {
        $item = Get-Item -LiteralPath $entry.path -Force -ErrorAction SilentlyContinue
        if (($null -ne $item) -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            $actual = Get-PhysicalDirectory $entry.path
            if ($actual.Equals($entry.target, [StringComparison]::OrdinalIgnoreCase)) {
                [IO.Directory]::Delete($entry.path)
            }
        }
    }
    throw
}

[pscustomobject]@{
    bundle = $bundle
    skills_directory = $destination
    skills = $plan
    note = 'Registration only. Keep this bundle path. No engine installation, scan, or security approval was performed.'
} | ConvertTo-Json -Depth 5
