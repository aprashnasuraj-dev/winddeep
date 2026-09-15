<#
.SYNOPSIS
Stages the pinned Windows tool payload declared in tools-manifest.json.
.DESCRIPTION
Every package must have a reviewed HTTPS URL, version, license, SHA-256,
destination, provides mapping and a non-invasive liveness probe. Downloads are
hash verified before installation. Direct files and ZIP archives are supported.
The script fails closed on an empty manifest, unsafe paths, hash mismatch,
missing archive members, or failed probes.
#>
[CmdletBinding()]
param(
    [string]$ManifestPath = (Join-Path $PSScriptRoot 'tools-manifest.json'),
    [string]$ToolsRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'tools')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Test-SafeRelativePath([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ([IO.Path]::IsPathRooted($Value)) { return $false }
    $parts = $Value -split '[\\/]'
    return -not ($parts -contains '..')
}

function Get-OptionalProperty([object]$Object, [string]$Name, $DefaultValue = $null) {
    if ($null -ne $Object -and $Object.PSObject.Properties.Name -contains $Name) {
        return $Object.$Name
    }
    return $DefaultValue
}

function Assert-Hash([string]$Path, [string]$Expected, [string]$Name) {
    if ($Expected -notmatch '^[0-9a-fA-F]{64}$') {
        throw "Invalid SHA256 for $Name"
    }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Expected.ToLowerInvariant()) {
        throw "SHA256 mismatch for $Name`: expected $Expected, got $actual"
    }
}

function Invoke-SafeProbe([string]$Executable, [object[]]$Arguments, [int[]]$ExpectedExitCodes, [string]$Name) {
    if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) {
        throw "Probe target missing for $Name`: $Executable"
    }
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $Executable
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $null = $psi.ArgumentList.Add([string]$argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $psi
    if (-not $process.Start()) { throw "Failed to start probe for $Name" }
    try {
        if (-not $process.WaitForExit(15000)) {
            try { $process.Kill($true) } catch { }
            throw "Probe timed out for $Name"
        }
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        if ($ExpectedExitCodes -notcontains $process.ExitCode) {
            $detail = (($stdout + "`n" + $stderr).Trim() -replace "`r?`n", ' ')
            if ($detail.Length -gt 500) { $detail = $detail.Substring(0, 500) }
            throw "Probe failed for $Name with exit $($process.ExitCode): $detail"
        }
    } finally {
        $process.Dispose()
    }
}

if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    throw "Tool manifest not found: $ManifestPath"
}
$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
if (-not ($manifest.PSObject.Properties.Name -contains 'tools')) {
    throw 'Tool manifest is missing the tools array.'
}
$tools = @($manifest.tools)
if ($tools.Count -eq 0) {
    throw 'Tool manifest is empty. A production release must explicitly package every registered external tool.'
}

$toolsRootFull = [IO.Path]::GetFullPath($ToolsRoot)
New-Item -ItemType Directory -Path $toolsRootFull -Force | Out-Null
$cacheRoot = Join-Path $env:TEMP 'WindeepToolCache'
New-Item -ItemType Directory -Path $cacheRoot -Force | Out-Null
$provided = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

foreach ($tool in $tools) {
    $name = [string]$tool.name
    $version = [string]$tool.version
    $url = [string]$tool.url
    $sha256 = [string]$tool.sha256
    $destinationRel = [string]$tool.destination
    $packageTypeRaw = [string](Get-OptionalProperty -Object $tool -Name 'package_type' -DefaultValue 'file')
    $packageType = if ([string]::IsNullOrWhiteSpace($packageTypeRaw)) { 'file' } else { $packageTypeRaw.ToLowerInvariant() }
    $license = [string]$tool.license
    $provides = @($tool.provides)
    $probe = @($tool.probe)
    $expectedRaw = Get-OptionalProperty -Object $tool -Name 'expected_exit_codes' -DefaultValue @(0)
    $expectedExitCodes = @($expectedRaw | ForEach-Object { [int]$_ })

    if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($version) -or
        [string]::IsNullOrWhiteSpace($license) -or $url -notmatch '^https://' -or
        $sha256 -notmatch '^[0-9a-fA-F]{64}$' -or -not (Test-SafeRelativePath $destinationRel) -or
        $provides.Count -eq 0 -or $probe.Count -eq 0 -or $expectedExitCodes.Count -eq 0) {
        throw "Invalid manifest entry: $name"
    }
    if ($packageType -notin @('file', 'zip')) { throw "Unsupported package_type '$packageType' for $name" }
    foreach ($alias in $provides) {
        if ([string]::IsNullOrWhiteSpace([string]$alias)) { throw "Empty provides alias for $name" }
        if (-not $provided.Add([string]$alias)) { throw "Duplicate provides mapping '$alias' in manifest" }
    }

    $destination = [IO.Path]::GetFullPath((Join-Path $toolsRootFull $destinationRel))
    if (-not $destination.StartsWith($toolsRootFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Destination escapes tools root for $name`: $destinationRel"
    }
    $destinationDir = Split-Path $destination -Parent
    New-Item -ItemType Directory -Path $destinationDir -Force | Out-Null

    $safeName = ($name -replace '[^A-Za-z0-9_.-]', '_')
    $cacheExtension = if ($packageType -eq 'zip') { '.zip' } else { '.bin' }
    $cacheFile = Join-Path $cacheRoot "$safeName-$version$cacheExtension"
    $cacheValid = $false
    if (Test-Path -LiteralPath $cacheFile -PathType Leaf) {
        try { Assert-Hash $cacheFile $sha256 $name; $cacheValid = $true }
        catch { Remove-Item -LiteralPath $cacheFile -Force -ErrorAction SilentlyContinue }
    }
    if (-not $cacheValid) {
        Write-Host "[download] $name $version"
        $partial = "$cacheFile.partial"
        Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue
        Invoke-WebRequest -Uri $url -OutFile $partial -UseBasicParsing
        Assert-Hash $partial $sha256 $name
        Move-Item -LiteralPath $partial -Destination $cacheFile -Force
    }

    if ($packageType -eq 'file') {
        Copy-Item -LiteralPath $cacheFile -Destination $destination -Force
    } else {
        $archivePath = [string](Get-OptionalProperty -Object $tool -Name 'archive_path' -DefaultValue '')
        if (-not (Test-SafeRelativePath $archivePath)) { throw "Invalid archive_path for $name" }
        $extractRoot = Join-Path $env:TEMP ("WindeepToolExtract-" + [guid]::NewGuid().ToString('N'))
        try {
            New-Item -ItemType Directory -Path $extractRoot -Force | Out-Null
            Expand-Archive -LiteralPath $cacheFile -DestinationPath $extractRoot -Force
            $source = [IO.Path]::GetFullPath((Join-Path $extractRoot $archivePath))
            $extractRootFull = [IO.Path]::GetFullPath($extractRoot)
            if (-not $source.StartsWith($extractRootFull, [StringComparison]::OrdinalIgnoreCase)) {
                throw "archive_path escapes extraction root for $name"
            }
            if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
                throw "Archive member missing for $name`: $archivePath"
            }
            Copy-Item -LiteralPath $source -Destination $destination -Force
        } finally {
            Remove-Item -LiteralPath $extractRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    if (-not (Test-Path -LiteralPath $destination -PathType Leaf)) {
        throw "Installed tool missing after staging: $destination"
    }
    Write-Host "[installed] $name $version -> $destination"
    Invoke-SafeProbe -Executable $destination -Arguments $probe -ExpectedExitCodes $expectedExitCodes -Name $name
    Write-Host "[probe PASS] $name"
}

Write-Host "Staged and verified $($tools.Count) portable tool package(s)."
