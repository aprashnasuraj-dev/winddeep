<#
.SYNOPSIS
Downloads and stages every pinned portable tool declared in tools-manifest.json.
.DESCRIPTION
Release builds are deterministic: every active entry requires a version, URL,
destination and SHA-256. Direct files and ZIP release assets are supported.
The script never installs system-wide software and writes an installed manifest
with the verified hashes that were actually staged.
#>
[CmdletBinding()]
param(
    [string]$ManifestPath = (Join-Path $PSScriptRoot 'tools-manifest.json'),
    [string]$ToolsRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'tools'),
    [switch]$AllowEmpty
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    throw "Tool manifest not found: $ManifestPath"
}
$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
$entries = @($manifest.tools)
if ($entries.Count -eq 0 -and -not $AllowEmpty) {
    throw 'Tool manifest is empty. Release builds require every configured wrapper to have a pinned installer entry.'
}

New-Item -ItemType Directory -Path $ToolsRoot -Force | Out-Null
$cacheRoot = Join-Path (Split-Path $PSScriptRoot -Parent) '.cache\tools'
New-Item -ItemType Directory -Path $cacheRoot -Force | Out-Null
$staged = [System.Collections.Generic.List[object]]::new()
$seenNames = @{}
$seenDestinations = @{}

function Assert-Sha256 {
    param([string]$Path, [string]$Expected, [string]$Name)
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Expected.ToLowerInvariant()) {
        throw "SHA256 mismatch for $Name`: expected $Expected, got $actual"
    }
    return $actual
}

foreach ($tool in $entries) {
    $name = [string]$tool.name
    $version = [string]$tool.version
    $url = [string]$tool.url
    $sha256 = [string]$tool.sha256
    $destinationName = [string]$tool.destination
    if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($version) -or
        [string]::IsNullOrWhiteSpace($url) -or [string]::IsNullOrWhiteSpace($sha256) -or
        [string]::IsNullOrWhiteSpace($destinationName)) {
        throw 'Each tool manifest entry requires name, version, url, sha256, and destination.'
    }
    if ($sha256 -notmatch '^[0-9a-fA-F]{64}$') {
        throw "Invalid SHA256 for $name"
    }
    if ($seenNames.ContainsKey($name)) { throw "Duplicate tool manifest name: $name" }
    if ($seenDestinations.ContainsKey($destinationName.ToLowerInvariant())) { throw "Duplicate tool destination: $destinationName" }
    $seenNames[$name] = $true
    $seenDestinations[$destinationName.ToLowerInvariant()] = $true

    $lifecycle = if ($null -ne $tool.PSObject.Properties['lifecycle']) { [string]$tool.lifecycle } else { 'active' }
    if ($lifecycle -in @('archived', 'deprecated', 'dead', 'unmaintained')) {
        throw "Refusing to package $name because lifecycle=$lifecycle"
    }

    $destination = Join-Path $ToolsRoot $destinationName
    $destinationDir = Split-Path $destination -Parent
    New-Item -ItemType Directory -Path $destinationDir -Force | Out-Null

    if (Test-Path -LiteralPath $destination -PathType Leaf) {
        $existing = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
        $installedSha = if ($null -ne $tool.PSObject.Properties['installed_sha256']) { [string]$tool.installed_sha256 } else { $sha256 }
        if ($existing -eq $installedSha.ToLowerInvariant()) {
            Write-Host "[cached] $name $version"
            $staged.Add([ordered]@{ name=$name; version=$version; destination=$destinationName; sha256=$existing; source=$url })
            continue
        }
        Remove-Item -LiteralPath $destination -Force
    }

    $archiveType = if ($null -ne $tool.PSObject.Properties['archive']) { ([string]$tool.archive).ToLowerInvariant() } else { 'none' }
    $cacheName = ($name -replace '[^A-Za-z0-9._-]', '_') + '-' + ($version -replace '[^A-Za-z0-9._-]', '_') + $(if ($archiveType -eq 'zip') { '.zip' } else { '.download' })
    $download = Join-Path $cacheRoot $cacheName
    $needsDownload = $true
    if (Test-Path -LiteralPath $download -PathType Leaf) {
        try {
            [void](Assert-Sha256 -Path $download -Expected $sha256 -Name $name)
            $needsDownload = $false
        } catch {
            Remove-Item -LiteralPath $download -Force
        }
    }
    if ($needsDownload) {
        Write-Host "[download] $name $version"
        Invoke-WebRequest -Uri $url -OutFile $download -UseBasicParsing
        [void](Assert-Sha256 -Path $download -Expected $sha256 -Name $name)
    }

    if ($archiveType -eq 'none') {
        Copy-Item -LiteralPath $download -Destination $destination -Force
    } elseif ($archiveType -eq 'zip') {
        $extract = Join-Path $env:TEMP ('windeep-tool-' + [guid]::NewGuid().ToString('N'))
        try {
            Expand-Archive -LiteralPath $download -DestinationPath $extract -Force
            $member = if ($null -ne $tool.PSObject.Properties['archive_member']) { [string]$tool.archive_member } else { '' }
            if (-not [string]::IsNullOrWhiteSpace($member)) {
                $source = Join-Path $extract $member
                if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
                    throw "Archive member '$member' not found for $name"
                }
            } else {
                $binaryName = if ($null -ne $tool.PSObject.Properties['binary']) { [IO.Path]::GetFileName([string]$tool.binary) } else { [IO.Path]::GetFileName($destinationName) }
                $matches = @(Get-ChildItem -LiteralPath $extract -Recurse -File | Where-Object Name -ieq $binaryName)
                if ($matches.Count -ne 1) {
                    throw "Expected exactly one '$binaryName' in archive for $name; found $($matches.Count)"
                }
                $source = $matches[0].FullName
            }
            Copy-Item -LiteralPath $source -Destination $destination -Force
        } finally {
            Remove-Item -LiteralPath $extract -Recurse -Force -ErrorAction SilentlyContinue
        }
    } else {
        throw "Unsupported archive type '$archiveType' for $name"
    }

    $installedHash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($null -ne $tool.PSObject.Properties['installed_sha256']) {
        $expectedInstalled = ([string]$tool.installed_sha256).ToLowerInvariant()
        if ($installedHash -ne $expectedInstalled) {
            throw "Installed-file SHA256 mismatch for $name`: expected $expectedInstalled, got $installedHash"
        }
    } elseif ($archiveType -eq 'none' -and $installedHash -ne $sha256.ToLowerInvariant()) {
        throw "Staged SHA256 mismatch for $name"
    }

    $staged.Add([ordered]@{ name=$name; version=$version; destination=$destinationName; sha256=$installedHash; source=$url })
    Write-Host "[installed] $name $version -> $destination"
}

$installedManifest = [ordered]@{
    schema_version = 1
    generated_utc = [DateTime]::UtcNow.ToString('o')
    tool_count = $staged.Count
    tools = $staged
}
$installedManifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $ToolsRoot 'INSTALLED-MANIFEST.json') -Encoding utf8
Write-Host "Staged $($staged.Count) verified tool(s)."
