<#
.SYNOPSIS
Downloads, verifies, extracts and probes pinned Windows tool assets.
.DESCRIPTION
Only entries in installer/tools-manifest.json are installable. Every network
artifact is SHA-256 verified before extraction. Archive members and destination
paths are constrained beneath temporary/tools roots, and each installed tool is
validated with a non-invasive liveness probe.
#>
[CmdletBinding()]
param(
    [string]$ManifestPath = (Join-Path $PSScriptRoot 'tools-manifest.json'),
    [string]$ToolsRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'tools')
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest

function Resolve-SafeChildPath([string]$Root, [string]$Relative) {
    if ([IO.Path]::IsPathRooted($Relative)) { throw "Absolute destination/member is forbidden: $Relative" }
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    $candidate = [IO.Path]::GetFullPath((Join-Path $Root $Relative))
    if (-not $candidate.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path escapes installation root: $Relative"
    }
    return $candidate
}

function Invoke-SafeProbe($Tool, [string]$Binary) {
    $probe = @($Tool.probe)
    if ($probe.Count -eq 0) { throw "Missing safe probe for $($Tool.name)" }
    $expected = @($Tool.expected_exit_codes)
    if ($expected.Count -eq 0) { $expected = @(0) }
    $stdout = [IO.Path]::GetTempFileName()
    $stderr = [IO.Path]::GetTempFileName()
    try {
        $process = Start-Process -FilePath $Binary -ArgumentList $probe -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        if ($expected -notcontains $process.ExitCode) {
            $out = ((Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue) + (Get-Content -LiteralPath $stderr -Raw -ErrorAction SilentlyContinue)).Trim()
            throw "Liveness probe failed for $($Tool.name): exit $($process.ExitCode) $out"
        }
    } finally {
        Remove-Item -LiteralPath $stdout,$stderr -Force -ErrorAction SilentlyContinue
    }
}

if (-not (Test-Path -LiteralPath $ManifestPath)) { throw "Tool manifest not found: $ManifestPath" }
$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
if ($manifest.platform -and $manifest.platform -ne 'windows-amd64') { throw "Unsupported tool manifest platform: $($manifest.platform)" }
New-Item -ItemType Directory -Path $ToolsRoot -Force | Out-Null
$ToolsRoot = (Resolve-Path -LiteralPath $ToolsRoot).Path
$cacheRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'runtime\cache\tools'
New-Item -ItemType Directory -Path $cacheRoot -Force | Out-Null

foreach ($tool in @($manifest.tools)) {
    foreach ($field in @('name','version','url','sha256','destination','license','redistribution_review')) {
        if ([string]::IsNullOrWhiteSpace([string]$tool.$field)) { throw "$($tool.name): required manifest field '$field' is missing" }
    }
    if (-not ([string]$tool.url).StartsWith('https://')) { throw "$($tool.name): source URL must use HTTPS" }
    if ([string]$tool.sha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw "$($tool.name): invalid SHA-256" }
    $destination = Resolve-SafeChildPath $ToolsRoot ([string]$tool.destination)
    New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
    $sidecar = "$destination.source.sha256"
    $expectedHash = ([string]$tool.sha256).ToLowerInvariant()

    $cached = $false
    if (Test-Path -LiteralPath $destination) {
        if ($tool.archive -eq 'zip') {
            if (Test-Path -LiteralPath $sidecar) {
                $cached = ((Get-Content -LiteralPath $sidecar -Raw).Trim().ToLowerInvariant() -eq $expectedHash)
            }
        } else {
            $cached = ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() -eq $expectedHash)
        }
        if ($cached) {
            try { Invoke-SafeProbe $tool $destination; Write-Host "[cached] $($tool.name) $($tool.version)"; continue }
            catch { Write-Warning $_; $cached = $false }
        }
        Remove-Item -LiteralPath $destination,$sidecar -Force -ErrorAction SilentlyContinue
    }

    $extension = if ($tool.archive -eq 'zip') { '.zip' } else { '.bin' }
    $download = Join-Path $cacheRoot ("{0}-{1}{2}" -f $tool.name,$tool.version,$extension)
    $needsDownload = $true
    if (Test-Path -LiteralPath $download) {
        $needsDownload = ((Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash)
    }
    if ($needsDownload) {
        Remove-Item -LiteralPath $download -Force -ErrorAction SilentlyContinue
        Invoke-WebRequest -Uri ([string]$tool.url) -OutFile $download -UseBasicParsing
    }
    $actual = (Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expectedHash) {
        Remove-Item -LiteralPath $download -Force -ErrorAction SilentlyContinue
        throw "SHA256 mismatch for $($tool.name): expected $expectedHash, got $actual"
    }

    if ($tool.archive -eq 'zip') {
        if ([string]::IsNullOrWhiteSpace([string]$tool.archive_member)) { throw "$($tool.name): zip entry requires archive_member" }
        $extractRoot = Join-Path ([IO.Path]::GetTempPath()) ("windeep-tool-{0}" -f [Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $extractRoot -Force | Out-Null
        try {
            Expand-Archive -LiteralPath $download -DestinationPath $extractRoot -Force
            $member = Resolve-SafeChildPath $extractRoot ([string]$tool.archive_member)
            if (-not (Test-Path -LiteralPath $member -PathType Leaf)) { throw "$($tool.name): archive member not found: $($tool.archive_member)" }
            Copy-Item -LiteralPath $member -Destination $destination -Force
            Set-Content -LiteralPath $sidecar -Value $expectedHash -NoNewline -Encoding ascii
        } finally {
            Remove-Item -LiteralPath $extractRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    } else {
        Copy-Item -LiteralPath $download -Destination $destination -Force
    }

    Invoke-SafeProbe $tool $destination
    Write-Host "[installed] $($tool.name) $($tool.version) -> $destination"
}

Write-Host "Verified $(@($manifest.tools).Count) bundled Windows tools."
