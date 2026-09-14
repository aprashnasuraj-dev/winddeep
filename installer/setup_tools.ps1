<#
.SYNOPSIS
Downloads pinned portable tool assets declared in tools-manifest.json.
.DESCRIPTION
The downloader is deterministic: each entry supplies a URL, destination path,
and SHA-256 digest. Files are accepted only when the digest matches. An empty
manifest is valid during bootstrap and performs no network downloads.
#>
[CmdletBinding()]
param(
    [string]$ManifestPath = (Join-Path $PSScriptRoot 'tools-manifest.json'),
    [string]$ToolsRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'tools')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not (Test-Path -LiteralPath $ManifestPath)) {
    throw "Tool manifest not found: $ManifestPath"
}

$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
New-Item -ItemType Directory -Path $ToolsRoot -Force | Out-Null

foreach ($tool in @($manifest.tools)) {
    if ([string]::IsNullOrWhiteSpace($tool.name) -or
        [string]::IsNullOrWhiteSpace($tool.url) -or
        [string]::IsNullOrWhiteSpace($tool.sha256) -or
        [string]::IsNullOrWhiteSpace($tool.destination)) {
        throw 'Each tool manifest entry requires name, url, sha256, and destination.'
    }

    $destination = Join-Path $ToolsRoot $tool.destination
    $destinationDir = Split-Path $destination -Parent
    New-Item -ItemType Directory -Path $destinationDir -Force | Out-Null

    if (Test-Path -LiteralPath $destination) {
        $existing = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($existing -eq $tool.sha256.ToLowerInvariant()) {
            Write-Host "[cached] $($tool.name)"
            continue
        }
        Remove-Item -LiteralPath $destination -Force
    }

    $temporary = "$destination.download"
    Invoke-WebRequest -Uri $tool.url -OutFile $temporary -UseBasicParsing
    $actual = (Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash.ToLowerInvariant()
    $expected = $tool.sha256.ToLowerInvariant()
    if ($actual -ne $expected) {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        throw "SHA256 mismatch for $($tool.name): expected $expected, got $actual"
    }
    Move-Item -LiteralPath $temporary -Destination $destination -Force
    Write-Host "[installed] $($tool.name) -> $destination"
}
