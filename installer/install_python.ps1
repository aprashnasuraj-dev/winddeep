<#
.SYNOPSIS
Bundles the pinned Python 3.11 embeddable runtime used by packaged helper tools.
.DESCRIPTION
Downloads the official CPython 3.11.9 x64 embeddable ZIP, verifies the SHA-256
from Python's Windows release manifest, extracts it into runtime/python, and
configures site-package discovery without installing anything system-wide.
#>
[CmdletBinding()]
param(
    [string]$Version = '3.11.9',
    [string]$RuntimeRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'runtime\python'),
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Version -ne '3.11.9') {
    throw "Unsupported embedded runtime version '$Version'. Update URL and SHA256 together before changing the pin."
}

$Url = 'https://www.python.org/ftp/python/3.11.9/python-3.11.9-embeddable-amd64.zip'
$ExpectedSha256 = '33b448f95fecb7c6f802157dbd5e6b40a2ad9bfc8b95ca634a06ba4073ad1ac0'
$RepoRoot = Split-Path $PSScriptRoot -Parent
$CacheDir = Join-Path $RepoRoot '.cache\python'
$Archive = Join-Path $CacheDir 'python-3.11.9-embeddable-amd64.zip'

New-Item -ItemType Directory -Path $CacheDir -Force | Out-Null
if ($Force -and (Test-Path -LiteralPath $RuntimeRoot)) {
    Remove-Item -LiteralPath $RuntimeRoot -Recurse -Force
}

$download = $true
if (Test-Path -LiteralPath $Archive -PathType Leaf) {
    $cachedHash = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($cachedHash -eq $ExpectedSha256) {
        Write-Host '[cached] CPython embeddable runtime archive'
        $download = $false
    } else {
        Remove-Item -LiteralPath $Archive -Force
    }
}

if ($download) {
    Write-Host "Downloading pinned CPython $Version embeddable runtime..."
    Invoke-WebRequest -Uri $Url -OutFile $Archive -UseBasicParsing
    $actual = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $ExpectedSha256) {
        Remove-Item -LiteralPath $Archive -Force -ErrorAction SilentlyContinue
        throw "CPython runtime SHA256 mismatch. Expected $ExpectedSha256, got $actual"
    }
}

if (Test-Path -LiteralPath $RuntimeRoot) {
    Remove-Item -LiteralPath $RuntimeRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $RuntimeRoot -Force | Out-Null
Expand-Archive -LiteralPath $Archive -DestinationPath $RuntimeRoot -Force

$pth = Join-Path $RuntimeRoot 'python311._pth'
if (-not (Test-Path -LiteralPath $pth)) {
    throw "Embedded runtime path file not found: $pth"
}
$lines = @(Get-Content -LiteralPath $pth)
$updated = [System.Collections.Generic.List[string]]::new()
$hasSitePackages = $false
$hasImportSite = $false
foreach ($line in $lines) {
    if ($line.Trim() -eq 'Lib\site-packages') { $hasSitePackages = $true }
    if ($line.Trim() -eq 'import site') { $hasImportSite = $true }
    if ($line.Trim() -eq '#import site') {
        $updated.Add('import site')
        $hasImportSite = $true
    } else {
        $updated.Add($line)
    }
}
if (-not $hasSitePackages) { $updated.Add('Lib\site-packages') }
if (-not $hasImportSite) { $updated.Add('import site') }
$updated | Set-Content -LiteralPath $pth -Encoding ascii
New-Item -ItemType Directory -Path (Join-Path $RuntimeRoot 'Lib\site-packages') -Force | Out-Null

$python = Join-Path $RuntimeRoot 'python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Embedded python.exe missing after extraction: $python"
}
$versionText = & $python -c 'import sys; print(sys.version)'
if ($LASTEXITCODE -ne 0 -or -not ($versionText -match '^3\.11\.9')) {
    throw "Embedded Python verification failed: $versionText"
}

$metadata = [ordered]@{
    version = $Version
    url = $Url
    sha256 = $ExpectedSha256
    architecture = 'amd64'
}
$metadata | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $RuntimeRoot 'RUNTIME-METADATA.json') -Encoding utf8
Write-Host "[installed] CPython $Version embedded runtime -> $RuntimeRoot"
