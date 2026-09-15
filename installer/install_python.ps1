<#
.SYNOPSIS
Stages the pinned CPython 3.11 Windows embeddable runtime for Windeep releases.
.DESCRIPTION
Downloads the official python.org x64 embeddable archive, verifies its SHA-256,
and expands it under runtime/python. This runtime is for bundled Python-based
external tools; the Windeep application itself is packaged by PyInstaller.
#>
[CmdletBinding()]
param(
    [string]$Version = '3.11.9',
    [string]$Destination = (Join-Path (Split-Path $PSScriptRoot -Parent) 'runtime\python')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$known = @{
    '3.11.9' = @{
        Url = 'https://www.python.org/ftp/python/3.11.9/python-3.11.9-embeddable-amd64.zip'
        Sha256 = '33b448f95fecb7c6f802157dbd5e6b40a2ad9bfc8b95ca634a06ba4073ad1ac0'
    }
}

if (-not $known.ContainsKey($Version)) {
    throw "Unsupported embedded Python version '$Version'. Add a reviewed python.org URL and SHA-256 before changing the release runtime."
}

$asset = $known[$Version]
$cacheRoot = Join-Path $env:TEMP 'WindeepRuntimeCache'
$archive = Join-Path $cacheRoot "python-$Version-embed-amd64.zip"
New-Item -ItemType Directory -Path $cacheRoot -Force | Out-Null

function Assert-Hash([string]$Path, [string]$Expected) {
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Expected.ToLowerInvariant()) {
        throw "SHA256 mismatch for $Path`: expected $Expected, got $actual"
    }
}

if (Test-Path -LiteralPath $archive) {
    try { Assert-Hash $archive $asset.Sha256 }
    catch { Remove-Item -LiteralPath $archive -Force }
}
if (-not (Test-Path -LiteralPath $archive)) {
    Write-Host "Downloading CPython $Version embeddable runtime..."
    Invoke-WebRequest -Uri $asset.Url -OutFile $archive -UseBasicParsing
    Assert-Hash $archive $asset.Sha256
}

if (Test-Path -LiteralPath $Destination) {
    Remove-Item -LiteralPath $Destination -Recurse -Force
}
New-Item -ItemType Directory -Path $Destination -Force | Out-Null
Expand-Archive -LiteralPath $archive -DestinationPath $Destination -Force

$pth = Get-ChildItem -LiteralPath $Destination -Filter 'python*._pth' | Select-Object -First 1
if ($null -ne $pth) {
    $content = Get-Content -LiteralPath $pth.FullName
    $content = $content | ForEach-Object { if ($_ -eq '#import site') { 'import site' } else { $_ } }
    $content | Set-Content -LiteralPath $pth.FullName -Encoding ascii
}

$python = Join-Path $Destination 'python.exe'
if (-not (Test-Path -LiteralPath $python)) { throw "Embedded python.exe missing after extraction: $python" }
$reported = (& $python --version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $reported -notmatch [regex]::Escape($Version)) {
    throw "Embedded runtime self-check failed: $reported"
}
Write-Host "Embedded runtime ready: $reported -> $Destination"
