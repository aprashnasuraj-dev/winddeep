<#
.SYNOPSIS
Stages the pinned CPython 3.11 runtime and Playwright Chromium for Windeep.
.DESCRIPTION
Downloads the official python.org x64 embeddable archive, verifies its SHA-256,
expands it under runtime/python, and stages the Playwright-managed Chromium
revision under runtime/playwright-browsers. The application itself is packaged
by PyInstaller; the embedded Python runtime is for bundled Python-based tools.
#>
[CmdletBinding()]
param(
    [string]$Version = '3.11.9',
    [string]$Destination = (Join-Path (Split-Path $PSScriptRoot -Parent) 'runtime\python')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path $PSScriptRoot -Parent
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

# Playwright browser binaries are a separate runtime dependency. G3 installs
# the Python Playwright package; stage the exact Chromium revision it expects so
# the installed and portable applications never require a post-install download.
$browsers = Join-Path $repoRoot 'runtime\playwright-browsers'
if (Test-Path -LiteralPath $browsers) { Remove-Item -LiteralPath $browsers -Recurse -Force }
New-Item -ItemType Directory -Path $browsers -Force | Out-Null
$oldBrowsers = $env:PLAYWRIGHT_BROWSERS_PATH
$oldGc = $env:PLAYWRIGHT_SKIP_BROWSER_GC
try {
    $env:PLAYWRIGHT_BROWSERS_PATH = $browsers
    $env:PLAYWRIGHT_SKIP_BROWSER_GC = '1'
    & python -m playwright install chromium
    if ($LASTEXITCODE -ne 0) { throw "Playwright Chromium install failed with exit code $LASTEXITCODE" }
    $browserFiles = @(Get-ChildItem -LiteralPath $browsers -Recurse -File -ErrorAction Stop)
    if ($browserFiles.Count -eq 0) { throw "Playwright Chromium staging produced no files in $browsers" }
    Write-Host "Playwright Chromium staged -> $browsers"
} finally {
    if ($null -eq $oldBrowsers) { Remove-Item Env:PLAYWRIGHT_BROWSERS_PATH -ErrorAction SilentlyContinue } else { $env:PLAYWRIGHT_BROWSERS_PATH = $oldBrowsers }
    if ($null -eq $oldGc) { Remove-Item Env:PLAYWRIGHT_SKIP_BROWSER_GC -ErrorAction SilentlyContinue } else { $env:PLAYWRIGHT_SKIP_BROWSER_GC = $oldGc }
}
