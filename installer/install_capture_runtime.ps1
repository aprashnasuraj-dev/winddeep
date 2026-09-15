param(
    [string]$Destination = 'runtime\capture-python'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

# Accept either a repository-relative destination or an explicit absolute path.
# Do not Join-Path an already-rooted Windows path (for example D:\runtime)
# onto $PSScriptRoot; PowerShell would produce an invalid path such as
# <repo>\installer\D:\runtime.
if ([IO.Path]::IsPathRooted($Destination)) {
    $destinationPath = [IO.Path]::GetFullPath($Destination)
} else {
    $destinationPath = [IO.Path]::GetFullPath((Join-Path $root $Destination))
}
$cache = Join-Path $root 'runtime\cache'
New-Item -ItemType Directory -Path $cache -Force | Out-Null

# Python 3.12.10 is the final 3.12 bugfix release with the classic Windows
# installer. Its x64 installer is signed by the Python Software Foundation.
$pythonVersion = '3.12.10'
$pythonUrl = "https://www.python.org/ftp/python/$pythonVersion/python-$pythonVersion-amd64.exe"
$pythonSha256 = '67b5635e80ea51072b87941312d00ec8927c4db9ba18938f7ad2d27b328b95fb'
$installer = Join-Path $cache "python-$pythonVersion-amd64.exe"

if (-not (Test-Path -LiteralPath $installer) -or (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant() -ne $pythonSha256) {
    Invoke-WebRequest -UseBasicParsing -Uri $pythonUrl -OutFile $installer
}
$actual = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $pythonSha256) { throw "Python $pythonVersion installer hash mismatch: $actual" }
$signature = Get-AuthenticodeSignature -FilePath $installer
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Python Software Foundation') {
    throw "Python capture runtime signature validation failed: $($signature.Status) $($signature.SignerCertificate.Subject)"
}

if (Test-Path -LiteralPath $destinationPath) { Remove-Item -LiteralPath $destinationPath -Recurse -Force }
New-Item -ItemType Directory -Path $destinationPath -Force | Out-Null
$args = @(
    '/quiet',
    'InstallAllUsers=0',
    "TargetDir=$destinationPath",
    'Include_pip=1',
    'Include_launcher=0',
    'Include_test=0',
    'Include_doc=0',
    'Include_tcltk=0',
    'PrependPath=0',
    'Shortcuts=0',
    'AssociateFiles=0'
)
$process = Start-Process -FilePath $installer -ArgumentList $args -Wait -PassThru
if ($process.ExitCode -ne 0) { throw "Python $pythonVersion capture runtime install failed with exit code $($process.ExitCode)" }

$python = Join-Path $destinationPath 'python.exe'
if (-not (Test-Path -LiteralPath $python)) { throw "Capture python.exe not found at $python" }
& $python -c "import sys; assert sys.version_info[:2] == (3, 12), sys.version"
if ($LASTEXITCODE -ne 0) { throw 'Capture Python version validation failed' }

& $python -m pip install --disable-pip-version-check --no-input --no-warn-script-location -r (Join-Path $root 'requirements-capture.txt')
if ($LASTEXITCODE -ne 0) { throw 'mitmproxy capture runtime installation failed' }
& $python -m pip check
if ($LASTEXITCODE -ne 0) { throw 'mitmproxy capture runtime dependency check failed' }

$mitmdump = Join-Path $destinationPath 'Scripts\mitmdump.exe'
if (-not (Test-Path -LiteralPath $mitmdump)) { throw "mitmdump.exe not found at $mitmdump" }
$versionText = (& $mitmdump --version 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0 -or $versionText -notmatch '12\.2\.3') { throw "Unexpected mitmdump runtime: $versionText" }

# Freeze the exact transitive environment assembled in CI. This lock is shipped
# with the release and consumed by SBOM/installation audit evidence.
& $python -m pip freeze --all | Sort-Object | Set-Content -LiteralPath (Join-Path $root 'runtime\capture-requirements.lock') -Encoding ascii
Write-Host "Pinned capture runtime ready: Python $pythonVersion / mitmproxy 12.2.3"
