<#
.SYNOPSIS
Validates the Windeep installer and portable build on Windows 10/11.
.DESCRIPTION
Installs Windeep silently into an isolated directory, verifies the complete
runtime/tool/capture payload, launches the installed and portable applications
on loopback, checks health/auth/dashboard contracts, uninstalls, and writes
reports/windows_install_audit.md. No external target is contacted and no scan
is started.
#>
[CmdletBinding()]
param(
    [string]$InstallerPath = "dist\Windeep-Setup.exe",
    [string]$PortablePath = "dist\Windeep",
    [string]$ReportPath = "reports\windows_install_audit.md",
    [int]$StartupTimeoutSeconds = 45
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$manifestPath = Join-Path $repoRoot 'installer\tools-manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

function Resolve-RepoPath([string]$Path) {
    if ([IO.Path]::IsPathRooted($Path)) { return $Path }
    return Join-Path $repoRoot $Path
}
$installer = Resolve-RepoPath $InstallerPath
$portable = Resolve-RepoPath $PortablePath
$report = Resolve-RepoPath $ReportPath
$workRoot = Join-Path $env:TEMP ("WindeepReleaseAudit-" + [guid]::NewGuid().ToString('N'))
$installDir = Join-Path $workRoot 'installed'
$stateDir = Join-Path $workRoot 'state'
$checks = [System.Collections.Generic.List[object]]::new()
$processes = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()

function Add-Check([string]$Name, [bool]$Passed, [string]$Detail) {
    $checks.Add([pscustomobject]@{ Name = $Name; Passed = $Passed; Detail = $Detail }) | Out-Null
}
function Get-FreePort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start(); try { return ([Net.IPEndPoint]$listener.LocalEndpoint).Port } finally { $listener.Stop() }
}
function Test-Payload([string]$Root, [string]$Label) {
    Add-Check "$Label executable" (Test-Path -LiteralPath (Join-Path $Root 'Windeep.exe')) (Join-Path $Root 'Windeep.exe')
    Add-Check "$Label VERSION" (Test-Path -LiteralPath (Join-Path $Root 'VERSION')) 'VERSION must ship'
    Add-Check "$Label app source" (Test-Path -LiteralPath (Join-Path $Root 'app\capture\standalone.py')) 'capture runtime must import the exact packaged app source'
    Add-Check "$Label release policy" (Test-Path -LiteralPath (Join-Path $Root 'app\tools\release-policy.json')) '137-tool release policy must ship'
    Add-Check "$Label embedded Python 3.11" (Test-Path -LiteralPath (Join-Path $Root 'runtime\python\python.exe')) 'main embedded runtime required'
    $capturePython = Join-Path $Root 'runtime\capture-python\python.exe'
    $mitmdump = Join-Path $Root 'runtime\capture-python\Scripts\mitmdump.exe'
    Add-Check "$Label capture Python 3.12" (Test-Path -LiteralPath $capturePython) $capturePython
    Add-Check "$Label mitmdump 12.2.3" (Test-Path -LiteralPath $mitmdump) $mitmdump
    if (Test-Path -LiteralPath $capturePython) {
        $version = (& $capturePython -c "import sys; print('.'.join(map(str,sys.version_info[:3])))" 2>&1 | Out-String).Trim()
        Add-Check "$Label capture Python version" ($LASTEXITCODE -eq 0 -and $version -match '^3\.12\.') $version
    }
    if (Test-Path -LiteralPath $mitmdump) {
        $version = (& $mitmdump --version 2>&1 | Out-String).Trim()
        Add-Check "$Label mitmproxy version" ($LASTEXITCODE -eq 0 -and $version -match '12\.2\.3') $version
    }
    foreach ($tool in @($manifest.tools)) {
        $binary = Join-Path $Root (Join-Path 'tools' ([string]$tool.destination))
        Add-Check "$Label tool $($tool.name)" (Test-Path -LiteralPath $binary) $binary
        if (Test-Path -LiteralPath $binary) {
            $proc = Start-Process -FilePath $binary -ArgumentList @($tool.probe) -NoNewWindow -Wait -PassThru
            Add-Check "$Label probe $($tool.name)" (@($tool.expected_exit_codes) -contains $proc.ExitCode) "exit=$($proc.ExitCode)"
        }
    }
}
function Test-WindeepHealth([string]$ExePath, [string]$StatePath, [string]$Label) {
    if (-not (Test-Path -LiteralPath $ExePath)) { Add-Check "$Label executable launch" $false "missing: $ExePath"; return }
    $port = Get-FreePort
    $oldPort = $env:WINDEEP_PORT; $oldState = $env:WINDEEP_STATE_DIR
    $env:WINDEEP_PORT = [string]$port; $env:WINDEEP_STATE_DIR = $StatePath
    try {
        New-Item -ItemType Directory -Path $StatePath -Force | Out-Null
        $proc = Start-Process -FilePath $ExePath -PassThru -WindowStyle Hidden
        $processes.Add($proc) | Out-Null
        $deadline = (Get-Date).AddSeconds($StartupTimeoutSeconds); $healthy = $false; $lastError = ''
        while ((Get-Date) -lt $deadline -and -not $proc.HasExited) {
            try {
                $health = Invoke-RestMethod -Uri "http://127.0.0.1:$port/api/health" -TimeoutSec 2
                if ($health.status -eq 'ok' -and $health.localhost_only -eq $true -and [int]$health.tool_count -eq 137) { $healthy = $true; break }
                $lastError = "unexpected payload: $($health | ConvertTo-Json -Compress -Depth 6)"
            } catch { $lastError = $_.Exception.Message }
            Start-Sleep -Milliseconds 500
        }
        Add-Check "$Label health" $healthy $(if ($healthy) { "loopback health PASS; 137 integrations" } elseif ($proc.HasExited) { "process exited $($proc.ExitCode)" } else { $lastError })
        if ($healthy) {
            $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
            $handshake = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$port/api/handshake" -WebSession $session -TimeoutSec 5
            Add-Check "$Label auth handshake" (-not [string]::IsNullOrWhiteSpace([string]$handshake.csrf_token)) 'session cookie + CSRF issued'
            $page = Invoke-WebRequest -Uri "http://127.0.0.1:$port/" -WebSession $session -TimeoutSec 5 -UseBasicParsing
            $fullUi = $page.StatusCode -eq 200 -and $page.Content -match 'brain-console' -and $page.Content -match 'live-traffic' -and $page.Content -match 'testpack-form'
            Add-Check "$Label production UI" $fullUi "HTTP $($page.StatusCode); dashboard integration markers checked"
            $settings = Invoke-RestMethod -Uri "http://127.0.0.1:$port/api/settings" -WebSession $session -TimeoutSec 5
            Add-Check "$Label guardrail contract" ($settings.encryption_at_rest -eq $true -and $settings.signed_consent_required -eq $true -and $settings.localhost_only -eq $true) ($settings | ConvertTo-Json -Compress -Depth 5)
        }
        if (-not $proc.HasExited) { $proc.Kill(); $proc.WaitForExit(5000) | Out-Null }
    } finally {
        if ($null -eq $oldPort) { Remove-Item Env:WINDEEP_PORT -ErrorAction SilentlyContinue } else { $env:WINDEEP_PORT = $oldPort }
        if ($null -eq $oldState) { Remove-Item Env:WINDEEP_STATE_DIR -ErrorAction SilentlyContinue } else { $env:WINDEEP_STATE_DIR = $oldState }
    }
}

New-Item -ItemType Directory -Path $workRoot -Force | Out-Null
try {
    Add-Check 'Windows version' ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT -and [Environment]::OSVersion.Version.Major -ge 10) ([Environment]::OSVersion.VersionString)
    Add-Check 'Installer exists' (Test-Path -LiteralPath $installer) $installer
    Add-Check 'Portable directory exists' (Test-Path -LiteralPath $portable) $portable
    if (Test-Path -LiteralPath $installer) {
        $args = @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-',"/DIR=$installDir")
        $install = Start-Process -FilePath $installer -ArgumentList $args -Wait -PassThru
        Add-Check 'Silent installer exit code' ($install.ExitCode -eq 0) "exit=$($install.ExitCode)"
        if ($install.ExitCode -eq 0) {
            Test-Payload $installDir 'Installed'
            Test-WindeepHealth (Join-Path $installDir 'Windeep.exe') (Join-Path $stateDir 'installed') 'Installed build'
        }
        $uninstaller = Join-Path $installDir 'unins000.exe'
        if (Test-Path -LiteralPath $uninstaller) {
            $uninstall = Start-Process -FilePath $uninstaller -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART') -Wait -PassThru
            Add-Check 'Silent uninstall' ($uninstall.ExitCode -eq 0) "exit=$($uninstall.ExitCode)"
        } else { Add-Check 'Silent uninstall' $false "missing: $uninstaller" }
    }
    if (Test-Path -LiteralPath $portable) {
        Test-Payload $portable 'Portable'
        Test-WindeepHealth (Join-Path $portable 'Windeep.exe') (Join-Path $stateDir 'portable') 'Portable build'
    }
} catch { Add-Check 'Audit execution' $false $_.Exception.ToString() }
finally {
    foreach ($proc in $processes) { try { if (-not $proc.HasExited) { $proc.Kill(); $proc.WaitForExit(3000) | Out-Null } } catch { } }
    New-Item -ItemType Directory -Path (Split-Path $report -Parent) -Force | Out-Null
    $failed = @($checks | Where-Object { -not $_.Passed })
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('# Windows Install Audit') | Out-Null; $lines.Add('') | Out-Null
    $lines.Add("Overall: **$(if ($failed.Count -eq 0) { 'PASS' } else { 'FAIL' })**") | Out-Null; $lines.Add('') | Out-Null
    $lines.Add('| Check | Result | Detail |') | Out-Null; $lines.Add('|---|---|---|') | Out-Null
    foreach ($check in $checks) {
        $detail = ([string]$check.Detail).Replace('|','\|').Replace("`r",'').Replace("`n",'<br>')
        $lines.Add("| $($check.Name) | **$(if ($check.Passed) { 'PASS' } else { 'FAIL' })** | $detail |") | Out-Null
    }
    $lines.Add('') | Out-Null; $lines.Add("Failures: **$($failed.Count)**") | Out-Null
    $lines | Set-Content -LiteralPath $report -Encoding utf8
    Remove-Item -LiteralPath $workRoot -Recurse -Force -ErrorAction SilentlyContinue
}
if (@($checks | Where-Object { -not $_.Passed }).Count -gt 0) { exit 1 }
exit 0
