<#
.SYNOPSIS
Validates the Windeep installer and portable build on Windows 10/11.
.DESCRIPTION
Installs Windeep silently into a temporary directory, launches the installed
application on loopback, checks /api/health, verifies the portable tree, then
uninstalls and writes reports/windows_install_audit.md. No external target is
contacted and no security scan is started.
#>
[CmdletBinding()]
param(
    [string]$InstallerPath = "dist\Windeep-Setup.exe",
    [string]$PortablePath = "dist\Windeep",
    [string]$ReportPath = "reports\windows_install_audit.md",
    [int]$StartupTimeoutSeconds = 35
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
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
    $listener.Start()
    try { return ([Net.IPEndPoint]$listener.LocalEndpoint).Port }
    finally { $listener.Stop() }
}

function Test-WindeepHealth([string]$ExePath, [string]$StatePath, [string]$Label) {
    if (-not (Test-Path -LiteralPath $ExePath)) {
        Add-Check "$Label executable" $false "missing: $ExePath"
        return
    }
    $port = Get-FreePort
    $oldPort = $env:WINDEEP_PORT
    $oldState = $env:WINDEEP_STATE_DIR
    $env:WINDEEP_PORT = [string]$port
    $env:WINDEEP_STATE_DIR = $StatePath
    try {
        New-Item -ItemType Directory -Path $StatePath -Force | Out-Null
        $proc = Start-Process -FilePath $ExePath -PassThru -WindowStyle Hidden
        $processes.Add($proc) | Out-Null
        $deadline = (Get-Date).AddSeconds($StartupTimeoutSeconds)
        $healthy = $false
        $lastError = ''
        while ((Get-Date) -lt $deadline -and -not $proc.HasExited) {
            try {
                $response = Invoke-RestMethod -Uri "http://127.0.0.1:$port/api/health" -TimeoutSec 2
                if ($response.status -eq 'ok' -and $response.localhost_only -eq $true) {
                    $healthy = $true
                    break
                }
                $lastError = "unexpected health payload: $($response | ConvertTo-Json -Compress -Depth 6)"
            } catch {
                $lastError = $_.Exception.Message
            }
            Start-Sleep -Milliseconds 500
        }
        Add-Check "$Label health" $healthy $(if ($healthy) { "loopback /api/health PASS on port $port" } elseif ($proc.HasExited) { "process exited with code $($proc.ExitCode)" } else { $lastError })
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
        $args = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-', "/DIR=$installDir")
        $install = Start-Process -FilePath $installer -ArgumentList $args -Wait -PassThru
        Add-Check 'Silent installer exit code' ($install.ExitCode -eq 0) "exit=$($install.ExitCode)"
        $installedExe = Join-Path $installDir 'Windeep.exe'
        Add-Check 'Installed executable' (Test-Path -LiteralPath $installedExe) $installedExe
        Add-Check 'Installed VERSION' (Test-Path -LiteralPath (Join-Path $installDir 'VERSION')) 'VERSION must ship with installer'
        Add-Check 'Installed tool directory' (Test-Path -LiteralPath (Join-Path $installDir 'tools')) 'portable external tools must ship in the single installer'
        Add-Check 'Installed embedded Python' (Test-Path -LiteralPath (Join-Path $installDir 'runtime\python\python.exe')) 'embedded runtime required for Python-based bundled tools'
        Test-WindeepHealth $installedExe (Join-Path $stateDir 'installed') 'Installed build'

        $uninstaller = Join-Path $installDir 'unins000.exe'
        if (Test-Path -LiteralPath $uninstaller) {
            $uninstall = Start-Process -FilePath $uninstaller -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART') -Wait -PassThru
            Add-Check 'Silent uninstall' ($uninstall.ExitCode -eq 0) "exit=$($uninstall.ExitCode)"
        } else {
            Add-Check 'Silent uninstall' $false "uninstaller missing: $uninstaller"
        }
    }

    if (Test-Path -LiteralPath $portable) {
        $portableExe = Join-Path $portable 'Windeep.exe'
        Add-Check 'Portable executable' (Test-Path -LiteralPath $portableExe) $portableExe
        Add-Check 'Portable tool directory' (Test-Path -LiteralPath (Join-Path $portable 'tools')) 'portable archive must contain external tools'
        Add-Check 'Portable embedded Python' (Test-Path -LiteralPath (Join-Path $portable 'runtime\python\python.exe')) 'portable archive must contain embedded Python runtime'
        Test-WindeepHealth $portableExe (Join-Path $stateDir 'portable') 'Portable build'
    }
} catch {
    Add-Check 'Audit execution' $false $_.Exception.ToString()
} finally {
    foreach ($proc in $processes) {
        try { if (-not $proc.HasExited) { $proc.Kill(); $proc.WaitForExit(3000) | Out-Null } } catch { }
    }
    New-Item -ItemType Directory -Path (Split-Path $report -Parent) -Force | Out-Null
    $failed = @($checks | Where-Object { -not $_.Passed })
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('# Windows Install Audit') | Out-Null
    $lines.Add('') | Out-Null
    $lines.Add("Overall: **$(if ($failed.Count -eq 0) { 'PASS' } else { 'FAIL' })**") | Out-Null
    $lines.Add('') | Out-Null
    $lines.Add('| Check | Result | Detail |') | Out-Null
    $lines.Add('|---|---|---|') | Out-Null
    foreach ($check in $checks) {
        $detail = ([string]$check.Detail).Replace('|', '\|').Replace("`r", '').Replace("`n", '<br>')
        $lines.Add("| $($check.Name) | **$(if ($check.Passed) { 'PASS' } else { 'FAIL' })** | $detail |") | Out-Null
    }
    $lines.Add('') | Out-Null
    $lines.Add("Failures: **$($failed.Count)**") | Out-Null
    $lines | Set-Content -LiteralPath $report -Encoding utf8
    Remove-Item -LiteralPath $workRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if (@($checks | Where-Object { -not $_.Passed }).Count -gt 0) { exit 1 }
exit 0
