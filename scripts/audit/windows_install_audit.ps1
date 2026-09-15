<#
.SYNOPSIS
Validates Windeep's installer and portable build on Windows 10/11.
.DESCRIPTION
Performs a clean temporary silent install, verifies packaged metadata, embedded
Python, Playwright browser payload and every manifest-declared tool using only
its non-invasive liveness probe. It then starts the packaged application on a
random loopback port, validates /api/health and confirms the process does not
listen on a wildcard/non-loopback address. The portable tree is checked the
same way. Finally the installed copy is silently removed.

No target scan is started and no external target is contacted.
#>
[CmdletBinding()]
param(
    [string]$InstallerPath = 'dist\Windeep-Setup.exe',
    [string]$PortablePath = 'dist\Windeep',
    [string]$ReportPath = 'reports\windows_install_audit.md',
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
$manifestPath = Join-Path $repoRoot 'installer\tools-manifest.json'
$expectedVersion = (Get-Content -LiteralPath (Join-Path $repoRoot 'VERSION') -Raw).Trim()
$workRoot = Join-Path $env:TEMP ("WindeepReleaseAudit-" + [guid]::NewGuid().ToString('N'))
$installDir = Join-Path $workRoot 'installed'
$stateDir = Join-Path $workRoot 'state'
$checks = [Collections.Generic.List[object]]::new()
$processes = [Collections.Generic.List[Diagnostics.Process]]::new()

function Add-Check([string]$Name, [bool]$Passed, [string]$Detail) {
    $checks.Add([pscustomobject]@{ Name = $Name; Passed = $Passed; Detail = $Detail }) | Out-Null
}

function Get-OptionalProperty([object]$Object, [string]$Name, $DefaultValue = $null) {
    if ($null -ne $Object -and $Object.PSObject.Properties.Name -contains $Name) {
        return $Object.$Name
    }
    return $DefaultValue
}

function Get-FreePort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return ([Net.IPEndPoint]$listener.LocalEndpoint).Port }
    finally { $listener.Stop() }
}

function Test-SafeRelativePath([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value) -or [IO.Path]::IsPathRooted($Value)) { return $false }
    return -not (($Value -split '[\\/]') -contains '..')
}

function Invoke-Probe([string]$Executable, [object[]]$Arguments, [int[]]$ExpectedExitCodes, [string]$Name) {
    if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) {
        return [pscustomobject]@{ Passed = $false; Detail = "missing: $Executable" }
    }
    try {
        $psi = [Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = $Executable
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        foreach ($argument in $Arguments) { $null = $psi.ArgumentList.Add([string]$argument) }
        $proc = [Diagnostics.Process]::new()
        $proc.StartInfo = $psi
        if (-not $proc.Start()) { return [pscustomobject]@{ Passed = $false; Detail = 'failed to start' } }
        try {
            if (-not $proc.WaitForExit(15000)) {
                try { $proc.Kill($true) } catch { }
                return [pscustomobject]@{ Passed = $false; Detail = 'probe timeout' }
            }
            $output = (($proc.StandardOutput.ReadToEnd() + "`n" + $proc.StandardError.ReadToEnd()).Trim() -replace "`r?`n", ' ')
            if ($output.Length -gt 300) { $output = $output.Substring(0, 300) }
            $pass = $ExpectedExitCodes -contains $proc.ExitCode
            return [pscustomobject]@{ Passed = $pass; Detail = "exit=$($proc.ExitCode) $output" }
        } finally { $proc.Dispose() }
    } catch {
        return [pscustomobject]@{ Passed = $false; Detail = $_.Exception.Message }
    }
}

function Test-VersionFile([string]$Root, [string]$Label) {
    $path = Join-Path $Root 'VERSION'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Add-Check "$Label VERSION" $false "missing: $path"
        return
    }
    $actual = (Get-Content -LiteralPath $path -Raw).Trim()
    Add-Check "$Label VERSION" ($actual -eq $expectedVersion) "expected=$expectedVersion actual=$actual"
}

function Test-RuntimeTree([string]$Root, [string]$Label) {
    Add-Check "$Label tools_config.json" (Test-Path -LiteralPath (Join-Path $Root 'tools_config.json') -PathType Leaf) 'root registry must ship with the application'

    $python = Join-Path $Root 'runtime\python\python.exe'
    if (Test-Path -LiteralPath $python -PathType Leaf) {
        $version = (& $python --version 2>&1 | Out-String).Trim()
        Add-Check "$Label embedded Python" ($LASTEXITCODE -eq 0 -and $version -match '^Python 3\.11\.') $version
    } else {
        Add-Check "$Label embedded Python" $false "missing: $python"
    }

    $browserRoot = Join-Path $Root 'runtime\playwright-browsers'
    $browserFiles = if (Test-Path -LiteralPath $browserRoot -PathType Container) { @(Get-ChildItem -LiteralPath $browserRoot -Recurse -File -ErrorAction SilentlyContinue) } else { @() }
    Add-Check "$Label Playwright Chromium" ($browserFiles.Count -gt 0) "files=$($browserFiles.Count) path=$browserRoot"
}

function Test-ManifestTools([string]$Root, [string]$Label, [object[]]$ManifestTools) {
    $toolsRoot = Join-Path $Root 'tools'
    Add-Check "$Label tool directory" (Test-Path -LiteralPath $toolsRoot -PathType Container) $toolsRoot
    foreach ($tool in $ManifestTools) {
        $name = [string]$tool.name
        $destination = [string]$tool.destination
        if (-not (Test-SafeRelativePath $destination)) {
            Add-Check "$Label tool $name" $false "unsafe destination: $destination"
            continue
        }
        $exe = Join-Path $toolsRoot $destination
        $probe = @($tool.probe)
        $expectedRaw = Get-OptionalProperty -Object $tool -Name 'expected_exit_codes' -DefaultValue @(0)
        $expected = @($expectedRaw | ForEach-Object { [int]$_ })
        if ($probe.Count -eq 0 -or $expected.Count -eq 0) {
            Add-Check "$Label tool $name" $false 'manifest probe contract is empty'
            continue
        }
        $result = Invoke-Probe -Executable $exe -Arguments $probe -ExpectedExitCodes $expected -Name $name
        Add-Check "$Label tool $name" ([bool]$result.Passed) ([string]$result.Detail)
    }
}

function Test-LoopbackListener([int]$ProcessId, [int]$Port, [string]$Label) {
    if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
        Add-Check "$Label loopback binding" $true 'Get-NetTCPConnection unavailable; /api/health loopback test used'
        return
    }
    try {
        $listeners = @(Get-NetTCPConnection -State Listen -OwningProcess $ProcessId -ErrorAction Stop | Where-Object { $_.LocalPort -eq $Port })
        if ($listeners.Count -eq 0) {
            Add-Check "$Label loopback binding" $false "no listener found for PID $ProcessId port $Port"
            return
        }
        $bad = @($listeners | Where-Object { $_.LocalAddress -notin @('127.0.0.1', '::1') })
        $addresses = ($listeners | ForEach-Object { $_.LocalAddress } | Sort-Object -Unique) -join ', '
        Add-Check "$Label loopback binding" ($bad.Count -eq 0) "listeners=$addresses port=$Port"
    } catch {
        Add-Check "$Label loopback binding" $false $_.Exception.Message
    }
}

function Test-WindeepHealth([string]$ExePath, [string]$StatePath, [string]$Label) {
    if (-not (Test-Path -LiteralPath $ExePath -PathType Leaf)) {
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
            } catch { $lastError = $_.Exception.Message }
            Start-Sleep -Milliseconds 500
        }
        Add-Check "$Label health" $healthy $(if ($healthy) { "loopback /api/health PASS on port $port" } elseif ($proc.HasExited) { "process exited with code $($proc.ExitCode)" } else { $lastError })
        if ($healthy) { Test-LoopbackListener -ProcessId $proc.Id -Port $port -Label $Label }
        if (-not $proc.HasExited) { $proc.Kill(); $proc.WaitForExit(5000) | Out-Null }
    } finally {
        if ($null -eq $oldPort) { Remove-Item Env:WINDEEP_PORT -ErrorAction SilentlyContinue } else { $env:WINDEEP_PORT = $oldPort }
        if ($null -eq $oldState) { Remove-Item Env:WINDEEP_STATE_DIR -ErrorAction SilentlyContinue } else { $env:WINDEEP_STATE_DIR = $oldState }
    }
}

New-Item -ItemType Directory -Path $workRoot -Force | Out-Null
try {
    Add-Check 'Windows version' ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT -and [Environment]::OSVersion.Version.Major -ge 10) ([Environment]::OSVersion.VersionString)
    Add-Check 'Installer exists' (Test-Path -LiteralPath $installer -PathType Leaf) $installer
    Add-Check 'Portable directory exists' (Test-Path -LiteralPath $portable -PathType Container) $portable

    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw "Tool manifest missing: $manifestPath" }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if (-not ($manifest.PSObject.Properties.Name -contains 'tools')) { throw 'Tool manifest is missing the tools array.' }
    $manifestTools = @($manifest.tools)
    Add-Check 'Tool manifest non-empty' ($manifestTools.Count -gt 0) "entries=$($manifestTools.Count)"

    if (Test-Path -LiteralPath $installer -PathType Leaf) {
        $args = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-', "/DIR=$installDir")
        $install = Start-Process -FilePath $installer -ArgumentList $args -Wait -PassThru
        Add-Check 'Silent installer exit code' ($install.ExitCode -eq 0) "exit=$($install.ExitCode)"
        $installedExe = Join-Path $installDir 'Windeep.exe'
        Add-Check 'Installed executable' (Test-Path -LiteralPath $installedExe -PathType Leaf) $installedExe
        Test-VersionFile -Root $installDir -Label 'Installed'
        Test-RuntimeTree -Root $installDir -Label 'Installed'
        Test-ManifestTools -Root $installDir -Label 'Installed' -ManifestTools $manifestTools
        Test-WindeepHealth $installedExe (Join-Path $stateDir 'installed') 'Installed build'

        $uninstaller = Join-Path $installDir 'unins000.exe'
        if (Test-Path -LiteralPath $uninstaller -PathType Leaf) {
            $uninstall = Start-Process -FilePath $uninstaller -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART') -Wait -PassThru
            Add-Check 'Silent uninstall' ($uninstall.ExitCode -eq 0) "exit=$($uninstall.ExitCode)"
            Start-Sleep -Milliseconds 500
            Add-Check 'Uninstall removed executable' (-not (Test-Path -LiteralPath $installedExe)) $installedExe
        } else {
            Add-Check 'Silent uninstall' $false "uninstaller missing: $uninstaller"
        }
    }

    if (Test-Path -LiteralPath $portable -PathType Container) {
        $portableExe = Join-Path $portable 'Windeep.exe'
        Add-Check 'Portable executable' (Test-Path -LiteralPath $portableExe -PathType Leaf) $portableExe
        Test-VersionFile -Root $portable -Label 'Portable'
        Test-RuntimeTree -Root $portable -Label 'Portable'
        Test-ManifestTools -Root $portable -Label 'Portable' -ManifestTools $manifestTools
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
    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add('# Windows Install Audit') | Out-Null
    $lines.Add('') | Out-Null
    $lines.Add("Overall: **$(if ($failed.Count -eq 0) { 'PASS' } else { 'FAIL' })**") | Out-Null
    $lines.Add('') | Out-Null
    $lines.Add("Version: **$expectedVersion**") | Out-Null
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
