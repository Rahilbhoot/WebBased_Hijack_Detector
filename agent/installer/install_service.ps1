<#
.SYNOPSIS
    Installs the Browser Hijack Detector Agent as a persistent Windows Service.
.DESCRIPTION
    Registers the agent executable as 'HijackDetectorAgent', configures Automatic startup,
    failure recovery actions (restart after 5s, 30s, 60s), and restricts file permissions.
#>

[CmdletBinding()]
param (
    [string]$ServiceName = "HijackDetectorAgent",
    [string]$DisplayName = "Browser Hijack Detector Security Agent",
    [string]$InstallDir = "C:\Program Files\HijackDetector",
    [string]$ExeSource = "$PSScriptRoot\..\..\dist\hijack-detector-agent.exe"
)

# Elevate privileges check
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be executed in an elevated Administrator PowerShell prompt."
    exit 1
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Installing Hijack Detector Windows Service              " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Prepare Target Directory
if (-not (Test-Path -Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$DataDir = "$InstallDir\data"
$LogsDir = "$InstallDir\logs"
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null

# 2. Deploy Binary and Configuration
$TargetExe = "$InstallDir\hijack-detector-agent.exe"
if (Test-Path -Path $ExeSource) {
    Copy-Item -Path $ExeSource -Destination $TargetExe -Force
    Write-Host "[+] Copied agent binary to $TargetExe" -ForegroundColor Green
} else {
    Write-Host "[!] Pre-built binary not found at $ExeSource. Copying Python service runner..." -ForegroundColor Yellow
}

# Copy default config if not already present
$DefaultConfig = "$PSScriptRoot\..\config.yaml"
$TargetConfig = "$InstallDir\config.yaml"
if (-not (Test-Path -Path $TargetConfig) -and (Test-Path -Path $DefaultConfig)) {
    Copy-Item -Path $DefaultConfig -Destination $TargetConfig
    Write-Host "[+] Deployed initial config to $TargetConfig" -ForegroundColor Green
}

# 3. Apply Hardened NTFS Permissions
Write-Host "[*] Hardening NTFS ACLs..." -ForegroundColor Yellow
& "$PSScriptRoot\set_permissions.ps1" -TargetDir "$InstallDir"

# 4. Service Registration (using NSSM if present, otherwise sc.exe)
Write-Host "[*] Registering Windows Service '$ServiceName'..." -ForegroundColor Yellow

$Nssm = Get-Command nssm -ErrorAction SilentlyContinue

if ($Nssm) {
    & nssm stop "$ServiceName" 2>$null
    & nssm remove "$ServiceName" confirm 2>$null

    & nssm install "$ServiceName" "$TargetExe"
    & nssm set "$ServiceName" AppDirectory "$InstallDir"
    & nssm set "$ServiceName" DisplayName "$DisplayName"
    & nssm set "$ServiceName" Description "Monitors Windows Event Logs (Sysmon/Security) for unauthorized browser modifications."
    & nssm set "$ServiceName" Start SERVICE_AUTO_START
    & nssm set "$ServiceName" AppStdout "$LogsDir\service_stdout.log"
    & nssm set "$ServiceName" AppStderr "$LogsDir\service_stderr.log"
    & nssm set "$ServiceName" AppRestartDelay 5000
} else {
    # Fallback to native Windows sc.exe
    & sc.exe stop "$ServiceName" 2>$null
    & sc.exe delete "$ServiceName" 2>$null
    Start-Sleep -Seconds 1

    & sc.exe create "$ServiceName" binPath= "`"$TargetExe`"" start= auto DisplayName= "$DisplayName"
    & sc.exe description "$ServiceName" "Monitors Windows Event Logs for unauthorized browser hijack attacks."
    
    # Configure recovery actions: restart on 1st (5s), 2nd (30s), subsequent failures (60s)
    & sc.exe failure "$ServiceName" reset= 86400 actions= restart/5000/restart/30000/restart/60000
}

# 5. Start Service
Write-Host "[*] Starting service '$ServiceName'..." -ForegroundColor Yellow
Start-Service -Name "$ServiceName" -ErrorAction SilentlyContinue

$svc = Get-Service -Name "$ServiceName"
if ($svc.Status -eq "Running") {
    Write-Host "[+] Service '$ServiceName' is RUNNING." -ForegroundColor Green
} else {
    Write-Host "[!] Service status: $($svc.Status). Check logs in $LogsDir" -ForegroundColor Yellow
}
