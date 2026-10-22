<#
.SYNOPSIS
    Hardens Windows NTFS Access Control Lists (ACLs) for the Hijack Detector Agent installation.
.DESCRIPTION
    Restricts access to agent secrets and binaries so that standard unprivileged users cannot:
    - Read the API key from config.yaml or .env
    - Overwrite or tamper with the executable binary
    - Modify bookmarks or local outbox sqlite queues
#>

[CmdletBinding()]
param (
    [string]$TargetDir = "C:\Program Files\HijackDetector"
)

# Elevate privileges check
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be executed in an elevated Administrator PowerShell prompt."
    exit 1
}

Write-Host "[*] Applying hardened NTFS permissions to '$TargetDir'..." -ForegroundColor Cyan

if (-not (Test-Path -Path $TargetDir)) {
    Write-Error "Target directory '$TargetDir' does not exist."
    exit 1
}

# 1. Base directory inheritance: Disable inheritance, grant SYSTEM & Administrators Full Control
& icacls.exe "$TargetDir" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null

# 2. Restrict secrets files: config.yaml and .env strictly to Administrators (F) and SYSTEM (F)
$SecretFiles = @("$TargetDir\config.yaml", "$TargetDir\.env")
foreach ($sec in $SecretFiles) {
    if (Test-Path -Path $sec) {
        & icacls.exe "$sec" /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F" | Out-Null
        Write-Host "    [+] Restricted $sec to SYSTEM + Administrators only." -ForegroundColor Green
    }
}

# 3. Agent Binary: Administrators (Full), SYSTEM (Read & Execute)
$ExePath = "$TargetDir\hijack-detector-agent.exe"
if (Test-Path -Path $ExePath) {
    & icacls.exe "$ExePath" /inheritance:r /grant:r "*S-1-5-32-544:F" "*S-1-5-18:RX" | Out-Null
    Write-Host "    [+] Hardened $ExePath (Admin: Full, SYSTEM: Read/Execute)." -ForegroundColor Green
}

# 4. Data directory: SYSTEM + Administrators Full Control
$DataDir = "$TargetDir\data"
if (Test-Path -Path $DataDir) {
    & icacls.exe "$DataDir" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
    Write-Host "    [+] Restricted $DataDir to SYSTEM + Administrators." -ForegroundColor Green
}

# 5. Logs directory: SYSTEM + Administrators Full Control
$LogsDir = "$TargetDir\logs"
if (Test-Path -Path $LogsDir) {
    & icacls.exe "$LogsDir" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
    Write-Host "    [+] Restricted $LogsDir to SYSTEM + Administrators." -ForegroundColor Green
}

Write-Host "[+] NTFS permission hardening complete." -ForegroundColor Green
