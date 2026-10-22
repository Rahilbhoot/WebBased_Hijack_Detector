<#
.SYNOPSIS
    Uninstalls the Browser Hijack Detector Windows Service cleanly.
#>

[CmdletBinding()]
param (
    [string]$ServiceName = "HijackDetectorAgent"
)

# Elevate privileges check
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be executed in an elevated Administrator PowerShell prompt."
    exit 1
}

Write-Host "==========================================================" -ForegroundColor Yellow
Write-Host "  Uninstalling Hijack Detector Windows Service            " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Yellow

$svc = Get-Service -Name "$ServiceName" -ErrorAction SilentlyContinue

if ($svc) {
    if ($svc.Status -eq "Running") {
        Write-Host "[*] Stopping service '$ServiceName'..." -ForegroundColor Yellow
        Stop-Service -Name "$ServiceName" -Force
        Start-Sleep -Seconds 2
    }

    $Nssm = Get-Command nssm -ErrorAction SilentlyContinue
    if ($Nssm) {
        & nssm remove "$ServiceName" confirm
    } else {
        & sc.exe delete "$ServiceName"
    }
    Write-Host "[+] Service '$ServiceName' removed successfully." -ForegroundColor Green
} else {
    Write-Host "[i] Service '$ServiceName' was not found on this system." -ForegroundColor Gray
}
