<#
.SYNOPSIS
    Configures Windows auditing and Sysmon for the Browser Hijack Detector Lab.
.DESCRIPTION
    Enables:
    - Process Creation Auditing (Security Event 4688)
    - Command Line Process Auditing (ProcessCreationIncludeCmdLine_Enabled)
    - PowerShell Script Block Logging (Event 4104)
    - PowerShell Module Logging
    - Optional Sysmon download & installation with SwiftOnSecurity configuration
.NOTES
    Must be executed with elevated Administrator privileges inside the test VM.
#>

[CmdletBinding()]
param (
    [switch]$InstallSysmon = $false,
    [string]$SysmonConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
)

# 1. Verify Administrative Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script requires Administrator privileges. Please re-run PowerShell as Administrator."
    exit 1
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   Browser Hijack Detector - Lab Auditing Setup Script   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 2. Enable Process Creation Auditing (Security Event 4688)
Write-Host "[+] Configuring Audit Policy: Process Creation (Success & Failure)..." -ForegroundColor Yellow
try {
    & auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
    Write-Host "    [OK] Process Creation auditing enabled." -ForegroundColor Green
} catch {
    Write-Warning "    Failed to configure auditpol for Process Creation: $_"
}

# 3. Enable Command Line in Process Creation Events
Write-Host "[+] Enabling Command Line in Process Creation (Security Event 4688)..." -ForegroundColor Yellow
$auditRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $auditRegPath)) {
    New-Item -Path $auditRegPath -Force | Out-Null
}
Set-ItemProperty -Path $auditRegPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
Write-Host "    [OK] ProcessCreationIncludeCmdLine_Enabled set to 1." -ForegroundColor Green

# 4. Enable PowerShell Script Block Logging (Event 4104)
Write-Host "[+] Enabling PowerShell Script Block Logging..." -ForegroundColor Yellow
$psScriptBlockPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $psScriptBlockPath)) {
    New-Item -Path $psScriptBlockPath -Force | Out-Null
}
Set-ItemProperty -Path $psScriptBlockPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
Write-Host "    [OK] Script Block Logging enabled." -ForegroundColor Green

# 5. Enable PowerShell Module Logging
Write-Host "[+] Enabling PowerShell Module Logging..." -ForegroundColor Yellow
$psModuleLoggingPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (-not (Test-Path $psModuleLoggingPath)) {
    New-Item -Path $psModuleLoggingPath -Force | Out-Null
}
Set-ItemProperty -Path $psModuleLoggingPath -Name "EnableModuleLogging" -Value 1 -Type DWord -Force

$moduleNamesPath = "$psModuleLoggingPath\ModuleNames"
if (-not (Test-Path $moduleNamesPath)) {
    New-Item -Path $moduleNamesPath -Force | Out-Null
}
Set-ItemProperty -Path $moduleNamesPath -Name "*" -Value "*" -Type String -Force
Write-Host "    [OK] Module Logging enabled for all modules (*)." -ForegroundColor Green

# 6. Sysmon Verification or Optional Automated Installation
$sysmonService = Get-Service -Name "Sysmon", "Sysmon64" -ErrorAction SilentlyContinue | Select-Object -First 1

if ($sysmonService -and $sysmonService.Status -eq "Running") {
    Write-Host "[OK] Sysmon service ($($sysmonService.Name)) is already running." -ForegroundColor Green
} else {
    Write-Host "[-] Sysmon is not currently running." -ForegroundColor Yellow
    if ($InstallSysmon) {
        Write-Host "[+] Attempting automated download and installation of Sysmon..." -ForegroundColor Yellow
        $tempDir = Join-Path $env:TEMP "SysmonInstall"
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
        
        $sysmonZipPath = Join-Path $tempDir "Sysmon.zip"
        $sysmonConfigPath = Join-Path $tempDir "sysmonconfig-export.xml"
        
        Write-Host "    Downloading Sysmon from Microsoft Sysinternals..."
        Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $sysmonZipPath
        Expand-Archive -Path $sysmonZipPath -DestinationPath $tempDir -Force
        
        Write-Host "    Downloading SwiftOnSecurity Sysmon config..."
        Invoke-WebRequest -Uri $SysmonConfigUrl -OutFile $sysmonConfigPath
        
        $sysmonExe = if ([Environment]::Is64BitOperatingSystem) { Join-Path $tempDir "Sysmon64.exe" } else { Join-Path $tempDir "Sysmon.exe" }
        
        Write-Host "    Installing Sysmon service: $sysmonExe -accepteula -i $sysmonConfigPath"
        & $sysmonExe -accepteula -i $sysmonConfigPath
        
        Start-Sleep -Seconds 3
        $sysmonService = Get-Service -Name "Sysmon", "Sysmon64" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($sysmonService -and $sysmonService.Status -eq "Running") {
            Write-Host "    [OK] Sysmon successfully installed and running!" -ForegroundColor Green
        } else {
            Write-Warning "    Sysmon installation completed, but service was not detected in Running state."
        }
    } else {
        Write-Host "    TIP: To automatically download and install Sysmon with SwiftOnSecurity config, rerun:" -ForegroundColor Cyan
        Write-Host "    .\scripts\setup_lab_auditing.ps1 -InstallSysmon" -ForegroundColor White
    }
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Lab setup complete! Run .\scripts\verify_lab_auditing.ps1 to verify." -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
