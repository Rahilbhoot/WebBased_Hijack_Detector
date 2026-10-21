<#
.SYNOPSIS
    Verifies that all required Windows audit policies, registry keys, and Sysmon
    are functioning properly for the Browser Hijack Detector.
.DESCRIPTION
    Performs checks on:
    1. Process Creation audit policy
    2. Process Creation command-line inclusion registry setting
    3. PowerShell script block logging
    4. Sysmon service status and event channel
    5. Live canary event generation and detection
#>

[CmdletBinding()]
param ()

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   Browser Hijack Detector - Lab Auditing Verification   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$results = [System.Collections.Generic.List[PSCustomObject]]::new()

# Check 1: Process Creation Audit Policy
$auditPolOutput = & auditpol /get /subcategory:"Process Creation" 2>&1 | Out-String
$auditPolSuccess = $auditPolOutput -match "Success"
$results.Add([PSCustomObject]@{
    Component = "Audit Policy: Process Creation"
    Status    = if ($auditPolSuccess) { "PASS" } else { "FAIL" }
    Details   = if ($auditPolSuccess) { "Enabled for Success/Failure" } else { "Disabled or not configured" }
})

# Check 2: Process Creation Command Line Registry
$auditRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
$cmdLineEnabled = $false
if (Test-Path $auditRegPath) {
    $val = (Get-ItemProperty -Path $auditRegPath -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
    if ($val -eq 1) { $cmdLineEnabled = $true }
}
$results.Add([PSCustomObject]@{
    Component = "Audit Reg: Process CommandLine"
    Status    = if ($cmdLineEnabled) { "PASS" } else { "FAIL" }
    Details   = if ($cmdLineEnabled) { "Registry value is 1 (Enabled)" } else { "Missing or not set to 1" }
})

# Check 3: PowerShell Script Block Logging
$psScriptBlockPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$psLoggingEnabled = $false
if (Test-Path $psScriptBlockPath) {
    $val = (Get-ItemProperty -Path $psScriptBlockPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    if ($val -eq 1) { $psLoggingEnabled = $true }
}
$results.Add([PSCustomObject]@{
    Component = "PowerShell Script Block Logging"
    Status    = if ($psLoggingEnabled) { "PASS" } else { "WARN" }
    Details   = if ($psLoggingEnabled) { "Enabled (Event 4104 active)" } else { "Not configured in registry" }
})

# Check 4: Sysmon Service
$sysmonService = Get-Service -Name "Sysmon", "Sysmon64" -ErrorAction SilentlyContinue | Select-Object -First 1
$sysmonRunning = ($sysmonService -and $sysmonService.Status -eq "Running")
$results.Add([PSCustomObject]@{
    Component = "Sysmon Service"
    Status    = if ($sysmonRunning) { "PASS" } else { "WARN" }
    Details   = if ($sysmonRunning) { "Service '$($sysmonService.Name)' is Running" } else { "Service not detected or not running" }
})

# Check 5: Sysmon Operational Log Channel
$sysmonLog = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
$sysmonLogOk = ($sysmonLog -and $sysmonLog.IsEnabled)
$results.Add([PSCustomObject]@{
    Component = "Sysmon Event Log Channel"
    Status    = if ($sysmonLogOk) { "PASS" } else { "WARN" }
    Details   = if ($sysmonLogOk) { "Channel is enabled ($($sysmonLog.RecordCount) events recorded)" } else { "Channel not found or disabled" }
})

# Check 6: Live Canary Process Event Generation
Write-Host "`n[+] Spawning a test canary process to verify live event log capture..." -ForegroundColor Yellow
$canaryGuid = [System.Guid]::NewGuid().ToString()
$testCmd = "cmd.exe /c echo CANARY_$canaryGuid"
Start-Process -FilePath "cmd.exe" -ArgumentList "/c echo CANARY_$canaryGuid" -WindowStyle Hidden -Wait

Start-Sleep -Seconds 2

# Search for canary in Sysmon (Event 1) or Security (Event 4688)
$canaryDetected = $false
$detectedSource = "None"

if ($sysmonLogOk) {
    $sysmonEvent = Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-Sysmon/Operational"
        Id      = 1
    } -MaxEvents 20 -ErrorAction SilentlyContinue | Where-Object { $_.ToXml() -like "*CANARY_$canaryGuid*" } | Select-Object -First 1

    if ($sysmonEvent) {
        $canaryDetected = $true
        $detectedSource = "Sysmon (Event ID 1)"
    }
}

if (-not $canaryDetected) {
    $secEvent = Get-WinEvent -FilterHashtable @{
        LogName = "Security"
        Id      = 4688
    } -MaxEvents 20 -ErrorAction SilentlyContinue | Where-Object { $_.ToXml() -like "*CANARY_$canaryGuid*" } | Select-Object -First 1

    if ($secEvent) {
        $canaryDetected = $true
        $detectedSource = "Security (Event ID 4688 with CommandLine)"
    }
}

$results.Add([PSCustomObject]@{
    Component = "Live Canary Event Capture"
    Status    = if ($canaryDetected) { "PASS" } else { "FAIL" }
    Details   = if ($canaryDetected) { "Captured via $detectedSource" } else { "Canary command line not found in recent events" }
})

Write-Host "`n--- Verification Summary Table ---" -ForegroundColor Cyan
$results | Format-Table -AutoSize Component, Status, Details

$passCount = ($results | Where-Object { $_.Status -eq "PASS" }).Count
$totalCount = $results.Count

Write-Host "`nPassed $passCount of $totalCount verification checks." -ForegroundColor $(if ($passCount -ge 4) { "Green" } else { "Red" })

if ($passCount -lt $totalCount) {
    Write-Host "`nRecommendations:" -ForegroundColor Yellow
    Write-Host "1. To enable auditing automatically, run: .\scripts\setup_lab_auditing.ps1 -InstallSysmon"
    Write-Host "2. Ensure script is run from an elevated PowerShell window (Run as Administrator)."
}
