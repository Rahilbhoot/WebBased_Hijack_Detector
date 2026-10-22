<#
.SYNOPSIS
    Browser Hijack Detection - Attack Simulation Script
.DESCRIPTION
    Simulates common browser hijacking and persistence techniques in a safe,
    revertible manner to generate Windows Sysmon & Security events for testing.
.PARAMETER Attack
    The specific attack ID to simulate (1-7, or 0/omit for running all safe attacks).
#>

[CmdletBinding()]
param(
    [Parameter(Position=0, Mandatory=$false)]
    [int]$Attack = 0
)

$ErrorActionPreference = 'Continue'

function Write-Banner {
    param([string]$Title)
    Write-Host "`n========================================================" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Yellow
    Write-Host "========================================================" -ForegroundColor Cyan
}

function Simulate-Attack1 {
    Write-Banner 'Attack 1 (BH001): Browser launched with extension/proxy flags'
    Write-Host '[*] Simulating Chrome process launch with suspicious proxy parameters...' -ForegroundColor Gray
    
    $chromePath = "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"
    if (-not (Test-Path $chromePath)) {
        $chromePath = "$env:ProgramFiles(x86)\Google\Chrome\Application\chrome.exe"
    }
    
    if (Test-Path $chromePath) {
        Write-Host "[+] Found Google Chrome at: $chromePath" -ForegroundColor Green
        $proc = Start-Process -FilePath $chromePath -ArgumentList '--headless --disable-gpu --proxy-server="127.0.0.1:9999" about:blank' -PassThru
        Start-Sleep -Seconds 2
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        Write-Host '[OK] Spawned and terminated Chrome with --proxy-server flag (Sysmon Event ID 1 triggered).' -ForegroundColor Green
    } else {
        Write-Host '[INFO] Chrome binary not found in standard path. Simulating via cmd.exe...' -ForegroundColor Yellow
        Start-Process cmd.exe -ArgumentList '/c echo Simulated chrome.exe --proxy-server="127.0.0.1:9999"' -WindowStyle Hidden
        Write-Host '[OK] Simulated browser command line executed.' -ForegroundColor Green
    }
}

function Simulate-Attack2 {
    Write-Banner 'Attack 2 (BH002): Browser policy registry modification'
    Write-Host '[*] Writing test browser policy into HKCU:\Software\Policies\Google\Chrome...' -ForegroundColor Gray
    $regPath = 'HKCU:\Software\Policies\Google\Chrome'
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name 'HomepageLocation' -Value 'http://hijacked-search-portal.local' -Force
    Write-Host '[OK] Set HomepageLocation policy in registry (Sysmon Event ID 13 triggered).' -ForegroundColor Green
    Start-Sleep -Seconds 1
    
    Remove-ItemProperty -Path $regPath -Name 'HomepageLocation' -Force -ErrorAction SilentlyContinue
    Write-Host '[OK] Cleaned up test policy registry value.' -ForegroundColor Gray
}

function Simulate-Attack3 {
    Write-Banner 'Attack 3 (BH003): System proxy / PAC script changed'
    Write-Host '[*] Querying current Windows Internet Settings...' -ForegroundColor Gray
    $proxyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $origProxy = (Get-ItemProperty -Path $proxyPath -Name 'ProxyServer' -ErrorAction SilentlyContinue).ProxyServer
    
    Write-Host '[*] Setting test ProxyServer value: 127.0.0.1:8080...' -ForegroundColor Gray
    Set-ItemProperty -Path $proxyPath -Name 'ProxyServer' -Value '127.0.0.1:8080' -Force
    Write-Host '[OK] ProxyServer property modified (Sysmon Event ID 13 triggered).' -ForegroundColor Green
    Start-Sleep -Seconds 1
    
    if ($origProxy) {
        Set-ItemProperty -Path $proxyPath -Name 'ProxyServer' -Value $origProxy -Force
    } else {
        Remove-ItemProperty -Path $proxyPath -Name 'ProxyServer' -Force -ErrorAction SilentlyContinue
    }
    Write-Host '[OK] Restored original system proxy settings.' -ForegroundColor Gray
}

function Simulate-Attack4 {
    Write-Banner 'Attack 4 (BH004): Hosts file modification'
    Write-Host '[*] Testing hosts file modification (requires Administrator)...' -ForegroundColor Gray
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    try {
        $testLine = '# [TEST-HIJACK-DETECTOR] 127.0.0.1 malicious-test-site.local'
        Add-Content -Path $hostsPath -Value "`n$testLine" -ErrorAction Stop
        Write-Host '[OK] Appended test entry to hosts file (Sysmon Event ID 11 triggered).' -ForegroundColor Green
        Start-Sleep -Seconds 1
        $content = Get-Content -Path $hostsPath | Where-Object { $_ -notmatch '\[TEST-HIJACK-DETECTOR\]' }
        Set-Content -Path $hostsPath -Value $content -Force
        Write-Host '[OK] Cleaned up hosts file test entry.' -ForegroundColor Gray
    } catch {
        Write-Host '[WARN] Skipping hosts file edit: elevated Administrator rights required for BH004.' -ForegroundColor Yellow
    }
}

function Simulate-Attack5 {
    Write-Banner 'Attack 5 / 6 (BH005): Browser shortcut (.lnk) modified'
    $desktopPath = [Environment]::GetFolderPath('Desktop')
    $shortcutPath = Join-Path $desktopPath 'Google Chrome.lnk'
    Write-Host "[*] Creating/modifying test browser shortcut: $shortcutPath..." -ForegroundColor Gray
    
    $wsh = New-Object -ComObject WScript.Shell
    $shortcut = $wsh.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = 'cmd.exe'
    $shortcut.Arguments = '/c echo Hijacked shortcut launch & start msedge.exe --load-extension="C:\Temp\ext"'
    $shortcut.Description = 'Google Chrome'
    $shortcut.Save()
    Write-Host '[OK] Created test shortcut file with injected flags (Sysmon Event ID 11 triggered).' -ForegroundColor Green
    Start-Sleep -Seconds 2
    
    if (Test-Path $shortcutPath) {
        Remove-Item -Path $shortcutPath -Force
        Write-Host '[OK] Removed test desktop shortcut.' -ForegroundColor Gray
    }
}

function Simulate-Attack6 {
    Write-Banner 'Attack 7 (BH006): Suspicious scheduled task'
    Write-Host '[*] Creating temporary scheduled task simulating browser persistence...' -ForegroundColor Gray
    $taskName = 'TestBrowserHijackUpdate'
    schtasks.exe /create /tn $taskName /tr 'cmd.exe /c echo Suspicious browser redirect' /sc daily /st 00:00 /f | Out-Null
    Write-Host "[OK] Created scheduled task '$taskName' (Security Event ID 4698 triggered)." -ForegroundColor Green
    Start-Sleep -Seconds 2
    schtasks.exe /delete /tn $taskName /f | Out-Null
    Write-Host '[OK] Removed test scheduled task.' -ForegroundColor Gray
}

# Execution dispatcher
switch ($Attack) {
    1 { Simulate-Attack1 }
    2 { Simulate-Attack2 }
    3 { Simulate-Attack3 }
    4 { Simulate-Attack4 }
    5 { Simulate-Attack5 }
    6 { Simulate-Attack5 }
    7 { Simulate-Attack6 }
    Default {
        Write-Host "`nRunning all safe simulated attacks (1, 2, 3, 5, 7)..." -ForegroundColor Cyan
        Simulate-Attack1
        Simulate-Attack2
        Simulate-Attack3
        Simulate-Attack5
        Simulate-Attack6
        Write-Banner 'Simulation Complete'
        Write-Host 'Events have been generated in Windows Event Logs.' -ForegroundColor Green
        Write-Host 'Check your SOC dashboard (http://localhost:3000) or agent log to observe detections.' -ForegroundColor Green
    }
}
