<#
.SYNOPSIS
    Builds the single-file Windows executable for the Hijack Detector Agent.
.DESCRIPTION
    Uses PyInstaller to bundle the Python runtime, agent modules, and YAML rule configs
    into a standalone 'hijack-detector-agent.exe'.
#>

[CmdletBinding()]
param (
    [string]$OutputDir = "$PSScriptRoot\..\..\dist"
)

$ErrorActionPreference = "Stop"

Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  Building Hijack Detector Standalone Agent EXE       " -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan

# Ensure output directory exists
if (-not (Test-Path -Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$ProjectRoot = Resolve-Path "$PSScriptRoot\..\.."
$ServiceScript = "$ProjectRoot\agent\service.py"
$RulesDir = "$ProjectRoot\rules"

Write-Host "[*] Checking PyInstaller..." -ForegroundColor Yellow
if (-not (Get-Command pyinstaller -ErrorAction SilentlyContinue)) {
    Write-Host "[!] Installing PyInstaller..." -ForegroundColor Yellow
    pip install pyinstaller
}

Write-Host "[*] Packaging agent into standalone EXE..." -ForegroundColor Green

pyinstaller `
    --onefile `
    --noconfirm `
    --clean `
    --name "hijack-detector-agent" `
    --distpath "$OutputDir" `
    --paths "$ProjectRoot" `
    --add-data "$RulesDir;rules" `
    --hidden-import "win32evtlog" `
    --hidden-import "win32evtlogutil" `
    --hidden-import "yaml" `
    --hidden-import "requests" `
    --hidden-import "pydantic" `
    "$ServiceScript"

if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] Successfully created binary:" -ForegroundColor Green
    Write-Host "    $OutputDir\hijack-detector-agent.exe" -ForegroundColor White
} else {
    Write-Error "PyInstaller build failed with exit code $LASTEXITCODE."
}
