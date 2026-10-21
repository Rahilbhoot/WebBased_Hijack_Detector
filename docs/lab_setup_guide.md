# Safe Lab Environment Setup Guide

This guide walks through configuring an isolated Windows Virtual Machine (VM) for building, running, and testing the **Windows Log-Based Browser Hijack Detector**.

> [!WARNING]
> **Safety First:** Never run attack simulations or malware-like test commands on your primary workstation. All attack simulations must be executed strictly within an isolated VM with clean rollback snapshots.

---

## 1. Virtual Machine Provisioning

### Supported Hypervisors
- **Hyper-V** (Windows 10/11 Pro/Enterprise)
- **Oracle VirtualBox** (Free, cross-platform)
- **VMware Workstation Pro / Player**

### Recommended VM Specifications
| Resource | Minimum | Recommended |
|---|---|---|
| OS | Windows 10 / 11 64-bit | Windows 11 Enterprise (Evaluation) |
| vCPU | 2 cores | 4 cores |
| RAM | 4 GB | 8 GB |
| Disk | 50 GB dynamically allocated | 80 GB SSD |
| Network | Host-Only or NAT (isolated from corporate LAN) | NAT with internet access for package install |

---

## 2. Automated Lab Configuration (Recommended)

An automated script is provided in the repository to configure all required auditing policies and Sysmon in one step.

1. Open PowerShell inside the VM as **Administrator** (`Run as Administrator`).
2. Navigate to the project root directory:
   ```powershell
   cd D:\AllProjects\hijack-detector
   ```
3. Run the automated auditing setup script:
   ```powershell
   .\scripts\setup_lab_auditing.ps1 -InstallSysmon
   ```
4. Verify the setup with:
   ```powershell
   .\scripts\verify_lab_auditing.ps1
   ```

---

## 3. Manual Step-by-Step Configuration

If you prefer to configure the VM manually or need to troubleshoot specific components, follow these steps:

### 3.1 Install Sysmon with SwiftOnSecurity Configuration
1. Download Microsoft Sysinternals Sysmon:
   [https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Download the SwiftOnSecurity curated configuration:
   ```powershell
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "sysmonconfig-export.xml"
   ```
3. Install the 64-bit Sysmon driver and service:
   ```cmd
   Sysmon64.exe -accepteula -i sysmonconfig-export.xml
   ```
4. Confirm Sysmon is running:
   ```powershell
   Get-Service Sysmon64
   ```
5. Confirm the event channel exists:
   Open **Event Viewer** → `Applications and Services Logs` → `Microsoft` → `Windows` → `Sysmon` → `Operational`.

---

### 3.2 Enable Windows Security Process Auditing (Event 4688)

1. Open an elevated command prompt and enable detailed process tracking:
   ```cmd
   auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
   ```
2. Enable Command-Line capture in process creation:
   - **Method A (Registry):**
     ```powershell
     Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
     ```
   - **Method B (Group Policy Editor):**
     Run `gpedit.msc` → Navigate to:
     `Computer Configuration` → `Administrative Templates` → `System` → `Audit Process Creation`
     Double-click **"Include command line in process creation events"** → Select **Enabled** → Click **OK**.

---

### 3.3 Enable PowerShell Script Block and Module Logging (Event 4104)

1. Enable Script Block Logging via Registry:
   ```powershell
   $regPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
   if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
   Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
   ```
2. Enable Module Logging:
   ```powershell
   $modulePath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
   if (-not (Test-Path $modulePath)) { New-Item -Path $modulePath -Force | Out-Null }
   Set-ItemProperty -Path $modulePath -Name "*" -Value "*" -Type String -Force
   ```

---

### 3.4 Install Target Browsers and Runtime

1. **Google Chrome:** Download and install standard enterprise/consumer build.
2. **Microsoft Edge:** Pre-installed on Windows 10/11. Launch Edge once to complete initial profile generation.
3. **Python 3.11+:**
   - Install Python 3.11+ (ensure "Add python.exe to PATH" is checked).
   - Verify: `python --version` and `pip --version`.

---

## 4. Verification Checklist

Before running any attack simulations or starting the agent, run the verification script:
```powershell
.\scripts\verify_lab_auditing.ps1
```

Confirm that:
- [x] Process Creation Audit Policy: **PASS**
- [x] Process CommandLine Registry: **PASS**
- [x] PowerShell Script Block Logging: **PASS**
- [x] Sysmon Service Status: **PASS**
- [x] Sysmon Operational Channel: **PASS**
- [x] Live Canary Event Capture: **PASS**

---

## 5. VM Snapshotting (Critical Step)

Once all checks pass:
1. Close all browser and terminal windows.
2. In your hypervisor (VirtualBox / Hyper-V / VMware), take a snapshot.
3. Name the snapshot:
   ```
   lab-ready-sysmon-auditing
   ```
4. Description:
   *Clean state with Windows Auditing, Sysmon (SwiftOnSecurity), Chrome, Edge, and Python 3.11+ installed. Verified via verify_lab_auditing.ps1.*

> [!TIP]
> After every attack simulation run (Phases 6 and 14), revert the VM back to this snapshot so tests remain 100% reproducible and clean.
