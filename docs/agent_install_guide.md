# Endpoint Agent Enterprise Installation & Operations Guide

This guide walks through deploying the **Windows Log-Based Browser Hijack Detector Agent** in an enterprise production environment.

---

## 1. Prerequisites

1. **Operating System**: Windows 10 (21H2+), Windows 11, or Windows Server 2019/2022 (x64).
2. **Administrative Privileges**: Local Administrator access is required to read protected Security event logs and install Windows Services.
3. **Audit Policies Configured**: Ensure Sysmon and Windows Advanced Audit Policies are active:
   ```powershell
   powershell.exe -ExecutionPolicy Bypass -File .\scripts\setup_lab_auditing.ps1
   powershell.exe -ExecutionPolicy Bypass -File .\scripts\verify_lab_auditing.ps1
   ```
4. **Outbound Network Egress**: Port `443` (HTTPS) outbound access to the AWS API Gateway endpoint.

---

## 2. Packaging the Agent Binary

To build the standalone single-file binary:
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\agent\installer\build.ps1
```
The output executable will be placed in `dist\hijack-detector-agent.exe`.

---

## 3. Installation Flow

### Step 1: Prepare Installation Directory
Default path: `C:\Program Files\HijackDetector`

```powershell
mkdir "C:\Program Files\HijackDetector" -Force
mkdir "C:\Program Files\HijackDetector\data" -Force
mkdir "C:\Program Files\HijackDetector\logs" -Force
```

### Step 2: Copy Files
Copy the executable and configuration to the destination:
```powershell
copy-item .\dist\hijack-detector-agent.exe "C:\Program Files\HijackDetector\"
copy-item .\agent\config.yaml "C:\Program Files\HijackDetector\"
```

### Step 3: Configure Agent Credentials
Edit `C:\Program Files\HijackDetector\config.yaml` or place a `.env` file in the folder:
```yaml
device_id: "PC-WORKSTATION-01"
api_endpoint: "https://<api-gateway-id>.execute-api.us-east-1.amazonaws.com"
api_key: "bh_9876543210abcdef..."
heartbeat_interval_seconds: 120
poll_interval_seconds: 5
```

### Step 4: Install as a Windows Service with Auto-Restart
Execute the service installation script from an elevated Administrator prompt:
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\agent\installer\install_service.ps1
```

The script will:
- Register the service `HijackDetectorAgent` with automatic startup (`SERVICE_AUTO_START`).
- Set failure restart recovery:
  - **1st Failure**: Restart after 5 seconds.
  - **2nd Failure**: Restart after 30 seconds.
  - **Subsequent Failures**: Restart after 60 seconds.
- Automatically execute `set_permissions.ps1` to restrict access strictly to `SYSTEM` and `Administrators`.
- Start the service.

---

## 4. Verification & Health Monitoring

### Service Status
Verify the service is active and running:
```powershell
Get-Service -Name HijackDetectorAgent
```

Expected output:
```
Status   Name                 DisplayName
------   ----                 -----------
Running  HijackDetectorAgent  Browser Hijack Detector Security Agent
```

### Log Files
Check service activity in the hardened logs folder:
- Agent execution log: `C:\Program Files\HijackDetector\logs\agent.log`
- Service stdout/stderr: `C:\Program Files\HijackDetector\logs\service_stdout.log`

### Verify SOC Dashboard Connectivity
Open the SOC Dashboard:
1. Navigate to **Endpoints Fleet** (`/devices`).
2. Verify `PC-WORKSTATION-01` displays an animated green pulsing indicator and status `Online`.
3. Check that `Last Heartbeat` reflects the current time.

---

## 5. Service Maintenance & Uninstallation

To stop and remove the agent service cleanly:
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\agent\installer\uninstall_service.ps1
```
