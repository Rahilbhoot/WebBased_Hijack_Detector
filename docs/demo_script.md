# 5-Minute Live Demonstration Script

This script provides an exact, step-by-step talk track and execution plan for demonstrating the **Windows Log-Based Browser Hijack Detector** to stakeholders and evaluators.

---

## Demo Schedule & Timeline (Total: 5 Minutes)

| Time | Phase | Focus |
|---|---|---|
| **0:00 - 0:45** | Introduction | Problem statement, architecture, and live SOC dashboard overview |
| **0:45 - 1:45** | Attack Demo 1 | Simulating browser command-line shortcut hijacking & real-time detection |
| **1:45 - 2:45** | Attack Demo 2 | Multi-stage correlation chain (Registry policy + Browser proxy launch = CR01) |
| **2:45 - 3:30** | Cloud Verification | Amazon SNS email notification & S3 Object Lock raw log immutability |
| **3:30 - 4:15** | Defense & Resilience | Simulating service kill & silence monitoring alert |
| **4:15 - 5:00** | Conclusion & Q&A | Summary of results, cost efficiency (<$2.10/mo), and closing remarks |

---

## Detailed Step-by-Step Walkthrough

### Part 1: SOC Dashboard & Fleet Status (0:00 - 0:45)
- **Visual**: Show the React SOC Dashboard (`Overview` page).
- **Talk Track**:
  > *"Welcome everyone. Today we are demonstrating the Windows Log-Based Browser Hijack Detector. Traditional antiviruses often miss subtle browser hijackers that tamper with shortcut flags, registry policies, or Windows hosts files because they misuse legitimate Windows features. Our solution collects kernel-level Sysmon and Security events and correlates multi-stage attacks in real time."*
- **Action**:
  - Point out the **Security Operations Overview**: 4 KPI cards, live threat severity distribution donut chart, and the top triggered rules.
  - Navigate to **Endpoints Fleet** (`/devices`) showing our monitored machine `PC-LAB-01` with an active pulsing green **"Online"** status pill.

---

### Part 2: Simulation 1 — Shortcut Hijacking Attack (0:45 - 1:45)
- **Visual**: Terminal running on the victim Windows machine alongside the SOC dashboard.
- **Action**: Run the attack simulation script in PowerShell:
  ```powershell
  # Simulate modifying browser shortcut with malicious proxy flag
  powershell.exe -ExecutionPolicy Bypass -File .\scripts\simulate_attacks.ps1 -Attack 6
  ```
- **Talk Track**:
  > *"Here, malware has modified the Google Chrome desktop shortcut to inject an unauthorized proxy redirect. The endpoint agent detects the file creation event from Sysmon Event ID 11 and streams the normalized event to AWS."*
- **Visual**: Refresh the **Alerts Explorer** in the SOC Dashboard.
  - The alert appears with severity badge **Medium**, Rule **BH005**, score **30**.
  - Click **"Investigate"** to open the **Alert Detail Dossier**.
  - Show the plain-English threat narrative and the forensic evidence box showing the modified `.lnk` file.

---

### Part 3: Simulation 2 — Multi-Stage Correlated Attack (CR01) (1:45 - 2:45)
- **Visual**: Terminal executing a chained multi-stage attack.
- **Action**: In PowerShell, run the correlation chain:
  ```powershell
  # Step 1: Alter registry policy
  powershell.exe -ExecutionPolicy Bypass -File .\scripts\simulate_attacks.ps1 -Attack 2
  
  # Step 2: Immediately launch browser with proxy flag
  powershell.exe -ExecutionPolicy Bypass -File .\scripts\simulate_attacks.ps1 -Attack 1
  ```
- **Talk Track**:
  > *"Now we simulate a sophisticated multi-stage threat: first, the attacker forces a browser policy in the Windows Registry (BH002). Within 3 minutes, they launch Chrome with custom proxy parameters (BH001). Our cloud engine links these two distinct events across its sliding window, triggering Correlation Rule CR01 and applying a +30 bonus risk score."*
- **Visual**: In the Dashboard, open the new incident:
  - Severity: Glowing **High** (Score: **70 / 100**).
  - Show the **Correlated Timeline (&plusmn;10 min)** displaying the visual timeline node from the registry modification leading directly to the browser trigger.

---

### Part 4: Cloud Verification (SNS & S3 WORM) (2:45 - 3:30)
- **Visual**: Switch to Email client and AWS Console / Terminal.
- **Action**:
  1. Show the incoming **Amazon SNS notification email**:
     ```
     Subject: [HIGH] Browser Hijack Alert — PC-LAB-01
     Body: Device: PC-LAB-01 | Severity: HIGH (score: 70) | Rules: BH001, BH002 (CR01)
     ```
  2. Run the Object Lock verification script:
     ```powershell
     python scripts\verify_s3_object_lock.py --bucket <rawlogs-bucket-name>
     ```
- **Talk Track**:
  > *"Because this incident exceeded our High threshold of 60, Amazon SNS dispatched an immediate incident alert email to the SOC team in under 60 seconds. Furthermore, raw forensic telemetry is stored in S3 under WORM compliance mode with Object Lock, guaranteeing immutability for compliance and legal evidentiary standards."*

---

### Part 5: Silence Monitoring & Conclusion (3:30 - 5:00)
- **Visual**: Endpoint agent stop & Silence alert.
- **Action**:
  - Stop the agent service:
    ```powershell
    Stop-Service -Name HijackDetectorAgent
    ```
- **Talk Track**:
  > *"If an attacker attempts defense evasion by terminating the agent service, our AWS EventBridge silence checker detects the lack of heartbeats. After 10 minutes of silence, the endpoint automatically transitions to Offline and triggers an urgent silence alarm."*
- **Closing**:
  > *"In summary: 100% detection rate across all 8 attack vectors, sub-35s end-to-end latency, zero event loss, full MITRE ATT&CK alignment, and a total cloud running cost under $2.10/month. Thank you!"*
