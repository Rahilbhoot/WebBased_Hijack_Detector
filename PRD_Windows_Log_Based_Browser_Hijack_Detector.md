# Product Requirements Document (PRD)

# Windows Log-Based Browser Hijack Detector (Hybrid Endpoint + AWS Cloud)

| Field | Value |
|---|---|
| Document version | 1.0 |
| Date | 21 October 2026 |
| Status | Draft for review |
| Project type | Academic / portfolio security project |
| Target platform | Windows 10/11 endpoints, AWS backend |

---

## 1. Overview

### 1.1 Summary
The Windows Log-Based Browser Hijack Detector is a lightweight security tool that monitors Windows event logs (Sysmon, Security, System) to detect signs of **browser hijacking**: unauthorized changes to browser settings, extensions, proxies, or redirects. A small **agent** on each Windows PC collects and normalizes log events and ships them over HTTPS to an **AWS serverless backend**, where a rule engine scores the events, stores evidence and alerts, notifies administrators, and displays everything on a secure web dashboard.

### 1.2 Problem Statement
Browser hijackers (malware, PUPs, malicious policies) silently change homepages, search engines, extensions, proxy settings, and hosts-file entries. These changes leave footprints in Windows logs, but:
- Most users cannot read raw logs and never notice the footprints.
- Local logs can be **cleared by the attacker**, destroying evidence.
- Existing antivirus tools often do not explain *why* something was flagged.
- Small teams and students have no affordable, transparent way to monitor multiple PCs.

### 1.3 Vision
A transparent, explainable, low-cost detection system that turns raw Windows logs into clear, actionable browser-hijack alerts, with tamper-resistant evidence stored in the cloud.

### 1.4 Key Value Propositions
1. **Explainable detection:** every alert says which rules fired and why, in plain English.
2. **Tamper-resistant evidence:** logs are copied to the cloud before an attacker can erase them.
3. **Centralized visibility:** one dashboard for many PCs.
4. **Easy to maintain:** rules are editable files; update once, all devices benefit.
5. **Low cost:** serverless AWS design fits within free-tier limits for small deployments.

---

## 2. Goals and Non-Goals

### 2.1 Goals
- G1: Detect common browser-hijack techniques on Windows 10/11 for Chrome and Edge.
- G2: Provide a risk score (Low / Medium / High) with a human-readable explanation per alert.
- G3: Ship events to the cloud reliably, including during network outages.
- G4: Preserve raw logs in tamper-resistant storage.
- G5: Notify administrators of high-severity alerts within 60 seconds.
- G6: Provide an authenticated dashboard for alerts, devices, and rules.
- G7: Detect agent tampering or silence using heartbeats.
- G8: Deploy the whole backend reproducibly with Infrastructure as Code and CI/CD.

### 2.2 Non-Goals (v1)
- Automatic malware removal or remediation.
- Replacing antivirus or EDR products.
- Support for macOS, Linux, or mobile browsers.
- Firefox, Brave, Opera detection (planned for later).
- Kernel-level or driver-based monitoring.
- Machine-learning-based detection (stretch goal only).

---

## 3. Target Users and Personas

| Persona | Description | Needs |
|---|---|---|
| **Student / Home user (Primary)** | Non-expert who wants to know if their browser was tampered with | Simple alerts, plain-English explanations |
| **Small IT admin (Primary)** | Manages 5-50 PCs in a lab or small office | Central dashboard, email alerts, device status |
| **Security learner / Analyst (Secondary)** | Studies detection engineering | Visible rules, raw events, MITRE ATT&CK mapping |
| **Project evaluator (Secondary)** | Faculty/interviewer reviewing the project | Clear architecture, test evidence, demo flow |

---

## 4. Scope

### 4.1 In Scope
- Windows agent (collector, normalizer, sender, heartbeat)
- Local rule engine and SQLite storage (offline/standalone mode)
- AWS backend: ingestion API, cloud detection, storage, alerting
- Web dashboard with login
- Device registration and heartbeat monitoring
- Testing in an isolated VM lab
- Documentation and demo

### 4.2 Out of Scope (v1)
- Remediation actions, quarantine, or rollback
- Enterprise features: SSO with external IdPs, multi-tenant billing
- Mobile app

---

## 5. Detection Coverage

### 5.1 Hijack Techniques Covered

| Technique | Footprint | Log source |
|---|---|---|
| Browser launched with suspicious flags | Process command line | Sysmon 1 / Security 4688 |
| Forced extension install via policy | Registry change | Sysmon 12/13/14 |
| Homepage / search engine set by policy | Registry change | Sysmon 13 |
| System proxy or PAC script set | Registry change | Sysmon 13 |
| Hosts file tampering | File modification | Sysmon 11 |
| Browser shortcut (.lnk) modification | File change | Sysmon 11 |
| Malicious scheduled task / service | Task or service creation | Security 4698 / System 7045 |
| Rogue root certificate | Cert store change | Sysmon 13 / CAPI2 |
| Log clearing (defense evasion) | Log cleared | Security 1102 |

### 5.2 Initial Rule Catalog

| Rule ID | Name | Event type | Base score |
|---|---|---|---|
| BH001 | Browser launched with extension/proxy flags | process_create | 40 |
| BH002 | Browser policy registry modified | registry_set | 50 |
| BH003 | System proxy / PAC script changed | registry_set | 30 |
| BH004 | Hosts file modified | file_create | 40 |
| BH005 | Browser shortcut modified | file_create | 30 |
| BH006 | Suspicious scheduled task or service | task_create / service_install | 35 |
| BH007 | Security log cleared | log_cleared | 60 |
| BH008 | Root certificate added | registry_set | 45 |

### 5.3 Severity Mapping
| Score | Severity |
|---|---|
| 0-29 | Low |
| 30-59 | Medium |
| 60+ | High |

### 5.4 Correlation Rules
- CR01: Registry policy change followed by browser launch within 5 minutes by a non-installer parent process → +30.
- CR02: Proxy change plus hosts-file change on the same device within 10 minutes → +25.
- CR03: Any detection followed by log clearing on the same device → +30.

---

## 6. Functional Requirements

### 6.1 Agent (Windows)

| ID | Requirement | Priority |
|---|---|---|
| FR-A1 | Read new events from Sysmon, Security, System, and PowerShell logs | Must |
| FR-A2 | Persist the last-read position so restarts neither duplicate nor miss events | Must |
| FR-A3 | Normalize events into a common JSON schema with UTC timestamps and a unique event ID | Must |
| FR-A4 | Batch events (every 30 s or 100 events) and send via HTTPS with a device API key | Must |
| FR-A5 | Queue events locally during outages and retry with exponential backoff | Must |
| FR-A6 | Send a heartbeat every 2-5 minutes with device ID, agent version, uptime | Must |
| FR-A7 | Run as a Windows Service with automatic start on boot | Must |
| FR-A8 | Support a standalone offline mode with local rule evaluation and SQLite | Should |
| FR-A9 | Load configuration from a protected config file | Must |
| FR-A10 | Log its own errors to a rotating local file without crashing | Must |
| FR-A11 | Auto-update rules from the cloud | Could |

### 6.2 Cloud Ingestion

| ID | Requirement | Priority |
|---|---|---|
| FR-C1 | Expose `POST /events` via API Gateway, authenticated per device | Must |
| FR-C2 | Validate payload size, schema, and required fields; reject invalid input | Must |
| FR-C3 | Store raw batches in S3 using `device_id/YYYY/MM/DD/HH-mm-ss.json` | Must |
| FR-C4 | Deduplicate events using the event ID | Should |
| FR-C5 | Throttle requests per device to prevent floods | Should |

### 6.3 Cloud Detection

| ID | Requirement | Priority |
|---|---|---|
| FR-D1 | Evaluate each event against rules loaded from S3 (cached for a few minutes) | Must |
| FR-D2 | Calculate a score and severity from matching rules | Must |
| FR-D3 | Apply correlation rules using a short-lived per-device event history | Should |
| FR-D4 | Apply a whitelist (trusted publishers, paths) before scoring | Must |
| FR-D5 | Write alerts to DynamoDB with rule IDs, score, severity, explanation, and raw event | Must |
| FR-D6 | Deduplicate repeat alerts within a time window | Should |
| FR-D7 | Map each rule to a MITRE ATT&CK technique ID | Should |

### 6.4 Alerting

| ID | Requirement | Priority |
|---|---|---|
| FR-N1 | Publish High-severity alerts to an SNS topic delivering email | Must |
| FR-N2 | Throttle notifications (one per device per rule per 15 minutes) | Should |
| FR-N3 | Optional Telegram notification | Could |
| FR-N4 | Alert when a device stops sending heartbeats for more than 10 minutes | Must |

### 6.5 Dashboard

| ID | Requirement | Priority |
|---|---|---|
| FR-W1 | Login via Cognito; only authenticated users may view data | Must |
| FR-W2 | Overview page: totals, severity chart, recent alerts | Must |
| FR-W3 | Alerts list with filters (device, severity, date range) and sorting | Must |
| FR-W4 | Alert detail page: "why was this flagged?", rules fired, raw event | Must |
| FR-W5 | Devices page: last seen, status (Online/Offline), agent version, alert count | Should |
| FR-W6 | Rules page: view active rules | Should |
| FR-W7 | Roles: admin (manage devices/rules) and viewer (read-only) | Could |

### 6.6 Device Management

| ID | Requirement | Priority |
|---|---|---|
| FR-M1 | Register a new device and issue a unique API key | Must |
| FR-M2 | Revoke a device key immediately | Should |
| FR-M3 | Store only hashed device keys in the backend | Must |

---

## 7. Non-Functional Requirements

| Category | Requirement |
|---|---|
| **Performance** | Agent CPU use under 3% and memory under 100 MB on average |
| **Latency** | End-to-end (action → alert in DynamoDB) under 30 s; email under 60 s |
| **Reliability** | No event loss during outages up to 24 hours (local queue); retries are idempotent |
| **Scalability** | Backend handles at least 50 devices on serverless scaling without redesign |
| **Security** | HTTPS only; encryption at rest; least-privilege IAM; no secrets in code; Object Lock on raw logs |
| **Privacy** | Command lines may contain sensitive data; collect only required fields; restrict dashboard access |
| **Cost** | Fit within AWS free tier for up to ~5 devices; monthly cost under USD 5 otherwise |
| **Maintainability** | Rules and whitelist stored as editable files; IaC for all cloud resources |
| **Observability** | CloudWatch logs and alarms for Lambda errors; agent self-logging |
| **Usability** | Alerts understandable by a non-expert; setup documented step by step |
| **Compatibility** | Windows 10/11 (64-bit); Chrome and Edge current versions |

---

## 8. System Architecture

### 8.1 High-Level Flow

```
Windows PC (Agent)                                AWS Cloud
┌─────────────────────────┐   HTTPS + API key   ┌──────────────────────────────────┐
│ Sysmon/Security logs    │ ──────────────────→ │ API Gateway                      │
│  → Collector            │                     │   → Lambda: ingest               │
│  → Normalizer           │                     │        ├→ S3 (raw logs, locked)  │
│  → Sender (batch+queue) │                     │        └→ Lambda: detect         │
│  → Heartbeat            │ ←── pulls rules ─── │              ├→ DynamoDB (alerts)│
└─────────────────────────┘                     │              └→ SNS (email/TG)   │
                                                │ EventBridge → Lambda: heartbeat  │
                                                │ Dashboard (CloudFront/S3 or      │
                                                │   Express.js on ECS/EC2)         │
                                                │ Cognito (login)                  │
                                                └──────────────────────────────────┘
```

### 8.2 Components

| Component | Responsibility | Technology |
|---|---|---|
| Collector | Reads new Windows events | Python, `Get-WinEvent` / `pywin32` |
| Normalizer | Converts events to common JSON | Python |
| Sender | Batching, retry, offline queue | Python, `requests` |
| API Gateway | Public HTTPS front door, auth, throttling | AWS API Gateway (HTTP API) |
| Ingest Lambda | Validate and store raw batches | AWS Lambda (Python) |
| Detect Lambda | Rule engine, scoring, correlation | AWS Lambda (Python) |
| Raw log store | Tamper-resistant evidence | S3 (versioning, Object Lock, encryption) |
| Rules store | `rules.yaml`, whitelist, blocklist | S3 |
| Alert store | Alerts, devices, event history | DynamoDB |
| Notifier | Email/SMS/Telegram | SNS |
| Scheduler | Periodic offline-device check | EventBridge + Lambda |
| Auth | Dashboard login | Cognito (JWT authorizer) |
| Dashboard | Visualization | React on S3 + CloudFront, or Express.js in Docker on ECS/EC2 |
| IaC | Reproducible deployment | Terraform (or AWS SAM) |
| CI/CD | Test and deploy automation | GitHub Actions (OIDC to AWS) |

### 8.3 Design Principles
- **Pure-function rule engine:** `evaluate(event, rules, history) → alert | None`, reusable in both the agent and Lambda.
- **Agent stays thin:** collect, normalize, send. Detection logic lives centrally.
- **Fail safe:** an unreachable cloud never stops local collection.
- **Least privilege everywhere.**

---

## 9. Data Model

### 9.1 Normalized Event (agent → cloud)

```json
{
  "event_id": "uuid",
  "device_id": "PC-LAB-01",
  "timestamp": "2026-10-21T10:30:15Z",
  "type": "process_create",
  "source_event_id": 1,
  "process_image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "command_line": "chrome.exe --proxy-server=127.0.0.1:9999",
  "parent_image": "C:\\Users\\student\\AppData\\evil.exe",
  "user": "LAB\\student",
  "registry_key": null,
  "registry_value_name": null,
  "registry_value": null,
  "file_path": null
}
```

### 9.2 DynamoDB Tables

**alerts**
| Attribute | Type | Notes |
|---|---|---|
| device_id | String | Partition key |
| timestamp | String | Sort key (ISO 8601 UTC) |
| alert_id | String | Unique ID |
| rule_ids | List | Rules that fired |
| score | Number | Total score |
| severity | String | Low / Medium / High (GSI) |
| explanation | String | Plain-English reason |
| mitre_ids | List | ATT&CK technique IDs |
| raw_event | Map | Original normalized event |

**devices**
| Attribute | Type | Notes |
|---|---|---|
| device_id | String | Partition key |
| api_key_hash | String | Hashed key |
| last_seen | String | Updated by heartbeat |
| status | String | Online / Offline / Revoked |
| agent_version | String | |

**event_history** (TTL ~1 hour): `device_id`, `timestamp`, `type`, `summary`, `ttl`

### 9.3 S3 Layout
- `hijackdet-<env>-rawlogs/<device_id>/YYYY/MM/DD/HH-mm-ss.json` (Object Lock, versioning)
- `hijackdet-<env>-config/rules.yaml`, `whitelist.yaml`, `blocklist.yaml`

---

## 10. API Specification

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/events` | Device API key | Submit a batch of normalized events |
| POST | `/heartbeat` | Device API key | Report device is alive |
| GET | `/rules` | Device API key | Agent fetches current rules (optional) |
| GET | `/alerts` | Cognito JWT | List alerts with filters |
| GET | `/alerts/{id}` | Cognito JWT | Alert detail |
| GET | `/devices` | Cognito JWT | List devices and status |
| GET | `/stats` | Cognito JWT | Aggregate counts for charts |
| POST | `/devices` | Cognito JWT (admin) | Register device, return API key once |
| DELETE | `/devices/{id}/key` | Cognito JWT (admin) | Revoke key |

**Example `POST /events` request**
```json
{
  "device_id": "PC-LAB-01",
  "agent_version": "1.0.0",
  "events": [ { "...normalized event..." } ]
}
```
**Responses:** `202 Accepted` (stored), `400` (invalid payload), `401/403` (bad key), `413` (too large), `429` (throttled).

---

## 11. Security and Privacy Requirements

1. **Transport:** TLS (HTTPS) for all communication.
2. **At rest:** S3 and DynamoDB encryption enabled; versioning plus Object Lock on raw logs.
3. **Authentication:** per-device API keys (hashed in storage); Cognito JWT for dashboard users; MFA recommended for admins.
4. **Authorization:** IAM role per Lambda with only the permissions it needs.
5. **Secrets:** stored in AWS Secrets Manager or environment variables; never committed to Git.
6. **Agent protection:** NTFS permissions restrict config/binaries to administrators; heartbeat detects agent shutdown.
7. **Input validation:** strict schema and size checks at the API.
8. **Dependency hygiene:** `pip-audit`, Dependabot.
9. **Privacy:** minimize collected fields; document data retention (default 90 days for raw logs, configurable lifecycle rule).
10. **Threat model summary:**

| Threat | Mitigation |
|---|---|
| Attacker clears local logs | Events already shipped to S3; alert on Event 1102 |
| Attacker kills the agent | Heartbeat-silence alert |
| Stolen device key | Per-device keys, instant revocation, throttling |
| Forged events from a rogue client | API key auth, validation, anomaly checks |
| Cloud credential leak | OIDC for CI/CD, no keys in repo, least privilege |

---

## 12. Technology Stack

| Layer | Choice |
|---|---|
| Agent | Python 3.11+, `pywin32`, `requests`, `PyYAML`, PyInstaller, NSSM |
| Log sources | Sysmon (SwiftOnSecurity config), Windows Security/System logs |
| Cloud | AWS: API Gateway, Lambda, S3, DynamoDB, SNS, EventBridge, Cognito, CloudWatch, Secrets Manager, CloudFront |
| Dashboard | React (static) or Express.js + Docker on ECS/EC2 |
| IaC | Terraform (or AWS SAM) |
| CI/CD | GitHub Actions with OIDC |
| Testing | pytest, Windows VM lab, attack-simulation scripts |
| Local DB | SQLite (standalone mode) |

---

## 13. Development Phases and Milestones

| Phase | Name | Key deliverable | Est. time |
|---|---|---|---|
| 0 | Planning and setup | Repo, scope, tool choices | 2 days |
| 1 | Safe lab | Windows VM, Sysmon, command-line auditing | 2 days |
| 2 | Log collection | Collector script with saved position | 3 days |
| 3 | Normalizer | Uniform JSON events, unit tests | 2 days |
| 4 | Rule engine and scoring | Working local detection with correlation | 5 days |
| 5 | Local storage, alerts, whitelist | Complete standalone detector | 3 days |
| 6 | Local testing | Simulation results, false-positive tuning | 3 days |
| 7 | Cloud foundation | AWS account, MFA, Budget, Terraform basics | 3 days |
| 8 | Cloud ingestion | Agent → API → Lambda → S3 with offline queue | 7 days |
| 9 | Cloud detection | Rules in Lambda, alerts in DynamoDB | 7 days |
| 10 | Cloud alerting | SNS email notifications with throttling | 3 days |
| 11 | Dashboard and login | Cognito-protected dashboard | 12 days |
| 12 | Fleet features | Heartbeat, device registry, silence alerts | 6 days |
| 13 | CI/CD and hardening | Pipelines, IAM review, Object Lock, service packaging | 7 days |
| 14 | Final testing, docs, demo | Metrics, documentation, 5-minute demo | 7 days |
| 15 | Stretch goals | Firefox, threat intel, ML, remediation | Optional |

**Minimum viable product (MVP):** Phases 0-10 plus a basic dashboard.

---

## 14. Testing Strategy

### 14.1 Test Types
- **Unit tests:** normalizer and rule engine using saved sample events.
- **Integration tests:** agent → API → Lambda → S3/DynamoDB/SNS.
- **Attack simulations (VM only, harmless):**
  - Launch Chrome with `--proxy-server=127.0.0.1:9999` → BH001
  - Add a dummy value under the Edge policy key → BH002
  - Set a fake `AutoConfigURL` → BH003
  - Add a harmless line to `hosts` → BH004
  - Clear the Security log → BH007
- **Resilience tests:** internet loss, invalid key, event flood, Lambda failure, agent kill.
- **False-positive tests:** normal browsing, Windows Update, browser sync, app installs.
- **Security tests:** unauthorized API calls, tampered payloads, expired JWT.

### 14.2 Test Environment Rules
All simulations run **only inside an isolated VM with snapshots**. Never test on a primary machine.

---

## 15. Success Metrics

| Metric | Target |
|---|---|
| Detection rate on simulated attacks | ≥ 95% |
| False-positive rate during normal use | ≤ 5% of alerts after tuning |
| End-to-end alert latency | < 30 s (dashboard), < 60 s (email) |
| Event loss after 1-hour outage | 0 |
| Agent resource usage | < 3% CPU, < 100 MB RAM |
| Time to register and onboard a new device | < 10 minutes |
| Monthly cloud cost (3 devices) | < USD 5 (ideally free tier) |
| Full backend redeploy via IaC | One command / one pipeline run |

---

## 16. Risks and Mitigations

| Risk | Impact | Likelihood | Mitigation |
|---|---|---|---|
| High false positives | Alert fatigue | High | Whitelists, correlation, tuning, severity scoring |
| Attacker disables logging or Sysmon | Blind spots | Medium | Heartbeat alerts, Event 1102 rule, Sysmon service monitoring |
| Cloud cost overrun | Unexpected bill | Medium | AWS Budget alert, `terraform destroy`, free-tier design |
| Rules miss novel techniques | Missed detections | Medium | Documented limits, regular rule updates, ML stretch goal |
| Schedule overrun | Incomplete project | Medium | MVP-first phasing; local detector works before cloud |
| Sensitive data in command lines | Privacy exposure | Medium | Field minimization, access control, retention limits |
| Browser changes via sync not in registry | Undetected hijack | Medium | Documented limitation; future profile-file monitoring |

---

## 17. Limitations (Known)
- Detects only what logs capture; no visibility if logging is fully disabled before infection.
- Detection and alerting only; no automatic cleanup.
- Rule-based logic may miss unknown techniques.
- v1 covers Chrome and Edge on Windows only.

---

## 18. Future Enhancements
- Firefox support (profile file monitoring: `prefs.js`, `extensions.json`)
- Extension reputation checks (S3 blocklist, VirusTotal API)
- ML anomaly detection with SageMaker
- One-click remediation or automatic setting rollback
- SIEM integration (Wazuh, Elastic, Splunk)
- Role-based access and multi-tenant support
- Mobile push notifications

---

## 19. Deliverables

1. Source code repository (agent, cloud, dashboard, tests)
2. Terraform/SAM templates for the entire backend
3. CI/CD pipeline definitions
4. Rule catalog with MITRE ATT&CK mapping
5. Lab setup guide (VM, Sysmon, auditing)
6. Test report with metrics
7. Architecture and API documentation
8. 5-minute demo script and screenshots
9. Final report / presentation

---

## 20. Demo Script (5 Minutes)

1. Show the clean lab VM and the empty dashboard.
2. Run a simulated hijack (proxy flag plus policy change).
3. Show the **email alert** arriving.
4. Open the dashboard and walk through the **"why was this flagged?"** view.
5. Clear the local Security log, then show the evidence still safe in S3.
6. Stop the agent and show the **"device silent"** alert.
7. Show the one-command redeploy (Terraform / pipeline).

---

## 21. Open Questions

- Dashboard hosting: static React on S3 + CloudFront, or Express.js in Docker on ECS/EC2?
- IaC tool: Terraform or AWS SAM?
- Raw log retention period (30, 90, or 365 days)?
- Will Telegram notifications be included in v1?
- Number of lab VMs available for the multi-device test?

---

## 22. Glossary

| Term | Meaning |
|---|---|
| **Browser hijack** | Unauthorized modification of browser settings, extensions, or traffic routing |
| **Sysmon** | Microsoft Sysinternals tool providing detailed Windows event logging |
| **Agent** | Small program on each PC that collects and ships logs |
| **Normalizer** | Component that converts raw events into a uniform format |
| **Rule engine** | Logic that matches events to detection rules and scores them |
| **Correlation** | Combining multiple events over time into a stronger signal |
| **Whitelist** | List of trusted items excluded from alerts |
| **Heartbeat** | Periodic "I'm alive" message from an agent |
| **Object Lock** | S3 feature that prevents objects from being changed or deleted |
| **IaC** | Infrastructure as Code: defining cloud resources in text files |
| **CI/CD** | Automated testing and deployment on every code change |
| **MITRE ATT&CK** | Public knowledge base of attacker tactics and techniques |
| **JWT** | Signed token proving a user's identity after login |
| **TTL** | Time-to-live: automatic deletion of a record after a set time |
