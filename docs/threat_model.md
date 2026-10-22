# Security Threat Model (STRIDE)

This document provides a systematic security threat analysis of the **Windows Log-Based Browser Hijack Detector** using the **Microsoft STRIDE** methodology:
- **S**poofing
- **T**ampering
- **R**epudiation
- **I**nformation Disclosure
- **D**enial of Service
- **E**levation of Privilege

---

## 1. Threat Matrix & Countermeasure Mapping

| Threat Category | Threat Scenario | Impact | Applied Countermeasure / Mitigation | Residual Risk |
|---|---|---|---|---|
| **Spoofing** | Rogue host sends false event telemetry pretending to be a legitimate endpoint. | High | Custom API Key Authorizer checks SHA-256 hash. If `device_id` in payload does not match token context, request is rejected with `403 Forbidden`. | Low |
| **Spoofing** | Attacker attempts to impersonate SOC analyst on dashboard. | High | AWS Cognito User Pools with strict password complexity, multi-factor authentication (MFA) option, and RS256 JWT validation. | Low |
| **Tampering** | Malware deletes or edits local `bookmarks.json` or `queue.sqlite` to blind the agent. | High | Windows NTFS ACLs applied via `set_permissions.ps1`: files are restricted strictly to `SYSTEM` and `Administrators`. Unprivileged users/malware cannot modify. | Low |
| **Tampering** | Attacker modifies raw event logs stored in cloud. | Critical | S3 Object Lock in Compliance mode. Files are WORM-immutable; cannot be edited or deleted for 90 days even by AWS account owner. | Very Low |
| **Repudiation** | Attacker clears Windows Security event logs (`wevtutil cl Security`) to hide their tracks. | High | Detection Rule **BH007** detects Event ID 1102 / 104 (`log_cleared`). Correlation chain **CR03** applies a +30 bonus penalty and triggers instant High alert. | Low |
| **Information Disclosure** | Plaintext API key exposed in configuration repository or git history. | High | Keys loaded via `${API_KEY}` environment expansion. `.env` and `.key` files excluded in `.gitignore`. One-time display during enrollment. | Low |
| **Denial of Service** | Network connection cut off between endpoint and cloud. | Medium | SQLite local outbox buffers events persistently with backoff retry. Zero event loss upon reconnection. | Low |
| **Denial of Service** | Attacker generates high event volume to cause runaway cloud bills. | Medium | AWS Budget configured with $5.00 alarm. Ingestion throttled and validated before DynamoDB writes. Deduplication suppresses repeat alerts. | Low |
| **Elevation of Privilege**| Exploiting an agent bug to gain SYSTEM code execution from unprivileged account. | High | Agent uses pure Python parsing libraries; executable binary is owned by Administrators with read-only execution permissions for SYSTEM. | Low |

---

## 2. Attack Surface Analysis

1. **Endpoint Attack Surface**:
   - Local IPC: The agent does not expose listening network ports or unauthenticated named pipes on the local machine. It acts purely as a consumer of Windows Event Logs.
   - File Permissions: The installation folder `C:\Program Files\HijackDetector` is locked down using `icacls.exe`.
2. **Cloud Boundary Attack Surface**:
   - API Gateway HTTP API exposes only `/events`, `/heartbeat`, and `/devices`.
   - All inbound payloads are validated against strict Pydantic schemas before processing. SQL injection and command injection payloads are treated as inert strings.
3. **CI/CD Supply Chain**:
   - Build scripts do not rely on static long-lived AWS IAM access keys; all GitHub Actions deployments use OpenID Connect (OIDC).
   - Dependabot actively monitors dependencies for known CVEs.
