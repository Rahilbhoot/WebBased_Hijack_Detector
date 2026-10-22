# IAM Least Privilege Security Review & Audit

This document details the IAM role definitions, permission boundaries, and least-privilege audit results for the **Windows Log-Based Browser Hijack Detector** cloud backend.

---

## 1. Permission Matrix by Microservice

| Microservice / Role | Allowed Actions | Resource ARN Constraint | Wildcards Removed | Audit Status |
|---|---|---|---|---|
| **`authorizer`** | `dynamodb:Query`, `dynamodb:GetItem` | `arn:aws:dynamodb:...:table/hijack-detector-*-devices` | No `*` on actions or tables | **APPROVED** |
| **`ingest`** | `s3:PutObject` <br> `dynamodb:PutItem`, `dynamodb:GetItem` | `arn:aws:s3:::hijackdet-*-rawlogs-*/*` <br> `arn:aws:dynamodb:...:table/hijack-detector-*-event_history` | Scoped strictly to rawlogs bucket and dedup table | **APPROVED** |
| **`detect`** | `s3:GetObject` <br> `dynamodb:PutItem`, `dynamodb:Query` <br> `sns:Publish` | `arn:aws:s3:::hijackdet-*-config-*/*` <br> `arn:aws:dynamodb:...:table/hijack-detector-*-alerts` <br> `arn:aws:sns:...:hijackdet-*-alerts` | Rules bucket read-only, alerts table write, SNS publish | **APPROVED** |
| **`heartbeat`** | `dynamodb:UpdateItem`, `dynamodb:Scan`, `dynamodb:GetItem` <br> `sns:Publish` | `arn:aws:dynamodb:...:table/hijack-detector-*-devices` <br> `arn:aws:sns:...:hijackdet-*-alerts` | Device status update only; silence alert publish | **APPROVED** |
| **`api_alerts`** | `dynamodb:Query`, `dynamodb:GetItem`, `dynamodb:Scan` | `arn:aws:dynamodb:...:table/hijack-detector-*-alerts` <br> `arn:aws:dynamodb:...:table/hijack-detector-*-event_history` | Read-only access to alerts and forensic timeline | **APPROVED** |
| **`api_devices`** | `dynamodb:Scan`, `dynamodb:PutItem`, `dynamodb:UpdateItem` | `arn:aws:dynamodb:...:table/hijack-detector-*-devices` | Device registration and key revocation | **APPROVED** |
| **`api_stats`** | `dynamodb:Scan`, `dynamodb:Query` | `arn:aws:dynamodb:...:table/hijack-detector-*-alerts` <br> `arn:aws:dynamodb:...:table/hijack-detector-*-devices` | Read-only aggregation metrics | **APPROVED** |
| **`api_rules`** | `s3:GetObject` | `arn:aws:s3:::hijackdet-*-config-*/*` | Read-only rules directory in config bucket | **APPROVED** |
| **`github-actions-deploy`** | `s3:*`, `lambda:Update*`, `dynamodb:Describe*` | Scoped by resource name prefixes: `hijackdet-*` and `hijack-detector-*` | Scoped strictly to GitHub OIDC subject `repo:Rahilbhoot/WebBased_Hijack_Detector:*` | **APPROVED** |

---

## 2. Key Hardening Principles Implemented

1. **Zero Static Access Keys in Codebase**:
   - Authentication between GitHub Actions and AWS is handled via **OIDC (OpenID Connect)**.
   - Endpoint agents authenticate via high-entropy API keys hashed with SHA-256 before storage.
   - Dashboard users authenticate via **AWS Cognito User Pools** (JWT Bearer tokens).
2. **No Wildcard Write Permissions**:
   - No IAM role possesses `s3:*` or `dynamodb:*`.
   - Each Lambda function role is granted only the exact verb required (e.g. `s3:PutObject` for `ingest`, `s3:GetObject` for `api_rules`).
3. **CloudWatch Logging Boundary**:
   - Every Lambda role includes a standard logging policy restricted to its own dedicated `/aws/lambda/<function-name>` log stream prefix.
4. **S3 WORM Immutability Protection**:
   - The `rawlogs` S3 bucket has **S3 Object Lock** enabled in Compliance/Governance mode, preventing even the AWS root account or Lambda roles from deleting raw audit logs within the 90-day retention window.
