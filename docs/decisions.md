# Architecture & Project Decisions

This document records the foundational architecture and technology decisions for the Windows Log-Based Browser Hijack Detector project.

---

## Decision 1: Dashboard Hosting Architecture
- **Decision:** Static Single-Page Application (SPA) built with React (Vite) hosted on **Amazon S3 + CloudFront CDN**, authenticating directly with **Amazon Cognito User Pool**.
- **Rationale:** Serverless, zero maintenance, scales automatically, and fits neatly within the AWS Free Tier. Avoids ongoing EC2/ECS container compute costs for small teams and student deployments.
- **Alternative Considered:** Node.js/Express in Docker on AWS ECS/EC2 (rejected due to continuous compute cost and container management overhead).

---

## Decision 2: Infrastructure as Code (IaC) Tool
- **Decision:** **HashiCorp Terraform** (AWS Provider v5+).
- **Rationale:** Modular, widely recognized in security engineering portfolios, state locking with S3 and DynamoDB, rich ecosystem, and declarative syntax.
- **Alternative Considered:** AWS SAM / CloudFormation (Terraform was preferred for cleaner multi-service configuration and porting).

---

## Decision 3: Raw Log Storage Retention & Immutability
- **Decision:** **90 days** retention with **S3 Object Lock** in Compliance/Governance mode and Versioning enabled. S3 Lifecycle Rules will transition/expire logs after 90 days.
- **Rationale:** Balances forensics capabilities with storage costs. Fulfills the anti-tamper goal (attacker clearing event logs cannot clear S3 Object Locked logs).

---

## Decision 4: Telegram Notification Priority
- **Decision:** Deferred to **Phase 15 (Stretch Goals)**. High-severity alerts in v1 will reliably deliver through **Amazon SNS Email**.
- **Rationale:** Keeps core delivery focused on standard, zero-third-party-cost cloud notifications for MVP.

---

## Decision 5: Lab Virtual Machine Setup
- **Decision:** 1 primary isolated Windows 10/11 VM (Hyper-V, VirtualBox, or VMware Workstation) with Sysmon v15+ (SwiftOnSecurity configuration) and Group Policy process command-line auditing enabled. A snapshot named `lab-ready-sysmon-auditing` must be created prior to any simulation runs.
- **Rationale:** Guarantees repeatable testing, safe execution of attack scripts, and instant rollback.
