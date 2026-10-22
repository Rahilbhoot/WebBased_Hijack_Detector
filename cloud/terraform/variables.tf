# ==========================================
# Input Variables for Cloud Infrastructure
# ==========================================

variable "aws_region" {
  type        = string
  description = "AWS region for deploying cloud resources"
  default     = "us-east-1"
}

variable "environment" {
  type        = string
  description = "Deployment environment (e.g., dev, staging, prod)"
  default     = "dev"
}

variable "project_name" {
  type        = string
  description = "Prefix and identifier for all project resources"
  default     = "hijack-detector"
}

variable "alert_email" {
  type        = string
  description = "Email address to receive High-severity alerts and budget alarms"
  default     = "alert-recipient@example.com"
}

variable "raw_log_retention_days" {
  type        = number
  description = "Number of days before raw event log batches in S3 are deleted"
  default     = 90
}

variable "object_lock_mode" {
  type        = string
  description = "S3 Object Lock retention mode (GOVERNANCE or COMPLIANCE)"
  default     = "GOVERNANCE"
}

variable "budget_limit_amount" {
  type        = string
  description = "Monthly budget limit in USD to trigger billing alerts"
  default     = "5.0"
}

variable "enable_budget" {
  type        = bool
  description = "Set to true to create an AWS Cost Budget alarm"
  default     = true
}

variable "github_repo" {
  type        = string
  description = "GitHub repository (owner/repo) permitted to deploy via OIDC"
  default     = "Rahilbhoot/WebBased_Hijack_Detector"
}
