# ==========================================
# Terraform Outputs
# ==========================================

output "aws_region" {
  description = "AWS Region where resources are deployed"
  value       = var.aws_region
}

output "environment" {
  description = "Deployment environment"
  value       = var.environment
}

# --- S3 Buckets ---
output "s3_raw_logs_bucket_name" {
  description = "Name of the S3 bucket storing raw Windows event log batches"
  value       = aws_s3_bucket.raw_logs.id
}

output "s3_raw_logs_bucket_arn" {
  description = "ARN of the S3 bucket storing raw Windows event log batches"
  value       = aws_s3_bucket.raw_logs.arn
}

output "s3_config_bucket_name" {
  description = "Name of the S3 bucket storing rules and whitelist configurations"
  value       = aws_s3_bucket.config.id
}

output "s3_config_bucket_arn" {
  description = "ARN of the S3 bucket storing rules and whitelist configurations"
  value       = aws_s3_bucket.config.arn
}

# --- DynamoDB Tables ---
output "dynamodb_alerts_table" {
  description = "Name of the DynamoDB table for browser hijack alerts"
  value       = aws_dynamodb_table.alerts.name
}

output "dynamodb_devices_table" {
  description = "Name of the DynamoDB table for registered endpoint devices"
  value       = aws_dynamodb_table.devices.name
}

output "dynamodb_event_history_table" {
  description = "Name of the DynamoDB table for sliding window correlation events"
  value       = aws_dynamodb_table.event_history.name
}

# --- SNS ---
output "sns_alerts_topic_arn" {
  description = "ARN of the SNS topic used for High-severity alert emails"
  value       = aws_sns_topic.alerts.arn
}

# --- Cognito ---
output "cognito_user_pool_id" {
  description = "ID of the Cognito User Pool for dashboard authentication"
  value       = aws_cognito_user_pool.pool.id
}

output "cognito_user_pool_client_id" {
  description = "ID of the Cognito App Client for the React SPA dashboard"
  value       = aws_cognito_user_pool_client.client.id
}

output "cognito_domain" {
  description = "Cognito hosted domain name prefix"
  value       = aws_cognito_user_pool_domain.domain.domain
}

# --- API Gateway ---
output "api_gateway_endpoint" {
  description = "Base URL of the HTTP API Gateway"
  value       = aws_apigatewayv2_api.main.api_endpoint
}

# --- Secrets Manager ---
output "admin_secret_arn" {
  description = "ARN of the master enrollment secret in Secrets Manager"
  value       = aws_secretsmanager_secret.admin_secret.arn
}

# --- Lambda Functions ---
output "lambda_authorizer_arn" {
  description = "ARN of the Device Authorizer Lambda"
  value       = aws_lambda_function.authorizer.arn
}

output "lambda_ingest_arn" {
  description = "ARN of the Event Ingestion Lambda"
  value       = aws_lambda_function.ingest.arn
}

output "lambda_detect_arn" {
  description = "ARN of the Detection Lambda"
  value       = aws_lambda_function.detect.arn
}

