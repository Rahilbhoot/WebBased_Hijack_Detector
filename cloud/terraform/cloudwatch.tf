# ==========================================
# CloudWatch Log Groups & Alarms
# ==========================================

locals {
  lambda_functions = [
    "authorizer",
    "ingest",
    "detect",
    "heartbeat",
    "api-alerts",
    "api-devices",
    "api-stats",
    "api-rules"
  ]
}

# ------------------------------------------
# Pre-created Log Groups with 7-day retention
# ------------------------------------------
resource "aws_cloudwatch_log_group" "lambdas" {
  for_each          = toset(local.lambda_functions)
  name              = "/aws/lambda/${var.project_name}-${var.environment}-${each.value}"
  retention_in_days = 7

  tags = {
    Function = each.value
  }
}

# ------------------------------------------
# Lambda Error Alarms -> SNS Alert
# ------------------------------------------
resource "aws_cloudwatch_metric_alarm" "ingest_errors" {
  alarm_name          = "${var.project_name}-${var.environment}-ingest-errors"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "Triggered when Ingest Lambda experiences >= 5 errors in 5 minutes"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    FunctionName = "${var.project_name}-${var.environment}-ingest"
  }
}

resource "aws_cloudwatch_metric_alarm" "detect_errors" {
  alarm_name          = "${var.project_name}-${var.environment}-detect-errors"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "Triggered when Detect Lambda experiences >= 5 errors in 5 minutes"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    FunctionName = "${var.project_name}-${var.environment}-detect"
  }
}
