# ==========================================
# Lambda Packaging, IAM Roles & Functions
# ==========================================

# ------------------------------------------
# Package Lambda Code
# ------------------------------------------
data "archive_file" "lambda_bundle" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda"
  output_path = "${path.module}/.build/lambda_bundle.zip"
  excludes    = ["__pycache__", "*.pyc"]
}

# ------------------------------------------
# Shared IAM Assume Role Policy
# ------------------------------------------
data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# ------------------------------------------
# 1. Authorizer Lambda & IAM
# ------------------------------------------
resource "aws_iam_role" "authorizer" {
  name               = "${var.project_name}-${var.environment}-authorizer-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

resource "aws_iam_role_policy_attachment" "authorizer_basic" {
  role       = aws_iam_role.authorizer.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_policy" "authorizer_policy" {
  name        = "${var.project_name}-${var.environment}-authorizer-policy"
  description = "Allows Authorizer Lambda to query devices DynamoDB table"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = [
          aws_dynamodb_table.devices.arn,
          "${aws_dynamodb_table.devices.arn}/index/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "authorizer_custom" {
  role       = aws_iam_role.authorizer.name
  policy_arn = aws_iam_policy.authorizer_policy.arn
}

resource "aws_lambda_function" "authorizer" {
  function_name    = "${var.project_name}-${var.environment}-authorizer"
  role             = aws_iam_role.authorizer.arn
  handler          = "authorizer.handler"
  runtime          = "python3.11"
  filename         = data.archive_file.lambda_bundle.output_path
  source_code_hash = data.archive_file.lambda_bundle.output_base64sha256
  timeout          = 10
  memory_size      = 256

  environment {
    variables = {
      DEVICES_TABLE_NAME = aws_dynamodb_table.devices.name
    }
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-authorizer"
  }
}

# ------------------------------------------
# 2. Ingest Lambda & IAM
# ------------------------------------------
resource "aws_iam_role" "ingest" {
  name               = "${var.project_name}-${var.environment}-ingest-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

resource "aws_iam_role_policy_attachment" "ingest_basic" {
  role       = aws_iam_role.ingest.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_policy" "ingest_policy" {
  name        = "${var.project_name}-${var.environment}-ingest-policy"
  description = "Permissions for Ingest Lambda to write S3 raw logs, DynamoDB event history, and invoke Detect Lambda"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.raw_logs.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem"
        ]
        Resource = aws_dynamodb_table.event_history.arn
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = aws_lambda_function.detect.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ingest_custom" {
  role       = aws_iam_role.ingest.name
  policy_arn = aws_iam_policy.ingest_policy.arn
}

resource "aws_lambda_function" "ingest" {
  function_name    = "${var.project_name}-${var.environment}-ingest"
  role             = aws_iam_role.ingest.arn
  handler          = "ingest.handler"
  runtime          = "python3.11"
  filename         = data.archive_file.lambda_bundle.output_path
  source_code_hash = data.archive_file.lambda_bundle.output_base64sha256
  timeout          = 15
  memory_size      = 256

  environment {
    variables = {
      RAW_LOGS_BUCKET     = aws_s3_bucket.raw_logs.id
      EVENT_HISTORY_TABLE = aws_dynamodb_table.event_history.name
      DETECT_LAMBDA_NAME  = aws_lambda_function.detect.function_name
    }
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-ingest"
  }
}

# ------------------------------------------
# 3. Detect Lambda & IAM
# ------------------------------------------
resource "aws_iam_role" "detect" {
  name               = "${var.project_name}-${var.environment}-detect-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

resource "aws_iam_role_policy_attachment" "detect_basic" {
  role       = aws_iam_role.detect.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_policy" "detect_policy" {
  name        = "${var.project_name}-${var.environment}-detect-policy"
  description = "Permissions for Detect Lambda to load rules from S3, write alerts to DynamoDB, and notify SNS"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.config.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = [
          aws_dynamodb_table.alerts.arn,
          "${aws_dynamodb_table.alerts.arn}/index/*",
          aws_dynamodb_table.event_history.arn,
          aws_dynamodb_table.devices.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.alerts.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "detect_custom" {
  role       = aws_iam_role.detect.name
  policy_arn = aws_iam_policy.detect_policy.arn
}

resource "aws_lambda_function" "detect" {
  function_name    = "${var.project_name}-${var.environment}-detect"
  role             = aws_iam_role.detect.arn
  handler          = "detect.handler"
  runtime          = "python3.11"
  filename         = data.archive_file.lambda_bundle.output_path
  source_code_hash = data.archive_file.lambda_bundle.output_base64sha256
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      CONFIG_BUCKET       = aws_s3_bucket.config.id
      ALERTS_TABLE        = aws_dynamodb_table.alerts.name
      EVENT_HISTORY_TABLE = aws_dynamodb_table.event_history.name
      DEVICES_TABLE       = aws_dynamodb_table.devices.name
      SNS_TOPIC_ARN       = aws_sns_topic.alerts.arn
    }
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-detect"
  }
}

# ------------------------------------------
# API Gateway HTTP Authorizer & Ingest Integration
# ------------------------------------------
resource "aws_apigatewayv2_authorizer" "device_auth" {
  api_id                            = aws_apigatewayv2_api.main.id
  authorizer_type                   = "REQUEST"
  authorizer_uri                    = aws_lambda_function.authorizer.invoke_arn
  authorizer_payload_format_version = "2.0"
  enable_simple_responses           = true
  identity_sources                  = ["$request.header.x-api-key"]
  name                              = "${var.project_name}-${var.environment}-device-authorizer"
  authorizer_result_ttl_in_seconds  = 60
}

resource "aws_apigatewayv2_integration" "ingest" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.ingest.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "post_events" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "POST /events"
  target             = "integrations/${aws_apigatewayv2_integration.ingest.id}"
  authorization_type = "CUSTOM"
  authorizer_id      = aws_apigatewayv2_authorizer.device_auth.id
}

# ------------------------------------------
# Lambda Permissions for API Gateway
# ------------------------------------------
resource "aws_lambda_permission" "api_gateway_authorizer" {
  statement_id  = "AllowAPIGatewayAuthorizerInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.authorizer.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/authorizers/${aws_apigatewayv2_authorizer.device_auth.id}"
}

resource "aws_lambda_permission" "api_gateway_ingest" {
  statement_id  = "AllowAPIGatewayIngestInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ingest.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*/events"
}

# ------------------------------------------
# 4. Heartbeat Lambda & IAM
# ------------------------------------------
resource "aws_iam_role" "heartbeat" {
  name               = "${var.project_name}-${var.environment}-heartbeat-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

resource "aws_iam_role_policy_attachment" "heartbeat_basic" {
  role       = aws_iam_role.heartbeat.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_policy" "heartbeat_policy" {
  name        = "${var.project_name}-${var.environment}-heartbeat-policy"
  description = "Permissions for Heartbeat Lambda to update devices and publish silence alerts to SNS"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Scan",
          "dynamodb:Query"
        ]
        Resource = [
          aws_dynamodb_table.devices.arn,
          "${aws_dynamodb_table.devices.arn}/index/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.alerts.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "heartbeat_custom" {
  role       = aws_iam_role.heartbeat.name
  policy_arn = aws_iam_policy.heartbeat_policy.arn
}

resource "aws_lambda_function" "heartbeat" {
  function_name    = "${var.project_name}-${var.environment}-heartbeat"
  role             = aws_iam_role.heartbeat.arn
  handler          = "heartbeat.handler"
  runtime          = "python3.11"
  filename         = data.archive_file.lambda_bundle.output_path
  source_code_hash = data.archive_file.lambda_bundle.output_base64sha256
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      DEVICES_TABLE_NAME        = aws_dynamodb_table.devices.name
      SNS_TOPIC_ARN             = aws_sns_topic.alerts.arn
      SILENCE_THRESHOLD_SECONDS = "600"
    }
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-heartbeat"
  }
}

# --- Heartbeat API Gateway Route ---
resource "aws_apigatewayv2_integration" "heartbeat" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.heartbeat.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "post_heartbeat" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "POST /heartbeat"
  target             = "integrations/${aws_apigatewayv2_integration.heartbeat.id}"
  authorization_type = "CUSTOM"
  authorizer_id      = aws_apigatewayv2_authorizer.device_auth.id
}

resource "aws_lambda_permission" "api_gateway_heartbeat" {
  statement_id  = "AllowAPIGatewayHeartbeatInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.heartbeat.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*/heartbeat"
}

# ------------------------------------------
# EventBridge Silence Checker Schedule
# ------------------------------------------
resource "aws_cloudwatch_event_rule" "silence_check" {
  name                = "${var.project_name}-${var.environment}-silence-check"
  description         = "Periodic silence detection checking for offline agents every 5 minutes"
  schedule_expression = "rate(5 minutes)"
}

resource "aws_cloudwatch_event_target" "silence_check" {
  rule      = aws_cloudwatch_event_rule.silence_check.name
  target_id = "TriggerHeartbeatSilenceCheck"
  arn       = aws_lambda_function.heartbeat.arn
}

resource "aws_lambda_permission" "eventbridge_heartbeat" {
  statement_id  = "AllowEventBridgeHeartbeatInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.heartbeat.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.silence_check.arn
}
