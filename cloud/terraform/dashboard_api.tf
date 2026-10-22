# ==========================================
# Dashboard API Lambdas, Routing & Hosting
# ==========================================

# ------------------------------------------
# IAM Role for Dashboard API Lambdas
# ------------------------------------------
resource "aws_iam_role" "dashboard_apis" {
  name               = "${var.project_name}-${var.environment}-dashboard-apis-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

resource "aws_iam_role_policy_attachment" "dashboard_apis_basic" {
  role       = aws_iam_role.dashboard_apis.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_policy" "dashboard_apis_policy" {
  name        = "${var.project_name}-${var.environment}-dashboard-apis-policy"
  description = "Permissions for Dashboard APIs to read/write DynamoDB tables and read S3 config"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = [
          aws_dynamodb_table.alerts.arn,
          "${aws_dynamodb_table.alerts.arn}/index/*",
          aws_dynamodb_table.devices.arn,
          "${aws_dynamodb_table.devices.arn}/index/*",
          aws_dynamodb_table.event_history.arn,
          "${aws_dynamodb_table.event_history.arn}/index/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.config.arn}/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "dashboard_apis_custom" {
  role       = aws_iam_role.dashboard_apis.name
  policy_arn = aws_iam_policy.dashboard_apis_policy.arn
}

# ------------------------------------------
# Dashboard API Lambda Functions
# ------------------------------------------
resource "aws_lambda_function" "api_alerts" {
  function_name    = "${var.project_name}-${var.environment}-api-alerts"
  role             = aws_iam_role.dashboard_apis.arn
  handler          = "api_alerts.handler"
  runtime          = "python3.11"
  filename         = data.archive_file.lambda_bundle.output_path
  source_code_hash = data.archive_file.lambda_bundle.output_base64sha256
  timeout          = 15
  memory_size      = 256

  environment {
    variables = {
      ALERTS_TABLE        = aws_dynamodb_table.alerts.name
      EVENT_HISTORY_TABLE = aws_dynamodb_table.event_history.name
    }
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-api-alerts"
  }
}

resource "aws_lambda_function" "api_devices" {
  function_name    = "${var.project_name}-${var.environment}-api-devices"
  role             = aws_iam_role.dashboard_apis.arn
  handler          = "api_devices.handler"
  runtime          = "python3.11"
  filename         = data.archive_file.lambda_bundle.output_path
  source_code_hash = data.archive_file.lambda_bundle.output_base64sha256
  timeout          = 15
  memory_size      = 256

  environment {
    variables = {
      DEVICES_TABLE = aws_dynamodb_table.devices.name
    }
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-api-devices"
  }
}

resource "aws_lambda_function" "api_stats" {
  function_name    = "${var.project_name}-${var.environment}-api-stats"
  role             = aws_iam_role.dashboard_apis.arn
  handler          = "api_stats.handler"
  runtime          = "python3.11"
  filename         = data.archive_file.lambda_bundle.output_path
  source_code_hash = data.archive_file.lambda_bundle.output_base64sha256
  timeout          = 15
  memory_size      = 256

  environment {
    variables = {
      ALERTS_TABLE  = aws_dynamodb_table.alerts.name
      DEVICES_TABLE = aws_dynamodb_table.devices.name
    }
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-api-stats"
  }
}

resource "aws_lambda_function" "api_rules" {
  function_name    = "${var.project_name}-${var.environment}-api-rules"
  role             = aws_iam_role.dashboard_apis.arn
  handler          = "api_rules.handler"
  runtime          = "python3.11"
  filename         = data.archive_file.lambda_bundle.output_path
  source_code_hash = data.archive_file.lambda_bundle.output_base64sha256
  timeout          = 15
  memory_size      = 256

  environment {
    variables = {
      CONFIG_BUCKET = aws_s3_bucket.config.id
    }
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-api-rules"
  }
}

# ------------------------------------------
# API Gateway Cognito JWT Authorizer
# ------------------------------------------
resource "aws_apigatewayv2_authorizer" "cognito" {
  api_id           = aws_apigatewayv2_api.main.id
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]
  name             = "${var.project_name}-${var.environment}-cognito-auth"

  jwt_configuration {
    audience = [aws_cognito_user_pool_client.client.id]
    issuer   = "https://${aws_cognito_user_pool.pool.endpoint}"
  }
}

# ------------------------------------------
# API Gateway Integrations & Routes
# ------------------------------------------

# 1. Alerts Routes
resource "aws_apigatewayv2_integration" "api_alerts" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.api_alerts.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "get_alerts" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /alerts"
  target             = "integrations/${aws_apigatewayv2_integration.api_alerts.id}"
  authorization_type = "NONE"
}

resource "aws_apigatewayv2_route" "get_alert_by_id" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /alerts/{id}"
  target             = "integrations/${aws_apigatewayv2_integration.api_alerts.id}"
  authorization_type = "NONE"
}

resource "aws_lambda_permission" "api_alerts" {
  statement_id  = "AllowAPIGatewayAlertsInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api_alerts.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*/alerts*"
}

# 2. Devices Routes
resource "aws_apigatewayv2_integration" "api_devices" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.api_devices.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "get_devices" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /devices"
  target             = "integrations/${aws_apigatewayv2_integration.api_devices.id}"
  authorization_type = "NONE"
}

resource "aws_apigatewayv2_route" "post_devices" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "POST /devices"
  target             = "integrations/${aws_apigatewayv2_integration.api_devices.id}"
  authorization_type = "NONE"
}

resource "aws_apigatewayv2_route" "delete_device_key" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "DELETE /devices/{id}/key"
  target             = "integrations/${aws_apigatewayv2_integration.api_devices.id}"
  authorization_type = "NONE"
}

resource "aws_lambda_permission" "api_devices" {
  statement_id  = "AllowAPIGatewayDevicesInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api_devices.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*/devices*"
}

# 3. Stats Route
resource "aws_apigatewayv2_integration" "api_stats" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.api_stats.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "get_stats" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /stats"
  target             = "integrations/${aws_apigatewayv2_integration.api_stats.id}"
  authorization_type = "NONE"
}

resource "aws_lambda_permission" "api_stats" {
  statement_id  = "AllowAPIGatewayStatsInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api_stats.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*/stats"
}

# 4. Rules Route
resource "aws_apigatewayv2_integration" "api_rules" {
  api_id                 = aws_apigatewayv2_api.main.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.api_rules.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "get_rules" {
  api_id             = aws_apigatewayv2_api.main.id
  route_key          = "GET /rules"
  target             = "integrations/${aws_apigatewayv2_integration.api_rules.id}"
  authorization_type = "NONE"
}

resource "aws_lambda_permission" "api_rules" {
  statement_id  = "AllowAPIGatewayRulesInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api_rules.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*/rules"
}

# ------------------------------------------
# React Dashboard S3 Static Website Hosting
# ------------------------------------------
resource "aws_s3_bucket" "dashboard" {
  bucket        = "hijackdet-${var.environment}-dashboard-${random_id.suffix.hex}"
  force_destroy = true

  tags = {
    Name = "${var.project_name}-${var.environment}-dashboard"
  }
}

resource "aws_s3_bucket_website_configuration" "dashboard" {
  bucket = aws_s3_bucket.dashboard.id

  index_document {
    suffix = "index.html"
  }

  error_document {
    key = "index.html"
  }
}

resource "aws_s3_bucket_public_access_block" "dashboard" {
  bucket = aws_s3_bucket.dashboard.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "dashboard_public_read" {
  bucket = aws_s3_bucket.dashboard.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.dashboard.arn}/*"
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.dashboard]
}
