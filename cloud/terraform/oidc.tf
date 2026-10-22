# ==========================================
# GitHub Actions OIDC Integration (Task 13.4)
# Allows secure deployment from GitHub Actions without long-lived static AWS access keys
# ==========================================

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c58769335b7a1ce2daf3e4142f9a239968413b8"
  ]
}

# Trust Policy: Restrict assume role strictly to the configured repository and main branch
data "aws_iam_policy_document" "github_actions_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repo}:*"]
    }
  }
}

resource "aws_iam_role" "github_actions_deploy" {
  name               = "${var.project_name}-${var.environment}-github-actions-deploy"
  assume_role_policy = data.aws_iam_policy_document.github_actions_assume_role.json

  tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
    Purpose     = "CI/CD Deployment via GitHub Actions OIDC"
  }
}

# Scoped Permissions Policy for Infrastructure & Dashboard Deployment
resource "aws_iam_role_policy" "github_actions_deploy_policy" {
  name = "github-actions-deploy-permissions"
  role = aws_iam_role.github_actions_deploy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3DeployPermissions"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "s3:GetBucketLocation",
          "s3:GetBucketVersioning",
          "s3:GetBucketPolicy",
          "s3:PutBucketPolicy",
        ]
        Resource = [
          aws_s3_bucket.config.arn,
          "${aws_s3_bucket.config.arn}/*",
          aws_s3_bucket.raw_logs.arn,
          "${aws_s3_bucket.raw_logs.arn}/*",
          aws_s3_bucket.access_logs.arn,
          "${aws_s3_bucket.access_logs.arn}/*",
        ]
      },
      {
        Sid    = "LambdaUpdatePermissions"
        Effect = "Allow"
        Action = [
          "lambda:UpdateFunctionCode",
          "lambda:UpdateFunctionConfiguration",
          "lambda:GetFunction",
          "lambda:PublishVersion",
        ]
        Resource = "arn:aws:lambda:${var.aws_region}:*:function:${var.project_name}-${var.environment}-*"
      },
      {
        Sid    = "APIGatewayRead"
        Effect = "Allow"
        Action = [
          "apigateway:GET",
          "apigateway:PATCH",
          "apigateway:PUT",
        ]
        Resource = "*"
      },
      {
        Sid    = "DynamoDBTableAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:DescribeTable",
          "dynamodb:UpdateTable",
        ]
        Resource = "arn:aws:dynamodb:${var.aws_region}:*:table/hijack-detector-${var.environment}-*"
      }
    ]
  })
}
