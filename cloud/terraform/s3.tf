# ==========================================
# S3 Buckets Configuration
# ==========================================

resource "random_id" "suffix" {
  byte_length = 4
}

# ------------------------------------------
# Raw Event Logs Bucket (WORM / Object Lock)
# ------------------------------------------
resource "aws_s3_bucket" "raw_logs" {
  bucket              = "hijackdet-${var.environment}-rawlogs-${random_id.suffix.hex}"
  object_lock_enabled = true
  force_destroy       = true
}

resource "aws_s3_bucket_versioning" "raw_logs" {
  bucket = aws_s3_bucket.raw_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "raw_logs" {
  bucket = aws_s3_bucket.raw_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "raw_logs" {
  bucket = aws_s3_bucket.raw_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_object_lock_configuration" "raw_logs" {
  bucket = aws_s3_bucket.raw_logs.id

  rule {
    default_retention {
      mode = var.object_lock_mode
      days = var.raw_log_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.raw_logs]
}

resource "aws_s3_bucket_lifecycle_configuration" "raw_logs" {
  bucket = aws_s3_bucket.raw_logs.id

  rule {
    id     = "expire-raw-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = var.raw_log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# ------------------------------------------
# Configuration Bucket (Rules & Whitelist)
# ------------------------------------------
resource "aws_s3_bucket" "config" {
  bucket        = "hijackdet-${var.environment}-config-${random_id.suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "config" {
  bucket = aws_s3_bucket.config.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  bucket = aws_s3_bucket.config.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "config" {
  bucket = aws_s3_bucket.config.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ------------------------------------------
# Detection Rules & Whitelist Files in S3
# ------------------------------------------
resource "aws_s3_object" "detection_rules" {
  bucket       = aws_s3_bucket.config.id
  key          = "rules/rules.yaml"
  source       = "${path.module}/../../rules/rules.yaml"
  etag         = filemd5("${path.module}/../../rules/rules.yaml")
  content_type = "application/x-yaml"
}

resource "aws_s3_object" "whitelist" {
  bucket       = aws_s3_bucket.config.id
  key          = "rules/whitelist.yaml"
  source       = "${path.module}/../../rules/whitelist.yaml"
  etag         = filemd5("${path.module}/../../rules/whitelist.yaml")
  content_type = "application/x-yaml"
}

resource "aws_s3_object" "correlation_rules" {
  bucket       = aws_s3_bucket.config.id
  key          = "rules/correlation_rules.yaml"
  source       = "${path.module}/../../rules/correlation_rules.yaml"
  etag         = filemd5("${path.module}/../../rules/correlation_rules.yaml")
  content_type = "application/x-yaml"
}
