# ==========================================
# DynamoDB Tables Configuration
# ==========================================

# ------------------------------------------
# Alerts Table
# ------------------------------------------
resource "aws_dynamodb_table" "alerts" {
  name         = "${var.project_name}-${var.environment}-alerts"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "device_id"
  range_key    = "timestamp"

  attribute {
    name = "device_id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  attribute {
    name = "severity"
    type = "S"
  }

  global_secondary_index {
    name            = "SeverityIndex"
    hash_key        = "severity"
    range_key       = "timestamp"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-alerts"
  }
}

# ------------------------------------------
# Devices Table (Registry & Status)
# ------------------------------------------
resource "aws_dynamodb_table" "devices" {
  name         = "${var.project_name}-${var.environment}-devices"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "device_id"

  attribute {
    name = "device_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-devices"
  }
}

# ------------------------------------------
# Event History Table (Sliding Window & TTL)
# ------------------------------------------
resource "aws_dynamodb_table" "event_history" {
  name         = "${var.project_name}-${var.environment}-event-history"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "device_id"
  range_key    = "timestamp"

  attribute {
    name = "device_id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = false
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-event-history"
  }
}
