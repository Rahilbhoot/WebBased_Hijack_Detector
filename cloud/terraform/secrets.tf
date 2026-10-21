# ==========================================
# AWS Secrets Manager Configuration
# ==========================================

resource "random_id" "admin_enrollment_key" {
  byte_length = 32
}

resource "aws_secretsmanager_secret" "admin_secret" {
  name                    = "${var.project_name}-${var.environment}-admin-secret"
  description             = "Master enrollment secret and admin configuration for ${var.project_name}"
  recovery_window_in_days = 0

  tags = {
    Name = "${var.project_name}-${var.environment}-admin-secret"
  }
}

resource "aws_secretsmanager_secret_version" "admin_secret_val" {
  secret_id = aws_secretsmanager_secret.admin_secret.id
  secret_string = jsonencode({
    initial_enrollment_key = random_id.admin_enrollment_key.hex
    created_at             = timestamp()
    description            = "Use this key to authorize the first administrative device registration"
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}
