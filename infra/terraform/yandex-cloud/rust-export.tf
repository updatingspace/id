# Account exports have a dedicated private bucket. Application jobs revoke
# download access at 24 hours; lifecycle rules bound orphaned uploads/objects.
# Escrow snapshots need a full 24-hour waiting period plus a 24-hour delivery
# window, so their fallback expiry must be later than the application deadline.
resource "random_password" "export_operation" {
  count   = var.enable_rust_export && var.export_operation_secret_id == "" ? 1 : 0
  length  = 64
  special = false
}

resource "random_id" "export_escrow" {
  count       = var.enable_rust_export ? 1 : 0
  byte_length = 32
}

resource "random_password" "deletion_operation" {
  count   = var.enable_rust_account_deletion_api ? 1 : 0
  length  = 64
  special = false
}

resource "yandex_storage_bucket" "export" {
  count         = var.enable_rust_export && var.manage_rust_export_bucket ? 1 : 0
  access_key    = yandex_iam_service_account_static_access_key.automation.access_key
  secret_key    = yandex_iam_service_account_static_access_key.automation.secret_key
  bucket        = local.export_bucket_name
  force_destroy = false

  lifecycle_rule {
    id      = "abort-incomplete-exports"
    enabled = true
    filter { prefix = "exports/" }
    abort_incomplete_multipart_upload_days = 1
  }

  lifecycle_rule {
    id      = "remove-orphan-owner-exports"
    enabled = true
    filter { prefix = "exports/user_" }
    expiration { days = 2 }
  }

  lifecycle_rule {
    id      = "remove-orphan-escrow-exports"
    enabled = true
    filter { prefix = "exports/escrow/" }
    expiration { days = 4 }
  }

  lifecycle { prevent_destroy = true }
}
