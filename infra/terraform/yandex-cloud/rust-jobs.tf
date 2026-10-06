# Disabled by default. The private job is deliberately absent from API Gateway.
locals {
  rust_mail_job_env = merge({
    ID_JOBS_HTTP_ENABLED                  = "true"
    ID_GRAVATAR_JOB_ENABLED               = var.enable_gravatar_job && var.gravatar_rust_jobs_container_id != "" ? "true" : "false"
    GRAVATAR_BATCH_LIMIT                  = "25"
    ID_PASSWORD_RESET_MAIL_ENABLED        = var.enable_rust_password_reset ? "true" : "false"
    ID_PASSWORD_RESET_URL                 = "${local.public_base_url}/reset-password"
    ID_EMAIL_VERIFY_MAIL_ENABLED          = var.enable_rust_email_verify ? "true" : "false"
    ID_EMAIL_VERIFY_URL                   = "${local.public_base_url}/verify-email"
    ID_MAGIC_LINK_MAIL_ENABLED            = var.gateway_rust_magic_link ? "true" : "false"
    ID_MAGIC_LINK_PUBLIC_URL              = "${local.public_base_url}/api/v1/auth/magic-link/consume"
    YDB_CREDENTIALS_MODE                  = "metadata"
    YDB_DATABASE                          = yandex_ydb_database_serverless.id.database_path
    YDB_ENDPOINT                          = split("?", yandex_ydb_database_serverless.id.ydb_full_endpoint)[0]
    MEDIA_STORAGE_DRIVER                  = lookup(local.backend_env, "MEDIA_STORAGE_DRIVER", "s3")
    S3_BUCKET_NAME                        = lookup(local.backend_env, "S3_BUCKET_NAME", local.media_bucket_name)
    S3_ENDPOINT_URL                       = lookup(local.backend_env, "S3_ENDPOINT_URL", "https://storage.yandexcloud.net")
    S3_REGION                             = lookup(local.backend_env, "S3_REGION", var.region)
    ID_EXPORT_JOBS_ENABLED                = var.enable_rust_export ? "true" : "false"
    ID_EXPORT_ESCROW_MAIL_ROLLOUT_ENABLED = var.enable_rust_export_delayed ? "true" : "false"
    ID_EXPORT_ESCROW_JOBS_ROLLOUT_ENABLED = var.enable_rust_export_delayed ? "true" : "false"
    ID_EXPORT_PUBLIC_ORIGIN               = local.public_base_url
    ID_EXPORT_S3_BUCKET_NAME              = var.enable_rust_export ? local.export_bucket_name : ""
    YMQ_QUEUE_URL                         = var.enable_rust_mail_queue ? yandex_message_queue.rust_mail[0].id : ""
    DEFAULT_FROM_EMAIL                    = lookup(local.backend_env, "DEFAULT_FROM_EMAIL", "")
    EMAIL_HOST                            = lookup(local.backend_env, "EMAIL_HOST", "")
    EMAIL_PORT                            = lookup(local.backend_env, "EMAIL_PORT", "587")
    EMAIL_USE_TLS                         = lookup(local.backend_env, "EMAIL_USE_TLS", "true")
    }, contains(keys(local.runtime_secret_entries), "EMAIL_HOST_USER") ? {} : {
    EMAIL_HOST_USER = lookup(local.backend_env, "EMAIL_HOST_USER", "")
  })
}

resource "yandex_function_trigger" "rust_mail_recovery_existing" {
  count = var.enable_rust_mail_recovery_timer && !var.enable_rust_mail_job ? 1 : 0
  name  = "${local.name_prefix}-rust-mail-recovery"

  timer {
    cron_expression = "*/5 * * * ? *"
  }
  container {
    id                 = var.gravatar_rust_jobs_container_id
    path               = "/internal/jobs/recover-mail"
    service_account_id = yandex_iam_service_account.scheduler[0].id
    retry_attempts     = 2
    retry_interval     = 60
  }
  depends_on = [yandex_serverless_container_iam_binding.gravatar_rust_invoker]
}

resource "yandex_function_trigger" "rust_export_recovery_existing" {
  count = var.enable_rust_export_recovery_timer ? 1 : 0
  name  = "${local.name_prefix}-rust-export-recovery"

  timer {
    cron_expression = "*/5 * * * ? *"
  }
  container {
    id                 = var.gravatar_rust_jobs_container_id
    path               = "/internal/jobs/recover-export"
    service_account_id = yandex_iam_service_account.scheduler[0].id
    retry_attempts     = 2
    retry_interval     = 60
  }
  depends_on = [yandex_serverless_container_iam_binding.gravatar_rust_invoker]
}

resource "yandex_function_trigger" "rust_verify_mail_recovery_existing" {
  count = var.enable_rust_verify_mail_recovery_timer ? 1 : 0
  name  = "${local.name_prefix}-rust-verify-mail-recovery"

  timer {
    cron_expression = "*/5 * * * ? *"
  }
  container {
    id                 = var.gravatar_rust_jobs_container_id
    path               = "/internal/jobs/recover-verify-mail"
    service_account_id = yandex_iam_service_account.scheduler[0].id
    retry_attempts     = 2
    retry_interval     = 60
  }
  depends_on = [yandex_serverless_container_iam_binding.gravatar_rust_invoker]
}

resource "yandex_function_trigger" "rust_security_mail_recovery_existing" {
  count = var.enable_rust_security_mail_recovery_timer ? 1 : 0
  name  = "${local.name_prefix}-rust-security-mail-recovery"

  timer {
    cron_expression = "*/5 * * * ? *"
  }
  container {
    id                 = var.gravatar_rust_jobs_container_id
    path               = "/internal/jobs/recover-security-mail"
    service_account_id = yandex_iam_service_account.scheduler[0].id
    retry_attempts     = 2
    retry_interval     = 60
  }
  depends_on = [yandex_serverless_container_iam_binding.gravatar_rust_invoker]
}

resource "yandex_function_trigger" "rust_reset_mail_recovery_existing" {
  count = var.enable_rust_reset_mail_recovery_timer ? 1 : 0
  name  = "${local.name_prefix}-rust-reset-mail-recovery"

  timer {
    cron_expression = "*/5 * * * ? *"
  }
  container {
    id                 = var.gravatar_rust_jobs_container_id
    path               = "/internal/jobs/recover-reset-mail"
    service_account_id = yandex_iam_service_account.scheduler[0].id
    retry_attempts     = 2
    retry_interval     = 60
  }
  depends_on = [yandex_serverless_container_iam_binding.gravatar_rust_invoker]
}

resource "yandex_function_trigger" "rust_password_mail_recovery_existing" {
  count = var.enable_rust_password_mail_recovery_timer ? 1 : 0
  name  = "${local.name_prefix}-rust-password-mail-recovery"

  timer {
    cron_expression = "*/5 * * * ? *"
  }
  container {
    id                 = var.gravatar_rust_jobs_container_id
    path               = "/internal/jobs/recover-password-mail"
    service_account_id = yandex_iam_service_account.scheduler[0].id
    retry_attempts     = 2
    retry_interval     = 60
  }
  depends_on = [yandex_serverless_container_iam_binding.gravatar_rust_invoker]
}

resource "yandex_iam_service_account" "rust_mail_queue_admin" {
  count = var.enable_rust_mail_queue ? 1 : 0
  name  = "${local.name_prefix}-mail-queue-admin"
}

resource "yandex_resourcemanager_folder_iam_member" "rust_mail_queue_admin" {
  count     = var.enable_rust_mail_queue ? 1 : 0
  folder_id = var.folder_id
  role      = "ymq.admin"
  member    = "serviceAccount:${yandex_iam_service_account.rust_mail_queue_admin[0].id}"
}

resource "yandex_iam_service_account_static_access_key" "rust_mail_queue_admin" {
  count              = var.enable_rust_mail_queue ? 1 : 0
  service_account_id = yandex_iam_service_account.rust_mail_queue_admin[0].id
  description        = "Terraform-only key for the Rust mail queue"
}

resource "yandex_message_queue" "rust_mail" {
  count                      = var.enable_rust_mail_queue ? 1 : 0
  name                       = "${local.name_prefix}-new-device-mail"
  region_id                  = var.region
  access_key                 = yandex_iam_service_account_static_access_key.rust_mail_queue_admin[0].access_key
  secret_key                 = yandex_iam_service_account_static_access_key.rust_mail_queue_admin[0].secret_key
  visibility_timeout_seconds = 600
  message_retention_seconds  = 1209600

  depends_on = [yandex_resourcemanager_folder_iam_member.rust_mail_queue_admin]

  lifecycle {
    prevent_destroy = true
  }
}

resource "yandex_iam_service_account" "rust_mail_queue_writer" {
  count = var.enable_rust_mail_queue ? 1 : 0
  name  = "${local.name_prefix}-mail-queue-writer"
}

resource "yandex_resourcemanager_folder_iam_member" "rust_mail_queue_writer" {
  count     = var.enable_rust_mail_queue ? 1 : 0
  folder_id = var.folder_id
  role      = "ymq.writer"
  member    = "serviceAccount:${yandex_iam_service_account.rust_mail_queue_writer[0].id}"
}

resource "yandex_iam_service_account_static_access_key" "rust_mail_queue_writer" {
  count              = var.enable_rust_mail_queue ? 1 : 0
  service_account_id = yandex_iam_service_account.rust_mail_queue_writer[0].id
  description        = "Send-only key for Rust mail outbox wakeups"
}

resource "yandex_lockbox_secret" "rust_mail_queue_writer" {
  count       = var.enable_rust_mail_queue ? 1 : 0
  name        = "${local.name_prefix}-mail-queue-writer"
  description = "Rust mail queue SendMessage credentials"
}

resource "yandex_lockbox_secret_version" "rust_mail_queue_writer" {
  count     = var.enable_rust_mail_queue ? 1 : 0
  secret_id = yandex_lockbox_secret.rust_mail_queue_writer[0].id

  entries {
    key        = "YMQ_ACCESS_KEY_ID"
    text_value = yandex_iam_service_account_static_access_key.rust_mail_queue_writer[0].access_key
  }
  entries {
    key        = "YMQ_SECRET_ACCESS_KEY"
    text_value = yandex_iam_service_account_static_access_key.rust_mail_queue_writer[0].secret_key
  }
}

resource "yandex_lockbox_secret_iam_member" "rust_mail_queue_writer" {
  count     = var.enable_rust_mail_queue ? 1 : 0
  secret_id = yandex_lockbox_secret.rust_mail_queue_writer[0].id
  role      = "lockbox.payloadViewer"
  member    = "serviceAccount:${yandex_iam_service_account.runtime.id}"
}

resource "yandex_iam_service_account" "rust_mail_trigger" {
  count = var.enable_rust_mail_job ? 1 : 0
  name  = "${local.name_prefix}-mail-trigger"
}

resource "yandex_resourcemanager_folder_iam_member" "rust_mail_trigger_reader" {
  count     = var.enable_rust_mail_job ? 1 : 0
  folder_id = var.folder_id
  role      = "ymq.reader"
  member    = "serviceAccount:${yandex_iam_service_account.rust_mail_trigger[0].id}"
}

resource "yandex_serverless_container" "rust_mail_job" {
  count              = var.enable_rust_mail_job ? 1 : 0
  name               = "${local.name_prefix}-rust-mail"
  description        = "Private Rust account-security mail worker"
  memory             = 512
  cores              = 1
  core_fraction      = 100
  concurrency        = 1
  execution_timeout  = "600s"
  service_account_id = yandex_iam_service_account.runtime.id

  depends_on = [
    yandex_resourcemanager_folder_iam_member.runtime_image_puller,
    yandex_lockbox_secret_iam_member.runtime_payload_viewer,
    yandex_ydb_database_iam_binding.runtime_editor,
    yandex_lockbox_secret_iam_member.rust_mail_queue_writer,
  ]

  runtime {
    type = "http"
  }
  dynamic "connectivity" {
    for_each = local.backend_network_id != "" ? [1] : []
    content {
      network_id = local.backend_network_id
    }
  }
  metadata_options {
    gce_http_endpoint = 1
  }
  image {
    url         = "cr.yandex/${local.container_registry_id}/updatingspace-id-jobs:${var.rust_mail_job_image_tag}"
    digest      = var.rust_mail_job_image_digest
    environment = local.rust_mail_job_env
  }
  dynamic "secrets" {
    for_each = nonsensitive(toset([
      for key in keys(local.runtime_secret_entries) : key
      if contains(["EMAIL_HOST_USER", "EMAIL_HOST_PASSWORD", "S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY"], key) || (var.enable_rust_password_reset && key == "ID_PASSWORD_RESET_HMAC_KEY") || (var.enable_rust_email_verify && key == "ID_EMAIL_VERIFY_HMAC_KEY") || (var.gateway_rust_magic_link && contains(["ID_TOKEN_HASH_SECRET", "DJANGO_SECRET_KEY"], key)) || (var.enable_rust_export_delayed && key == "ID_EXPORT_ESCROW_KEY")
    ]))
    content {
      id                   = yandex_lockbox_secret.runtime.id
      version_id           = yandex_lockbox_secret_version.runtime.id
      key                  = secrets.key
      environment_variable = secrets.key
    }
  }
  dynamic "secrets" {
    for_each = var.enable_rust_mail_queue ? toset(["YMQ_ACCESS_KEY_ID", "YMQ_SECRET_ACCESS_KEY"]) : toset([])
    content {
      id                   = yandex_lockbox_secret.rust_mail_queue_writer[0].id
      version_id           = yandex_lockbox_secret_version.rust_mail_queue_writer[0].id
      key                  = secrets.key
      environment_variable = secrets.key
    }
  }
  log_options {
    log_group_id = yandex_logging_group.id.id
    min_level    = "INFO"
  }

  lifecycle {
    precondition {
      condition = (
        var.enable_rust_mail_queue &&
        var.rust_mail_job_image_tag != "" &&
        var.rust_mail_job_image_digest != "" &&
        local.rust_mail_job_env.EMAIL_HOST != "" &&
        local.rust_mail_job_env.DEFAULT_FROM_EMAIL != "" &&
        (!var.enable_rust_password_reset || contains(nonsensitive(keys(local.runtime_secret_entries)), "ID_PASSWORD_RESET_HMAC_KEY")) &&
        (!var.enable_rust_email_verify || contains(nonsensitive(keys(local.runtime_secret_entries)), "ID_EMAIL_VERIFY_HMAC_KEY")) &&
        (!var.gateway_rust_magic_link || contains(nonsensitive(keys(local.runtime_secret_entries)), "ID_TOKEN_HASH_SECRET") || contains(nonsensitive(keys(local.runtime_secret_entries)), "DJANGO_SECRET_KEY"))
      )
      error_message = "Rust mail job requires the persistent queue, an exact CI image tag/digest, SMTP host/from address and HMAC keys for enabled recovery flows."
    }
  }
}

resource "yandex_serverless_container_iam_binding" "rust_mail_invoker" {
  count        = var.enable_rust_mail_job ? 1 : 0
  container_id = yandex_serverless_container.rust_mail_job[0].id
  role         = "serverless.containers.invoker"
  members      = ["serviceAccount:${yandex_iam_service_account.rust_mail_trigger[0].id}"]
}

resource "yandex_function_trigger" "rust_mail_recovery" {
  count = var.enable_rust_mail_job ? 1 : 0
  name  = "${local.name_prefix}-mail-recovery"

  timer {
    cron_expression = "*/5 * * * ? *"
  }
  container {
    id                 = yandex_serverless_container.rust_mail_job[0].id
    path               = "/internal/jobs/recover"
    service_account_id = yandex_iam_service_account.rust_mail_trigger[0].id
    retry_attempts     = 2
    retry_interval     = 60
  }
  depends_on = [
    yandex_serverless_container_iam_binding.rust_mail_invoker,
    data.yandex_serverless_container.deployed_rust_mail_job,
  ]
}

resource "yandex_function_trigger" "rust_mail_publish" {
  count = var.enable_rust_mail_job ? 1 : 0
  name  = "${local.name_prefix}-mail-publish"

  timer {
    cron_expression = "* * * * ? *"
  }
  container {
    id                 = yandex_serverless_container.rust_mail_job[0].id
    path               = "/internal/jobs/publish"
    service_account_id = yandex_iam_service_account.rust_mail_trigger[0].id
    retry_attempts     = 2
    retry_interval     = 60
  }
  depends_on = [
    yandex_serverless_container_iam_binding.rust_mail_invoker,
    data.yandex_serverless_container.deployed_rust_mail_job,
  ]
}

resource "yandex_function_trigger" "rust_mail_queue" {
  count = var.enable_rust_mail_job ? 1 : 0
  name  = "${local.name_prefix}-mail-queue"

  message_queue {
    queue_id           = yandex_message_queue.rust_mail[0].arn
    service_account_id = yandex_iam_service_account.rust_mail_trigger[0].id
    batch_cutoff       = "5"
    batch_size         = "10"
    visibility_timeout = "600"
  }
  container {
    id                 = yandex_serverless_container.rust_mail_job[0].id
    path               = "/internal/jobs/mail"
    service_account_id = yandex_iam_service_account.rust_mail_trigger[0].id
    retry_attempts     = 2
    retry_interval     = 60
  }
  depends_on = [
    yandex_resourcemanager_folder_iam_member.rust_mail_trigger_reader,
    yandex_serverless_container_iam_binding.rust_mail_invoker,
    data.yandex_serverless_container.deployed_rust_mail_job,
  ]
}
