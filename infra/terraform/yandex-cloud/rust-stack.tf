locals {
  rust_api_env = merge(local.backend_env, {
    BUILD_ID                                   = var.rust_api_image_tag
    ID_AUTH_ME_ENABLED                         = "true"
    ID_AUTH_ADMIN_READ_ENABLED                 = var.gateway_rust_admin ? "true" : "false"
    ID_AUTH_ADMIN_SUSPEND_ENABLED              = var.gateway_rust_admin_suspend ? "true" : "false"
    ID_AUTH_ADMIN_CLIENT_REDIRECTS_ENABLED     = var.gateway_rust_admin_client_redirects ? "true" : "false"
    ID_AUTH_FORM_TOKEN_ENABLED                 = "true"
    ID_AUTH_LOGIN_PILOT_ENABLED                = "true"
    ID_AUTH_SESSIONS_READ_ENABLED              = "true"
    ID_AUTH_SESSIONS_MUTATIONS_ROLLOUT_ENABLED = "true"
    ID_AUTH_LOGOUT_ROLLOUT_ENABLED             = "true"
    ID_AUTH_PROFILE_ROLLOUT_ENABLED            = "true"
    ID_AUTH_AVATAR_DELETE_ROLLOUT_ENABLED      = var.gateway_rust_avatar_delete ? "true" : "false"
    ID_AUTH_AVATAR_UPLOAD_ROLLOUT_ENABLED      = var.gateway_rust_avatar_upload ? "true" : "false"
    ID_AUTH_PREFERENCES_ROLLOUT_ENABLED        = "true"
    ID_AUTH_APPS_PILOT_ENABLED                 = "true"
    ID_AUTH_SECURITY_READ_PILOT_ENABLED        = "true"
    ID_AUTH_EMAIL_CANCEL_PILOT_ENABLED         = var.gateway_rust_email_cancel ? "true" : "false"
    ID_AUTH_EMAIL_CHANGE_PILOT_ENABLED         = var.gateway_rust_email_change ? "true" : "false"
    ID_AUTH_PASSWORD_CHANGE_PILOT_ENABLED      = var.gateway_rust_password_change ? "true" : "false"
    ID_AUTH_JWT_SESSION_PILOT_ENABLED          = var.gateway_rust_account_jwt ? "true" : "false"
    ID_OIDC_JWKS_ENABLED                       = "false"
    ID_OIDC_TOKEN_ROLLOUT_ENABLED              = "true"
    ID_OIDC_AUTHORIZE_ROLLOUT_ENABLED          = "true"
    ID_AUTH_PASSKEY_LOGIN_PILOT_ENABLED        = "true"
    ID_AUTH_PASSWORD_RESET_PILOT_ENABLED       = var.enable_rust_password_reset ? "true" : "false"
    ID_AUTH_OAUTH_PROVIDERS_ENABLED            = var.gateway_rust_oauth_providers ? "true" : "false"
    ID_INTERNAL_IDENTITY_ENABLED               = var.gateway_rust_internal_identity ? "true" : "false"
    ID_AUTH_EXCHANGE_ROLLOUT_ENABLED           = var.gateway_rust_exchange ? "true" : "false"
    ID_AUTH_MAGIC_LINK_CONSUME_ROLLOUT_ENABLED = var.gateway_rust_magic_link ? "true" : "false"
    ID_AUTH_MAGIC_LINK_REQUEST_PILOT_ENABLED   = var.gateway_rust_magic_link ? "true" : "false"
    ID_MAGIC_LINK_REDIRECT_ORIGINS             = var.gateway_rust_magic_link ? var.magic_link_redirect_origins : ""
    ID_MAGIC_LINK_DEFAULT_REDIRECT             = var.gateway_rust_magic_link ? var.magic_link_default_redirect : ""
    ID_MAGIC_LINK_PUBLIC_URL                   = "${local.public_base_url}/api/v1/auth/magic-link/consume"
    ID_PORTAL_ME_ENABLED                       = var.gateway_rust_portal_me ? "true" : "false"
    ID_AUTH_EMAIL_VERIFY_PILOT_ENABLED         = var.enable_rust_email_verify ? "true" : "false"
    ID_AUTH_EMAIL_RESEND_ENABLED               = var.gateway_rust_email_resend ? "true" : "false"
    ID_AUTH_SIGNUP_PILOT_ENABLED               = var.enable_rust_signup ? "true" : "false"
    ID_RUST_EARLY_ROLLOUT_ENABLED              = "true"
    ID_WEBAUTHN_RP_ID                          = var.public_domain
    ID_WEBAUTHN_ORIGIN                         = local.public_base_url
    YDB_ENDPOINT                               = split("?", local.backend_env.YDB_ENDPOINT)[0]
    S3_QUERYSTRING_AUTH                        = "true"
    ID_EXPORT_S3_BUCKET_NAME                   = var.enable_rust_export ? local.export_bucket_name : ""
    ID_EXPORT_API_ROLLOUT_ENABLED              = var.enable_rust_export_api ? "true" : "false"
    ID_EXPORT_DELAYED_ROLLOUT_ENABLED          = var.enable_rust_export_delayed ? "true" : "false"
    ID_AUTH_DELETION_ROLLOUT_ENABLED           = var.enable_rust_account_deletion_api ? "true" : "false"
  })

  rust_web_env = {
    BUILD_ID                              = var.rust_web_image_tag
    ID_WEB_LOGIN_PILOT_ENABLED            = "true"
    ID_WEB_PASSKEY_PILOT_ENABLED          = "true"
    ID_WEB_RECOVERY_PILOT_ENABLED         = var.enable_rust_password_reset ? "true" : "false"
    ID_WEB_EMAIL_VERIFY_PILOT_ENABLED     = var.enable_rust_email_verify ? "true" : "false"
    ID_WEB_SIGNUP_PILOT_ENABLED           = var.enable_rust_signup || var.gateway_rust_signup_page ? "true" : "false"
    ID_WEB_ACCOUNT_PILOT_ENABLED          = "true"
    ID_WEB_ADMIN_ENABLED                  = var.gateway_rust_admin ? "true" : "false"
    ID_WEB_ADMIN_SUSPEND_ENABLED          = var.gateway_rust_admin_suspend ? "true" : "false"
    ID_WEB_ADMIN_CLIENT_REDIRECTS_ENABLED = var.gateway_rust_admin_client_redirects ? "true" : "false"
    ID_WEB_SESSIONS_PILOT_ENABLED         = "true"
    ID_WEB_LOGOUT_PILOT_ENABLED           = "true"
    ID_WEB_PROFILE_PILOT_ENABLED          = "true"
    ID_WEB_PREFERENCES_PILOT_ENABLED      = "true"
    ID_WEB_CONSENTS_PILOT_ENABLED         = "true"
    ID_WEB_CONSENT_PILOT_ENABLED          = "true"
    ID_WEB_APPS_PILOT_ENABLED             = "true"
    ID_WEB_SECURITY_PILOT_ENABLED         = "true"
    ID_WEB_LOGIN_HISTORY_PILOT_ENABLED    = "true"
    ID_WEB_PASSWORD_CHANGE_PILOT_ENABLED  = var.gateway_rust_password_change ? "true" : "false"
    ID_WEB_EMAIL_MANAGEMENT_ENABLED       = var.gateway_rust_email_status && var.gateway_rust_email_cancel && var.gateway_rust_email_verify_api ? "true" : "false"
    ID_WEB_EXPORTS_ENABLED                = var.enable_rust_export_api ? "true" : "false"
    ID_WEB_EXPORT_REDEEM_ENABLED          = var.enable_rust_export_delayed ? "true" : "false"
    ID_WEB_API_ORIGIN                     = local.public_base_url
  }
}

resource "yandex_iam_service_account" "rust_web" {
  count       = var.enable_rust_stack ? 1 : 0
  name        = "${local.name_prefix}-rust-web"
  description = "Topcoat UI: no direct YDB or Lockbox access"
}

resource "yandex_resourcemanager_folder_iam_member" "rust_web_image_puller" {
  count     = var.enable_rust_stack ? 1 : 0
  folder_id = var.folder_id
  role      = "container-registry.images.puller"
  member    = "serviceAccount:${yandex_iam_service_account.rust_web[0].id}"
}

resource "yandex_serverless_container" "rust_api" {
  count              = var.enable_rust_stack ? 1 : 0
  name               = "${local.name_prefix}-rust-api"
  description        = "UpdSpace ID Rust identity API"
  memory             = var.backend_memory_mb
  cores              = var.backend_cores
  core_fraction      = 100
  concurrency        = var.backend_concurrency
  execution_timeout  = "60s"
  service_account_id = yandex_iam_service_account.runtime.id

  depends_on = [
    yandex_resourcemanager_folder_iam_member.runtime_image_puller,
    yandex_lockbox_secret_iam_member.runtime_payload_viewer,
    yandex_ydb_database_iam_binding.runtime_editor,
  ]

  runtime { type = "http" }
  dynamic "connectivity" {
    for_each = local.backend_network_id != "" ? [1] : []
    content { network_id = local.backend_network_id }
  }
  metadata_options { gce_http_endpoint = 1 }
  image {
    url         = "cr.yandex/${local.container_registry_id}/updatingspace-id-api:${var.rust_api_image_tag}"
    digest      = var.rust_api_image_digest
    environment = local.rust_api_env
  }
  dynamic "secrets" {
    for_each = nonsensitive(toset(keys(local.runtime_secret_entries)))
    content {
      id                   = yandex_lockbox_secret.runtime.id
      version_id           = yandex_lockbox_secret_version.runtime.id
      key                  = secrets.key
      environment_variable = secrets.key
    }
  }
  dynamic "secrets" {
    for_each = var.enable_rust_export && var.export_operation_secret_id != "" ? [1] : []
    content {
      id                   = var.export_operation_secret_id
      version_id           = var.export_operation_secret_version_id
      key                  = "ID_EXPORT_OPERATION_KEY"
      environment_variable = "ID_EXPORT_OPERATION_KEY"
    }
  }
  log_options {
    log_group_id = yandex_logging_group.id.id
    min_level    = "INFO"
  }
  lifecycle {
    precondition {
      condition = (var.rust_api_image_tag != "" &&
        can(regex("^sha256:[0-9a-f]{64}$", var.rust_api_image_digest)) &&
        var.public_domain != "" &&
        contains(nonsensitive(keys(local.runtime_secret_entries)), "DJANGO_SECRET_KEY") &&
        contains(nonsensitive(keys(local.runtime_secret_entries)), "OIDC_PRIVATE_KEY_PEM") &&
        contains(nonsensitive(keys(local.runtime_secret_entries)), "OIDC_PUBLIC_KEY_PEM") &&
        contains(nonsensitive(keys(local.runtime_secret_entries)), "OIDC_REFRESH_TOKEN_SALT") &&
        contains(nonsensitive(keys(local.runtime_secret_entries)), "S3_ACCESS_KEY_ID") &&
        contains(nonsensitive(keys(local.runtime_secret_entries)), "S3_SECRET_ACCESS_KEY") &&
        (!var.enable_rust_export || var.export_operation_secret_id != "" || contains(nonsensitive(keys(local.runtime_secret_entries)), "ID_EXPORT_OPERATION_KEY")) &&
        (!var.enable_rust_account_deletion_api || contains(nonsensitive(keys(local.runtime_secret_entries)), "ID_DELETION_OPERATION_KEY")) &&
        (!var.enable_rust_password_reset || contains(nonsensitive(keys(local.runtime_secret_entries)), "ID_PASSWORD_RESET_HMAC_KEY")) &&
        (!var.enable_rust_email_verify || contains(nonsensitive(keys(local.runtime_secret_entries)), "ID_EMAIL_VERIFY_HMAC_KEY")) &&
      (!(var.gateway_rust_internal_identity || var.gateway_rust_portal_me) || contains(nonsensitive(keys(local.runtime_secret_entries)), "BFF_INTERNAL_HMAC_SECRET")))
      error_message = "Rust API requires a tested image tag/digest, public RP domain, session and OIDC signing/refresh secrets, S3 media signing keys and HMAC keys for enabled recovery flows."
    }
  }
}

resource "yandex_serverless_container" "rust_web" {
  count              = var.enable_rust_stack ? 1 : 0
  name               = "${local.name_prefix}-rust-web"
  description        = "UpdSpace ID Topcoat SSR"
  memory             = 512
  cores              = 1
  core_fraction      = 100
  concurrency        = 8
  execution_timeout  = "30s"
  service_account_id = yandex_iam_service_account.rust_web[0].id
  depends_on         = [yandex_resourcemanager_folder_iam_member.rust_web_image_puller]

  runtime { type = "http" }
  image {
    url         = "cr.yandex/${local.container_registry_id}/updatingspace-id-web:${var.rust_web_image_tag}"
    digest      = var.rust_web_image_digest
    environment = local.rust_web_env
  }
  log_options {
    log_group_id = yandex_logging_group.id.id
    min_level    = "INFO"
  }
  lifecycle {
    precondition {
      condition = (var.rust_web_image_tag != "" &&
      can(regex("^sha256:[0-9a-f]{64}$", var.rust_web_image_digest)))
      error_message = "Topcoat UI requires a tested image tag and digest."
    }
  }
}

resource "yandex_serverless_container_iam_binding" "gateway_rust_api_invoker" {
  count        = var.enable_rust_stack ? 1 : 0
  container_id = yandex_serverless_container.rust_api[0].id
  role         = "serverless.containers.invoker"
  members      = ["serviceAccount:${yandex_iam_service_account.gateway.id}"]
}

resource "yandex_serverless_container_iam_binding" "gateway_rust_web_invoker" {
  count        = var.enable_rust_stack ? 1 : 0
  container_id = yandex_serverless_container.rust_web[0].id
  role         = "serverless.containers.invoker"
  members      = ["serviceAccount:${yandex_iam_service_account.gateway.id}"]
}
