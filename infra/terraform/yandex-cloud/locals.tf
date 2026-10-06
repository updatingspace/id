locals {
  name_prefix = lower(replace(var.name_prefix, "_", "-"))

  public_base_url = var.public_domain != "" ? "https://${var.public_domain}" : "https://id.localhost"

  frontend_bucket_name  = var.frontend_bucket_name != "" ? var.frontend_bucket_name : "${local.name_prefix}-frontend-${substr(md5("${var.folder_id}-frontend"), 0, 8)}"
  media_bucket_name     = var.media_bucket_name != "" ? var.media_bucket_name : "${local.name_prefix}-media-${substr(md5("${var.folder_id}-media"), 0, 8)}"
  export_bucket_name    = var.export_bucket_name != "" ? var.export_bucket_name : "${local.name_prefix}-exports-${substr(md5("${var.folder_id}-exports"), 0, 8)}"
  container_registry_id = var.container_registry_id != "" ? var.container_registry_id : yandex_container_registry.id[0].id
  backend_network_id    = var.existing_network_id != "" ? var.existing_network_id : (var.enable_serverless_vpc ? yandex_vpc_network.id[0].id : "")

  runtime_secret_entries = merge(
    var.lockbox_secret_entries,
    var.live_secret_entries,
    var.enable_rust_export && var.export_operation_secret_id == "" ? {
      ID_EXPORT_OPERATION_KEY = random_password.export_operation[0].result
    } : {},
    var.enable_rust_export ? {
      ID_EXPORT_ESCROW_KEY = random_id.export_escrow[0].b64_std
    } : {},
    {
      S3_ACCESS_KEY_ID     = lookup(var.live_secret_entries, "S3_ACCESS_KEY_ID", yandex_iam_service_account_static_access_key.automation.access_key)
      S3_SECRET_ACCESS_KEY = lookup(var.live_secret_entries, "S3_SECRET_ACCESS_KEY", yandex_iam_service_account_static_access_key.automation.secret_key)
    },
    var.monium_api_key != "" ? {
      MONIUM_API_KEY = var.monium_api_key
    } : {},
    var.enable_shared_cache ? {
      REDIS_URL = "rediss://:${random_password.cache[0].result}@c-${yandex_mdb_redis_cluster.cache[0].id}.rw.mdb.yandexcloud.net:6380/0?ssl_cert_reqs=required&socket_connect_timeout=3&socket_timeout=3"
    } : {},
  )

  allowed_hosts = join(",", compact([
    var.public_domain,
    ".yandexcloud.net",
    "localhost",
    "127.0.0.1",
  ]))

  default_from_domain = var.public_domain != "" ? var.public_domain : "id.localhost"

  backend_env = { for key, value in merge(
    {
      BUILD_ID                    = var.container_image_tag
      CORS_ALLOWED_ORIGINS        = local.public_base_url
      CSRF_TRUSTED_ORIGINS        = local.public_base_url
      DB_DRIVER                   = "ydb"
      DEFAULT_FROM_EMAIL          = "no-reply@${local.default_from_domain}"
      DJANGO_ALLOWED_HOSTS        = local.allowed_hosts
      DJANGO_DEBUG                = "false"
      ID_ACTIVATION_BASE_URL      = local.public_base_url
      ID_PUBLIC_BASE_URL          = "${local.public_base_url}/api/v1"
      LOG_FORMAT                  = "json"
      LOG_LEVEL                   = "INFO"
      MEDIA_PUBLIC_BASE_URL       = "https://storage.yandexcloud.net/${local.media_bucket_name}"
      MEDIA_STORAGE_DRIVER        = "s3"
      MONIUM_PROJECT              = "folder__${var.folder_id}"
      OIDC_ISSUER                 = local.public_base_url
      OIDC_PUBLIC_BASE_URL        = local.public_base_url
      MONIUM_CLUSTER              = var.name_prefix
      MONIUM_SERVICE_NAME         = "updspace-id"
      OTEL_ENABLED                = var.monium_api_key != "" ? "true" : "false"
      OTEL_SERVICE_NAME           = "updspace-id"
      OTEL_EXPORTER_OTLP_ENDPOINT = "ingest.monium.yandex.cloud:443"
      OTEL_TRACES_SAMPLER         = "parentbased_traceidratio"
      OTEL_TRACES_SAMPLER_ARG     = "0.1"
      S3_BUCKET_NAME              = local.media_bucket_name
      S3_ENDPOINT_URL             = "https://storage.yandexcloud.net"
      S3_REGION                   = var.region
      SECURE_SSL_REDIRECT         = "true"
      SESSION_COOKIE_SECURE       = "true"
      YDB_CREDENTIALS_MODE        = "metadata"
      YDB_DATABASE                = yandex_ydb_database_serverless.id.database_path
      YDB_ENDPOINT                = yandex_ydb_database_serverless.id.ydb_full_endpoint
      YDB_NAME                    = "default"
    },
    var.live_service_environment,
    var.service_environment,
    {
      BUILD_ID        = var.container_image_tag
      YDB_CACHE_TABLE = yandex_ydb_table.cache.path
      # This stack's media bucket is private; browsers need signed object URLs.
      S3_QUERYSTRING_AUTH = "true"
    },
  ) : key => value if key != "PORT" } # Injected by Serverless Containers.

  api_gateway_spec = templatefile("${path.module}/templates/api-gateway.openapi.yaml.tftpl", {
    backend_container_id                 = var.gateway_rust_me_container_id != "" ? var.gateway_rust_me_container_id : yandex_serverless_container.rust_api[0].id
    rust_api_container_id                = var.gateway_rust_me || var.gateway_rust_form_token || var.gateway_rust_jwks || var.gateway_rust_login_api || var.gateway_rust_passkey_login || var.gateway_rust_passkey_registration || var.gateway_rust_totp_management || var.gateway_rust_passkey_rename || var.gateway_rust_passkey_delete || var.gateway_rust_email_verify_api || var.gateway_rust_signup_api || var.gateway_rust_password_reset_api || var.gateway_rust_health || var.gateway_rust_oauth_providers || var.gateway_rust_internal_identity || var.gateway_rust_exchange || var.gateway_rust_magic_link || var.gateway_rust_portal_me ? (var.gateway_rust_me_container_id != "" ? var.gateway_rust_me_container_id : yandex_serverless_container.rust_api[0].id) : ""
    rust_sessions_container_id           = var.gateway_rust_sessions_container_id != "" ? var.gateway_rust_sessions_container_id : (var.gateway_rust_me_container_id != "" ? var.gateway_rust_me_container_id : (var.enable_rust_stack ? yandex_serverless_container.rust_api[0].id : ""))
    rust_sessions_mutations_container_id = var.gateway_rust_sessions_mutations_container_id != "" ? var.gateway_rust_sessions_mutations_container_id : (var.enable_rust_stack ? yandex_serverless_container.rust_api[0].id : "")
    web_container_id                     = var.gateway_use_rust || var.gateway_rust_login || var.gateway_rust_account || var.gateway_rust_admin || var.gateway_rust_recovery_pages || var.gateway_rust_signup_page || var.gateway_rust_home_page || var.gateway_rust_oidc ? (var.gateway_rust_web_container_id != "" ? var.gateway_rust_web_container_id : yandex_serverless_container.rust_web[0].id) : ""
    gateway_use_rust                     = var.gateway_use_rust
    gateway_rust_me                      = var.gateway_rust_me
    gateway_rust_form_token              = var.gateway_rust_form_token
    gateway_rust_jwks                    = var.gateway_rust_jwks
    gateway_rust_discovery               = var.gateway_rust_discovery
    gateway_rust_oidc                    = var.gateway_rust_oidc
    gateway_rust_oidc_authorize_post     = var.gateway_rust_oidc_authorize_post
    oidc_rust_routes = {
      "/oauth/authorize"         = var.gateway_rust_oidc_authorize_post ? ["get", "post"] : ["get"]
      "/oauth/authorize/prepare" = ["get"]
      "/oauth/authorize/approve" = ["post"]
      "/oauth/authorize/deny"    = ["post"]
      "/oauth/token"             = ["post"]
      "/oauth/revoke"            = ["post"]
      "/oauth/userinfo"          = ["get", "post"]
    }
    gateway_rust_login_api            = var.gateway_rust_login_api
    gateway_rust_passkey_login        = var.gateway_rust_passkey_login
    gateway_rust_passkey_registration = var.gateway_rust_passkey_registration
    gateway_rust_totp_management      = var.gateway_rust_totp_management
    gateway_rust_passkey_rename       = var.gateway_rust_passkey_rename
    gateway_rust_passkey_delete       = var.gateway_rust_passkey_delete
    gateway_rust_email_verify_api     = var.gateway_rust_email_verify_api
    gateway_rust_signup_api           = var.gateway_rust_signup_api
    gateway_rust_password_reset_api   = var.gateway_rust_password_reset_api
    gateway_rust_health               = var.gateway_rust_health
    gateway_rust_oauth_providers      = var.gateway_rust_oauth_providers
    gateway_rust_internal_identity    = var.gateway_rust_internal_identity
    gateway_rust_exchange             = var.gateway_rust_exchange
    gateway_rust_magic_link           = var.gateway_rust_magic_link
    gateway_rust_portal_me            = var.gateway_rust_portal_me
    gateway_rust_sessions_read        = var.gateway_rust_sessions_read
    gateway_rust_sessions_mutations   = var.gateway_rust_sessions_mutations
    gateway_rust_logout               = var.gateway_rust_logout
    gateway_rust_profile              = var.gateway_rust_profile
    gateway_rust_avatar_delete        = var.gateway_rust_avatar_delete
    gateway_rust_avatar_upload        = var.gateway_rust_avatar_upload
    gateway_rust_preferences          = var.gateway_rust_preferences
    gateway_rust_apps                 = var.gateway_rust_apps
    gateway_rust_security_read        = var.gateway_rust_security_read
    gateway_rust_email_status         = var.gateway_rust_email_status
    gateway_rust_email_cancel         = var.gateway_rust_email_cancel
    gateway_rust_email_resend         = var.gateway_rust_email_resend
    gateway_rust_email_change         = var.gateway_rust_email_change
    gateway_rust_password_change      = var.gateway_rust_password_change
    gateway_rust_account_jwt          = var.gateway_rust_account_jwt
    gateway_rust_export               = var.enable_rust_export_api
    gateway_rust_export_delayed       = var.enable_rust_export_delayed
    security_read_routes = concat([
      "/api/v1/auth/mfa/status",
      "/api/v1/auth/passkeys",
      "/api/v1/auth/security",
      "/api/v1/auth/login-history",
    ], var.gateway_rust_email_status ? ["/api/v1/auth/email"] : [])
    gateway_rust_login          = var.gateway_rust_login
    gateway_rust_account        = var.gateway_rust_account
    gateway_rust_admin          = var.gateway_rust_admin
    gateway_rust_recovery_pages = var.gateway_rust_recovery_pages
    enable_rust_password_reset  = var.enable_rust_password_reset
    enable_rust_email_verify    = var.enable_rust_email_verify
    enable_rust_signup          = var.enable_rust_signup
    gateway_rust_signup_page    = var.gateway_rust_signup_page
    gateway_rust_home_page      = var.gateway_rust_home_page
    frontend_static_routes      = var.gateway_use_rust ? concat(var.enable_rust_signup || var.gateway_rust_signup_page ? [] : ["signup"], var.enable_rust_password_reset ? [] : ["forgot-password", "reset-password"], var.enable_rust_email_verify ? [] : ["verify-email"]) : concat(var.gateway_rust_login ? [] : ["login"], var.gateway_rust_signup_page ? [] : ["signup"], var.gateway_rust_oidc ? ["legacy/account"] : ["authorize", "legacy/account"], var.gateway_rust_account ? [] : ["account"], var.gateway_rust_recovery_pages ? [] : ["forgot-password", "reset-password", "verify-email"])
    frontend_bucket             = local.frontend_bucket_name
    gateway_service_account_id  = yandex_iam_service_account.gateway.id
  })

  api_gateway_id     = var.existing_api_gateway_id != "" ? data.yandex_api_gateway.existing[0].id : yandex_api_gateway.id[0].id
  api_gateway_domain = var.existing_api_gateway_id != "" ? data.yandex_api_gateway.existing[0].domain : yandex_api_gateway.id[0].domain
}
