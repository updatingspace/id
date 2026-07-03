locals {
  name_prefix = lower(replace(var.name_prefix, "_", "-"))

  public_base_url = var.public_domain != "" ? "https://${var.public_domain}" : "https://id.localhost"

  frontend_bucket_name  = var.frontend_bucket_name != "" ? var.frontend_bucket_name : "${local.name_prefix}-frontend-${substr(md5("${var.folder_id}-frontend"), 0, 8)}"
  media_bucket_name     = var.media_bucket_name != "" ? var.media_bucket_name : "${local.name_prefix}-media-${substr(md5("${var.folder_id}-media"), 0, 8)}"
  container_registry_id = var.container_registry_id != "" ? var.container_registry_id : yandex_container_registry.id[0].id

  runtime_secret_entries = merge(
    var.lockbox_secret_entries,
    {
      S3_ACCESS_KEY_ID     = yandex_iam_service_account_static_access_key.automation.access_key
      S3_SECRET_ACCESS_KEY = yandex_iam_service_account_static_access_key.automation.secret_key
    },
  )

  allowed_hosts = join(",", compact([
    var.public_domain,
    ".yandexcloud.net",
    "localhost",
    "127.0.0.1",
  ]))

  default_from_domain = var.public_domain != "" ? var.public_domain : "id.localhost"

  backend_env = merge(
    {
      CORS_ALLOWED_ORIGINS   = local.public_base_url
      CSRF_TRUSTED_ORIGINS   = local.public_base_url
      DB_DRIVER              = "ydb"
      DEFAULT_FROM_EMAIL     = "no-reply@${local.default_from_domain}"
      DJANGO_ALLOWED_HOSTS   = local.allowed_hosts
      DJANGO_DEBUG           = "false"
      ID_ACTIVATION_BASE_URL = local.public_base_url
      ID_PUBLIC_BASE_URL     = "${local.public_base_url}/api/v1"
      LOG_FORMAT             = "json"
      LOG_LEVEL              = "INFO"
      MEDIA_PUBLIC_BASE_URL  = "https://storage.yandexcloud.net/${local.media_bucket_name}"
      MEDIA_STORAGE_DRIVER   = "s3"
      OIDC_ISSUER            = local.public_base_url
      OIDC_PUBLIC_BASE_URL   = local.public_base_url
      PORT                   = "8080"
      S3_BUCKET_NAME         = local.media_bucket_name
      S3_ENDPOINT_URL        = "https://storage.yandexcloud.net"
      S3_REGION              = var.region
      SECURE_SSL_REDIRECT    = "true"
      SESSION_COOKIE_SECURE  = "true"
      YDB_CREDENTIALS_MODE   = "metadata"
      YDB_DATABASE           = yandex_ydb_database_serverless.id.database_path
      YDB_ENDPOINT           = yandex_ydb_database_serverless.id.ydb_full_endpoint
      YDB_NAME               = "default"
    },
    var.service_environment,
  )

  api_gateway_spec = templatefile("${path.module}/templates/api-gateway.openapi.yaml.tftpl", {
    backend_container_id       = yandex_serverless_container.backend.id
    frontend_bucket            = local.frontend_bucket_name
    gateway_service_account_id = yandex_iam_service_account.gateway.id
  })
}
