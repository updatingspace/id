locals {
  name_prefix = lower(replace(var.name_prefix, "_", "-"))

  public_base_url = var.public_domain != "" ? "https://${var.public_domain}" : "https://id.localhost"

  frontend_bucket_name  = var.frontend_bucket_name != "" ? var.frontend_bucket_name : "${local.name_prefix}-frontend-${substr(md5("${var.folder_id}-frontend"), 0, 8)}"
  media_bucket_name     = var.media_bucket_name != "" ? var.media_bucket_name : "${local.name_prefix}-media-${substr(md5("${var.folder_id}-media"), 0, 8)}"
  container_registry_id = var.container_registry_id != "" ? var.container_registry_id : yandex_container_registry.id[0].id
  backend_network_id    = var.existing_network_id != "" ? var.existing_network_id : (var.enable_serverless_vpc ? yandex_vpc_network.id[0].id : "")

  runtime_secret_entries = merge(
    var.lockbox_secret_entries,
    var.live_secret_entries,
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
    },
  ) : key => value if key != "PORT" } # Injected by Serverless Containers.

  api_gateway_spec = templatefile("${path.module}/templates/api-gateway.openapi.yaml.tftpl", {
    backend_container_id       = local.backend_ids[var.rollout_active_slot]
    frontend_bucket            = local.frontend_bucket_name
    gateway_service_account_id = yandex_iam_service_account.gateway.id
  })

  api_gateway_id     = var.existing_api_gateway_id != "" ? data.yandex_api_gateway.existing[0].id : yandex_api_gateway.id[0].id
  api_gateway_domain = var.existing_api_gateway_id != "" ? data.yandex_api_gateway.existing[0].domain : yandex_api_gateway.id[0].domain
}
