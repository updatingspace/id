resource "yandex_vpc_network" "id" {
  count = var.enable_serverless_vpc ? 1 : 0

  name = "${local.name_prefix}-network"
}

resource "yandex_vpc_subnet" "serverless" {
  count = var.enable_serverless_vpc ? 1 : 0

  name           = "${local.name_prefix}-subnet"
  zone           = var.default_zone
  network_id     = yandex_vpc_network.id[0].id
  v4_cidr_blocks = [var.serverless_subnet_cidr]
}

resource "yandex_logging_group" "id" {
  name             = "${local.name_prefix}-logs"
  retention_period = var.log_retention_period
}

resource "yandex_iam_service_account" "runtime" {
  name        = "${local.name_prefix}-runtime"
  description = "Runtime identity for UpdSpace ID serverless container"
}

resource "yandex_iam_service_account" "gateway" {
  name        = "${local.name_prefix}-gateway"
  description = "Identity for API Gateway integrations"
}

resource "yandex_iam_service_account" "automation" {
  name        = "${local.name_prefix}-automation"
  description = "Static-key identity for Object Storage automation"
}

resource "yandex_iam_service_account" "ci" {
  name        = "${local.name_prefix}-ci"
  description = "GitHub Actions deploy identity"
}

resource "yandex_resourcemanager_folder_iam_member" "automation_storage_editor" {
  folder_id = var.folder_id
  role      = "storage.editor"
  member    = "serviceAccount:${yandex_iam_service_account.automation.id}"
}

resource "yandex_lockbox_secret" "runtime" {
  name        = "${local.name_prefix}-runtime"
  description = "Runtime secrets for UpdSpace ID"
}

resource "yandex_lockbox_secret_version" "runtime" {
  secret_id = yandex_lockbox_secret.runtime.id

  dynamic "entries" {
    for_each = local.runtime_secret_entries
    content {
      key        = entries.key
      text_value = entries.value
    }
  }
}

resource "yandex_lockbox_secret_iam_member" "runtime_payload_viewer" {
  secret_id = yandex_lockbox_secret.runtime.id
  role      = "lockbox.payloadViewer"
  member    = "serviceAccount:${yandex_iam_service_account.runtime.id}"
}

resource "yandex_iam_service_account_static_access_key" "automation" {
  service_account_id = yandex_iam_service_account.automation.id
  description        = "Static access key for Object Storage automation"
}

resource "yandex_container_registry" "id" {
  count = var.container_registry_id == "" ? 1 : 0

  name = "${local.name_prefix}-registry"
}

resource "yandex_storage_bucket" "frontend" {
  access_key    = yandex_iam_service_account_static_access_key.automation.access_key
  secret_key    = yandex_iam_service_account_static_access_key.automation.secret_key
  bucket        = local.frontend_bucket_name
  force_destroy = var.object_storage_force_destroy
}

resource "yandex_storage_bucket" "media" {
  access_key    = yandex_iam_service_account_static_access_key.automation.access_key
  secret_key    = yandex_iam_service_account_static_access_key.automation.secret_key
  bucket        = local.media_bucket_name
  force_destroy = var.object_storage_force_destroy
}

resource "yandex_ydb_database_serverless" "id" {
  name        = var.ydb_database_name
  location_id = var.region
}

resource "yandex_ydb_database_iam_binding" "runtime_editor" {
  database_id = yandex_ydb_database_serverless.id.id
  role        = "ydb.editor"
  members     = ["serviceAccount:${yandex_iam_service_account.runtime.id}"]
}

resource "yandex_storage_bucket_iam_binding" "gateway_frontend_viewer" {
  bucket  = yandex_storage_bucket.frontend.bucket
  role    = "storage.viewer"
  members = ["serviceAccount:${yandex_iam_service_account.gateway.id}"]
}

resource "yandex_resourcemanager_folder_iam_member" "runtime_image_puller" {
  folder_id = var.folder_id
  role      = "container-registry.images.puller"
  member    = "serviceAccount:${yandex_iam_service_account.runtime.id}"
}

resource "yandex_serverless_container" "backend" {
  name               = "${local.name_prefix}-backend"
  description        = "UpdSpace ID backend"
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

  runtime {
    type = "http"
  }

  dynamic "connectivity" {
    for_each = var.enable_serverless_vpc ? [1] : []
    content {
      network_id = yandex_vpc_network.id[0].id
    }
  }

  metadata_options {
    gce_http_endpoint = 1
  }

  dynamic "provision_policy" {
    for_each = var.min_ready_instances > 0 ? [1] : []
    content {
      min_instances = var.min_ready_instances
    }
  }

  image {
    url         = "cr.yandex/${local.container_registry_id}/updatingspace-id-backend:${var.container_image_tag}"
    environment = local.backend_env
  }

  dynamic "secrets" {
    for_each = local.runtime_secret_entries
    content {
      id                   = yandex_lockbox_secret.runtime.id
      version_id           = yandex_lockbox_secret_version.runtime.id
      key                  = secrets.key
      environment_variable = secrets.key
    }
  }

  log_options {
    log_group_id = yandex_logging_group.id.id
    min_level    = "INFO"
  }
}

resource "yandex_serverless_container_iam_binding" "gateway_backend_invoker" {
  container_id = yandex_serverless_container.backend.id
  role         = "serverless.containers.invoker"
  members      = ["serviceAccount:${yandex_iam_service_account.gateway.id}"]
}

resource "yandex_api_gateway" "id" {
  name        = "${local.name_prefix}-gateway"
  description = "UpdSpace ID gateway for API/OIDC routes and frontend assets"
  spec        = local.api_gateway_spec

  depends_on = [
    yandex_serverless_container_iam_binding.gateway_backend_invoker,
    yandex_storage_bucket_iam_binding.gateway_frontend_viewer,
  ]

  dynamic "custom_domains" {
    for_each = var.certificate_id != "" && var.public_domain != "" ? [1] : []
    content {
      fqdn           = var.public_domain
      certificate_id = var.certificate_id
    }
  }
}

resource "yandex_dns_zone" "public" {
  count = var.manage_dns_zone ? 1 : 0

  name        = "${replace(local.name_prefix, "-", "")}-public"
  description = "Public DNS zone for ${var.public_zone}"
  zone        = "${var.public_zone}."
  public      = true
}

resource "yandex_dns_recordset" "gateway" {
  count = var.manage_dns_zone && var.public_domain != "" ? 1 : 0

  zone_id = yandex_dns_zone.public[0].id
  name    = "${var.public_domain}."
  type    = "CNAME"
  ttl     = 300
  data    = [yandex_api_gateway.id.domain]
}
