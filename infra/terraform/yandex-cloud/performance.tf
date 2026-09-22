resource "random_password" "cache" {
  count   = var.enable_shared_cache ? 1 : 0
  length  = 40
  special = false
}

data "yandex_iam_service_account" "deployer" {
  count = var.enable_gravatar_job && var.deployment_service_account_name != "" ? 1 : 0
  name  = var.deployment_service_account_name
}

resource "yandex_resourcemanager_folder_iam_member" "deployer_trigger_editor" {
  count     = var.enable_gravatar_job && var.deployment_service_account_name != "" ? 1 : 0
  folder_id = var.folder_id
  role      = "functions.editor"
  member    = "serviceAccount:${data.yandex_iam_service_account.deployer[0].id}"
}

resource "yandex_vpc_security_group" "cache" {
  count      = var.enable_shared_cache ? 1 : 0
  name       = "${local.name_prefix}-cache"
  network_id = local.backend_network_id

  ingress {
    protocol       = "TCP"
    port           = 6380
    v4_cidr_blocks = ["198.19.0.0/16"]
    description    = "TLS from Serverless Containers service subnets"
  }
  ingress {
    protocol          = "ANY"
    predefined_target = "self_security_group"
  }
  egress {
    protocol       = "ANY"
    v4_cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "yandex_mdb_redis_cluster" "cache" {
  count              = var.enable_shared_cache ? 1 : 0
  name               = "${local.name_prefix}-cache"
  environment        = "PRODUCTION"
  network_id         = local.backend_network_id
  security_group_ids = [yandex_vpc_security_group.cache[0].id]
  tls_enabled        = true
  persistence_mode   = "ON"

  config {
    password         = random_password.cache[0].result
    version          = "7.2"
    maxmemory_policy = "NOEVICTION"
  }
  resources {
    resource_preset_id = "hm3-c2-m8"
    disk_size          = 16
  }
  host {
    zone             = var.default_zone
    subnet_id        = var.cache_subnet_id
    assign_public_ip = false
  }
  maintenance_window {
    type = "ANYTIME"
  }

  lifecycle {
    precondition {
      condition     = local.backend_network_id != "" && var.cache_subnet_id != ""
      error_message = "Shared cache requires a VPC and cache_subnet_id."
    }
  }
}

resource "yandex_iam_service_account" "scheduler" {
  count = var.enable_gravatar_job ? 1 : 0
  name  = "${local.name_prefix}-scheduler"
}

resource "yandex_serverless_container" "gravatar" {
  count              = var.enable_gravatar_job ? 1 : 0
  name               = "${local.name_prefix}-gravatar"
  description        = "Bounded Gravatar refresh outside the authentication path"
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
    url         = "cr.yandex/${local.container_registry_id}/updatingspace-id-backend:${var.container_image_tag}"
    command     = ["gunicorn"]
    args        = ["app.jobs:application", "--bind", "0.0.0.0:8080", "--workers", "1", "--timeout", "590", "--access-logfile", "-", "--error-logfile", "-"]
    environment = merge(local.backend_env, { GRAVATAR_BATCH_LIMIT = "25" })
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
  log_options {
    log_group_id = yandex_logging_group.id.id
    min_level    = "INFO"
  }
}

resource "yandex_serverless_container_iam_binding" "gravatar_invoker" {
  count        = var.enable_gravatar_job ? 1 : 0
  container_id = yandex_serverless_container.gravatar[0].id
  role         = "serverless.containers.invoker"
  members      = ["serviceAccount:${yandex_iam_service_account.scheduler[0].id}"]
}

resource "yandex_function_trigger" "gravatar" {
  count = var.enable_gravatar_job ? 1 : 0
  name  = "${local.name_prefix}-gravatar-hourly"

  timer {
    cron_expression = "17 * * * ? *"
  }
  container {
    id                 = yandex_serverless_container.gravatar[0].id
    path               = "/refresh-gravatars"
    service_account_id = yandex_iam_service_account.scheduler[0].id
    retry_attempts     = 2
    retry_interval     = 60
  }
  depends_on = [
    yandex_serverless_container_iam_binding.gravatar_invoker,
    yandex_resourcemanager_folder_iam_member.deployer_trigger_editor,
    data.yandex_serverless_container.deployed_gravatar,
  ]
}

# The provider cannot import the pre-existing gateway. Keep its desired spec
# and update trigger in Terraform state even in the compatibility mode.
resource "terraform_data" "existing_gateway_spec" {
  count            = var.existing_api_gateway_id != "" ? 1 : 0
  triggers_replace = [var.existing_api_gateway_id, sha256(local.api_gateway_spec)]
  input = {
    gateway_id = var.existing_api_gateway_id
    spec       = local.api_gateway_spec
  }
  provisioner "local-exec" {
    command = "python3 '${path.module}/../../../scripts/ci/update-yc-gateway.py'"
    environment = {
      YC_GATEWAY_ID   = self.input.gateway_id
      YC_GATEWAY_SPEC = self.input.spec
    }
  }
  depends_on = [
    data.yandex_serverless_container.deployed_backend,
    yandex_serverless_container_iam_binding.gateway_backend_invoker,
    yandex_storage_bucket_iam_binding.gateway_frontend_viewer,
  ]
}
