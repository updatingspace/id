variable "blue_green_enabled" {
  description = "Prepare an inactive backend before switching gateway traffic."
  type        = bool
  default     = false
}

variable "rollout_active_slot" {
  description = "Backend slot receiving public gateway traffic."
  type        = string
  default     = "blue"
  validation {
    condition     = contains(["blue", "green"], var.rollout_active_slot)
    error_message = "rollout_active_slot must be blue or green."
  }
}

variable "rollout_target_slot" {
  description = "Slot receiving the new image/configuration; unchanged across release phases."
  type        = string
  default     = "blue"
  validation {
    condition     = contains(["blue", "green"], var.rollout_target_slot)
    error_message = "rollout_target_slot must be blue or green."
  }
}

variable "retire_other_backend" {
  description = "Release the old slot's prepared capacity only after successful smoke."
  type        = bool
  default     = false
}

variable "candidate_min_ready_instances" {
  description = "Override only for releasing a failed candidate’s prepared capacity."
  type        = number
  default     = null
  validation {
    condition     = var.candidate_min_ready_instances == null || var.candidate_min_ready_instances == 0
    error_message = "The cleanup override may only disable prepared capacity."
  }
}

variable "retained_backend_config" {
  description = "Private snapshot of the live backend, held unchanged while preparing its replacement."
  sensitive   = true
  default     = null
  type = object({
    image_url                = string
    environment              = map(string)
    memory                   = number
    cores                    = number
    core_fraction            = number
    concurrency              = number
    execution_timeout        = string
    service_account_id       = string
    network_id               = string
    min_instances            = number
    provision_policy_present = optional(bool, false)
    log_group_id             = string
    log_min_level            = string
    metadata_options = object({
      gce_http_endpoint    = number
      aws_v1_http_endpoint = number
    })
    secrets = list(object({
      id                   = string
      version_id           = string
      key                  = string
      environment_variable = string
    }))
  })
}

locals {
  desired_backend = {
    image_url                = "cr.yandex/${local.container_registry_id}/updatingspace-id-backend:${var.container_image_tag}"
    environment              = sensitive(local.backend_env)
    memory                   = var.backend_memory_mb
    cores                    = var.backend_cores
    core_fraction            = 100
    concurrency              = var.backend_concurrency
    execution_timeout        = "60s"
    service_account_id       = yandex_iam_service_account.runtime.id
    network_id               = local.backend_network_id
    min_instances            = coalesce(var.candidate_min_ready_instances, var.min_ready_instances)
    provision_policy_present = false
    log_group_id             = yandex_logging_group.id.id
    log_min_level            = "INFO"
    metadata_options = {
      gce_http_endpoint    = 1
      aws_v1_http_endpoint = 0
    }
    secrets = [for key in nonsensitive(sort(keys(local.runtime_secret_entries))) : {
      id                   = yandex_lockbox_secret.runtime.id
      version_id           = yandex_lockbox_secret_version.runtime.id
      key                  = key
      environment_variable = key
    }]
  }
  retained_backend = var.retained_backend_config == null ? local.desired_backend : merge(var.retained_backend_config, {
    min_instances = var.retire_other_backend ? 0 : var.retained_backend_config.min_instances
  })
  blue_backend  = !var.blue_green_enabled || var.rollout_target_slot == "blue" ? local.desired_backend : local.retained_backend
  green_backend = var.rollout_target_slot == "green" ? local.desired_backend : local.retained_backend
  backend_ids = merge(
    { blue = yandex_serverless_container.backend.id },
    var.blue_green_enabled ? { green = yandex_serverless_container.backend_green[0].id } : {},
  )
  backend_urls = merge(
    { blue = yandex_serverless_container.backend.url },
    var.blue_green_enabled ? { green = yandex_serverless_container.backend_green[0].url } : {},
  )
  backend_invokers = concat(
    ["serviceAccount:${yandex_iam_service_account.gateway.id}"],
    var.blue_green_enabled ? ["serviceAccount:${data.yandex_iam_service_account.deployer[0].id}"] : [],
  )
}

resource "terraform_data" "rollout_safety" {
  lifecycle {
    precondition {
      condition = !var.blue_green_enabled || (
        var.retained_backend_config != null && var.deployment_service_account_name != ""
      )
      error_message = "Blue/green rollout requires a live runtime snapshot and a deployment service account."
    }
    precondition {
      condition     = var.blue_green_enabled || (var.rollout_active_slot == "blue" && var.rollout_target_slot == "blue")
      error_message = "The green slot requires blue_green_enabled."
    }
  }
}

output "backend_slots" {
  description = "Non-secret slot identity used by the release coordinator."
  value = {
    enabled     = var.blue_green_enabled
    active_slot = var.rollout_active_slot
    target_slot = var.rollout_target_slot
    ids         = local.backend_ids
    urls        = local.backend_urls
  }
}
