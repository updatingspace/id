variable "blue_green_enabled" {
  description = "Manage the existing Rust API green container under its historical Terraform address."
  type        = bool
  default     = false
}

variable "legacy_backend_enabled" {
  description = "Deprecated compatibility input for private tfvars. The Django resource is removed and cannot be enabled."
  type        = bool
  default     = false

  validation {
    condition     = !var.legacy_backend_enabled
    error_message = "The Django backend was retired; deploy the Rust API containers instead."
  }
}

variable "rollout_active_slot" {
  description = "Historical active slot, retained for existing runtime tfvars; only the Rust green slot remains."
  type        = string
  default     = "green"
  validation {
    condition     = var.rollout_active_slot == "green"
    error_message = "Only the Rust green slot remains."
  }
}

variable "rollout_target_slot" {
  description = "Historical target slot, retained for existing runtime tfvars; only the Rust green slot remains."
  type        = string
  default     = "green"
  validation {
    condition     = var.rollout_target_slot == "green"
    error_message = "Only the Rust green slot remains."
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
    log_group_id             = optional(string, "")
    log_folder_id            = optional(string, "")
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
    image_url                = "cr.yandex/${local.container_registry_id}/updatingspace-id-api:${var.rust_api_image_tag}"
    environment              = sensitive(local.rust_api_env)
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
    log_folder_id            = ""
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
  green_backend = local.retained_backend
  backend_ids   = var.blue_green_enabled ? { green = yandex_serverless_container.backend_green[0].id } : {}
  backend_urls  = var.blue_green_enabled ? { green = yandex_serverless_container.backend_green[0].url } : {}
  backend_invokers = concat(
    ["serviceAccount:${yandex_iam_service_account.gateway.id}"],
    var.blue_green_enabled ? ["serviceAccount:${data.yandex_iam_service_account.deployer[0].id}"] : [],
  )
}

resource "terraform_data" "rollout_safety" {
  lifecycle {
    precondition {
      condition     = (var.gateway_use_rust || var.gateway_rust_catchall) && (var.enable_rust_stack || var.gateway_rust_me_container_id != "")
      error_message = "Gateway requires a Rust API container and Rust routing."
    }
    precondition {
      condition     = var.enable_rust_stack || var.gateway_rust_web_container_id != ""
      error_message = "Gateway fallback requires a Topcoat web container."
    }
    precondition {
      condition = !var.blue_green_enabled || (
        var.retained_backend_config != null && var.deployment_service_account_name != ""
      )
      error_message = "Blue/green rollout requires a live runtime snapshot and a deployment service account."
    }
    precondition {
      condition = !var.blue_green_enabled || (
        var.retained_backend_config != null &&
        var.gateway_rust_catchall
      )
      error_message = "The retained Rust API requires a live green snapshot and Rust-only Gateway catch-all."
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
