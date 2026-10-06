# The provider reports failed revision deployments as warnings. Read the cloud
# again after each update, rather than trusting proposed resource state.
data "yandex_serverless_container" "deployed_backend" {
  count        = var.legacy_backend_enabled ? 1 : 0
  container_id = yandex_serverless_container.backend[0].id
  depends_on   = [yandex_serverless_container.backend]

  lifecycle {
    postcondition {
      condition = try(
        self.revision_id != null && self.revision_id != "" &&
        self.image[0].url == local.blue_backend.image_url &&
        tomap(self.image[0].environment) == tomap(local.blue_backend.environment),
        false,
      )
      error_message = "YC did not deploy the requested backend revision. Inspect deployment warnings; an apply with only the previous revision is not successful."
    }
  }
}

data "yandex_serverless_container" "deployed_green" {
  count        = var.blue_green_enabled ? 1 : 0
  container_id = yandex_serverless_container.backend_green[0].id
  depends_on   = [yandex_serverless_container.backend_green[0]]

  lifecycle {
    postcondition {
      condition = try(
        self.revision_id != null && self.revision_id != "" &&
        self.image[0].url == local.green_backend.image_url &&
        tomap(self.image[0].environment) == tomap(local.green_backend.environment),
        false,
      )
      error_message = "YC did not deploy the requested backend revision. Inspect deployment warnings; an apply with only the previous revision is not successful."
    }
  }
}

data "yandex_serverless_container" "deployed_rust_api" {
  count        = var.enable_rust_stack ? 1 : 0
  container_id = yandex_serverless_container.rust_api[0].id
  depends_on   = [yandex_serverless_container.rust_api]

  lifecycle {
    postcondition {
      condition = try(
        self.revision_id != null && self.revision_id != "" &&
        self.image[0].url == "cr.yandex/${local.container_registry_id}/updatingspace-id-api:${var.rust_api_image_tag}" &&
        self.image[0].digest == var.rust_api_image_digest &&
        tomap(self.image[0].environment) == tomap(local.rust_api_env),
        false,
      )
      error_message = "YC did not deploy the tested Rust API digest and environment."
    }
  }
}

data "yandex_serverless_container" "existing_magic_api" {
  count        = var.gateway_rust_magic_link && !var.enable_rust_stack ? 1 : 0
  container_id = var.gateway_rust_me_container_id

  lifecycle {
    postcondition {
      condition = try(
        self.revision_id != "" &&
        self.image[0].environment["ID_AUTH_MAGIC_LINK_CONSUME_ROLLOUT_ENABLED"] == "true" &&
        self.image[0].environment["ID_AUTH_MAGIC_LINK_REQUEST_PILOT_ENABLED"] == "true" &&
        self.image[0].environment["ID_MAGIC_LINK_REDIRECT_ORIGINS"] == var.magic_link_redirect_origins,
        false,
      )
      error_message = "The existing Rust API revision is not configured for magic-link request and consume."
    }
  }
}

data "yandex_serverless_container" "existing_magic_jobs" {
  count        = var.gateway_rust_magic_link && !var.enable_rust_mail_job ? 1 : 0
  container_id = var.gravatar_rust_jobs_container_id

  lifecycle {
    postcondition {
      condition = try(
        self.revision_id != "" &&
        self.image[0].environment["ID_MAGIC_LINK_MAIL_ENABLED"] == "true" &&
        self.image[0].environment["ID_MAGIC_LINK_PUBLIC_URL"] == "${local.public_base_url}/api/v1/auth/magic-link/consume",
        false,
      )
      error_message = "The existing private Rust jobs revision is not configured to deliver magic links."
    }
  }
}

data "yandex_serverless_container" "deployed_rust_web" {
  count        = var.enable_rust_stack ? 1 : 0
  container_id = yandex_serverless_container.rust_web[0].id
  depends_on   = [yandex_serverless_container.rust_web]

  lifecycle {
    postcondition {
      condition = try(
        self.revision_id != null && self.revision_id != "" &&
        self.image[0].url == "cr.yandex/${local.container_registry_id}/updatingspace-id-web:${var.rust_web_image_tag}" &&
        self.image[0].digest == var.rust_web_image_digest &&
        tomap(self.image[0].environment) == tomap(local.rust_web_env),
        false,
      )
      error_message = "YC did not deploy the tested Topcoat UI digest and environment."
    }
  }
}

data "yandex_serverless_container" "deployed_gravatar" {
  count        = var.enable_gravatar_job && var.gravatar_rust_jobs_container_id == "" ? 1 : 0
  container_id = yandex_serverless_container.gravatar[0].id
  depends_on   = [yandex_serverless_container.gravatar]

  lifecycle {
    postcondition {
      condition = try(
        self.revision_id != null && self.revision_id != "" &&
        self.image[0].url == "cr.yandex/${local.container_registry_id}/updatingspace-id-backend:${var.container_image_tag}" &&
        tomap(self.image[0].environment) == tomap(merge(local.backend_env, { GRAVATAR_BATCH_LIMIT = "25" })),
        false,
      )
      error_message = "YC did not deploy the requested Gravatar revision. Inspect deployment warnings before enabling the timer."
    }
  }
}

data "yandex_serverless_container" "deployed_rust_mail_job" {
  count        = var.enable_rust_mail_job ? 1 : 0
  container_id = yandex_serverless_container.rust_mail_job[0].id
  depends_on   = [yandex_serverless_container.rust_mail_job]

  lifecycle {
    postcondition {
      condition = try(
        self.revision_id != null && self.revision_id != "" &&
        self.image[0].url == "cr.yandex/${local.container_registry_id}/updatingspace-id-jobs:${var.rust_mail_job_image_tag}" &&
        self.image[0].digest == var.rust_mail_job_image_digest &&
        tomap(self.image[0].environment) == tomap(local.rust_mail_job_env),
        false,
      )
      error_message = "YC did not deploy the requested Rust mail job image digest and environment."
    }
  }
}
