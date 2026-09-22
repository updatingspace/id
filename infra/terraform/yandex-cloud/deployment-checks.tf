# The provider reports failed revision deployments as warnings. Read the cloud
# again after each update, rather than trusting proposed resource state.
data "yandex_serverless_container" "deployed_backend" {
  container_id = yandex_serverless_container.backend.id
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

data "yandex_serverless_container" "deployed_gravatar" {
  count        = var.enable_gravatar_job ? 1 : 0
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
