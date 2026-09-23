# Non-secret production settings, passed explicitly after runtime tfvars.
# No continuously prepared capacity while production has no regular traffic.
min_ready_instances = 0
# A dedicated managed cache is unnecessary for the current traffic and budget.
enable_shared_cache             = false
enable_gravatar_job             = true
default_zone                    = "ru-central1-a"
enable_serverless_vpc           = false
deployment_service_account_name = "updspace-id-github-actions"

# Prepare the inactive backend before switching public routes.
blue_green_enabled = true

# Canonical Go duration avoids a perpetual framework-provider diff (same 7 days).
log_retention_period = "168h0m0s"
