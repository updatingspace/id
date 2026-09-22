# Non-secret production settings, passed explicitly after runtime tfvars.
min_ready_instances = 1
# A dedicated managed cache is unnecessary for the current traffic and budget.
enable_shared_cache             = false
enable_gravatar_job             = true
default_zone                    = "ru-central1-a"
enable_serverless_vpc           = false
deployment_service_account_name = "updspace-id-github-actions"

# Prepare the inactive backend before switching public routes.
blue_green_enabled = true
