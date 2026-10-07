# Non-secret production settings, passed explicitly after runtime tfvars.
# Near-zero traffic: no permanently prepared capacity. Cold starts are expected.
min_ready_instances = 0
# A dedicated managed cache is unnecessary for the current traffic and budget.
enable_shared_cache             = false
enable_gravatar_job             = true
gravatar_rust_jobs_container_id = "bba9v82d1op2qbh2kqtt"
enable_rust_mail_recovery_timer = false
# The private bucket and recovery trigger already exist outside this Terraform state.
enable_rust_export                       = true
manage_rust_export_bucket                = false
enable_rust_export_api                   = true
enable_rust_export_delayed               = true
enable_rust_export_recovery_timer        = false
export_bucket_name                       = "updspace-id-exports-e3dd0415"
export_operation_secret_id               = "e6qm55c5cse0fop78d8q"
export_operation_secret_version_id       = "e6qc54j59eca11ujnppp"
enable_rust_verify_mail_recovery_timer   = true
enable_rust_security_mail_recovery_timer = true
enable_rust_password_mail_recovery_timer = false
default_zone                             = "ru-central1-a"
enable_serverless_vpc                    = false
deployment_service_account_name          = "updspace-id-github-actions"

# The former blue Django container is deleted. Pin the existing green Rust API
# to its live revision until Terraform ownership is reconciled.
blue_green_enabled  = true
rollout_active_slot = "green"
rollout_target_slot = "green"

# Existing Rust production containers and exact Gateway routes. The Python
# catch-all has been replaced; these IDs remain pinned until Terraform can
# manage the Rust-only deployment without recreating the old backend.
enable_rust_stack                            = false
gateway_use_rust                             = false
gateway_rust_catchall                        = true
gateway_rust_me_container_id                 = "bbak8734de8cabdaorc7"
gateway_rust_web_container_id                = "bbai4bjc8f21qg5fvjht"
gateway_rust_me                              = true
gateway_rust_form_token                      = true
gateway_rust_password_reset_api              = true
gateway_rust_login_api                       = true
gateway_rust_passkey_login                   = true
gateway_rust_passkey_registration            = true
gateway_rust_totp_management                 = true
gateway_rust_passkey_rename                  = true
gateway_rust_passkey_delete                  = true
gateway_rust_email_verify_api                = true
gateway_rust_email_resend                    = true
gateway_rust_signup_api                      = true
gateway_rust_oauth_providers                 = true
gateway_rust_internal_identity               = true
gateway_rust_exchange                        = true
gateway_rust_magic_link                      = true
magic_link_redirect_origins                  = "https://portal.updspace.com"
gateway_rust_portal_me                       = true
gateway_rust_sessions_read                   = true
gateway_rust_sessions_container_id           = "bba3ev9oenabp55se69m"
gateway_rust_sessions_mutations              = true
gateway_rust_sessions_mutations_container_id = "bbamj363kmhlj2nof0mo"
gateway_rust_logout                          = true
gateway_rust_profile                         = true
gateway_rust_avatar_delete                   = true
gateway_rust_avatar_upload                   = true
gateway_rust_preferences                     = true
gateway_rust_apps                            = true
gateway_rust_security_read                   = true
gateway_rust_email_status                    = true
gateway_rust_email_cancel                    = true
gateway_rust_email_change                    = true
gateway_rust_password_change                 = true
gateway_rust_health                          = true
gateway_rust_account_jwt                     = true
gateway_rust_jwks                            = true
gateway_rust_discovery                       = true
gateway_rust_oidc                            = true
gateway_rust_oidc_authorize_post             = true
gateway_rust_login                           = true
gateway_rust_account                         = true
gateway_rust_recovery_pages                  = true
gateway_rust_signup_page                     = true
gateway_rust_home_page                       = true

# Canonical Go duration avoids a perpetual framework-provider diff (same 7 days).
log_retention_period = "168h0m0s"
