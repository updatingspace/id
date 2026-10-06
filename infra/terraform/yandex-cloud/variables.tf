variable "cloud_id" {
  description = "Yandex Cloud ID."
  type        = string
}

variable "folder_id" {
  description = "Folder ID where the ID stack will be deployed."
  type        = string
}

variable "service_account_key_file" {
  description = "Optional path to a YC service account key JSON file."
  type        = string
  default     = null
}

variable "region" {
  description = "Primary YC region."
  type        = string
  default     = "ru-central1"
}

variable "default_zone" {
  description = "Primary availability zone for subnet-backed services."
  type        = string
  default     = "ru-central1-a"
}

variable "name_prefix" {
  description = "Shared prefix for all Yandex Cloud resources in this stack."
  type        = string
  default     = "updspace-id"
}

variable "public_domain" {
  description = "Public ID domain, for example id.updspace.com."
  type        = string
  default     = ""
}

variable "manage_dns_zone" {
  description = "Create and manage a public Cloud DNS zone and gateway record."
  type        = bool
  default     = false
}

variable "public_zone" {
  description = "DNS zone used when manage_dns_zone=true."
  type        = string
  default     = "updspace.com"
}

variable "certificate_id" {
  description = "Existing certificate ID from Certificate Manager."
  type        = string
  default     = ""
}

variable "existing_api_gateway_id" {
  description = "Existing API Gateway ID to reuse when the provider cannot import a previously created gateway."
  type        = string
  default     = ""
}

variable "enable_rust_stack" {
  description = "Create the separately deployable Rust API and Topcoat UI containers."
  type        = bool
  default     = false
}

variable "gateway_use_rust" {
  description = "Route the existing public gateway to the Rust API and Topcoat UI."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_use_rust || var.enable_rust_stack
    error_message = "gateway_use_rust requires enable_rust_stack."
  }
}

variable "gateway_rust_catchall" {
  description = "Route the remaining /api/v1 catch-all and legacy /health to the verified Rust API. Unsupported old API paths return Rust 404."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_catchall || (var.gateway_rust_health && (var.enable_rust_stack || var.gateway_rust_me_container_id != ""))
    error_message = "gateway_rust_catchall requires Rust health and a Rust API container."
  }
}

variable "gateway_rust_me" {
  description = "Route only GET /api/v1/auth/me to the Rust API while remaining API paths stay on the existing backend."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_me || var.enable_rust_stack || var.gateway_rust_me_container_id != ""
    error_message = "gateway_rust_me requires either enable_rust_stack or gateway_rust_me_container_id."
  }
}

variable "gateway_rust_me_container_id" {
  description = "Existing Rust API container for the /me slice when the container quota prevents creating a separate Rust stack."
  type        = string
  default     = ""

  validation {
    condition     = var.gateway_rust_me_container_id == "" || can(regex("^bba[a-z0-9]{17}$", var.gateway_rust_me_container_id))
    error_message = "gateway_rust_me_container_id must be a YC serverless container ID."
  }
}

variable "gateway_rust_form_token" {
  description = "Route only GET /api/v1/auth/form_token to the Rust API during the transition."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_form_token || var.enable_rust_stack || var.gateway_rust_me_container_id != ""
    error_message = "gateway_rust_form_token requires either enable_rust_stack or gateway_rust_me_container_id."
  }
}

variable "gateway_rust_jwks" {
  description = "Route only public OIDC JWKS GET paths to the Rust API while token endpoints stay on the existing backend."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_jwks || var.enable_rust_stack || var.gateway_rust_me_container_id != ""
    error_message = "gateway_rust_jwks requires either enable_rust_stack or gateway_rust_me_container_id."
  }
}

variable "gateway_rust_discovery" {
  description = "Route public OIDC discovery to the verified Rust sessions container independently of token endpoints."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_discovery || var.enable_rust_stack || var.gateway_rust_sessions_container_id != ""
    error_message = "gateway_rust_discovery requires either enable_rust_stack or gateway_rust_sessions_container_id."
  }
}

variable "gateway_rust_oidc" {
  description = "Route the complete OAuth/OIDC authorize, token, UserInfo and revoke flow plus Topcoat consent to verified Rust revisions."
  type        = bool
  default     = false

  validation {
    condition = !var.gateway_rust_oidc || var.enable_rust_stack || (
      var.gateway_rust_sessions_mutations_container_id != "" && var.gateway_rust_web_container_id != ""
    )
    error_message = "gateway_rust_oidc requires verified Rust OIDC API and Topcoat web container IDs or enable_rust_stack."
  }
}

variable "gateway_rust_oidc_authorize_post" {
  description = "Route POST /oauth/authorize to the verified Rust OIDC API."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_oidc_authorize_post || var.gateway_rust_oidc || var.gateway_use_rust
    error_message = "gateway_rust_oidc_authorize_post requires the Rust OIDC route group."
  }
}

variable "gateway_rust_login_api" {
  description = "Route only POST/OPTIONS /api/v1/auth/login to the Rust API after authenticated production verification."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_login_api || var.enable_rust_stack || var.gateway_rust_me_container_id != ""
    error_message = "gateway_rust_login_api requires either enable_rust_stack or gateway_rust_me_container_id."
  }
}

variable "gateway_rust_passkey_login" {
  description = "Route passkey login begin/complete to the verified Rust API revision."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_passkey_login || (var.gateway_rust_login_api && (var.enable_rust_stack || var.gateway_rust_me_container_id != ""))
    error_message = "gateway_rust_passkey_login requires Rust login and an API container."
  }
}

variable "gateway_rust_passkey_registration" {
  description = "Route passkey registration begin/complete to Rust after the index, shared MFA key and browser flow are verified."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_passkey_registration || var.enable_rust_stack || var.gateway_rust_me_container_id != ""
    error_message = "gateway_rust_passkey_registration requires a Rust API container."
  }
}

variable "gateway_rust_totp_management" {
  description = "Route TOTP enrollment, disable and recovery-code rotation to the verified Rust API revision."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_totp_management || var.enable_rust_stack || var.gateway_rust_me_container_id != ""
    error_message = "gateway_rust_totp_management requires a Rust API container."
  }
}

variable "gateway_rust_passkey_rename" {
  description = "Route passkey rename to the verified Rust API revision."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_passkey_rename || var.enable_rust_stack || var.gateway_rust_me_container_id != ""
    error_message = "gateway_rust_passkey_rename requires a Rust API container."
  }
}

variable "gateway_rust_passkey_delete" {
  description = "Route passkey deletion to Rust after the durable security-mail worker and selective trigger are live."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_passkey_delete || var.enable_rust_stack || var.gateway_rust_me_container_id != ""
    error_message = "gateway_rust_passkey_delete requires a Rust API container."
  }
}

variable "gateway_rust_email_verify_api" {
  description = "Route POST/OPTIONS email-verification request and confirm to the existing Rust API revision."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_email_verify_api || var.enable_rust_stack || var.gateway_rust_me_container_id != ""
    error_message = "gateway_rust_email_verify_api requires a Rust API container ID or enable_rust_stack."
  }
}

variable "gateway_rust_email_resend" {
  description = "Route authenticated resend of primary-address verification to the verified Rust API and existing mail worker."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_email_resend || (var.gateway_rust_email_verify_api && (var.enable_rust_stack || var.gateway_rust_me_container_id != ""))
    error_message = "gateway_rust_email_resend requires the Rust verification API route and container."
  }
}

variable "gateway_rust_signup_api" {
  description = "Route POST/OPTIONS signup to the existing Rust API revision."
  type        = bool
  default     = false

  validation {
    condition = !var.gateway_rust_signup_api || (
      var.gateway_rust_form_token && var.gateway_rust_email_verify_api && (var.enable_rust_stack || var.gateway_rust_me_container_id != "")
    )
    error_message = "gateway_rust_signup_api requires Rust form-token, email verification, and an API container."
  }
}

variable "gateway_rust_password_reset_api" {
  description = "Route POST/OPTIONS password-reset request and confirm to the existing Rust API revision."
  type        = bool
  default     = false

  validation {
    condition = !var.gateway_rust_password_reset_api || (
      var.gateway_rust_form_token && (var.enable_rust_stack || var.gateway_rust_me_container_id != "")
    )
    error_message = "gateway_rust_password_reset_api requires Rust form-token and an API container."
  }
}

variable "gateway_rust_health" {
  description = "Route GET /healthz and /readyz to the Rust API container."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_health || var.enable_rust_stack || var.gateway_rust_me_container_id != ""
    error_message = "gateway_rust_health requires a Rust API container."
  }
}

variable "gateway_rust_oauth_providers" {
  description = "Route public OAuth provider inventory to the Rust API."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_oauth_providers || var.enable_rust_stack || var.gateway_rust_me_container_id != ""
    error_message = "gateway_rust_oauth_providers requires a Rust API container."
  }
}

variable "gateway_rust_internal_identity" {
  description = "Route signed Portal/BFF identity lookup to the Rust API."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_internal_identity || var.enable_rust_stack || var.gateway_rust_me_container_id != ""
    error_message = "gateway_rust_internal_identity requires a Rust API container."
  }
}

variable "gateway_rust_exchange" {
  description = "Route the signed, one-time BFF exchange code endpoint to the Rust API."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_exchange || var.enable_rust_stack || var.gateway_rust_me_container_id != ""
    error_message = "gateway_rust_exchange requires a Rust API container."
  }
}

variable "gateway_rust_magic_link" {
  description = "Route magic-link request and consume through the Rust API with durable Rust mail jobs."
  type        = bool
  default     = false

  validation {
    condition = !var.gateway_rust_magic_link || (
      (var.enable_rust_stack || var.gateway_rust_me_container_id != "") &&
      (var.enable_rust_mail_job || var.gravatar_rust_jobs_container_id != "") &&
      var.gateway_rust_exchange
    )
    error_message = "gateway_rust_magic_link requires deployed Rust API/jobs containers and Rust BFF exchange."
  }
  validation {
    condition     = !var.gateway_rust_magic_link || trimspace(var.magic_link_redirect_origins) != ""
    error_message = "gateway_rust_magic_link requires an explicit HTTPS redirect-origin allowlist."
  }
}

variable "magic_link_redirect_origins" {
  description = "Comma-separated HTTPS origins allowed for Portal magic-link callbacks."
  type        = string
  default     = ""
}

variable "magic_link_default_redirect" {
  description = "Optional callback used when the request omits redirect_to. Must match the allowlist."
  type        = string
  default     = ""
}

variable "gateway_rust_portal_me" {
  description = "Route tenant-scoped Portal /api/v1/me to the Rust API."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_portal_me || var.enable_rust_stack || var.gateway_rust_me_container_id != ""
    error_message = "gateway_rust_portal_me requires a Rust API container."
  }
}

variable "gateway_rust_sessions_read" {
  description = "Route only GET/OPTIONS /api/v1/auth/sessions to Rust while session mutations remain on Python."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_sessions_read || var.enable_rust_stack || var.gateway_rust_me_container_id != "" || var.gateway_rust_sessions_container_id != ""
    error_message = "gateway_rust_sessions_read requires a Rust API container ID or enable_rust_stack."
  }
}

variable "gateway_rust_sessions_container_id" {
  description = "Optional separate Rust API container for GET /sessions while login remains on the tested API revision."
  type        = string
  default     = ""

  validation {
    condition     = var.gateway_rust_sessions_container_id == "" || can(regex("^bba[a-z0-9]{17}$", var.gateway_rust_sessions_container_id))
    error_message = "gateway_rust_sessions_container_id must be a YC serverless container ID."
  }
}

variable "gateway_rust_sessions_mutations" {
  description = "Route session DELETE and bulk POST/OPTIONS to a separately verified Rust API revision."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_sessions_mutations || var.enable_rust_stack || var.gateway_rust_sessions_mutations_container_id != ""
    error_message = "gateway_rust_sessions_mutations requires a verified Rust container ID or enable_rust_stack."
  }
}

variable "gateway_rust_sessions_mutations_container_id" {
  description = "Rust container separately verified for session revocation, independent of read and login revisions."
  type        = string
  default     = ""

  validation {
    condition     = var.gateway_rust_sessions_mutations_container_id == "" || can(regex("^bba[a-z0-9]{17}$", var.gateway_rust_sessions_mutations_container_id))
    error_message = "gateway_rust_sessions_mutations_container_id must be a YC serverless container ID."
  }
}

variable "gateway_rust_logout" {
  description = "Route POST/OPTIONS /api/v1/auth/logout to a verified Rust API revision."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_logout || var.enable_rust_stack || var.gateway_rust_sessions_mutations_container_id != ""
    error_message = "gateway_rust_logout requires a verified Rust container ID or enable_rust_stack."
  }
}

variable "gateway_rust_profile" {
  description = "Route PATCH/OPTIONS /api/v1/auth/profile to a verified Rust API revision."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_profile || var.enable_rust_stack || var.gateway_rust_sessions_mutations_container_id != ""
    error_message = "gateway_rust_profile requires a verified Rust container ID or enable_rust_stack."
  }
}

variable "gateway_rust_avatar_delete" {
  description = "Route DELETE/OPTIONS /api/v1/auth/avatar to the verified Rust mutation API with private S3 access."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_avatar_delete || var.enable_rust_stack || var.gateway_rust_sessions_mutations_container_id != ""
    error_message = "gateway_rust_avatar_delete requires a verified Rust mutation API container ID or enable_rust_stack."
  }
}

variable "gateway_rust_avatar_upload" {
  description = "Route POST /api/v1/auth/avatar to the verified Rust mutation API with private S3 access."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_avatar_upload || var.enable_rust_stack || var.gateway_rust_sessions_mutations_container_id != ""
    error_message = "gateway_rust_avatar_upload requires a verified Rust mutation API container ID or enable_rust_stack."
  }
}

variable "gateway_rust_preferences" {
  description = "Route preferences, timezones and account consents to a verified Rust API revision."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_preferences || var.enable_rust_stack || var.gateway_rust_sessions_mutations_container_id != ""
    error_message = "gateway_rust_preferences requires a verified Rust container ID or enable_rust_stack."
  }
}

variable "gateway_rust_apps" {
  description = "Route account-owned OAuth applications list and revoke to a verified Rust API revision."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_apps || var.enable_rust_stack || var.gateway_rust_sessions_mutations_container_id != ""
    error_message = "gateway_rust_apps requires a verified Rust API container ID or enable_rust_stack."
  }
}

variable "gateway_rust_security_read" {
  description = "Route MFA status, passkey inventory, security snapshot and login history reads to a verified Rust API revision."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_security_read || var.enable_rust_stack || var.gateway_rust_sessions_mutations_container_id != ""
    error_message = "gateway_rust_security_read requires a verified Rust API container ID or enable_rust_stack."
  }
}

variable "gateway_rust_email_status" {
  description = "Route the authenticated email status GET to the verified Rust security-read API revision."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_email_status || var.gateway_rust_security_read
    error_message = "gateway_rust_email_status requires gateway_rust_security_read."
  }
}

variable "gateway_rust_email_cancel" {
  description = "Route the authenticated pending email-change cancellation DELETE to a verified Rust API revision."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_email_cancel || var.enable_rust_stack || var.gateway_rust_sessions_mutations_container_id != ""
    error_message = "gateway_rust_email_cancel requires a verified Rust API container ID or enable_rust_stack."
  }
}

variable "gateway_rust_email_change" {
  description = "Route authenticated email-change requests to Rust after the claim schema and mail worker are deployed."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_email_change || ((var.enable_rust_stack || var.gateway_rust_sessions_mutations_container_id != "") && var.gateway_rust_email_cancel && var.gateway_rust_email_verify_api)
    error_message = "gateway_rust_email_change requires the verified mutation API, cancellation and Rust confirmation routes."
  }
}

variable "gateway_rust_password_change" {
  description = "Route password change to Rust only after durable security-mail delivery is enabled and tested."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_password_change || var.enable_rust_stack || var.gateway_rust_sessions_mutations_container_id != ""
    error_message = "gateway_rust_password_change requires a verified Rust API container ID or enable_rust_stack."
  }
}

variable "gateway_rust_account_jwt" {
  description = "Route session-derived account JWT issuance and account refresh rotation to a verified Rust API revision."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_account_jwt || var.enable_rust_stack || var.gateway_rust_sessions_mutations_container_id != ""
    error_message = "gateway_rust_account_jwt requires a verified Rust API container ID or enable_rust_stack."
  }
}

variable "gateway_rust_login" {
  description = "Route only the Topcoat login page and its assets through the existing Gateway."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_login || var.enable_rust_stack || var.gateway_rust_web_container_id != ""
    error_message = "gateway_rust_login requires either enable_rust_stack or gateway_rust_web_container_id."
  }
}

variable "gateway_rust_account" {
  description = "Route the Topcoat account page while retaining the React cabinet at /legacy/account."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_account || var.enable_rust_stack || var.gateway_rust_web_container_id != ""
    error_message = "gateway_rust_account requires either enable_rust_stack or gateway_rust_web_container_id."
  }
}

variable "gateway_rust_recovery_pages" {
  description = "Route the Topcoat password recovery and email verification pages through the existing Gateway."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_recovery_pages || var.enable_rust_stack || var.gateway_rust_web_container_id != ""
    error_message = "gateway_rust_recovery_pages requires either enable_rust_stack or gateway_rust_web_container_id."
  }
}

variable "gateway_rust_web_container_id" {
  description = "Existing Topcoat container used for the login slice."
  type        = string
  default     = ""

  validation {
    condition     = var.gateway_rust_web_container_id == "" || can(regex("^bba[a-z0-9]{17}$", var.gateway_rust_web_container_id))
    error_message = "gateway_rust_web_container_id must be a YC serverless container ID."
  }
}

variable "rust_api_image_tag" {
  description = "Immutable CI-tested Rust API image tag."
  type        = string
  default     = ""
}

variable "rust_api_image_digest" {
  description = "Exact CI-tested Rust API image digest."
  type        = string
  default     = ""
}

variable "rust_web_image_tag" {
  description = "Immutable CI-tested Topcoat UI image tag."
  type        = string
  default     = ""
}

variable "rust_web_image_digest" {
  description = "Exact CI-tested Topcoat UI image digest."
  type        = string
  default     = ""
}

variable "serverless_subnet_cidr" {
  description = "Subnet CIDR for serverless resources."
  type        = string
  default     = "10.20.0.0/24"
}

variable "enable_serverless_vpc" {
  description = "Create a dedicated VPC network for the backend serverless container. Existing stacks that already manage this network should set this to true before planning."
  type        = bool
  default     = false
}

variable "ydb_database_name" {
  description = "Serverless YDB database name."
  type        = string
  default     = "updspace-id"
}

variable "frontend_bucket_name" {
  description = "Optional explicit Object Storage bucket name for frontend assets."
  type        = string
  default     = ""
}

variable "media_bucket_name" {
  description = "Optional explicit Object Storage bucket name for avatars/media."
  type        = string
  default     = ""
}

variable "enable_rust_export" {
  description = "Enable Rust export jobs after their schema is applied. Public export API remains separately gated."
  type        = bool
  default     = false
}

variable "manage_rust_export_bucket" {
  description = "Create the private export bucket in this Terraform state. Set false for an existing bucket managed outside this state."
  type        = bool
  default     = true

  validation {
    condition     = !var.enable_rust_export || var.manage_rust_export_bucket || var.export_bucket_name != ""
    error_message = "An externally managed export bucket requires export_bucket_name."
  }
}

variable "enable_rust_export_api" {
  description = "Enable the Rust export HTTP API only after the private bucket, schema, jobs and reauthentication are verified."
  type        = bool
  default     = false

  validation {
    condition     = !var.enable_rust_export_api || (var.enable_rust_export && (var.enable_rust_stack || var.gateway_rust_sessions_mutations_container_id != ""))
    error_message = "enable_rust_export_api requires enable_rust_export and a Rust mutation API container."
  }
}

variable "enable_rust_export_delayed" {
  description = "Route the delayed export redemption page/API after the escrow schema, mail jobs and 48-hour private-object lifecycle have been verified."
  type        = bool
  default     = false

  validation {
    condition     = !var.enable_rust_export_delayed || (var.enable_rust_export && var.enable_rust_export_api)
    error_message = "Delayed export requires the private export bucket and Rust export API."
  }
}

variable "enable_rust_export_recovery_timer" {
  description = "Recover only pending and expired exports on the existing private Rust jobs container."
  type        = bool
  default     = false

  validation {
    condition     = !var.enable_rust_export_recovery_timer || (var.enable_rust_export && var.enable_gravatar_job && var.gravatar_rust_jobs_container_id != "")
    error_message = "Export recovery requires the private export bucket and existing Rust jobs container with scheduler identity."
  }
}

variable "export_bucket_name" {
  description = "Optional private Object Storage bucket name for full account exports."
  type        = string
  default     = ""
}

variable "export_operation_secret_id" {
  description = "Existing Lockbox secret ID containing ID_EXPORT_OPERATION_KEY; empty lets Terraform generate the key."
  type        = string
  default     = ""

  validation {
    condition     = var.export_operation_secret_id == "" || can(regex("^e6[a-z0-9]{18}$", var.export_operation_secret_id))
    error_message = "export_operation_secret_id must be a Lockbox secret ID."
  }
}

variable "export_operation_secret_version_id" {
  description = "Pinned version of the existing export operation secret."
  type        = string
  default     = ""

  validation {
    condition     = (var.export_operation_secret_id == "") == (var.export_operation_secret_version_id == "")
    error_message = "Both export operation secret ID and version ID must be set together."
  }
}

variable "object_storage_force_destroy" {
  description = "Allow Terraform to delete non-empty Object Storage buckets."
  type        = bool
  default     = false
}

variable "container_image_tag" {
  description = "Backend container image tag."
  type        = string
  default     = "latest"
}

variable "container_registry_id" {
  description = "Optional existing Container Registry ID. When empty, Terraform creates a registry."
  type        = string
  default     = ""
}

variable "backend_memory_mb" {
  description = "Backend HTTP container memory in MB."
  type        = number
  default     = 1024
}

variable "backend_cores" {
  description = "Backend HTTP container cores."
  type        = number
  default     = 1
}

variable "backend_concurrency" {
  description = "Backend HTTP container concurrency."
  type        = number
  default     = 8
}

variable "min_ready_instances" {
  description = "Prepared backend instances. Default 0 avoids idle capacity charges; opt into 1 only when measured cold-start latency justifies the cost."
  type        = number
  default     = 0

  validation {
    condition     = var.min_ready_instances >= 0 && floor(var.min_ready_instances) == var.min_ready_instances
    error_message = "min_ready_instances must be a non-negative integer."
  }
}

variable "service_environment" {
  description = "Additional plain-text environment variables for the backend."
  type        = map(string)
  default     = {}
}

variable "lockbox_secret_entries" {
  description = "Plain-text runtime secrets placed into Lockbox."
  type        = map(string)
  default     = {}
  sensitive   = true
}

variable "monium_api_key" {
  description = "API key with yc.monium.telemetry.write scope for Monium telemetry export."
  type        = string
  default     = ""
  sensitive   = true
}

variable "log_retention_period" {
  description = "Cloud Logging group retention period."
  type        = string
  default     = "168h"
}

variable "existing_network_id" {
  description = "Existing VPC with subnets in all availability zones for private cache access."
  type        = string
  default     = ""
}

variable "cache_subnet_id" {
  description = "Existing subnet for the managed cache host."
  type        = string
  default     = ""
}

variable "enable_shared_cache" {
  type    = bool
  default = false
}

variable "deployment_service_account_name" {
  description = "Existing CI service account to grant timer deployment permissions."
  type        = string
  default     = ""
}

variable "enable_gravatar_job" {
  type    = bool
  default = false
}

variable "gravatar_rust_jobs_container_id" {
  description = "Existing private Rust jobs container to receive the hourly Gravatar timer. Empty keeps the legacy Django Gravatar container."
  type        = string
  default     = ""

  validation {
    condition     = var.gravatar_rust_jobs_container_id == "" || can(regex("^[a-z0-9]{20}$", var.gravatar_rust_jobs_container_id))
    error_message = "gravatar_rust_jobs_container_id must be empty or a YC container ID."
  }
}

variable "enable_rust_mail_recovery_timer" {
  description = "Run only the security-mail outboxes on the existing private Rust jobs container; does not start deletion or export recovery."
  type        = bool
  default     = false

  validation {
    condition     = !var.enable_rust_mail_recovery_timer || (var.enable_gravatar_job && var.gravatar_rust_jobs_container_id != "")
    error_message = "Rust mail recovery requires the existing private Rust jobs container and scheduler identity."
  }
}

variable "enable_rust_verify_mail_recovery_timer" {
  description = "Recover only Rust email-verification intents on the existing private jobs container. The deployed revision must enable verification mail and use the API's verification key."
  type        = bool
  default     = false

  validation {
    condition     = !var.enable_rust_verify_mail_recovery_timer || (var.enable_gravatar_job && var.gravatar_rust_jobs_container_id != "")
    error_message = "Rust verification-mail recovery requires the existing private jobs container and scheduler identity."
  }
}

variable "enable_rust_reset_mail_recovery_timer" {
  description = "Recover only Rust password-reset intents on the existing private jobs container. The deployed revision must enable reset mail and use the API's reset key."
  type        = bool
  default     = false

  validation {
    condition     = !var.enable_rust_reset_mail_recovery_timer || (var.enable_gravatar_job && var.gravatar_rust_jobs_container_id != "")
    error_message = "Rust reset-mail recovery requires the existing private Rust jobs container and scheduler identity."
  }
}

variable "enable_rust_password_mail_recovery_timer" {
  description = "Recover only password-change notification intents on the existing private Rust jobs container."
  type        = bool
  default     = false

  validation {
    condition     = !var.enable_rust_password_mail_recovery_timer || (var.enable_gravatar_job && var.gravatar_rust_jobs_container_id != "")
    error_message = "Rust password-change mail recovery requires the existing private Rust jobs container and scheduler identity."
  }
}

variable "enable_rust_security_mail_recovery_timer" {
  description = "Recover only Rust passkey-removal notices on the existing private jobs container."
  type        = bool
  default     = false

  validation {
    condition     = !var.enable_rust_security_mail_recovery_timer || (var.enable_gravatar_job && var.gravatar_rust_jobs_container_id != "")
    error_message = "Rust security-mail recovery requires the existing private Rust jobs container and scheduler identity."
  }
}

variable "enable_rust_mail_job" {
  description = "Deploy the private Rust mail outbox worker, recovery timer and YMQ trigger. Requires enable_rust_mail_queue."
  type        = bool
  default     = false
}

variable "enable_rust_password_reset" {
  description = "Enable Rust password recovery in API, Topcoat and private mail jobs after the schema and shared Lockbox key are ready."
  type        = bool
  default     = false

  validation {
    condition     = !var.enable_rust_password_reset || (var.enable_rust_stack && var.enable_rust_mail_job && var.enable_rust_mail_queue)
    error_message = "Rust password recovery requires the Rust API/UI, private mail job and persistent queue."
  }
}

variable "enable_rust_email_verify" {
  description = "Enable Rust email verification in API, Topcoat and private mail jobs after schema and Lockbox key are ready."
  type        = bool
  default     = false

  validation {
    condition     = !var.enable_rust_email_verify || (var.enable_rust_stack && var.enable_rust_mail_job && var.enable_rust_mail_queue)
    error_message = "Rust email verification requires the Rust API/UI, private mail job and persistent queue."
  }
}

variable "enable_rust_signup" {
  description = "Enable Rust signup only after local registration, email delivery and identity checks pass."
  type        = bool
  default     = false

  validation {
    condition     = !var.enable_rust_signup || (var.enable_rust_stack && var.enable_rust_email_verify)
    error_message = "Rust signup requires the Rust API and durable email verification job."
  }
}

variable "gateway_rust_signup_page" {
  description = "Serve the Topcoat signup page while keeping the current signup API implementation."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_signup_page || var.enable_rust_stack || var.gateway_rust_web_container_id != ""
    error_message = "The Topcoat signup page requires either enable_rust_stack or gateway_rust_web_container_id."
  }
}

variable "gateway_rust_home_page" {
  description = "Serve the public landing page from Topcoat independently of the API cutover."
  type        = bool
  default     = false

  validation {
    condition     = !var.gateway_rust_home_page || var.enable_rust_stack || var.gateway_rust_web_container_id != ""
    error_message = "The Topcoat landing page requires either enable_rust_stack or gateway_rust_web_container_id."
  }
}

variable "enable_rust_mail_queue" {
  description = "Provision the persistent YMQ mail queue and its writer credentials independently of the worker, so rollback can stop the worker without destroying queued messages."
  type        = bool
  default     = false
}

variable "rust_mail_job_image_tag" {
  description = "Immutable CI-tested tag for the Rust jobs image. Required when enable_rust_mail_job is true."
  type        = string
  default     = ""
}

variable "rust_mail_job_image_digest" {
  description = "Exact sha256 digest of the CI-tested Rust jobs image. Required when enable_rust_mail_job is true."
  type        = string
  default     = ""

  validation {
    condition     = var.rust_mail_job_image_digest == "" || can(regex("^sha256:[0-9a-f]{64}$", var.rust_mail_job_image_digest))
    error_message = "rust_mail_job_image_digest must be empty or a sha256 digest."
  }
}

variable "live_service_environment" {
  description = "Existing runtime settings preserved by the deployment snapshot script. Explicit service_environment values take precedence."
  type        = map(string)
  default     = {}
}

variable "live_secret_entries" {
  description = "Current Lockbox values preserved during rollout to avoid reverting out-of-band rotations."
  type        = map(string)
  default     = {}
  sensitive   = true
}
