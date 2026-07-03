output "api_gateway_id" {
  description = "API Gateway resource ID."
  value       = yandex_api_gateway.id.id
}

output "api_gateway_invoke_domain" {
  description = "Default invoke domain assigned by Yandex API Gateway."
  value       = yandex_api_gateway.id.domain
}

output "public_base_url" {
  description = "Public base URL used by ID runtime settings."
  value       = local.public_base_url
}

output "frontend_bucket_name" {
  description = "Object Storage bucket used for the frontend bundle."
  value       = yandex_storage_bucket.frontend.bucket
}

output "media_bucket_name" {
  description = "Object Storage bucket used for avatars/media."
  value       = yandex_storage_bucket.media.bucket
}

output "container_registry_id" {
  description = "Container Registry ID for Yandex Container Registry pushes."
  value       = local.container_registry_id
}

output "backend_invoke_url" {
  description = "Private invoke URL for the backend serverless container."
  value       = yandex_serverless_container.backend.url
}

output "ydb_endpoint" {
  description = "YDB endpoint for DB_DRIVER=ydb deployments."
  value       = yandex_ydb_database_serverless.id.ydb_full_endpoint
}

output "ydb_database" {
  description = "YDB database path for DB_DRIVER=ydb deployments."
  value       = yandex_ydb_database_serverless.id.database_path
}

output "runtime_lockbox_secret_id" {
  description = "Lockbox secret ID with runtime secrets and static S3 credentials."
  value       = yandex_lockbox_secret.runtime.id
}

output "runtime_lockbox_secret_version_id" {
  description = "Current Lockbox secret version for runtime secret injection."
  value       = yandex_lockbox_secret_version.runtime.id
}

output "service_accounts" {
  description = "Service account IDs created by this Terraform stack."
  value = {
    runtime    = yandex_iam_service_account.runtime.id
    gateway    = yandex_iam_service_account.gateway.id
    automation = yandex_iam_service_account.automation.id
    ci         = yandex_iam_service_account.ci.id
  }
}

output "object_storage_access_key_id" {
  description = "Static Object Storage access key used by frontend publish automation."
  value       = yandex_iam_service_account_static_access_key.automation.access_key
  sensitive   = true
}

output "object_storage_secret_access_key" {
  description = "Static Object Storage secret key used by frontend publish automation."
  value       = yandex_iam_service_account_static_access_key.automation.secret_key
  sensitive   = true
}
