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
  description = "Prepared backend instances. Set 0 explicitly to trade cold-start latency for lower idle cost."
  type        = number
  default     = 1

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

variable "enable_gravatar_job" {
  type    = bool
  default = false
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
