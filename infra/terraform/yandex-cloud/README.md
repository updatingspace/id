# Yandex Cloud Terraform

Production-like low-cost stack for UpdSpace ID:

- API Gateway for same-origin API/OIDC routes and frontend assets
- Serverless Container for Django backend
- Object Storage buckets for frontend and avatars/media
- Serverless YDB as the production database
- Lockbox for runtime secrets

Apply order:

1. Copy `terraform.tfvars.example` to a private tfvars file and fill real values.
2. Run local validation: `scripts/ci/check-yc-terraform-local.sh`.
3. Configure an S3-compatible remote state backend and save its backend config
   as the `YC_TF_BACKEND_CONFIG_B64` GitHub Actions secret.
4. `terraform -chdir=infra/terraform/yandex-cloud init -backend-config=backend.hcl`
5. For an already-created stack, import existing Yandex Cloud resources into
   the remote state before enabling auto-apply.
6. `terraform -chdir=infra/terraform/yandex-cloud plan`
7. `terraform -chdir=infra/terraform/yandex-cloud apply`
8. Configure GitHub Actions secrets used by `.github/workflows/deploy-yandex-cloud.yml`.

Example backend config for Yandex Object Storage:

```hcl
bucket                      = "updspace-id-tfstate"
key                         = "prod/terraform.tfstate"
region                      = "ru-central1"
endpoint                    = "https://storage.yandexcloud.net"
access_key                  = "<state bucket access key>"
secret_key                  = "<state bucket secret key>"
skip_credentials_validation = true
skip_region_validation      = true
skip_requesting_account_id  = true
skip_s3_checksum            = true
```

Encode it for GitHub Actions with:

```bash
base64 -w0 backend.hcl
```

The deploy workflow refuses `YC_TERRAFORM_AUTO_APPLY=true` when the configured
remote state is empty. This prevents a fresh runner from creating duplicate
resources when the real stack already exists.

## Serverless VPC upgrade note

`enable_serverless_vpc` defaults to `false` for new low-cost deployments to
avoid consuming VPC quota when the backend only needs public Yandex Cloud
services.

For an existing Terraform-managed stack that already created the dedicated
network/subnet and serverless container connectivity, set
`enable_serverless_vpc = true` before planning this version. Otherwise Terraform
will plan to remove the network/subnet and detach container connectivity.

OpenTofu note: the Yandex provider source is intentionally pinned as
`registry.terraform.io/yandex-cloud/yandex`, because the provider is not
published in the OpenTofu public registry.
