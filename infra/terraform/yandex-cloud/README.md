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
3. `terraform -chdir=infra/terraform/yandex-cloud init`
4. `terraform -chdir=infra/terraform/yandex-cloud plan`
5. `terraform -chdir=infra/terraform/yandex-cloud apply`
6. Configure GitHub Actions secrets used by `.github/workflows/deploy-yandex-cloud.yml`.

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
