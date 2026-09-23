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

## Observability and Monium

The backend emits JSON logs with `request_id`, Django/Prometheus metrics at
`/metrics`, and OpenTelemetry traces for Monium.

Tracing is enabled by Terraform when `monium_api_key` is provided. For
production, prefer routing traces through an OpenTelemetry Collector and keep
the Monium API key outside the application. The deploy workflow passes
`YC_MONIUM_API_KEY` into the sensitive Terraform variable `monium_api_key`, which
then writes `MONIUM_API_KEY` into the runtime Lockbox secret.

```hcl
service_environment = {
  MONIUM_PROJECT               = "<monium-project-id>"
  MONIUM_CLUSTER               = "prod"
  MONIUM_SERVICE_NAME          = "updspace-id"
  OTEL_EXPORTER_OTLP_ENDPOINT  = "ingest.monium.yandex.cloud:443"
  OTEL_TRACES_SAMPLER          = "parentbased_traceidratio"
  OTEL_TRACES_SAMPLER_ARG      = "0.1"
}

monium_api_key = "<api-key>"
```

## Serverless VPC upgrade note

`enable_serverless_vpc` defaults to `false` for new low-cost deployments to
avoid consuming VPC quota when the backend only needs public Yandex Cloud
services.

For an existing Terraform-managed stack that already created the dedicated
network/subnet and serverless container connectivity, set
`enable_serverless_vpc = true` before planning this version. Otherwise Terraform
will plan to remove the network/subnet and detach container connectivity.

If an API Gateway was created before this state was bootstrapped, set
`existing_api_gateway_id` (or `TF_VAR_existing_api_gateway_id` in CI) to reuse it
as a data source. The current Yandex provider does not support importing
`yandex_api_gateway`, so this compatibility mode prevents duplicate gateway
creation while the rest of the stack remains Terraform-managed.

In this compatibility mode, `terraform_data.existing_gateway_spec` tracks the
specification hash and invokes the YC CLI adapter during apply. Local apply
and CI use the same adapter. Authenticate YC before planning/applying; the
identity needs permission to update the gateway. The gateway itself is not
recreated and its existing domain attachment is retained.

OpenTofu note: the Yandex provider source is intentionally pinned as
`registry.terraform.io/yandex-cloud/yandex`, because the provider is not
published in the OpenTofu public registry.

## Latency and frontend releases

`min_ready_instances` defaults to **0**, including in the example tfvars and
the production profile. This avoids prepared-capacity charges at zero traffic;
the first request after the platform stops a container can wait for a cold start.
The platform controls how long idle, unprepared instances are retained; there is
no configured 15/30-minute grace-period guarantee. Nonzero prepared capacity is
an explicit cost decision and remains billable during idle time. Inspect both
the plan and deployed revision; a fast warm response does not prove a fast cold
start. Prepared capacity does not eliminate cold starts above that capacity.

The checked-in `production.performance.tfvars` disables managed Redis to avoid
the fixed host cost at the current traffic level. With YDB and no `REDIS_URL`,
the backend uses the existing serverless YDB for shared transient state.
Terraform creates `id_shared_cache` with automatic TTL cleanup. Form tokens
are consumed atomically and rate-limit increments use serializable transactions
across container instances. Prepared capacity is not an instance limit.
This adds database requests/storage without a dedicated cache host.

The optional managed cache configuration is not part of the production rollout.
Enabling it requires an explicit cost decision, `enable_shared_cache = true`,
cache deployment permissions and `--shared-cache` on the runtime snapshot.
It uses one hm3-c2-m8 host and 16 GB storage (not HA), private TLS, generated
Lockbox credentials and the bundled YC root certificate. The default snapshot
preserves live connectivity and does not attach containers to a new VPC.

The same profile enables a separate scale-to-zero Gravatar container and hourly
timer (minute 17 UTC, 25 profiles per batch, two retries). Only the scheduler
service account can invoke it; no public gateway route is created.

The production deployment identity is the existing `updspace-id-github-actions`
account, distinct from the legacy `updspace-id-ci` resource. Terraform grants
it `functions.editor` for timer management, without managed-cache permissions;
its existing VPC and IAM administration permissions support initial provisioning.

Always pass `-var-file=production.performance.tfvars` after private runtime
variables when planning production. CI does this explicitly, so an older
`min_ready_instances = 1` in its runtime secret cannot restore paid prepared
capacity. To opt in later, change the production profile as an explicit cost
decision rather than relying on a lower-precedence runtime variable.
Before planning, `scripts/ci/snapshot-yc-runtime.py` preserves the active
revision's environment and Lockbox values in a mode-0600 ignored tfvars file.
This prevents rollback of manual secret rotations and loss of SMTP settings.
Live secrets take precedence over old runtime tfvars; rotate them in Lockbox
and activate the new version before a subsequent snapshot, or explicitly update
the private snapshot for an intentional Terraform-managed rotation. Never commit
these files. The workflow rejects deletion/replacement of persistent resources.

Known SPA routes map directly to `index.html`. `/assets/{file+}` has no SPA
fallback, so missing chunks return an error instead of HTML with status 200.
The smoke script checks missing-asset 404 and `no-store` on session responses.

The publisher uploads assets first and index last. Fingerprinted Vite assets
receive `public,max-age=31536000,immutable`; index retains `no-cache`. Previous
assets are intentionally not deleted. Cleanup must retain every asset needed
by supported open clients and rollback releases; do not restore `sync --delete`.
Rollback consists of republishing the previous release's assets and index.

Cloudflare settings are outside this Terraform module. Check the actual
cache headers after deployment: browser TTL rules can override origin TTL.
Keep account/API/OAuth responses out of shared caches; do not enable a blanket
Cache Everything rule. No CDN/DNS migration is performed by these changes.

## Backend release slots

The production workflow uses two private backend containers (`blue` and `green`).
The original `yandex_serverless_container.backend` resource remains the blue
slot; existing data, domains and resource identities are preserved. The gateway
routes to one slot. Every release selects the other slot from the **live gateway
specification**, including after a rollback, rather than trusting a stale output.

The single release job keeps a private runtime snapshot and rollback files on its
runner. It prepares the inactive slot, runs backward-compatible YDB migrations,
builds the frontend, and saves the previous Object Storage `index.html`. It then
waits for nonzero prepared-capacity configuration to settle when enabled and checks
`/readyz` and form-token issuance through the private container URL using the
CI service account. Only a verified revision can receive public gateway traffic.
The IAM token is never forwarded to a redirect or arbitrary host.

The coordinator (`scripts/ci/yc_rollout.py`) validates each saved Terraform plan:

- Preparation cannot update the serving container or gateway. Adding only
  sensitive marks to identical, fully known values is allowed: Terraform 1.15.7
  persists these marks in state without calling the provider. Removing marks
  or changing any runtime value remains forbidden.
- Promotion and rollback may change only the gateway specification.
- Capacity cleanup may only remove the inactive slot's prepared capacity.
- Deletion or replacement of persistent resources remains forbidden. A secret
  version still referenced by the serving backend cannot be deleted during
  preparation; rotating it requires retaining that version through overlap.

After promotion, publication still uploads frontend dependencies before index.
If publication or public smoke fails, the job restores the previous index and
backend, then releases the failed candidate's prepared capacity. Database
migrations are not reversed: releases must remain compatible with the previous
backend during overlap and rollback. Schema removal requires a separate release
following an expand/migrate/contract sequence.

Successful public smoke is the release commit point. Failure to retire the old
prepared capacity is reported as a failed job but does **not** roll traffic back
to that old slot. The production profile sets the new slot to zero prepared
instances. The serving slot retains its live configuration until retirement;
after transition to this profile, both slots have zero prepared instances.
Finite readiness checks still run before promotion; they do not keep an idle
container alive after deployment.
They also do not establish a user-visible 500 ms latency bound. If prepared
capacity is explicitly enabled later, both slots may be billed during overlap.

For recovery, retain the private snapshot, release image tag and manifest from
the same run while invoking coordinator phases. `rollback` is only valid before
capacity retirement; `abort` requires the gateway to point to the original slot.
A stopped runner or a manual gateway change requires inspecting live routing and
revisions before recovery. Never publish manifests, tfvars, state or saved plans
as CI artifacts. Do not run a bare production apply with default slot values;
use the snapshot and guarded coordinator. Disabling `blue_green_enabled` after
a green slot exists would propose deletion and is rejected by the plan guard.

Before the first two-slot release, the cloud needs one additional container slot
and capacity for two prepared instances during overlap. Container quotas are
shared with other services in the cloud. A quota failure before candidate
creation leaves public routing unchanged; cleanup can resolve partial Terraform
state even when the new slot outputs have not yet been saved. CI reports only
a fixed error category, keeping raw provider diagnostics private. The production
log retention is the canonical `168h0m0s` (the same seven days), avoiding a
framework-provider duration-normalization diff during promotion.
