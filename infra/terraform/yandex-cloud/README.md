# Yandex Cloud Terraform

Production-like low-cost stack for UpdSpace ID:

- API Gateway for same-origin API/OIDC routes and frontend assets
- Serverless Container for Django backend
- Object Storage buckets for frontend and avatars/media
- Serverless YDB as the production database
- Lockbox for runtime secrets

The Rust export bucket is opt-in (`enable_rust_export = true`). It is private,
separate from frontend/media storage, aborts incomplete multipart uploads after
one day, and expires orphaned objects after two days. Jobs delete finished
archives after 24 hours and during account deletion. The bucket has
`prevent_destroy`; disabling the flag does not delete archived data. Validate
with OpenTofu locally, then review a plan against the existing remote state
before applying. The public Rust export routes remain in local pilot mode.

For a first production API slice, `gateway_rust_me = true` routes only
`GET /api/v1/auth/me` to the Rust API. The `/api/v1/{proxy+}` catch-all and
all OAuth routes keep their existing backend until the complete API is ready.
When the serverless-container quota is full, set
`gateway_rust_me_container_id` to an existing Rust revision's container ID
and leave `enable_rust_stack = false`. The `rust_me` workflow-dispatch input
selects this slice after the Rust image is built and deployed. Full
`gateway_use_rust = true` still requires the separately deployed stack.
`gateway_rust_login = true` similarly routes only the Topcoat `/login` page
and `/_id` assets; set `gateway_rust_web_container_id` when using an existing
web container. The rest of the React UI remains in Object Storage.
`gateway_rust_account = true` routes `/account` to Topcoat and keeps the full
React cabinet at `/legacy/account` during migration. Publish a React bundle
that recognizes `/legacy/account` before linking to it from Topcoat.
`gateway_rust_recovery_pages = true` routes only `/forgot-password`,
`/reset-password`, and `/verify-email` to that Topcoat container. Keep the
form-token consumer compatible with the shared-cache codec during a mixed
deployment. The production Python compatibility revision now reads and writes
the portable codec; verify that revision and run `idctl cache-audit
--require-portable` before routing token issuance to Rust.
`gateway_rust_jwks = true` routes only `/oauth/jwks` and
`/.well-known/jwks.json` to a Rust API revision with
`ID_OIDC_JWKS_ENABLED=true`. Verify the complete public key set against the
previous issuer response before changing either route.
`gateway_rust_form_token = true` separately routes only
`GET /api/v1/auth/form_token` to the same Rust API container selected by
`gateway_rust_me_container_id`. Enable it only after the deployed Python
version can consume Rust's portable shared-cache values, or after every
form-token consumer has moved to Rust.
`gateway_rust_login_api = true` separately routes only `POST` and `OPTIONS`
`/api/v1/auth/login` to that Rust API container. Production enabled this route
after a verified test-account login, Rust `/me` restore, Python `/sessions`
cookie/header compatibility and Chromium login with an `/account` reload. The
remaining account routes still use the Python compatibility container.
`gateway_rust_sessions_read = true` routes only `GET` and `OPTIONS`
`/api/v1/auth/sessions` to Rust. `gateway_rust_sessions_container_id` may pin a
separate verified Rust container so the login revision stays independent.
Grant the Gateway service account `serverless.containers.invoker` on that
container before changing the route. `gateway_rust_sessions_mutations = true`
independently routes DELETE `/sessions/{sid}` and POST `/sessions/bulk` and
`/sessions/_bulk` to a revision with
`ID_AUTH_SESSIONS_MUTATIONS_ROLLOUT_ENABLED=true`.
`gateway_rust_sessions_mutations_container_id` pins that verified revision;
the production rollout uses a separate container from the read route.
`gateway_rust_logout = true` also routes POST/OPTIONS `/api/v1/auth/logout`
to the mutation container. Enable `ID_AUTH_LOGOUT_ROLLOUT_ENABLED=true` on its
verified revision before switching the Gateway path.
`gateway_rust_profile = true` routes PATCH/OPTIONS `/api/v1/auth/profile`
to the same verified container when `ID_AUTH_PROFILE_ROLLOUT_ENABLED=true`.
`gateway_rust_health = true` routes `/healthz` and `/readyz` to the Rust API.
`gateway_rust_catchall = true` also routes the remaining `/api/v1/{proxy+}`
fallback and `/health` to Rust. Unsupported legacy API paths return 404;
the Rust `/health` response is a readiness result, not the old detailed
Django component report. The Python container can be removed after the
Terraform-managed backend resource and state are retired.
`gateway_rust_preferences = true` routes GET/PATCH/OPTIONS preferences,
GET timezones, GET/OPTIONS consents, and POST/OPTIONS consent revocation
to the same verified container when
`ID_AUTH_PREFERENCES_ROLLOUT_ENABLED=true`.
`gateway_rust_oidc = true` routes the complete OAuth authorize, token,
UserInfo and revoke flow to the mutation container and GET `/oauth/consent`
to Topcoat. Enable both `ID_OIDC_TOKEN_ROLLOUT_ENABLED=true` and
`ID_OIDC_AUTHORIZE_ROLLOUT_ENABLED=true` on the API revision and
`ID_WEB_CONSENT_PILOT_ENABLED=true` on the web revision first. Do not split
the token flow between old and new revisions: the deployed Python image
lacks refresh-family persistence. `gateway_rust_apps = true` separately
routes account OAuth applications list/revoke to the same API revision after
`ID_AUTH_APPS_PILOT_ENABLED=true` has passed a private check.
`gateway_rust_security_read = true` routes GET/OPTIONS MFA status, passkeys,
combined security and login history to the verified API revision after
`ID_AUTH_SECURITY_READ_PILOT_ENABLED=true` has passed a private check.

For the existing hourly Gravatar timer, set `gravatar_rust_jobs_container_id`
to the tested private Rust jobs container after that revision enables
`ID_GRAVATAR_JOB_ENABLED=true` and `POST /refresh-gravatars` passes a private
smoke. With `enable_gravatar_job=true`, the timer and scheduler invocation
permission then target Rust; the dedicated Django Gravatar container is no
longer part of the desired infrastructure. Keep the public Gateway separate
from this private route.

Production note (2026-10-06): the legacy Django container has been deleted
from YC but is still recorded in this Terraform state. Production tfvars set
`legacy_backend_enabled=false` and require a private snapshot of the live
Rust green revision. The current
`.github/workflows/deploy-yandex-cloud.yml` deploys the existing Rust API,
Topcoat UI and jobs containers directly by tested image digest; it does not
run Terraform or publish the React bundle. Before a separate production
Terraform plan, run `snapshot-yc-runtime.py --retire-legacy` with the verified
Rust API container and Gateway IDs, then inspect the plan with
`check-yc-plan.py --retire-legacy-backend --snapshot` using that private file.
Only the already-deleted blue container and its invoker binding may be removed;
the serving green revision must stay unchanged. Do not apply a plan that
changes other resources.

Terraform bootstrap/reference order for a new stack:

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

The production Rust deploy workflow does not initialize or apply Terraform.

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

`min_ready_instances` defaults to **0**, including in the example and production
profile. This avoids prepared-capacity charges during idle periods; the first
request after inactivity can incur a cold start. Application changes reduce
unnecessary requests and session writes without a new always-on service. Opt into
`1` only after measuring real login latency and agreeing an idle-capacity budget.
This is a configuration change for the next reviewed deployment, not a claim that
the live revision has already changed. Prepared capacity is not an instance limit.

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
variables when planning production. CI does this explicitly, so the checked-in
scale-to-zero setting takes precedence over older prepared-capacity settings in
its runtime secret.
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

## Tested revision gate

Production rollout is triggered only after the `ID CI/CD` push workflow completes
successfully on `main` or `master`. Every checkout and image tag uses that run's
exact `head_sha`, including when the default branch has moved. Before reading
production secrets or pushing an image, `check-tested-revision.py` verifies the
run's repository, SHA, branch, workflow, conclusion and all eight required jobs,
including Rust API and Topcoat checks.
Missing, failed, cancelled or skipped required jobs stop deployment. A manual
rollout requires successful push CI for the selected SHA too; it never waits on
an idle runner for another workflow. PRs retain build-only validation.

The gate uses the read-only [GitHub Actions REST API](https://docs.github.com/en/rest/actions/workflow-runs).
No cloud resources, credentials, or billed prepared capacity are changed merely
by editing this profile or running the local regression tests.
## Rust mail outbox pilot

Both flags are off by default. Enable `enable_rust_mail_queue` first to create
the persistent standard YMQ queue, a send-only writer key in Lockbox, and
separate admin/reader identities. Then `enable_rust_mail_job` creates the
private `id-jobs` container, the queue trigger, a one-minute publish timer, and
a five-minute direct-SMTP recovery timer. Only the trigger identity may invoke
the container. Its routes are absent from API Gateway. The queue has
`prevent_destroy` and remains enabled when rolling back the worker.

The image tag and SHA-256 digest must identify the same CI-tested
`Dockerfile.jobs` artifact; `EMAIL_HOST` and `DEFAULT_FROM_EMAIL` must be
present. The signed YMQ publisher and timer path have only been tested against
a loopback SQS fixture and local YDB. A real staging YMQ/IAM test, image build
and publication, rollback rehearsal, and production acceptance remain open.
Terraform validation checks the configuration, without deploying any resource.
`enable_rust_password_reset` and `enable_rust_email_verify` independently
enable their API, Topcoat page and mail worker paths. Both are off by default,
require the queue and private worker, and require their separate HMAC keys in
runtime Lockbox. Run `idctl password-reset-schema` or
`idctl email-verify-schema` respectively before enabling a route.

## Early Rust API and Topcoat routing

The deployment workflow now builds digest-pinned `updatingspace-id-api` and
`updatingspace-id-web` images from the tested SHA and creates separate scale-to-zero
containers. The Topcoat service account has no YDB or Lockbox access. The Rust API
uses the existing runtime identity and signing secret; `idctl` audits ambiguous
login email/passkey records and builds the passkey index before routing changes.
Its private avatar URLs are signed with the runtime S3 credentials; the Rust
container keeps `S3_QUERYSTRING_AUTH=true`. A real GET from the private media
bucket remains a rollout check.

Set the GitHub Actions repository variable `YC_RUST_GATEWAY_ENABLED=true` to keep
Rust routing active across automatic deployments. A manual workflow dispatch may
select `rust_gateway=true` for one deployment; if the repository variable remains
false, the next automatic deployment routes back to Python. Rollback is the same
workflow with `rust_gateway=false` after clearing the repository variable. The
Python container and additive YDB schema remain during this early stage.

The current Rust Gateway route serves `/`, `/login`, `/account`, and `/_id/*`
from Topcoat, and API/OAuth paths from Axum. The targeted smoke verifies API
readiness, login assets, session response headers and form-token issuance. This
is an **early rollout**, not functional parity: signup and several
account/OIDC operations still need Rust implementations. The remaining React
pages are published as transitional assets and may call unavailable API routes.
Do not record those scenarios as accepted until their real browser/API checks
pass. No production route change has been verified merely by local Terraform
validation or container builds.
