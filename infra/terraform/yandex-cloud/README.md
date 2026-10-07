# Yandex Cloud infrastructure for UpdSpace ID

This module describes API Gateway routing, Serverless YDB, Object Storage,
Lockbox, identities and timers for the Rust `id-api`, Topcoat `id-web` and
`id-jobs` stack. The deploy workflow in
[`.github/workflows/deploy-yandex-cloud.yml`](../../../.github/workflows/deploy-yandex-cloud.yml)
builds tested Rust images and updates the **existing** API, web and jobs
containers. The API image is deployed to the main, sessions-read and
mutations containers because the live Gateway sends requests to all three;
all five active Rust containers are included in revision capture and rollback.
The workflow does not apply OpenTofu or publish a React bundle.

The checked-in [`production.performance.tfvars`](production.performance.tfvars)
records the intended Rust routing and scale-to-zero configuration. It is not a
snapshot of the current cloud environment. In particular,
`enable_rust_export_delayed` is not enabled there: the production export path
still delivers an archive without the requested 24-hour wait. The delayed
export and deletion flow has local YDB/Object Storage/SMTP coverage, but still
needs production rehearsal and explicit activation.
The next API/web revision stops accepting new immediate exports while keeping
status and downloads for existing requests. The UI shows that new requests are
temporarily unavailable until the delayed flow is activated across API, web
and jobs. This source change alone does not alter the live production revision.

## Validation and production changes

Run local syntax and provider validation with:

```sh
scripts/ci/check-yc-terraform-local.sh
```

For a production plan, initialize the existing remote state with its private
backend configuration and pass the private runtime variables plus
`production.performance.tfvars` to `tofu plan`. First inspect current live
Gateway routes, container revisions, Lockbox secret versions, IAM bindings and
persistent resources with `yc`. The Terraform state can contain a legacy
Django backend that was already removed manually; do not recreate it or change
serving Rust revisions as an incidental effect of state reconciliation.
The retired blue resource is no longer declared. Before the first apply with
this revision, compare `tofu state list` with `yc serverless container list`.
If state still tracks the absent blue container or its invoker binding, remove
only those stale addresses from state after verifying their cloud IDs are gone.
Review the planned green Rust container, Gateway, YDB, buckets and Lockbox
changes separately.
Review every planned change before applying. Do not apply a plan that replaces
YDB, buckets, secrets, the Gateway, or live Rust containers unexpectedly.
There is currently no automated live-state snapshot or plan guard in the
project; manual review is required until a Rust/Node replacement is built.
Keep backend configuration and secrets outside Git.

The production deploy workflow is triggered only for a SHA whose `ID CI/CD`
push run passed. `idctl verify-tested-revision` checks the exact repository,
branch, SHA, workflow conclusion and required jobs before image publishing.
The three images are deployed by digest to the existing containers, followed
by Gateway and smoke checks. A local source change does not reach production
until the tested SHA is available to GitHub Actions and this workflow succeeds.

## Routing and runtime

API Gateway presents ID pages and HTTP routes on one origin. `id-web` renders
pages and calls `id-api`; it has no direct YDB or signing-key access. `id-jobs`
uses private trigger/timer routes. `/_id/*` is served with explicit CSS/JS MIME
types; account, authentication and OAuth responses must not enter shared
caches. `min_ready_instances` defaults to zero, so cold-start latency remains
a measured part of the user experience.
The catch-all GET route now reaches Topcoat. Unknown paths return its 404
instead of a React `index.html` from Object Storage. The former frontend
bucket is temporarily retained as a Terraform-managed resource, but Gateway
has no route for it; this Terraform revision removes the old Gateway viewer
permission when applied. Remove the bucket in a separate
reviewed state change after the last old assets are no longer needed.
The hourly Gravatar timer requires `gravatar_rust_jobs_container_id` and calls
the Rust jobs container. Terraform no longer contains the retired Django
Gravatar container or blue backend resources. The historical green resource
continues to pin the active Rust API container without replacing it.

The Rust export bucket is private and separate from public frontend/media
storage. `enable_rust_export` provisions it; `enable_rust_export_api` selects
the owner-scoped API. `enable_rust_export_delayed` additionally enables the
24-hour escrow, notification, timed mail and fragment-token redemption path.
It must be deployed coherently
to the mutations API, Topcoat web and jobs. Before exposing delayed export,
run `scripts/ci/check-yc-delayed-export.mjs` with
`RUST_MUTATIONS_CONTAINER_ID`, `RUST_WEB_CONTAINER_ID` and
`RUST_JOBS_CONTAINER_ID` set to the live IDs, and `ID_GATEWAY_ID` set to the
active Gateway; set `EXPECTED_BUILD_ID` to the
tested deployment SHA. The check verifies flags, the same versioned escrow
key binding, private bucket, public origin, recovery timer and exact Gateway
routes for request, status, owner and email-link cancellation, download,
redemption, delivery and cancellation pages without printing
secrets. The deploy workflow then opens both public pages and sends invalid
download/cancellation tokens through the Gateway as a side-effect-free smoke.
A passing configuration and smoke check still requires the full mail, storage,
deletion and redemption rehearsal.
Do not set the delayed flag until the corresponding jobs, SMTP, Object Storage,
key retention, cancellation and delete-after-export scenarios have passed on
the target environment. A live session cannot bypass the cooldown.

`enable_rust_mail_queue` provisions standard Yandex Message Queue and IAM
for mail. `enable_rust_mail_job` adds the private jobs container and triggers.
Queue delivery can repeat, so outbox and worker operations must remain
idempotent. The existing Gateway is updated through
[`scripts/ci/update-yc-gateway.sh`](../../../scripts/ci/update-yc-gateway.sh)
when `existing_api_gateway_id` is set; the domain attachment is retained.
The provider source is pinned to `registry.terraform.io/yandex-cloud/yandex`
for OpenTofu compatibility.

The current Rust UI has only a read-only deletion-request lookup, and its
`/admin/` route is disabled in production. The additional
`gateway_rust_admin_suspend` gate exposes the password-confirmed account
suspension review and API route only when the operator area is enabled. Neither
gate is active in production, and this must not be counted as full Rust
administration. The remaining
functional and interface gaps are tracked in
[`docs/rust-migration/identity-ux-and-export.md`](../../../docs/rust-migration/identity-ux-and-export.md).
