# Yandex Cloud infrastructure for UpdSpace ID

This module describes API Gateway routing, Serverless YDB, Object Storage,
Lockbox, identities and timers for the Rust `id-api`, Topcoat `id-web` and
`id-jobs` stack. The deploy workflow in
[`.github/workflows/deploy-yandex-cloud.yml`](../../../.github/workflows/deploy-yandex-cloud.yml)
builds tested Rust images and updates the **existing** API, web and jobs
containers. The API image is deployed to the main, sessions-read and
mutations containers because the live Gateway sends requests to all three;
all five active Rust containers are included in revision capture and rollback.
Rollback restores the captured image, environment, secret bindings and runtime
limits from each prior revision. It refuses to overwrite a revision changed
outside the deployment. The local CI double exercises both outcomes.
The workflow does not apply OpenTofu or publish a React bundle.
Before any schema or revision change, it dry-runs cloning all five active
Rust revisions with the tested image digests and SHA. A missing or ambiguous
active revision, incompatible environment, or secret collision stops the
deployment before the first production mutation.
After deployment, it checks that each of the five unique active revisions
actually serves the expected Rust image repository, digest and tested SHA;
an older still-active image fails the workflow and triggers rollback.

The checked-in [`production.performance.tfvars`](production.performance.tfvars)
records the intended Rust routing and scale-to-zero configuration. It is not a
snapshot of the current cloud environment. On 2026-10-07 the delayed export
routes and flags were enabled on the existing production Gateway, mutations
API, Topcoat web and jobs revisions. The live readiness gate passed and the
public pages, scripts and unauthenticated API denial passed smoke checks.
The real 24-hour notification, delivery, cancellation, post-deletion redemption
and freeze/resume journey still needs an end-to-end production rehearsal with
a disposable account;
these smoke checks do not establish user acceptance. The deletion API and
its recovery timer remain disabled and require a separate rollout.

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
The [2026-10-07 state reconciliation snapshot](../../../docs/rust-migration/production-state-reconciliation.md)
lists retired container addresses still present in remote state and the live
Rust resources that must remain untouched.

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
instead of a React `index.html` from Object Storage. The former React bucket
has no Gateway route and is no longer declared as a managed resource. A plan
against the current remote state should show its deletion; treat that as a
separate, explicit cleanup, not an incidental side effect of an unrelated
apply. As of 2026-10-07 the live bucket still held 110 old objects. Confirm
no old assets are needed, empty only this bucket, then review a plan that
deletes only the retired frontend bucket while preserving media and export
storage. The deprecated `frontend_bucket_name` input remains temporarily
accepted so private tfvars do not break during the transition; it no longer
creates a bucket.
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
A passing configuration and smoke check does not complete acceptance of the
enabled feature. The real 24-hour mail, storage, key retention, cancellation,
delete-after-export, redemption and freeze/resume scenarios still require a
production rehearsal. A live session cannot bypass the cooldown.

The account-deletion API and private recovery timer are a separate rollout.
Before enabling either flag or adding the Gateway route, run
`scripts/ci/check-yc-account-deletion.mjs` with the live mutation API, jobs and
Gateway IDs plus the tested `EXPECTED_BUILD_ID`. It requires a distinct
versioned deletion-operation key binding, both rollout flags, delayed export
escrow jobs, a private timer pointed at Rust jobs, and the exact public API
route. CI rejects a partially enabled bundle; the deploy workflow repeats the
check before and after every image update. On 2026-10-07 the live check
reported `disabled`: the key binding, rollout flags and timer were absent.
Do not expose a deletion control until the production export-after-deletion
journey and full cleanup have been rehearsed on a disposable account.

The live Gateway also routes Portal magic-link request and both consume
methods to the existing Rust API. The production tfvars pins the Portal HTTPS
redirect origin and `gateway_rust_magic_link=true`, matching the already
enabled API and jobs revisions. The deploy workflow checks safe malformed
requests before and after image replacement. Those checks prove routing and
fail-closed responses; production mail delivery and the Portal callback still
need an end-to-end test with a disposable account.

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
