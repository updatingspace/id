# Production state before enabling delayed Rust export

This records the 2026-10-07 pre-rollout state. Later the same day the serving
mutations API and jobs revisions were bound to the managed escrow key, the
delayed export flags and Gateway routes were enabled, and the live readiness
gate plus unauthenticated public smoke passed. The full production owner,
email and post-deletion journey remains unverified. Reinspect live YC before
using any historical revision ID or state detail below.

## State cleanup completed on 2026-10-07

Both retired Python container IDs below were rechecked as `NotFound` in YC.
OpenTofu initialized the existing S3 backend with state locking, confirmed
all six exact addresses with `state rm -dry-run`, then removed only those six
addresses from the remote state. The state serial advanced from 104 to 105.
`yandex_serverless_container.backend_green[0]` remains in state and continues
to name the serving Rust API. No production container or Gateway route was
changed by this state operation.

An isolated OpenTofu plan on a temporary copy then changed exactly
`random_id.export_escrow[0]` and `yandex_lockbox_secret_version.runtime`.
Applying that plan advanced state serial to 106 and created Lockbox version
`e6q9lm8k2k3bo0efe5b1`. Its 32-byte escrow key is new; all ten prior
Lockbox values were compared with the preceding version and preserved
unchanged. At that point the API and jobs revisions did not yet bind the new key.
The targeted replacement scheduled the preceding version
`e6q2gi6p6j9hjbbmkhi2` for destruction while production revisions still
referenced it. At 14:52 UTC, ID returned HTTP 502 through both Cloudflare and
the direct Gateway. We cancelled destruction of that exact version; both it
and the new version are now `ACTIVE`. Public API and OIDC prepare returned
HTTP 200 again, and a real Portal → ID → Portal login/consent cycle passed.
Do not schedule destruction of either version while an active revision still
binds it. A targeted runtime secret-version apply is unsafe unless the old
version is kept active through revision replacement. Recheck version statuses,
all active bindings, and public routes before another OpenTofu apply.
The runtime version now has `prevent_destroy` in OpenTofu. Future rotations
need an explicit staged-version change: create and inspect the replacement
while the pinned version stays active, rebind every serving API, web and jobs
revision, and verify those revisions and public routes. Only after no active
revision refers to the old version may an operator deliberately remove the
guard in a reviewed migration. Never bypass it with `-target` or state surgery
during normal deployment.
The complete, non-targeted OpenTofu plan and delayed-export rollout remain
outstanding; do not infer them from the targeted apply.

On 2026-10-07, all 11 additive `idctl` schema commands were rerun successfully
against production YDB with the deploy service account. The exact database ID,
command list, verification time and schema-source digest are recorded in
`production-ydb-schema-receipt.json`. GitHub-hosted runners repeatedly failed
at `cache-schema` while the same commands succeeded from the operator host; the
underlying runner-to-YDB failure has not been established because private job
logs were unavailable. Deployment therefore checks the receipt against live
YDB metadata and current schema source, rather than opening a query connection
from the runner. A change to any listed schema source or `idctl` command wiring
invalidates the receipt and blocks deployment until an operator applies and
verifies the new schema, then records a fresh receipt. The receipt does not
prove that the YDB data stayed unchanged after verification.

The section below is the read-only snapshot taken before that cleanup. Recheck
every ID immediately before another state change; it is not an authorization
to apply an old plan.

The OpenTofu S3 state is `updspace-id-tfstate-d97a0810/prod/terraform.tfstate`
(serial 104 at inspection). Its managed runtime Lockbox version is
`e6q2gi6p6j9hjbbmkhi2` in secret `e6qmt92a9bpdsr3vj9j7`. That version has
ten entries but no `ID_EXPORT_ESCROW_KEY`; the state has no
`random_id.export_escrow` instance. The checked-in production variables enable
the export bucket but leave delayed export disabled. A container image update
alone therefore cannot enable the 24-hour flow.

The state still contains two container IDs that `yc serverless container get`
returned as `NotFound`:

| Retired cloud ID | Stale state addresses |
| --- | --- |
| `bbab7jbbhqhupu9idvh0` (old backend) | `data.yandex_serverless_container.deployed_backend`, `yandex_serverless_container.backend`, `yandex_serverless_container_iam_binding.gateway_backend_invoker` |
| `bbag1meddpkcqkfnohoc` (old Gravatar container) | `data.yandex_serverless_container.deployed_gravatar[0]`, `yandex_serverless_container.gravatar[0]`, `yandex_serverless_container_iam_binding.gravatar_invoker[0]` |

Keep `yandex_serverless_container.backend_green[0]` and
`data.yandex_serverless_container.deployed_green[0]`: their ID
`bbak8734de8cabdaorc7` exists and serves the Rust API. Keep
`yandex_function_trigger.gravatar[0]`: it is active and invokes Rust jobs
`bba9v82d1op2qbh2kqtt`, not the retired container. The live Gateway had 121
integrations across the four serving Rust containers; no separate ID-named
serverless functions appeared in the folder inventory.

Before an OpenTofu apply, initialize the **existing** S3 backend using the
private operator configuration, compare a fresh state serial and cloud IDs,
and remove only the six verified stale addresses from state with
`tofu state rm`. This edits state only; it must not delete the live Rust API or
Gravatar trigger. Re-run `tofu plan` with the private runtime variables and
`production.performance.tfvars`. The plan must not recreate Django containers
or replace YDB, buckets, Gateway, a serving Rust container, or the values of
existing runtime keys.
Only then may the managed `random_id.export_escrow` and a new runtime Lockbox
version be applied. Bind that **same versioned key** to the mutation API and
jobs; do not create an independent ad-hoc escrow secret that a later OpenTofu
apply would replace. The delayed-export readiness gate and end-to-end flow
must pass on the tested Rust revision before Gateway routes are exposed.

The private backend configuration and runtime variables are not checked in.
The 2026-10-07 checkout had neither, so no state mutation or OpenTofu apply
was performed during this inspection. A `tofu state rm -dry-run` against a
private temporary copy of serial 104 matched exactly the six retired
addresses above and was discarded without writing to the production state.
