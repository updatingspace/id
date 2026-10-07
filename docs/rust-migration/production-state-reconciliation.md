# Production state before enabling delayed Rust export

Read-only snapshot taken on 2026-10-07. Recheck every ID immediately before a
state change; this document is not an authorization to apply an old plan.

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
was performed during this inspection.
