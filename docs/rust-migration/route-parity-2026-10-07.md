# Historical ID route comparison — 2026-10-07

This is an exact method/path comparison, not a claim of functional parity.
The last Django tree before removal (`32f22a6^`) declares 72 operations in
the eight first-party Ninja router files examined. The live Rust Gateway,
after the Portal magic-link route update, declares 84 operations. Normalizing
path parameter names leaves 16 historical operations without an exact live
method/path match. This comparison does not enumerate allauth, Django admin,
dev-only routes or dynamically registered routes; it also cannot prove that
matching routes have the same behavior.

| Historical route group | Missing operations | Current disposition |
|---|---:|---|
| `POST /api/v1/auth/data/export` | 1 | The new delayed `POST /api/v1/auth/data/exports` is live. It changes the interaction from immediate JSON to a 24-hour operation; full production delivery is not yet accepted. |
| `POST /api/v1/auth/account/delete` | 1 | The asynchronous Rust deletion API and UI exist locally, but their production route, key and recovery timer are disabled. This is an open user-facing gap. |
| `/api/v1/auth/oauth/login/{provider}`, `/link/{provider}`, `/unlink` | 3 | Rust currently exposes a provider inventory, not external-provider login/link/unlink. The live inventory returned `providers: []`; existing linked credentials and future provider enablement still need an explicit migration decision. |
| `/api/v1/applications` GET/POST, `/{id}/approve`, `/{id}/reject`, and `POST /api/v1/auth/activate` | 5 | Tenant applications belong to Portal in the current architecture, yet a Portal BFF checkout still proxies legacy application operations to ID. Verify the deployed Portal contract and move any live caller before retiring these operations as product scope. |
| `/api/v1/external-identities/{provider}/link/start` and `/callback`, `/api/v1/oauth/{provider}/login/start` and `/callback` | 4 | Tenant-scoped external identity flows have no Rust route. Do not infer from the empty provider inventory that historical identity bindings can be dropped. |
| `/api/v1/migrations/aefvote/import` and `/claim-token/{user_id}` | 2 | Operator-only legacy import and claim issuance have no exact live route. Check outstanding migration records and operator use before retiring or replacing them with `idctl`. |

The three historical magic-link operations were missing before this audit.
`POST /api/v1/auth/magic-link/request` and both methods of `/consume` now
route to the existing Rust API. Invalid requests reached the Rust handlers
through the public domain and failed before mail or credential changes. A
real Portal callback, mail delivery and one-time consumption remain to be
verified.

Next acceptance work should resolve each row against a real consumer and
test the chosen replacement. Route presence alone is insufficient, and the
historical allauth/admin surface still needs its own inventory.
