# ID production verification — 2026-10-07

This document retains the earlier point-in-time observations below. They are
not a release sign-off and no longer describe the active revisions.

## Current production state on 2026-10-07

The five active Rust containers serve the CI-tested `22fccafb72459352235eb8ad841b372ef48d2c20`
images: API digest `sha256:9cf891c59a11089517a3af74204cf1fcc8bc1bd1560ede8f0030c0f01d342607`,
Topcoat digest `sha256:8527f4012047e8ab6a0988910ad0f003c16b25671387fa9290b2063f6f9575d5`,
and jobs digest `sha256:8a678ed608a474bd845103a9ccbe278d5b68625c4683e7027103a75aa6925ed5`.
The five active revision digests and `BUILD_ID` were verified with
`check-yc-rust-rollout.mjs --deployed`. The four containers that use the
runtime Lockbox secret are bound to version `e6q9lm8k2k3bo0efe5b1`; the
previous version remains ACTIVE for rollback. All public API, OIDC, session,
mutation and Topcoat asset-MIME smoke profiles passed after rebinding. A live
Portal → Topcoat consent → Portal SSO cycle passed on a synthetic account
before the secret rebinding; its secret values other than the new export escrow
key were unchanged.

The automatic deployment for that tested source, run `37650626628`, failed
after creating the API revision and then restored the captured revisions.
The exact API smoke failure was not available in the public GitHub annotation;
the same image digest passed operator-run public smoke and was deployed directly.
Commit `cee552d` added a sanitized smoke failure annotation. Both parallel
CI runs for that commit failed before deployment. The main run's five executed
jobs all passed, but its redundant final integration gate never appeared as a
job; the branch run also had one failing email-change integration step. The
gate has been removed from the next candidate because the reusable extended
integration job already contributes its result to the workflow. This
automatic-deploy gap remains open. Delayed export and
production admin remain disabled; physical iPhone Passkey registration and
24-hour export delivery have not been verified. This is not full release
sign-off.

The following `d189a0c` CI run reached Rust unit tests and failed because the
operator command's required-job fixture still named the removed gate. The
next candidate checks the reusable extended integration job directly and
limits Rust build parallelism to reduce peak resource use. This is a source
correction awaiting CI, not a new production revision.
Its first CI run then rejected an `expect` in that test under the repository's
Clippy policy. The follow-up uses a default value that makes the contract
assertion fail if the job is absent; the focused test and Clippy check passed
locally. It too awaits remote CI.

## Later production update on 2026-10-07

The tested commit `d8efc8a324a298c78b62c4c37a07955ee6143772` was
deployed directly through YC after its GitHub CI passed. The five active Rust
revisions (main API, sessions, mutations, Topcoat web and jobs) were checked
against that exact build ID and their tested image digests. Gateway still has
121 integrations across the four serving Rust containers and no Python ID
target. Public API, OIDC, web and asset-MIME smoke profiles passed.

On the live site, a synthetic verified account registered a Passkey through
Topcoat and the Rust API: both `/api/v1/auth/passkeys/begin` and `/complete`
returned 200 and the recovery-code screen appeared. This used a Chromium
virtual authenticator; the reported physical iPhone/Safari scenario remains
unverified. The then-current automatic deployment workflow failed during
Gateway preflight before changing containers. A follow-up release added a
specific error annotation for each preflight condition. Its automatic deploy
run `37638827863` identified the failure as inability of the GitHub deploy
identity to read the production Gateway specification; image build and push
passed, and no container revision changed in that run. A later diagnostic
revision reports the service account ID and sanitized YC error category so
the exact IAM or CLI failure can be corrected. A separate direct YC
deployment had completed successfully. On the same date the updated private
export-storage smoke passed against the production bucket, including exact
escrow-prefix listing before and after removal of synthetic objects. Delayed
export and production admin remain disabled.

The sections below record the earlier pre-deployment observations and must
not be read as current production status.

## Follow-up preflight on the current candidate

After local commit `6f72daf`, all API and web binaries passed `cargo check
--locked`; `docker build --check` found no warnings in the API, web or jobs
recipes. The public `web`, `api`, `oidc`, `sessions` and `mutations` HTTP smoke
profiles passed again. These are unauthenticated checks of the active site,
not evidence that this candidate has been deployed.

A fresh read-only Gateway validation found 121 container integrations across
the same four Rust serving containers, including both Passkey registration
routes on the main Rust API. The five active container build markers remain
`magic-link-7a9b8927` (API and jobs), `rust-oidc-discovery-20261005`
(sessions), `export-20261006-api-private` (mutations) and `ux-20261006-3`
(web). None identifies the current local commit. The iPhone Passkey fix and
later OIDC/admin changes are therefore still unpublished and unverified in
production.

## Observed deployment

- The active ID API Gateway (`d5d6almt4c5i2ao9e4ha`) has 121 container
  integrations: 47 to the Rust API (`bbak8734de8cabdaorc7`), 60 to Rust
  mutations (`bbamj363kmhlj2nof0mo`), 3 to Rust session reads
  (`bba3ev9oenabp55se69m`), and 11 to Topcoat web
  (`bbai4bjc8f21qg5fvjht`). No Gateway integration names a Python container.
- The active API revision is `bbaltaf4buhpuoontt5p` (2026-10-06) using
  `updatingspace-id-api@sha256:651c280ccad9e0f8ca18772eba57c651d8a6efa2e1c8a51cc419c29c316b7c3f`.
  The active web and jobs revisions are `bbakmjb4ao7ciumkal2p` and
  `bba7gk37q6f4c94d1u0q`.
- The five ID timers listed by Yandex Cloud point to the Rust jobs container
  (`bba9v82d1op2qbh2kqtt`). The container and function listings showed no
  active Django deployment belonging to ID. Portal services were not audited.

## Public, unauthenticated checks

`scripts/ci/smoke-yc-rust-http.mjs` passed all four profiles (`web`, `api`,
`sessions`, `mutations`) against `https://id.updspace.com` on this date:

- Home, login and signup return HTML; the login and signup JS/CSS return
  executable/script and stylesheet MIME types. Retired React assets and
  unknown pages return 404.
- `/health` and `/readyz` return JSON 200. Anonymous `/api/v1/auth/me` returns
  JSON 200. Sessions and export-status access without a session return JSON 401.
- Browser inspection confirmed that `/account` redirects an unauthenticated
  visitor to `/login?next=%2Faccount`, with no console error on the home or
  login page. `/admin/` returns 404 in production.
- A fresh browser read confirmed that the home page explains one account,
  connected services and user-controlled access, and that
  `/login?next=%2Faccount` serves the Topcoat login with password and passkey
  actions. This is a public-page check, not an authenticated journey.
- The strengthened public OIDC smoke passed against the live Gateway:
  discovery has the exact ID issuer and authorize/token/UserInfo/revoke/JWKS
  endpoints, advertises code + PKCE S256 and RS256, and JWKS contains one
  usable signing key. It does not test code exchange or a relying party.

These checks do not prove authenticated journeys, WebAuthn on a physical
authenticator, account deletion, delayed export, operator parity or latency
targets.

## Release gap

The local Passkey registration fix accepts a missing optional `credProps.rk`
response while rejecting explicit `rk=false`, persists the selected
passwordless mode, and has a real local-YDB concurrency/replay regression.
The user reported `INVALID_PASSKEY` from mobile registration. Both live
`/api/v1/auth/passkeys/{begin,complete}` Gateway routes target the API container
above. Its active revision predates the 2026-10-07 `credProps` fix and the old
code rejects absent `rk` with this exact public error. This is a strong cause,
not proof of the iPhone's unobserved credential payload: the sampled production
logs did not expose the rejection category for this attempt.

The local YDB regression passed with an omitted `credProps` result, including
20 concurrent completion attempts and replay rejection. The native Chromium
WebAuthn journey through Topcoat, Rust API and YDB also passed with an omitted
extension result. CI has a mandatory YDB registration step, but the updated
branch has not run on remote CI and the fix is not in the active API revision.
Physical iPhone verification remains required after deployment.

## Local candidate checks after the mobile report

On the unpublished Rust branch, `cargo clippy --locked --workspace
--all-targets -- -D warnings` and `cargo test --locked --workspace` passed on
2026-10-07. The workspace test run used local loopback access for the S3 and
YMQ doubles; the first sandboxed attempt could not bind their ports. Ignored
integration tests are not included in this workspace result. Separately, the
real local-YDB registration test passed with `credProps.rk` omitted, one
success among concurrent completions, and replay rejection. The Topcoat
Chromium check passed for a 390 px rejected-registration screen, no automatic
retry, recovery-code presentation and unknown-result review. The operator
export-status YDB test and Topcoat SSR smoke also passed. These checks do not
prove physical iPhone behavior or production release readiness.

Publishing this branch and deploying the tested image are outstanding.
The local deployment gate now requires five jobs in the current Rust CI
workflow, including the extended Rust/YDB/browser integration workflow. The
extended workflow is called from the main CI run, so the deploy trigger waits
for it. The four local `verify-tested-revision` tests and YAML dependency
structure check pass; no remote CI run has validated this branch.

The read-only delayed-export gate was rerun on 2026-10-07 for the active API,
web, jobs and Gateway revisions. It found the delayed API, web redemption and
escrow jobs/mail flags disabled; no versioned escrow key bound to API or jobs;
no jobs public export origin; and missing Gateway routes for cancellation,
redemption and the two delivery pages. All three active runtime `BUILD_ID`s
also differ from the current local commit. These findings block activation of
the 24-hour flow as one coherent user journey. The gate disclosed neither
secret values nor account data.

An attempted push of the complete local Rust branch to the configured GitHub
repository was rejected by automatic approval review before execution because
it would publish a large private-source payload. No branch or image was
published through that attempt. Do not reroute the same payload through a
container registry; obtain an explicit review decision for the exact branch
and destination before publishing.
Production rollout remains incomplete until the authenticated and operator
journeys, delayed export, data checks and performance gates are verified against
their actual production revisions.
