# ID production verification — 2026-10-07

This document retains the earlier point-in-time observations below. They are
not a release sign-off and no longer describe the active revisions.

## Account-deletion activation audit later on 2026-10-07

The production deletion gate returned `disabled`. A full readiness check found
five missing pieces: the API and jobs rollout flags, an API binding for a
versioned operation key, the public POST route, and the private recovery timer.
The production YDB already contains the request and three progress tables.
An aggregate status query returned two `succeeded`, three historical
`executed`, and one `running` request. The running request has all three
progress markers set (`avatar_done`, `profile_done`, `uuid_done`). Its read-only
operator audit found one inactive account, one suspended master identity, one
identity binding and 14 session-metadata rows; there were no matching
audit/outbox/application rows. Finalization removes session metadata, but
currently stops because the legacy cutover seal is absent. No account IDs,
addresses or request IDs were exported by this inspection.

An isolated, deletion-protected Lockbox key was created for a future rollout.
It is not bound to any container and its temporary API payload-viewer grant
was removed. A jobs revision with only the deletion flag enabled was briefly
deployed without a public route. The proposed permanent five-minute timer was
rejected by automatic approval review because it could irreversibly process
future account deletions beyond the previously authorized two requests. The
jobs container was restored to the prior image, secret bindings and disabled
deletion flag; the gate again returned `disabled`. No new deletion request was
accepted or processed through this attempt. The running request requires an
operator review before any permanent automatic recovery is enabled.

The old seal predicate required all four session tables to be empty. They
currently contain 69, 160, 213 and 240 records respectively, while the three
unscoped legacy tables are empty. Clearing those sessions would disrupt active
Rust users. A local change now checks only unscoped records before sealing;
its disposable-YDB regression passed with live-style session rows left intact,
and a read-only production dry-run reported `ready_to_seal: true`. Automatic
approval review rejected writing the production seal because it would remove
a global barrier to future account finalization. No production seal was written.

## Verified active deployment later on 2026-10-07

The public GitHub Actions pages show `ID CI/CD` run
[`37667811002`](https://github.com/updatingspace/id/actions/runs/37667811002)
and the downstream `Deploy Yandex Cloud Rust ID` run
[`37670065835`](https://github.com/updatingspace/id/actions/runs/37670065835)
completed successfully for `ddf002374952223ec0b258ca1ab7260d2be73dfc`.
The deploy run reports successful revision verification, image build/push and
deployment jobs. Its private step logs were not available in the signed-out
browser view. Earlier CI/deploy failures recorded below are historical and do
not describe the latest published revision.

A fresh YC container inventory found the five ID containers (main API,
sessions, mutations, Topcoat web and jobs) and no retired Django ID or Python
Gravatar container. The active revision of each ID container uses an
`updatingspace-id-api`, `updatingspace-id-web` or `updatingspace-id-jobs` image
and reports that same `BUILD_ID`. The API digest is
`sha256:9e725a4ba0bbe1e52c31c9425cebf24cbe865f101a56949534689f2ac3470856`,
the web digest is
`sha256:2bfa80d43fb32bf2c992be50051258e2c7d92e7cbe269fc5e7637c5b17696d64`,
and the jobs digest is
`sha256:8a678ed608a474bd845103a9ccbe278d5b68625c4683e7027103a75aa6925ed5`.
This confirms the serving images and tested SHA, not full feature or UX
acceptance. Additional local branch commits have not run in remote CI or
reached these containers.

## Latest read-only audit on 2026-10-07

All five active ID containers (main API, sessions, mutations, Topcoat web and
jobs) reported the same source build `ddf0023`. The live Gateway spec
references the four serving Rust containers and has no React Object Storage
fallback or Django target. The ID timers found in the folder all invoke Rust
jobs; no ID-named Cloud Function was present. The delayed-export readiness
gate passed for the active revisions, versioned escrow key, private bucket,
timer and Gateway routes. This establishes configuration alignment, not a
completed 24-hour owner, email and post-deletion acceptance journey.

The separate account-deletion readiness gate reported `disabled`: its public
API route and private recovery timer are not active. The retired React bucket
still exists with 110 objects, while no Gateway route uses it. Its removal is
prepared in source, but the remote Terraform plan and state change are not
verified. Production admin remains disabled; local UI changes after `ddf0023`
are not part of the active build. No functional parity or final migration sign-off is
claimed by this audit.

## Portal magic-link route update on 2026-10-07

The active Rust API already had magic-link request and consume enabled, and
Rust jobs had the mail worker, SMTP configuration, token-key binding and
private recovery timer. The checked production YDB schema receipt includes
`magic-link-schema`; the API redirect allowlist contains only the Portal
HTTPS origin. The Gateway was updated with exactly three operations:
`POST /api/v1/auth/magic-link/request`, `GET` and `POST`
`/api/v1/auth/magic-link/consume`. A byte-for-byte comparison showed that the
rest of its specification was unchanged.

Through the public domain, a request without tenant context returned Rust
`400 MISSING_TENANT`; GET consume without a query returned `400 INVALID_QUERY`,
and POST consume without tenant context returned `400 MISSING_TENANT`.
Responses were JSON with `Cache-Control: no-store`. Health, login, `/me` and
OIDC discovery still returned 200. These are side-effect-free routing checks:
no mail was requested. A real email, one-time consumption, Portal callback and
session exchange in production remain unverified.

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
The diagnostic rerun `37660810386` later identified the exact failure:
GitHub's runner received Cloudflare `403 text/html` for public `/health` while
the same image and public route passed operator-run smoke. Its rollback
completed successfully. The deploy workflow now reads the existing Yandex
Gateway system domain, verifies it against `*.apigw.yandexcloud.net`, and runs
machine smoke through that Gateway. OIDC discovery is still checked against
the public `https://id.updspace.com` issuer. A read-only Gateway smoke runs
before any revision change, so runner transport failure cannot trigger a
pointless deploy and rollback. Public-domain smoke remains a separate operator
check.
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
