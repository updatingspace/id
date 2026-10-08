# Rust coverage baseline (preparatory, not yet a required release gate)

This iteration measures the existing `rust-pilot.yml` integration scenario and
replays the required schema-job scenarios below through their shared
command source. It does not duplicate their test lists. The default required run still uses Rust
1.98.1. The optional `coverage=true` run uses a separately pinned nightly to
measure real branches. **The migration's coverage acceptance is not complete:**
the measured revisions below fail the thresholds; measuring the current revision,
covering remaining paths and promotion to a required job in
`idctl/tested_revision.rs` remain outstanding. A failed baseline must not be
made green by lowering thresholds or deleting production files/branches.

## Completed required scenarios: 2026-10-08

[Run 37722383642, job 113132781075](https://github.com/updatingspace/id/actions/runs/37722383642/job/113132781075)
measured exact revision `61402e7773d09bf0cce2bbf5641549acb3021217`.
Every required scenario completed; only the coverage threshold step failed.
Independent recount of artifact `11526269665` matched all exported counters:
20,053/23,779 lines (**84.33%**) and 3,239/5,208 represented LLVM branches
(**62.19%**). All 94 profile files, including 70 critical files, were present.
All 76 child start/completion receipts matched: API 9, jobs 4, UI 28 and idctl 35.
The archive SHA-256 is
`a199b0e84433023a76c7c83c4060438eb5f8d52895a8cfe4349ec49f5bbf6731`.
`scenario_completed=true` and `passed=false` are both intentional. Raw profiles
are absent from the artifact; this checks exported counters and receipts,
not a fresh LLVM export.

Later changes add HTTP logout authorization/revocation checks to the existing
session scenario and include Steam's OpenID verifier in the critical profile.
The current profile has 95 files, 71 critical; it has not yet been remeasured.
The older baseline above cannot prove coverage for those changes.

## First baseline: 2026-10-08

[Run 37709030505, job 113090266247](https://github.com/updatingspace/id/actions/runs/37709030505/job/113090266247)
measured immutable commit `6b8e96c618ac6772ce97a7bf34a666db90fb9510`.
All integration steps in that job completed successfully, with
`ID_COVERAGE_TESTS_SUCCEEDED: true`; only the strict coverage gate failed.
This is a baseline for that revision and scenario list, not production acceptance
or evidence about later provider/operator changes.

| Profile metric | Covered / total | Measured | Required |
|---|---:|---:|---:|
| Lines | 14,378 / 22,338 | 64.37% | 85% |
| LLVM branches | 2,272 / 4,920 | 46.18% | 80% |
| Critical files meeting both 100% gates | 1 / 69 | `id-compat/src/csrf.rs` only | 69 / 69 |

The raw JSON contains all 92 manifest files (146 files in total). Recomputing
the strict gate from that JSON after an in-memory source-root remap reproduced
every file count, total and failure in `result.json`. `mfa_secret.rs`,
`legacy_passkey.rs` and `bin/idctl/oidc_clients.rs` have zero measured branch
counts; they remain FAIL pending an explicit instrumentation review, not 100%.
The later [pinned compiler probe](branch-semantics.md) confirms that ordinary
`match`, `?` and an ensure-like macro can contain real decisions while emitting
zero branch counters. Thus this gate measures represented LLVM conditional
branches; it is not exhaustive source-decision coverage. Neither `condition`
nor the removed MC/DC option resolves that demonstrated limitation on the pin.
No zero-denominator exception or replacement metric has been approved.

The five largest critical deficits by uncovered lines are below. Paths are
relative to `crates/id-runtime/src/`.

| File | Lines | Branches | Next existing scenario to include in measurement |
|---|---:|---:|---|
| `admin_http.rs` | 27/629 (4.29%) | 7/186 (3.76%) | `admin_http_ydb` and the live operator journey, currently in the separate schema job |
| `internal_identity_http.rs` | 61/541 (11.28%) | 8/92 (8.70%) | Existing ignored `signed_lookup_rejects_unknown_banned_and_inactive_accounts` and `portal_me_checks_membership_and_legacy_cookie`; neither workflow currently invokes them |
| `email_change.rs` | 98/553 (17.72%) | 9/130 (6.92%) | Existing `email_change_ydb` from the separate schema job |
| `password_reset.rs` | 311/659 (47.19%) | 44/162 (27.16%) | Existing `password_reset_http_ydb` and ignored mail-claim/expiry test from the schema job |
| `data_export_escrow.rs` | 295/601 (49.08%) | 34/134 (25.37%) | Existing `data_export_escrow_ydb` and isolated export/delete scenario from the schema job |

These are gaps in the measured scenario set. Several tests already run in
`ci-cd.yml` outside this instrumented job; low coverage here does not mean that
those tests do not exist. Reuse those scenarios or merge compatible instrumented
profiles before deciding which additional tests are needed. Do not copy the long
test list or relax the profile to improve the number.

A bounded inventory at the same immutable revision distinguishes missing CI
execution from missing instrumentation. The email-change, admin, password-reset
and escrow tests above **already run in required CI**, but only outside this
coverage job. In contrast, neither workflow nor any CI-invoked script references
the following ignored tests:

| Existing ignored test | Source | Scope / prerequisite |
|---|---|---|
| `cancellation_cleans_confirmations_without_touching_primary_or_verified_email` | `crates/id-runtime/tests/email_cancel_http_ydb.rs:47` | Security profile; local YDB and email-cancel gate |
| `deletes_inactive_unbound_account_without_cutover_seal` | `crates/id-runtime/tests/legacy_unbound_deletion_ydb.rs:10` | Deletion cleanup; requires its own disposable DB, not an indiscriminate shared-table run |
| `empty_socialapp_table_returns_empty_inventory` | `crates/id-runtime/src/oauth_providers_http.rs:128` | Inventory in the profile; empty local legacy SocialApp fixture, not provider-login acceptance |
| `selects_only_due_opted_in_profiles`, `refreshes_profile_through_mock_gravatar_and_s3` | `crates/id-runtime/src/gravatar_job.rs:318,369` | Privacy opt-in and media refresh; outside this security profile |

The two `internal_identity_http` ignored tests named above are also absent from
all CI entrypoints at that baseline revision. Plain `cargo test --workspace` compiles these tests
but skips them. This inventory does not claim that adding the invocations alone
reaches the thresholds. `oidc_cross_version_ydb` is also uninvoked, but its
retired Python roundtrip is not a new blocker under the agreed Rust-only scope.

The [229-entry artifact, ID 11520878133](https://github.com/updatingspace/id/actions/runs/37709030505/artifacts/11520878133)
is 3,468,016 bytes with verified SHA-256
`43de4434f42c3a525690aedc3183378ea0bda5c55458b48b03a2ae19c9b9c3ca`.
Provenance matches pinned rustc commit `8d1a76430406c877b35d0b627e7f796dcf0dfeca`,
LLVM 23.1.3, cargo-llvm-cov 0.9.1, manifest hash
`2dbf7530faf647bfdca1a0725d326bcf071d34a1a3b9fc36ffec0a80759be787`
and Cargo.lock hash `b20abe2b5c8463ad647dbc59c4306b7f0007938a43c938801545978d15d2ba49`.
The runner validated 38 completed wrapper child profiles: 5 API, 19 web and 14
CLI; the archive contains their 38 start and 38 completion receipts. No jobs
server wrapper ran. The native smoke also proved actual branch counters,
graceful server shutdown and a direct `CARGO_BIN_EXE` child profile.

Evidence limit: the archive includes LLVM JSON and absolute-path receipts, but
not `.profraw`, `.profdata` or instrumented objects. It therefore supports an
independent counter/gate recalculation, but not repeating the LLVM export or
revalidating each child profile outside the runner. Direct integration children
have no individual wrapper receipts. The on-runner checks are evidence for
their documented scope; the artifact does not prove complete child accounting.

## Shared schema scenarios added after the first baseline

`scripts/ci/run-rust-security-scenarios.sh` is the command source for required
`ydb-schema-check` steps absent from ordinary `rust-pilot`. The first expansion
measured the following four cases with its instrumented compiler, target and
profile environment intact:

| Case | Tests |
|---|---|
| `password-reset` | `password_reset_http_ydb`, password-reset mail claim/expiry |
| `email-change` | `email_change_ydb`, `email_cancel_http_ydb` |
| `export-escrow` | `data_export_escrow_ydb` |
| `isolated-deletion` | `legacy_unbound_deletion_ydb`, `legacy_cutover_reset_ydb`, `data_export_delete_flow_ydb`, `admin_http_ydb` |

The ordinary extended run does not repeat these schema-job steps. Only
`coverage=true` replays them in the single instrumented job; their regular
required schema checks remain in place. The cancellation and unbound-deletion
tests were previously uninvoked. Unbound deletion now requires explicit
`ID_DISPOSABLE_YDB=true` on port 2137 and runs before the cutover seal in a
new container. Cleanup targets only the container ID created by that invocation
and preserves an earlier test failure even if container cleanup also fails.
The original local YDB on port 2136 is never sealed or globally drained by this case.

The export/delete test now stops both real `id-jobs` children through their
existing SIGINT handler, waits for successful exit and, during measurement,
requires the coverage wrapper's completion receipt and nonempty profile files.
It previously used SIGKILL, which could lose child coverage. A failed graceful
exit or missing receipt fails the scenario. This is a test-harness change;
graceful shutdown on the production platform's SIGTERM remains unverified and
is not claimed by this measurement. The expanded measurement below includes
these cases; the historical baseline above is unchanged.

## Expanded baseline: 2026-10-08

[Run 37712432551, job 113101197870](https://github.com/updatingspace/id/actions/runs/37712432551/job/113101197870)
measured immutable commit `9dead02d9d7b3394723e77ca94a1c8aa05a87ab6`.
Every applicable scenario step succeeded, including the four shared cases,
six internal-identity tests and the real export/delete jobs processes.
`scenario_completed` is true; the final gate is FAIL. This is a completed
measurement of that scenario set, not full feature or production acceptance.

| Profile metric | Covered / total | Measured | Required |
|---|---:|---:|---:|
| Lines | 17,668 / 22,403 | 78.86% | 85% |
| Represented LLVM conditional branches | 2,847 / 4,924 | 57.82% | 80% |
| Critical files meeting both 100% gates | 1 / 69 | `id-compat/src/csrf.rs` only | 69 / 69 |

All 92 manifest files are present among the 146 LLVM files. An independent
source-root remap and strict-checker recalculation reproduced every per-file
count, total and failure exactly. The source denominator changed between the
two immutable revisions; the increased counts reflect both scenario expansion
and intervening fixes, not a same-source performance comparison.

The five largest critical deficits by uncovered lines are below. Source paths
are relative to `crates/id-runtime/src/`; these counts do not imply a functional
failure or that no test exists.

| File | Lines | Branches | Narrow next action |
|---|---:|---:|---|
| `login_http.rs` | 620/842 (73.63%) | 75/128 (58.59%) | Its real HTTP test already ran. Review remaining validation/configuration and MFA refusal branches against the HTML report before adding focused cases. |
| `password_change.rs` | 84/268 (31.34%) | 10/46 (21.74%) | Include the already-required `password_change_http_ydb` schema-job scenario in instrumentation. Its change/session transaction paths at lines 61–174 have no execution in this measurement. |
| `data_export_http.rs` | 384/564 (68.09%) | 51/138 (36.96%) | Export/delete, escrow and operation scenarios ran. Review unexecuted configuration guards from lines 64–82 and remaining HTTP rejection paths; do not exclude production startup guards. |
| `signup.rs` | 59/230 (25.65%) | 14/44 (31.82%) | Include the already-required `signup_ydb` and real browser/backend signup scenario from the schema job before designing new tests. |
| `email_verify.rs` | 382/552 (69.20%) | 54/142 (38.03%) | Include the already-required `email_verify_http_ydb` and ignored mail-claim/expiry scenario from the schema job; request ownership checks at lines 189–255 are unexecuted here. |

The schema-job command sources remain `.github/workflows/ci-cd.yml`; this
expanded run reuses only the four cases listed above. It does not yet merge
all required schema-job profiles. Low counters for those other cases remain
a measurement gap until their existing tests are instrumented.

The added scenarios now measure internal identity at 529/541 lines and 89/92
branches, admin at 545/629 and 120/186, email change at 498/557 and 92/130,
password reset at 621/659 and 94/162, and escrow at 545/601 and 87/134.
Each remains below its critical 100/100 requirement. The three zero-branch
critical files remain FAIL: `mfa_secret.rs` (7/8 lines), `legacy_passkey.rs`
(50/52) and `bin/idctl/oidc_clients.rs` (80/97). The
[compiler probe](branch-semantics.md) explains why more execution alone does
not establish complete source-decision coverage for those files.

The [253-entry artifact, ID 11522329540](https://github.com/updatingspace/id/actions/runs/37712432551/artifacts/11522329540)
is 3,554,411 bytes with verified SHA-256
`63a576f1018f2861b94ada56e662e6d4ce6bc5f4a32b7a7594db2fa69d765193`.
Compiler, LLVM, cargo-llvm-cov, manifest and Cargo.lock hashes match the first
baseline's pins. The runner checked 50 completed wrapper children: 5 API,
19 web, 24 CLI and 2 jobs. The artifact contains all 50 paired start/completion
receipts with consistent PID-specific paths. The isolated export/delete test
also asserts that each jobs process exited successfully after SIGINT and
flushed a nonempty profile before the report runs.

The artifact still omits raw profiles, merged profdata and instrumented objects;
receipt pairing is independently checkable, but outside-runner profile existence
and LLVM re-export are not. Direct `CARGO_BIN_EXE_idctl` children inherit the
instrumented environment and are awaited by their process tests, but have no
individual wrapper receipts. The native smoke proves that direct-child mechanism,
not exhaustive accounting of every application child. No lost profile was
demonstrated by this audit; complete independent child accounting is not claimed.

The browser passkey-management assertions passed at 01:30:15.997 UTC; its next
step started at 01:33:14.906 UTC. Thus the observed delay was after assertions,
within cleanup/process exit, and the step eventually succeeded. A single bounded
local reproduction completed its browser, proxy and web-process cleanup in about
11 seconds. No CI cleanup phase was timed individually, so the cause is unknown;
no timeout or UI change is justified by this observation alone.

## Incomplete combined run: 2026-10-08

[Run 37716034564, job 113112581842](https://github.com/updatingspace/id/actions/runs/37716034564/job/113112581842)
measured immutable commit `13d3b272a5f164a3cfdd62fe8ce341da73414e6b` with the
expanded 94-file, 70-critical profile. This run **did not complete its scenario
set**. Step 42, `totp_setup_http_ydb`, failed after 3.18 seconds:
`one_totp_and_one_recovery_set_after_parallel_confirmation` received HTTP 503
`SERVICE_UNAVAILABLE` during 100 concurrent same-key recovery rotations through
two application instances. The log contains no underlying runtime error chain;
the database/readiness cause is not established by that response alone.

Provider integration (step 48), jobs shutdown (68), all shared schema replays
(75–79), and subsequent acceptance checks were skipped. Their wiring is present
but this run supplies no execution evidence for them. The reporter correctly
saved `scenario_completed: false` and `passed: false`. Available partial counters
are 8,248/23,771 lines (34.70%) and 1,440/5,210 represented LLVM branches (27.64%).
These are diagnostic partial data, **not a new completed baseline or a coverage
regression relative to 9dead02**. The historical completed counts are unchanged.

The [artifact, ID 11523299606](https://github.com/updatingspace/id/actions/runs/37716034564/artifacts/11523299606)
is 3,485,095 bytes with verified SHA-256
`3fd59e15ccea2bb18f55a832ffbc88824c40e0ae863f0c73d0bd8dfc696d701c`.
All 94 manifest files are present among 147 LLVM files. Independent recalculation
reproduced the per-file counts, totals and failures, including the mandatory
incomplete-scenario failure. The archive has 23 paired child receipts: 1 API,
8 web and 14 CLI. No jobs child ran. As in prior artifacts, actual raw profiles
are not archived, and direct-child accounting is not independently complete.

Provenance matches the exact commit, pinned rustc/LLVM/cargo-llvm-cov and unchanged
Cargo.lock hash above. The new manifest hash is
`ccdbc34f9507b155500c566d9389be5220b64d6e7228e3f12f7f32a02dd6544e`.
No measurement was retried or cancelled to conceal this failure. The separate
ordinary CI lint failure at this revision is also not a successful release gate.
A diagnosed correction and a complete run of the resulting exact revision are
still needed before evaluating the expanded profile.

## Incomplete schema replay: 2026-10-08

[Run 37718612866, job 113120816490](https://github.com/updatingspace/id/actions/runs/37718612866/job/113120816490)
measured immutable commit `a90d967622d7822c1ab789e0c5a5a6b4aeebfed1`.
This run passed the previously failing TOTP/recovery test, GitHub/Discord
integration, jobs SIGTERM/SIGINT shutdown, delayed export escrow and isolated
deletion/export-jobs/admin scenarios. Step 79 then passed
`password_change_http_ydb` in 21.71 seconds but failed
`password_mail::tests::sends_once_from_durable_intent` after 0.14 seconds with
`password mail timer dispatch failed`. The assertion records neither the HTTP
status nor the underlying error, so that message alone does not establish its
cause.

The two remaining password-mail tests, email-verification case and six browser
cases within `remaining-schema` did not run. The following cache-cutover gate
was skipped. `scenario_completed: false` and `passed: false` correctly preserve
the incomplete result; no measurement was restarted to replace this failure.

| Partial metric | Covered / total | Measured | Required |
|---|---:|---:|---:|
| Lines | 19,210 / 23,779 | 80.79% | 85% |
| Represented LLVM conditional branches | 3,095 / 5,208 | 59.43% | 80% |

These are diagnostic counters, **not a completed expanded baseline or final
coverage acceptance**. They must not be compared as a same-source regression
against earlier revisions. All 94 manifest files, including 70 critical files,
are present among 147 LLVM files. Independent source-root remapping and the
strict checker reproduced every file count, total and failure, including the
mandatory incomplete-scenario failure. The historical completed baselines
above remain unchanged.

The [artifact, ID 11525332185](https://github.com/updatingspace/id/actions/runs/37718612866/artifacts/11525332185)
is 3,690,742 bytes with verified SHA-256
`290bd26e5a892b9caf5406117f672df2d1c3ad3ebc8153891784fb75b9051b9e`.
Provenance records the exact source revision and the same pinned compiler,
LLVM, cargo-llvm-cov, Cargo.lock and 94-file manifest hashes as the previous
combined run. All 56 wrapper starts have matching completion receipts:
5 API, 21 web, 26 CLI and 4 jobs. The runner validated their nonempty profiles;
the artifact independently verifies receipt pairing and PID-specific paths,
but still omits raw profiles and instrumented objects. Direct integration
children have no exhaustive per-process receipt inventory. Successful signal
tests establish the exercised local process behavior, not production-platform
shutdown acceptance.

## Complete required schema inventory after the expanded baseline

The bounded inventory compared every Rust test and application/browser command
in `ydb-schema-check` with ordinary `rust-pilot` plus the four shared cases. It
found the following eight remaining groups. Their commands and feature gates
now live in the same shared script; the required schema job calls each case at
its original position. Coverage invokes `remaining-schema`, which calls these
cases in separate subprocesses so flags and the disposable endpoint cannot leak.

| New shared case | Preserved required commands |
|---|---|
| `password-change` | Password/security mail schemas; `password_change_http_ydb`; the three `password_mail` durable-delivery, concurrent-claim and deleted-account tests |
| `email-verification` | Repeated verification schema; `email_verify_http_ydb`; `signup_ydb`; `email_verify` mail-claim/expiry test |
| `recovery-browser` | `smoke-web-recovery-live.sh` and its real Rust/YDB fixture |
| `deletion-browser` | Fresh owned YDB on 2137; legacy/cache schemas, cutover test, export schemas and `smoke-web-deletion-live.sh` |
| `deletion-review-browser` | `smoke-web-deletion.sh`; UI request/gate checks with a synthetic API, not backend acceptance |
| `admin-browser` | `check-web-admin-suspend-browser.cjs`; UI requests with a synthetic API |
| `admin-live` | `smoke-web-admin-live.sh` and its real Rust/YDB fixture |
| `signup-browser` | `smoke-web-signup-live.sh` against the real backend |

The deletion browser case creates a different fresh container from
`isolated-deletion`, even though they sequentially reuse port 2137. Its trap
stops only the returned CID and preserves any primary test failure. Neither
case reuses or resets the primary 2136 DB. Runtime code and browser assertions
are unchanged. The ordinary schema job retains its binary-build prerequisite;
coverage has already built the instrumented binaries and uses their launchers.

The remaining schema groups already run in the coverage job: repeated
legacy/cache bootstrap; passkey index/registration; OIDC authorization; profile;
magic-link schema/request/consume/mail; the four shared cases; export-link,
passkey-management, TOTP, login and responsive browser checks; and native
WebAuthn. Compiler/package installation, the existing binary build and YDB
readiness are prerequisites, not omitted application scenarios. This inventory
covers `ydb-schema-check`; it does not claim every unrelated deployment/tooling
check or every possible product path belongs to the security profile.

The orchestration regression checks preserved test/library/browser invocations,
feature flags, measurement environment inheritance, failure propagation, owned
container cleanup and workflow-to-replay parity. New inline required Rust or
browser scenarios without a matching measurement invocation fail that check.
These local command checks do not substitute for the actual combined
instrumented run. **The first combined run stopped early as recorded above;
the immutable 9dead02 counts remain unchanged.** No threshold or exclusion
was changed to close these measurement omissions.

## Run the measurement

Pushes to `codex/rust-coverage-gates` run the preparatory measurement alongside
the ordinary stable checks. This branch-only job provides the first baseline;
it must be replaced by a required gate after the profile and test gaps are
resolved. Other branches keep the ordinary stable scenario.

After this branch has been published and the workflow is available for dispatch:

```sh
gh workflow run rust-pilot.yml --repo updatingspace/id \
  --ref codex/rust-coverage-gates --field coverage=true
```

Choose the same branch and `coverage=true` in the Actions UI when `gh` is not
authenticated. Dispatching a workflow that is not on the default branch yet may
require merging its definition first; publishing/dispatching is a separate
operator action, not performed by these scripts. The workflow is also callable
with `with: { coverage: true }`; the main CI currently leaves it false.

The run executes the same unit, ignored local-YDB and browser/backend commands
as the required extended run. It preserves stable checks in the ordinary CI;
the measurement run avoids recompiling that preceding stable fmt/clippy stage.
Compiler/tool installation is pinned in `toolchain.env`. Its isolated target is
`$RUNNER_TEMP/id-coverage/target`, not the workspace or shared build cache.
Only synthetic local YDB data is used. No production secrets or services are
needed. Existing scenario failures remain failures.

Artifacts `rust-coverage-<SHA>` contain raw LLVM JSON, per-file gate results,
HTML, compiler/SHA/profile/Cargo.lock provenance and server profile receipts.
Results from a failed or incomplete test scenario are partial evidence, even
if the available profile happens to meet a percentage. The result records
`scenario_completed`; incomplete runs set `passed: false` in the artifact and
fail the report step even when available counters meet the thresholds. Missing instrumented files or
metrics abort the gate rather than treating absent code as covered.

## Explicit review proposal

`security-profile.json` now lists **94 files, 70 critical** without globs. The
two historical measurements above used 92 files, 69 critical. The new profile
adds `provider_login.rs` as critical and runtime `lib.rs` as startup code, so
moving signal handling out of the API binary does not remove its denominator.
Both providers and the jobs shutdown regression run in the measured workflow.
This combined implementation requires a new measurement. Its scope
is the Rust implementation of authentication/authorization responsibilities,
not an arbitrary whole-workspace average. The thresholds are fixed at 85% lines
and 80% branches in aggregate; each critical file requires 100% of both.
The Node checker uses integer counts, not rounded percentages or LLVM regions.
A critical file with zero measured branches fails pending explicit review;
zero is never silently presented as measured 100%. Branches in production
failure paths, transaction guards and credential checks remain included.

The historical profile's six critical areas map as follows:

| Previous area | Current paths (all under `crates/`) |
|---|---|
| `accounts.api.security` | `id-compat/src/{headers,session,session_auth}.rs` and runtime session restore/issue/revoke/JWT decisions |
| `accounts.services.rate_limit` | `id-runtime/src/login_rate_limit.rs`, `cache_store.rs`, one-time form consumption |
| `core.security` | `id-compat/src/internal_hmac.rs`, `id-runtime/src/{internal_identity_http,exchange_http}.rs` |
| `core.http` | Request/context validation in those two HTTP modules; retired Portal tenant responsibilities are outside this ID profile |
| `core.errors` | Error decisions in the actual HTTP handlers; there is no invented common `errors.rs` |
| `idp.router` | `id-runtime/src/{oidc_authorize_http,oidc_token_http,oidc_jwks_http}.rs`, plus the transactional decisions they call |

The other historical areas are `accounts.api.exception_handlers`,
`core.logging_config`, `core.middleware`, `idp.services` and
`updspaceid.providers`. Responses/logging/middleware are distributed over the
listed HTTP handlers and API/jobs startup; OIDC services are listed explicitly
in the manifest. Linked-account GitHub/Discord login and callbacks now share
the critical `provider_login.rs` module. Real provider/Gateway acceptance,
Steam, link/unlink and provider signup remain incomplete. A high coverage
percentage cannot close those implementation and acceptance gaps.

The proposal additionally includes MFA/passkey proof and ceremony decisions,
password/email recovery, signup/magic-link ownership, operator mutations,
export capabilities and deletion authorization. Policy mixed with storage in a
file stays in the file-level denominator. UI, vendor code, background delivery,
S3 multipart and administrative schema/audit tooling are not automatically part
of this backend security profile. Separate feature acceptance still applies.

Only inline `#[cfg(test)]` modules in the measured files have
`#[cfg_attr(coverage_nightly, coverage(off))]`; the feature is enabled only for
nightly test compilations. No production function uses `coverage(off)`.
`coverage_nightly` is declared with `check-cfg`, so stable warning/lint policy
does not need a broad `allow`.

## Instrumentation and process lifetime

`rust-coverage.sh prepare` uses `cargo llvm-cov show-env` **before** building.
Version 0.9.1 sets a Rust compiler wrapper to instrument workspace crates;
`RUSTFLAGS=-Zcoverage-options=branch` enables the actual nightly branch counters.
Both are persisted across Actions steps along with `%p/%m` profile paths.
`LLVM_COV` and `LLVM_PROFDATA` are taken from the same pinned compiler sysroot.
Existing profiles/targets are never reused by `prepare`.

The existing scripts obtain binaries from `ID_RUST_BIN_DIR`. Coverage-only
launchers forward their SIGTERM/SIGINT to the real process and wait for profile
flush. Each start must have a completion receipt naming a nonempty profile for
that exact child PID. Report-time validation catches missing profiles even
when a shell harness ignores a failed cleanup `wait`. API and Topcoat already
handle SIGTERM; this change does not change application shutdown behavior.

Integration tests using `env!("CARGO_BIN_EXE_...")` bypass the launcher but still
inherit the instrumented build and profiling environment. The small native
probe verifies this separately: a Rust integration test waits for such a child
and checks its own PID's profile. It also verifies real SIGTERM + wait for a
server child, and proves that one side of an `if` gives 1/2 branches and fails,
while both sides give 2/2 and pass. This proves the mechanism, not coverage of
the actual application's server paths; their evidence comes from the full CI
run and its mandatory API/web/CLI receipts. Processes killed with SIGKILL cannot
be assumed to flush profiles. The coverage-only isolated export/delete case now
checks both jobs children separately before proceeding; its evidence is recorded
in the expanded baseline above.

## Local bounded verification

With the pinned nightly plus its bundled `llvm-tools-preview` and
`cargo-llvm-cov 0.9.1` on PATH:

```sh
node scripts/ci/test-check-rust-coverage.mjs
bash scripts/ci/smoke-rust-coverage.sh
```

The smoke creates and removes its own tiny, dependency-free Cargo project and
target. It does not compile the application or modify the workspace lockfile.
For a full local measurement, the preparation command writes `coverage.env`
which must be sourced before all builds/tests; the full existing integration
scenario should normally run in the prepared CI environment instead.

Primary references: [cargo-llvm-cov 0.9.1 external tests and exclusions](https://github.com/taiki-e/cargo-llvm-cov/blob/v0.9.1/README.md),
[nightly branch instrumentation](https://doc.rust-lang.org/unstable-book/compiler-flags/coverage-options.html),
[official pinned nightly distribution](https://static.rust-lang.org/dist/2026-10-07/channel-rust-nightly.toml).
