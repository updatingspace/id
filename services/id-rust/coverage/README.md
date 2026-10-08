# Rust coverage baseline (preparatory, not yet a required release gate)

This iteration measures the existing `rust-pilot.yml` integration scenario;
it does not duplicate its test list. The default required run still uses Rust
1.98.1. The optional `coverage=true` run uses a separately pinned nightly to
measure real branches. **The migration's coverage acceptance is not complete:**
the first full baseline, any missing tests, and promotion to a required job in
`idctl/tested_revision.rs` remain outstanding. A failed baseline must not be
made green by lowering thresholds or deleting production files/branches.

## Run the measurement

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
if the available profile happens to meet a percentage. The report step also
fails explicitly when preceding checks failed. Missing instrumented files or
metrics abort the gate rather than treating absent code as covered.

## Explicit review proposal

`security-profile.json` lists **92 files, 69 critical** without globs. Its scope
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
in the manifest. **External provider login/link/callback code is still absent**:
`oauth_providers_http.rs` is inventory, not a replacement for GitHub/Discord/Steam
authentication. A high coverage percentage cannot close that implementation gap.

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
be assumed to flush profiles. The extended scenario currently does not run the
separate destructive export/delete jobs-server test; it must not be counted as
covered by this measurement.

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
