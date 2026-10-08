# Pinned Rust coverage semantics — 2026-10-08

Compiler: `rustc 1.101.0-nightly`, commit `8d1a76430406c877b35d0b627e7f796dcf0dfeca`, LLVM `23.1.3`.
The exact compiler used by ID coverage built the dependency-free probe in
[`branch-semantics-probe/`](branch-semantics-probe/). No production source,
shared Cargo target, compiler default, dependency, coverage threshold or source
manifest was changed.

`main.rs` calls both success/failure alternatives of all four tiny functions and asserts their results. Compilation used `-C instrument-coverage -Zcoverage-options=branch`; `llvm-profdata` and `llvm-cov` are from that compiler's `rustlib/.../bin` directory.

| Function | Executed alternatives | Lines | branch mode | condition mode |
|---|---|---:|---:|---:|
| Ordinary `if` | true and false | 5/5 | 2/2 | 2/2 |
| `match Result` | Ok and Err | 5/5 | 0/0 | 0/0 |
| `?` propagation | success and early error | 4/4 | 0/0 | 0/0 |
| ensure-like local macro | success and early error | 4/4 | 0/0 | 0/0 |

The local macro reproduces `if !condition { return Err(()) }`; it is deliberately dependency-free, **not a test of the actual anyhow crate**. This is evidence about the represented syntactic shape, not every macro expansion or every match shape.

Original local artifacts are in `/tmp/id-coverage-branch-probe-9dead02`:
`llvm.json`, `condition.json`, `merged.profdata`, `condition.profdata`, two
instrumented binaries, raw profiles, sources and SHA-256 evidence. The `mcdc`
experiment failed before compilation with: `incorrect value mcdc ... block |
branch | condition was expected`.

## Reproduce without compiling ID

Use the already-installed compiler and matching LLVM tools from `toolchain.env`.
The following creates a fresh temporary directory and does not touch a Cargo
target. Run from `services/id-rust/coverage/`:

```sh
source toolchain.env
probe=$(mktemp -d /tmp/id-coverage-semantics.XXXXXX)
cp branch-semantics-probe/*.rs "$probe/"
sysroot=$(rustup run "$ID_COVERAGE_TOOLCHAIN" rustc --print sysroot)
host=$(rustup run "$ID_COVERAGE_TOOLCHAIN" rustc -vV | sed -n 's/^host: //p')
llvm="$sysroot/lib/rustlib/$host/bin"
cd "$probe"
rustup run "$ID_COVERAGE_TOOLCHAIN" rustc -vV
for mode in branch condition; do
  rustup run "$ID_COVERAGE_TOOLCHAIN" rustc --edition 2024 \
    -C instrument-coverage "-Zcoverage-options=$mode" main.rs -o "$mode-probe"
  LLVM_PROFILE_FILE="$probe/$mode-%p-%m.profraw" "./$mode-probe"
  "$llvm/llvm-profdata" merge -sparse "$probe/$mode-"*.profraw -o "$mode.profdata"
  "$llvm/llvm-cov" export "./$mode-probe" -instr-profile="$mode.profdata" > "$mode.json"
done
```

Inspect `data[0].files[].summary.branches` in both JSON exports. Each represented
`if` outcome executes; the three other files have zero branch entries despite
successful execution of both alternatives. `mcdc` can be tested separately with
the same compile command; its rejection is expected on this pin. With a compiler
installed under a custom directory, substitute its absolute `rustc` path and
matching `rustlib/$host/bin` tools for `rustup run` as in the recorded local run.

## Primary-source evidence

- [Rust Unstable Book](https://doc.rust-lang.org/unstable-book/compiler-flags/coverage-options.html) documents block/branch/condition; condition adds selected boolean-expression instrumentation.
- [Pinned compiler config.rs lines191–213](https://github.com/rust-lang/rust/blob/8d1a76430406c877b35d0b627e7f796dcf0dfeca/compiler/rustc_session/src/config.rs#L191-L213): the accepted coverage levels are Block, Branch and Condition. Condition is described as preparatory work toward future MC/DC.
- [Pinned options parser lines1665–1675](https://github.com/rust-lang/rust/blob/8d1a76430406c877b35d0b627e7f796dcf0dfeca/compiler/rustc_session/src/options.rs#L1665-L1675) accepts those three modes and one internal test-only span option; no MC/DC.
- [Pinned MIR builder lines308–346](https://github.com/rust-lang/rust/blob/8d1a76430406c877b35d0b627e7f796dcf0dfeca/compiler/rustc_mir_build/src/builder/coverageinfo.rs#L308-L346) registers two-way condition markers and conditional let markers. It does not establish complete source-decision coverage; the actual probe above demonstrates missing representations.
- [Rust PR144999](https://github.com/rust-lang/rust/pull/144999), merged 2025-08-08, removed the incomplete MC/DC implementation. [Tracking issue124144](https://github.com/rust-lang/rust/issues/124144) tracks further work.
- [cargo-llvm-cov v0.9.1 main.rs lines173–177](https://github.com/taiki-e/cargo-llvm-cov/blob/v0.9.1/src/main.rs#L173-L177) still implements `--mcdc` by passing the removed compiler option and explicitly notes its removal. Presence of that CLI flag is not evidence that the pinned compiler supports it.

The pinned compiler files and cargo-llvm-cov implementation were fetched from
official raw GitHub URLs and retained with the original local artifacts.

## Consequence for ID acceptance

No tested built-in option on the pinned/current compiler gives meaningful branch counters for these match/error-propagation/macro decisions. `condition` is not a fix and MC/DC is unavailable. No alternative compiler or third-party tool has been installed or qualified by this bounded check.

The branch metric in the current JSON must be named **represented LLVM conditional branches**, not all source decisions. Zero denominator does not prove that a function has no decisions and must not become 100%. The existing 0/0 critical-file failures and 85/80, 100/100 thresholds stay intact. More tests cannot create counters for a construct the compiler does not represent. Separate source-decision evidence or a qualified instrumentation approach remains necessary before asserting exhaustive security decision coverage; no replacement metric has been approved here.
