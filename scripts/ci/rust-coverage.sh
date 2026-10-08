#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${script_dir}/../../services/id-rust/coverage/toolchain.env"
command="${1:?usage: rust-coverage.sh prepare|report workspace output-directory}"
workspace="$(cd "${2:?workspace required}" && pwd)"
output="$(realpath -m "${3:?fresh output directory required}")"
export RUSTUP_TOOLCHAIN="$ID_COVERAGE_TOOLCHAIN"

if [[ "$command" == prepare ]]; then
  [[ -z "${RUSTFLAGS:-}${CARGO_ENCODED_RUSTFLAGS:-}${RUSTC_WRAPPER:-}" ]] || {
    echo 'Coverage requires a clean compiler environment' >&2; exit 1;
  }
  [[ "$(cargo llvm-cov --version)" == "cargo-llvm-cov ${ID_COVERAGE_CARGO_LLVM_COV_VERSION}" ]]
  rustc --version --verbose | grep -Fx "commit-hash: ${ID_COVERAGE_RUSTC_COMMIT}"
  rustc --version --verbose | grep -Fx "LLVM version: ${ID_COVERAGE_LLVM_VERSION}"
  host="$(rustc --version --verbose | sed -n 's/^host: //p')"
  llvm_bin="$(rustc --print sysroot)/lib/rustlib/${host}/bin"
  export LLVM_COV="${llvm_bin}/llvm-cov"
  export LLVM_PROFDATA="${llvm_bin}/llvm-profdata"
  "$LLVM_COV" --version | grep -F "LLVM version ${ID_COVERAGE_LLVM_VERSION}"
  test -x "$LLVM_PROFDATA"
  mkdir "$output" # Refuse stale profiles; never clean an existing/shared target.
  mkdir "$output/bin" "$output/children"
  export CARGO_TARGET_DIR="$output/target"
  export RUSTFLAGS='-Zcoverage-options=branch'
  export LLVM_PROFILE_FILE_NAME='rust-tests-%p-%m.profraw'
  cd "$workspace"
  cargo llvm-cov show-env --sh >"$output/instrumentation.env"
  # show-env has no --branch option. It preserves the explicit nightly RUSTFLAGS.
  source "$output/instrumentation.env"
  [[ "$RUSTFLAGS" == *'-Zcoverage-options=branch'* ]]
  [[ "${RUSTFLAGS}${__CARGO_LLVM_COV_RUSTC_WRAPPER_RUSTFLAGS:-}" == *'instrument-coverage'* ]]
  [[ "$CARGO_LLVM_COV_TARGET_DIR" == "$output/target" ]]
  for binary in id-api id-web id-jobs idctl; do
    ln -s "$script_dir/run-rust-coverage-child.sh" "$output/bin/$binary"
  done
  {
    printf 'export RUSTUP_TOOLCHAIN=%q\n' "$RUSTUP_TOOLCHAIN"
    printf 'export CARGO_TARGET_DIR=%q\n' "$CARGO_TARGET_DIR"
    printf 'export RUSTFLAGS=%q\n' "$RUSTFLAGS"
    printf 'export LLVM_COV=%q\nexport LLVM_PROFDATA=%q\n' "$LLVM_COV" "$LLVM_PROFDATA"
    cat "$output/instrumentation.env"
    printf 'export ID_RUST_BIN_DIR=%q\n' "$output/bin"
    printf 'export ID_COVERAGE_REAL_BIN_DIR=%q\n' "$output/target/debug"
    printf 'export ID_COVERAGE_RECEIPTS=%q\n' "$output/children"
    printf 'export CARGO_INCREMENTAL=0\nexport CARGO_PROFILE_DEV_DEBUG=0\nexport CARGO_PROFILE_TEST_DEBUG=0\n'
  } >"$output/coverage.env"
  source "$output/coverage.env"
  {
    git -C "$workspace" rev-parse HEAD
    rustc --version --verbose
    cargo llvm-cov --version
    sha256sum "$workspace/coverage/security-profile.json" "$workspace/Cargo.lock"
    printf 'RUSTFLAGS=%s\nLLVM_PROFILE_FILE=%s\n' "$RUSTFLAGS" "$LLVM_PROFILE_FILE"
  } >"$output/provenance.txt"
  if [[ -n "${GITHUB_ENV:-}" ]]; then
    while IFS= read -r declaration; do
      if [[ "$declaration" =~ ^export\ ([A-Z_0-9]+)= ]]; then
        key="${BASH_REMATCH[1]}"
        [[ "${!key}" != *$'\n'* ]]
        printf '%s=%s\n' "$key" "${!key}" >>"$GITHUB_ENV"
      fi
    done <"$output/coverage.env"
  fi
  printf 'Coverage environment: source %q\n' "$output/coverage.env"
elif [[ "$command" == report ]]; then
  source "$output/coverage.env"
  cd "$workspace"
  # Report all instrumented workspace binaries, including CARGO_BIN_EXE_* children.
  # The checker applies the explicit profile; no production paths are ignored here.
  cargo llvm-cov report --json --output-path "$output/llvm.json"
  cargo llvm-cov report --html --output-dir "$output/html"
  node "$script_dir/check-rust-coverage.mjs" "$output/llvm.json" \
    "$workspace/coverage/security-profile.json" "$workspace" "$output/children" "$output/result.json"
  [[ "${ID_COVERAGE_TESTS_SUCCEEDED:-false}" == true ]] || {
    echo 'Coverage run is incomplete: the full integration scenario did not pass' >&2; exit 1;
  }
else
  echo 'Expected prepare or report' >&2
  exit 1
fi
