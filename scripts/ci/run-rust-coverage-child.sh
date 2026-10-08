#!/usr/bin/env bash
set -euo pipefail

binary="$(basename "$0")"
: "${ID_COVERAGE_REAL_BIN_DIR:?}"
: "${ID_COVERAGE_RECEIPTS:?}"
: "${CARGO_LLVM_COV_TARGET_DIR:?}"
receipt="${ID_COVERAGE_RECEIPTS}/${binary}-$$"
export LLVM_PROFILE_FILE="${CARGO_LLVM_COV_TARGET_DIR}/${binary}-child-%p-%m.profraw"

"${ID_COVERAGE_REAL_BIN_DIR}/${binary}" "$@" &
child=$!
printf '%s\n' "$binary" "$child" "$LLVM_PROFILE_FILE" >"${receipt}.started"
trap 'kill -TERM "$child" 2>/dev/null || true' TERM
trap 'kill -INT "$child" 2>/dev/null || true' INT

# A trapped signal interrupts wait before the Rust process finishes flushing.
while true; do
  if wait "$child"; then status=0; else status=$?; fi
  if ! kill -0 "$child" 2>/dev/null; then break; fi
done
shopt -s nullglob
profiles=("${CARGO_LLVM_COV_TARGET_DIR}/${binary}-child-${child}-"*.profraw)
if ((${#profiles[@]} == 0)); then
  printf 'Coverage child %s/%s did not write a profile\n' "$binary" "$child" >&2
  exit 1
fi
for profile in "${profiles[@]}"; do test -s "$profile"; done
printf '%s\n' "${profiles[@]}" >"${receipt}.completed"
exit "$status"
