#!/usr/bin/env bash
# Shared by the required schema job and its instrumented coverage replay.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir/../../services/id-rust"
scenario="${1:?usage: run-rust-security-scenarios.sh password-reset|email-change|export-escrow|isolated-deletion}"
[[ $# == 1 ]] || { echo 'Expected one scenario' >&2; exit 1; }
[[ "${YDB_DATABASE:-}" == /local && "${YDB_CREDENTIALS_MODE:-}" == anonymous && "${DJANGO_DEBUG:-}" == true ]] || {
  echo 'Security scenarios require debug, anonymous local YDB' >&2; exit 1;
}
[[ "${YDB_ENDPOINT:-}" == grpc://localhost:2136 || "${YDB_ENDPOINT:-}" == grpc://127.0.0.1:2136 ]] || {
  echo 'Security scenarios must start from the local CI endpoint on port 2136' >&2; exit 1;
}

idctl() {
  if [[ -n "${ID_RUST_BIN_DIR:-}" ]]; then
    "${ID_RUST_BIN_DIR}/idctl" "$@"
  else
    cargo run --locked -p id-runtime --bin idctl -- "$@"
  fi
}

case "$scenario" in
  password-reset)
    export ID_AUTH_FORM_TOKEN_ENABLED=true ID_AUTH_PASSWORD_RESET_PILOT_ENABLED=true
    export ID_PASSWORD_RESET_HMAC_KEY=0707070707070707070707070707070707070707070707070707070707070707
    export CSRF_TRUSTED_ORIGINS=http://localhost:5175
    idctl password-reset-schema
    idctl password-reset-schema
    cargo test --locked -p id-runtime --test password_reset_http_ydb -- --ignored
    cargo test --locked -p id-runtime --lib password_reset::tests::mail_claim_is_single_owner_and_expiry_is_cleaned -- --ignored
    ;;
  email-change)
    export ID_AUTH_EMAIL_CHANGE_PILOT_ENABLED=true ID_AUTH_EMAIL_CANCEL_PILOT_ENABLED=true
    export CSRF_TRUSTED_ORIGINS=http://id.localhost
    idctl email-change-schema
    idctl email-change-schema
    idctl security-mail-schema
    cargo test --locked -p id-runtime --test email_change_ydb -- --ignored
    cargo test --locked -p id-runtime --test email_cancel_http_ydb -- --ignored
    ;;
  export-escrow)
    cargo test --locked -p id-runtime --test data_export_escrow_ydb -- --ignored
    ;;
  isolated-deletion)
    # This suite drains global deletion queues and seals legacy writers. It must
    # own a fresh database; never reuse the primary suite's YDB on port 2136.
    export YDB_ENDPOINT=grpc://127.0.0.1:2137 ID_DISPOSABLE_YDB=true
    export ID_EXPORT_TEST_REAL_S3=false
    container="$(docker run -d --rm --hostname localhost \
      -e GRPC_PORT=2137 -e MON_PORT=8766 -p 127.0.0.1:2137:2137 \
      ydbplatform/local-ydb@sha256:9e46fd45875551a75bcf34d0bb9ca0baa1d8763a4ccf2070af45f4467c4b7402)"
    [[ -n "$container" ]] || { echo 'YDB container creation returned no ID' >&2; exit 1; }
    cleanup() {
      local status=$?
      trap - EXIT
      if ! docker stop "$container"; then
        echo 'Failed to stop this scenario’s YDB container' >&2
        if ((status == 0)); then status=1; fi
      fi
      exit "$status"
    }
    trap cleanup EXIT
    YDB_CONTAINER_NAME="$container" YDB_LOCAL_ENDPOINT="$YDB_ENDPOINT" \
      "$script_dir/wait-for-ydb-local.sh"
    idctl legacy-schema --apply
    idctl cache-schema
    cargo test --locked -p id-runtime --test legacy_unbound_deletion_ydb -- --ignored
    cargo test --locked -p id-runtime --test legacy_cutover_reset_ydb -- --ignored
    idctl data-export-schema
    idctl data-export-escrow-schema
    idctl data-export-mail-schema
    cargo test --locked -p id-runtime --test data_export_delete_flow_ydb -- --ignored
    ID_AUTH_ADMIN_READ_ENABLED=true ID_AUTH_ADMIN_SUSPEND_ENABLED=true \
      ID_AUTH_ADMIN_CLIENT_REDIRECTS_ENABLED=true \
      cargo test --locked -p id-runtime --test admin_http_ydb -- --ignored
    ;;
  *) echo "Unknown security scenario: $scenario" >&2; exit 1 ;;
esac
