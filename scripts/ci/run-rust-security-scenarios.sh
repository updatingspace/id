#!/usr/bin/env bash
# Shared by the required schema job and its instrumented coverage replay.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir/../../services/id-rust"
scenario="${1:?usage: run-rust-security-scenarios.sh <scenario>}"
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

start_disposable_ydb() {
  # Both destructive scenarios own a fresh database and stop only their CID.
  export YDB_ENDPOINT=grpc://127.0.0.1:2137 ID_DISPOSABLE_YDB=true
  export ID_EXPORT_TEST_REAL_S3=false
  container="$(docker run -d --rm --hostname localhost \
    -e GRPC_PORT=2137 -e MON_PORT=8766 -p 127.0.0.1:2137:2137 \
    ydbplatform/local-ydb@sha256:9e46fd45875551a75bcf34d0bb9ca0baa1d8763a4ccf2070af45f4467c4b7402)"
  [[ -n "$container" ]] || { echo 'YDB container creation returned no ID' >&2; exit 1; }
  cleanup() {
    local scenario_exit=$?
    trap - EXIT
    if ! docker stop "$container"; then
      echo 'Failed to stop this scenario’s YDB container' >&2
      if ((scenario_exit == 0)); then scenario_exit=1; fi
    fi
    exit "$scenario_exit"
  }
  trap cleanup EXIT
  YDB_CONTAINER_NAME="$container" YDB_LOCAL_ENDPOINT="$YDB_ENDPOINT" \
    "$script_dir/wait-for-ydb-local.sh"
  idctl legacy-schema --apply
  idctl cache-schema
}

case "$scenario" in
  password-change)
    export ID_AUTH_PASSWORD_CHANGE_PILOT_ENABLED=true
    idctl password-mail-schema
    idctl security-mail-schema
    cargo test --locked -p id-runtime --test password_change_http_ydb -- --ignored
    cargo test --locked -p id-runtime --lib password_mail::tests::sends_once_from_durable_intent -- --ignored
    cargo test --locked -p id-runtime --lib password_mail::tests::two_clients_claim_one_password_mail -- --ignored
    cargo test --locked -p id-runtime --lib password_mail::tests::deleted_account_cancels_and_scrubs_pending_mail -- --ignored
    ;;
  password-reset)
    export ID_AUTH_FORM_TOKEN_ENABLED=true ID_AUTH_PASSWORD_RESET_PILOT_ENABLED=true
    export ID_PASSWORD_RESET_HMAC_KEY=0707070707070707070707070707070707070707070707070707070707070707
    export CSRF_TRUSTED_ORIGINS=http://localhost:5175
    idctl password-reset-schema
    idctl password-reset-schema
    cargo test --locked -p id-runtime --test password_reset_http_ydb -- --ignored
    cargo test --locked -p id-runtime --lib password_reset::tests::mail_claim_is_single_owner_and_expiry_is_cleaned -- --ignored
    ;;
  email-verification)
    export ID_AUTH_FORM_TOKEN_ENABLED=true ID_AUTH_EMAIL_VERIFY_PILOT_ENABLED=true
    export ID_AUTH_EMAIL_RESEND_ENABLED=true ID_AUTH_SIGNUP_PILOT_ENABLED=true
    export ID_EMAIL_VERIFY_HMAC_KEY=0808080808080808080808080808080808080808080808080808080808080808
    export CSRF_TRUSTED_ORIGINS=http://localhost:5175
    idctl email-verify-schema
    idctl email-verify-schema
    cargo test --locked -p id-runtime --test email_verify_http_ydb -- --ignored
    cargo test --locked -p id-runtime --test signup_ydb -- --ignored
    cargo test --locked -p id-runtime --lib email_verify::tests::mail_claim_is_single_owner_and_expiry_is_cleaned -- --ignored
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
    start_disposable_ydb
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
  recovery-browser)
    bash scripts/smoke-web-recovery-live.sh
    ;;
  deletion-browser)
    start_disposable_ydb
    cargo test --locked -p id-runtime --test legacy_cutover_reset_ydb -- --ignored
    idctl data-export-schema
    idctl data-export-escrow-schema
    idctl data-export-mail-schema
    bash scripts/smoke-web-deletion-live.sh
    ;;
  deletion-review-browser)
    bash scripts/smoke-web-deletion.sh
    ;;
  admin-browser)
    node scripts/check-web-admin-suspend-browser.cjs
    ;;
  admin-live)
    bash scripts/smoke-web-admin-live.sh
    ;;
  signup-browser)
    bash scripts/smoke-web-signup-live.sh
    ;;
  remaining-schema)
    # These required schema-job cases are absent from ordinary rust-pilot.
    # Separate subprocesses preserve each case's environment and disposal scope.
    for replay in password-change email-verification recovery-browser deletion-browser \
      deletion-review-browser admin-browser admin-live signup-browser; do
      bash "$script_dir/run-rust-security-scenarios.sh" "$replay"
    done
    ;;
  *) echo "Unknown security scenario: $scenario" >&2; exit 1 ;;
esac
