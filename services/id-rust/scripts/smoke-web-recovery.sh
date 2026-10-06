#!/usr/bin/env bash
set -euo pipefail

workspace_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin_dir="${ID_RUST_BIN_DIR:-${workspace_dir}/target/debug}"
port="${ID_PILOT_WEB_PORT:-13058}"
scratch_dir="$(mktemp -d)"
web_pid=""

cleanup() {
  if [[ -n "${web_pid}" ]]; then kill "${web_pid}" 2>/dev/null || true; wait "${web_pid}" 2>/dev/null || true; fi
  rm -rf "${scratch_dir}"
}
trap cleanup EXIT

ID_WEB_LOGIN_PILOT_ENABLED=true ID_WEB_RECOVERY_PILOT_ENABLED=true ID_WEB_EMAIL_VERIFY_PILOT_ENABLED=true \
  HOST=127.0.0.1 PORT="${port}" "${bin_dir}/id-web" >"${scratch_dir}/web.log" 2>&1 &
web_pid=$!

ready=false
for ((attempt=0; attempt<30; attempt++)); do
  if ! kill -0 "${web_pid}" 2>/dev/null; then cat "${scratch_dir}/web.log" >&2; exit 1; fi
  if curl --silent --fail --max-time 2 -D "${scratch_dir}/forgot.headers" \
    "http://127.0.0.1:${port}/forgot-password" >"${scratch_dir}/forgot.html"; then
    ready=true; break
  fi
  sleep 1
done
[[ "${ready}" == true ]]

rg -q 'id="forgot-form"' "${scratch_dir}/forgot.html"
rg -q '/_id/recovery.js' "${scratch_dir}/forgot.html"
rg -qi '^cache-control: no-store' "${scratch_dir}/forgot.headers"
rg -qi '^referrer-policy: no-referrer' "${scratch_dir}/forgot.headers"
rg -qi "frame-ancestors 'none'" "${scratch_dir}/forgot.headers"
curl --silent --fail --max-time 5 -D "${scratch_dir}/reset.headers" \
  "http://127.0.0.1:${port}/reset-password" >"${scratch_dir}/reset.html"
rg -q 'id="reset-form"' "${scratch_dir}/reset.html"
rg -q 'hidden' "${scratch_dir}/reset.html"
rg -qi '^cache-control: no-store' "${scratch_dir}/reset.headers"
curl --silent --fail --max-time 5 -D "${scratch_dir}/verify.headers" \
  "http://127.0.0.1:${port}/verify-email" >"${scratch_dir}/verify.html"
rg -q 'id="verify-form"' "${scratch_dir}/verify.html"
rg -q 'id="verify-request-form"' "${scratch_dir}/verify.html"
rg -qi '^cache-control: no-store' "${scratch_dir}/verify.headers"
curl --silent --fail --max-time 5 "http://127.0.0.1:${port}/_id/recovery.js" \
  >"${scratch_dir}/recovery.js"
node --check "${scratch_dir}/recovery.js"
rg -q '/api/v1/auth/password/reset/request' "${scratch_dir}/recovery.js"
rg -q '/api/v1/auth/password/reset/confirm' "${scratch_dir}/recovery.js"
rg -q '/api/v1/auth/email/verification/request' "${scratch_dir}/recovery.js"
rg -q '/api/v1/auth/email/verification/confirm' "${scratch_dir}/recovery.js"
curl --silent --fail --max-time 5 "http://127.0.0.1:${port}/login" \
  >"${scratch_dir}/login.html"
rg -q 'href="/forgot-password"' "${scratch_dir}/login.html"
echo 'Topcoat recovery and email verification SSR smoke: routes, headers, JS and login link'
