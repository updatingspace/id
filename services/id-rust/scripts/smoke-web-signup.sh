#!/usr/bin/env bash
set -euo pipefail

workspace_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin_dir="${ID_RUST_BIN_DIR:-${workspace_dir}/target/debug}"
port="${ID_PILOT_WEB_PORT:-13072}"
scratch_dir="$(mktemp -d)"
web_pid=""
cleanup() {
  if [[ -n "${web_pid}" ]]; then kill "${web_pid}" 2>/dev/null || true; wait "${web_pid}" 2>/dev/null || true; fi
  rm -rf "${scratch_dir}"
}
trap cleanup EXIT

ID_WEB_LOGIN_PILOT_ENABLED=true ID_WEB_SIGNUP_PILOT_ENABLED=true \
  HOST=127.0.0.1 PORT="${port}" "${bin_dir}/id-web" >"${scratch_dir}/web.log" 2>&1 &
web_pid=$!
ready=false
for ((attempt=0; attempt<30; attempt++)); do
  if ! kill -0 "${web_pid}" 2>/dev/null; then cat "${scratch_dir}/web.log" >&2; exit 1; fi
  if curl --silent --fail --max-time 2 -D "${scratch_dir}/signup.headers" \
    "http://127.0.0.1:${port}/signup" >"${scratch_dir}/signup.html"; then
    ready=true; break
  fi
  sleep 1
done
[[ "${ready}" == true ]]

rg -q 'id="signup-form"' "${scratch_dir}/signup.html"
rg -q 'id="consent-data"' "${scratch_dir}/signup.html"
rg -q '/_id/signup.js' "${scratch_dir}/signup.html"
rg -qi '^cache-control: no-store' "${scratch_dir}/signup.headers"
rg -qi '^referrer-policy: no-referrer' "${scratch_dir}/signup.headers"
rg -qi "frame-ancestors 'none'" "${scratch_dir}/signup.headers"
curl --silent --fail --max-time 5 "http://127.0.0.1:${port}/_id/signup.js" >"${scratch_dir}/signup.js"
node --check "${scratch_dir}/signup.js"
rg -q '/api/v1/auth/form_token\?purpose=register' "${scratch_dir}/signup.js"
rg -q '/api/v1/auth/signup' "${scratch_dir}/signup.js"
curl --silent --fail --max-time 5 "http://127.0.0.1:${port}/login" >"${scratch_dir}/login.html"
rg -q 'href="/signup"' "${scratch_dir}/login.html"
echo 'Topcoat signup SSR smoke: route, headers, JS and login link'
