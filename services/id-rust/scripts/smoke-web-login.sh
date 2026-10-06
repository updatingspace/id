#!/usr/bin/env bash
set -euo pipefail

workspace_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin_dir="${ID_RUST_BIN_DIR:-${workspace_dir}/target/debug}"
web_port="${ID_PILOT_WEB_PORT:-13008}"
scratch_dir="$(mktemp -d)"
web_pid=""

cleanup() {
  if [[ -n "${web_pid}" ]]; then kill "${web_pid}" 2>/dev/null || true; fi
  if [[ -n "${web_pid}" ]]; then wait "${web_pid}" 2>/dev/null || true; fi
  rm -rf "${scratch_dir}"
}
trap cleanup EXIT

ID_WEB_LOGIN_PILOT_ENABLED=true ID_WEB_PASSKEY_PILOT_ENABLED=true HOST=127.0.0.1 PORT="${web_port}" \
  "${bin_dir}/id-web" >"${scratch_dir}/web.log" 2>&1 &
web_pid=$!

ready=false
for ((attempt=0; attempt<30; attempt++)); do
  if ! kill -0 "${web_pid}" 2>/dev/null; then
    cat "${scratch_dir}/web.log" >&2
    exit 1
  fi
  if curl --silent --fail --max-time 2 \
    "http://127.0.0.1:${web_port}/login" >"${scratch_dir}/login.html"; then
    ready=true
    break
  fi
  sleep 1
done
[[ "${ready}" == true ]]
html="$(<"${scratch_dir}/login.html")"
[[ "${html}" == *'<form id="login-form" method="post" action="/login">'* ]]
[[ "${html}" == *'<fieldset id="mfa-fields"'* ]]
[[ "${html}" == *'id="passkey-login"'* ]]
[[ "${html}" == *'src="/_id/login.js"'* ]]

curl --silent --show-error --fail --max-time 5 -D "${scratch_dir}/headers" \
  "http://127.0.0.1:${web_port}/login" > /dev/null
headers="$(<"${scratch_dir}/headers")"
[[ "${headers,,}" == *'content-type: text/html'* ]]
[[ "${headers,,}" == *'cache-control: no-store'* ]]
[[ "${headers,,}" == *"content-security-policy: default-src 'none'; script-src 'self'"* ]]

for asset in login.js login.css; do
  curl --silent --show-error --fail --max-time 5 -D "${scratch_dir}/headers" \
    "http://127.0.0.1:${web_port}/_id/${asset}" >"${scratch_dir}/${asset}"
  headers="$(<"${scratch_dir}/headers")"
  [[ "${headers,,}" == *'x-content-type-options: nosniff'* ]]
  [[ -s "${scratch_dir}/${asset}" ]]
done
[[ "$(<"${scratch_dir}/login.js")" == *'"/api/v1/auth/form_token?purpose=login"'* ]]
[[ "$(<"${scratch_dir}/login.js")" == *'"/api/v1/auth/login"'* ]]
[[ "$(<"${scratch_dir}/login.js")" == *'"/api/v1/auth/passkeys/login/complete"'* ]]
status="$(curl --silent --show-error --max-time 5 -o /dev/null -w '%{http_code}' \
  -X POST "http://127.0.0.1:${web_port}/login")"
[[ "${status}" == 405 ]]

echo "Topcoat login pilot HTTP smoke: SSR, separate assets, CSP, POST-only fallback"
