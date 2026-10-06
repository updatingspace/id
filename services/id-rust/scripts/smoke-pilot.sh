#!/usr/bin/env bash
set -euo pipefail

workspace_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin_dir="${ID_RUST_BIN_DIR:-${workspace_dir}/target/debug}"
api_port="${ID_PILOT_API_PORT:-18081}"
web_port="${ID_PILOT_WEB_PORT:-13007}"
scratch_dir="$(mktemp -d)"
api_pid=""
web_pid=""

cleanup() {
  if [[ -n "${api_pid}" ]]; then kill "${api_pid}" 2>/dev/null || true; fi
  if [[ -n "${web_pid}" ]]; then kill "${web_pid}" 2>/dev/null || true; fi
  if [[ -n "${api_pid}" ]]; then wait "${api_pid}" 2>/dev/null || true; fi
  if [[ -n "${web_pid}" ]]; then wait "${web_pid}" 2>/dev/null || true; fi
  rm -rf "${scratch_dir}"
}
trap cleanup EXIT

PORT="${api_port}" "${bin_dir}/id-api" >"${scratch_dir}/api.log" 2>&1 &
api_pid=$!
HOST=127.0.0.1 PORT="${web_port}" "${bin_dir}/id-web" >"${scratch_dir}/web.log" 2>&1 &
web_pid=$!

ready=false
for ((attempt=0; attempt<45; attempt++)); do
  if ! kill -0 "${api_pid}" 2>/dev/null || ! kill -0 "${web_pid}" 2>/dev/null; then
    cat "${scratch_dir}/api.log" "${scratch_dir}/web.log" >&2
    exit 1
  fi
  if curl --silent --fail --max-time 2 "http://127.0.0.1:${api_port}/readyz" >"${scratch_dir}/ready.json" \
    && curl --silent --fail --max-time 2 "http://127.0.0.1:${web_port}/" >"${scratch_dir}/index.html"; then
    ready=true
    break
  fi
  sleep 1
done
[[ "${ready}" == true ]]
[[ "$(<"${scratch_dir}/ready.json")" == *'"status":"ready"'* ]]
[[ "$(<"${scratch_dir}/index.html")" == *'Пользовательский вход ещё не подключён.'* ]]

curl --silent --show-error --fail --max-time 5 -D "${scratch_dir}/headers" \
  "http://127.0.0.1:${api_port}/healthz" > /dev/null
response_headers="$(<"${scratch_dir}/headers")"
[[ "${response_headers,,}" == *'cache-control: no-store'* ]]

# The pilot must not masquerade as a functional authentication backend.
status="$(curl --silent --show-error --max-time 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${api_port}/api/v1/auth/me")"
[[ "${status}" == 404 ]]
status="$(curl --silent --show-error --max-time 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${api_port}/api/v1/auth/form_token?purpose=login")"
[[ "${status}" == 404 ]]

# Buffered SSR stays HTML even when a client requests Topcoat's streaming format.
curl --silent --show-error --fail --max-time 5 -H 'Accept: application/x-ndjson' \
  -D "${scratch_dir}/headers" "http://127.0.0.1:${web_port}/" >"${scratch_dir}/index.html"
response_headers="$(<"${scratch_dir}/headers")"
[[ "${response_headers,,}" == *'content-type: text/html'* ]]
[[ "$(<"${scratch_dir}/index.html")" == *'</html>'* ]]
echo 'Pilot HTTP smoke: YDB readiness, liveness/no-store, buffered Topcoat HTML, auth route absent'
