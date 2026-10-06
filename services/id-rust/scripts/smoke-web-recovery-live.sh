#!/usr/bin/env bash
set -euo pipefail

# Requires a migrated disposable local YDB, prebuilt id-api/id-web/idctl and Playwright Chromium.
workspace_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin_dir="${ID_RUST_BIN_DIR:-${workspace_dir}/target/debug}"
api_port="${ID_PILOT_API_PORT:-13061}"
web_port="${ID_PILOT_WEB_PORT:-13062}"
proxy_port="${ID_PILOT_PROXY_PORT:-13063}"
proxy_origin="http://127.0.0.1:${proxy_port}"
playwright_module="${ID_PLAYWRIGHT_MODULE:-${workspace_dir}/browser-tests/node_modules/@playwright/test}"
synthetic_session_key="synthetic-reset-browser-secret-min-32-chars"
synthetic_reset_key="4d806d24d1d8aef1e00baf70221d5299843ece84e69e503ce63985a69aa6a9c8"
umask 077
scratch_dir="$(mktemp -d)"
fixture_pid=""
api_pid=""
web_pid=""
proxy_pid=""

cleanup() {
  local status=$?
  trap - EXIT
  touch "${scratch_dir}/done"
  for pid in "${proxy_pid}" "${web_pid}" "${api_pid}"; do
    if [[ -n "${pid}" ]]; then kill "${pid}" 2>/dev/null || true; wait "${pid}" 2>/dev/null || true; fi
  done
  if [[ -n "${fixture_pid}" ]] && ! wait "${fixture_pid}"; then
    cat "${scratch_dir}/fixture.log" >&2
    status=1
  fi
  if [[ "${status}" -ne 0 ]]; then
    cat "${scratch_dir}/api.log" "${scratch_dir}/web.log" "${scratch_dir}/proxy.log" 2>/dev/null >&2 || true
  fi
  rm -rf "${scratch_dir}"
  exit "${status}"
}
trap cleanup EXIT

cat >"${scratch_dir}/proxy.cjs" <<'EOF'
const http = require('node:http');
const api = Number(process.env.ID_PILOT_API_PORT);
const web = Number(process.env.ID_PILOT_WEB_PORT);
const port = Number(process.env.ID_PILOT_PROXY_PORT);
http.createServer((incoming, outgoing) => {
  const path = new URL(incoming.url, `http://${incoming.headers.host}`).pathname;
  const target = ['/login', '/forgot-password', '/reset-password'].includes(path)
    || path.startsWith('/_id/') ? web : api;
  const forwarded = http.request({ hostname: '127.0.0.1', port: target, path: incoming.url,
    method: incoming.method, headers: { ...incoming.headers, host: `127.0.0.1:${target}` } },
  response => { outgoing.writeHead(response.statusCode, response.headers); response.pipe(outgoing); });
  forwarded.on('error', () => { if (!outgoing.headersSent) outgoing.writeHead(502); outgoing.end(); });
  incoming.pipe(forwarded);
}).listen(port, '127.0.0.1');
EOF

YDB_ENDPOINT="${YDB_ENDPOINT:-grpc://127.0.0.1:2136}" \
YDB_DATABASE=/local YDB_CREDENTIALS_MODE=anonymous \
DJANGO_DEBUG=true DJANGO_SECRET_KEY="${synthetic_session_key}" \
ID_PASSWORD_RESET_HMAC_KEY="${synthetic_reset_key}" \
  "${bin_dir}/idctl" password-reset-schema

YDB_ENDPOINT="${YDB_ENDPOINT:-grpc://127.0.0.1:2136}" \
YDB_DATABASE=/local YDB_CREDENTIALS_MODE=anonymous \
DJANGO_DEBUG=true DJANGO_SECRET_KEY="${synthetic_session_key}" \
ID_PASSWORD_RESET_HMAC_KEY="${synthetic_reset_key}" \
ID_RESET_BROWSER_FIXTURE_OUTPUT="${scratch_dir}/fixture.json" \
ID_RESET_BROWSER_KEY_OUTPUT="${scratch_dir}/key" \
ID_RESET_BROWSER_DONE="${scratch_dir}/done" \
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 \
  cargo test --manifest-path "${workspace_dir}/Cargo.toml" --locked -p id-runtime \
    --test password_reset_browser_fixture_ydb -- --ignored --nocapture >"${scratch_dir}/fixture.log" 2>&1 &
fixture_pid=$!
for ((attempt=0; attempt<120; attempt++)); do
  if [[ -s "${scratch_dir}/fixture.json" ]]; then break; fi
  if ! kill -0 "${fixture_pid}" 2>/dev/null; then cat "${scratch_dir}/fixture.log" >&2; exit 1; fi
  sleep 1
done
if [[ ! -s "${scratch_dir}/fixture.json" ]]; then cat "${scratch_dir}/fixture.log" >&2; exit 1; fi

YDB_ENDPOINT="${YDB_ENDPOINT:-grpc://127.0.0.1:2136}" \
YDB_DATABASE=/local YDB_CREDENTIALS_MODE=anonymous \
DJANGO_DEBUG=true DJANGO_SECRET_KEY="${synthetic_session_key}" \
ID_PASSWORD_RESET_HMAC_KEY="${synthetic_reset_key}" \
ID_AUTH_ME_ENABLED=true ID_AUTH_FORM_TOKEN_ENABLED=true \
ID_AUTH_PASSWORD_RESET_PILOT_ENABLED=true \
MEDIA_PUBLIC_BASE_URL=https://storage.yandexcloud.net/synthetic-id-media \
SESSION_COOKIE_SECURE=false CSRF_COOKIE_SECURE=false CSRF_TRUSTED_ORIGINS="${proxy_origin}" \
HOST=127.0.0.1 PORT="${api_port}" "${bin_dir}/id-api" >"${scratch_dir}/api.log" 2>&1 &
api_pid=$!
ID_WEB_LOGIN_PILOT_ENABLED=true ID_WEB_RECOVERY_PILOT_ENABLED=true \
HOST=127.0.0.1 PORT="${web_port}" "${bin_dir}/id-web" >"${scratch_dir}/web.log" 2>&1 &
web_pid=$!
ID_PILOT_API_PORT="${api_port}" ID_PILOT_WEB_PORT="${web_port}" \
ID_PILOT_PROXY_PORT="${proxy_port}" node "${scratch_dir}/proxy.cjs" >"${scratch_dir}/proxy.log" 2>&1 &
proxy_pid=$!

ready=false
for ((attempt=0; attempt<40; attempt++)); do
  for pid in "${api_pid}" "${web_pid}" "${proxy_pid}"; do
    if ! kill -0 "${pid}" 2>/dev/null; then exit 1; fi
  done
  if curl --silent --fail --max-time 2 "${proxy_origin}/readyz" >/dev/null &&
    curl --silent --fail --max-time 2 "${proxy_origin}/forgot-password" >/dev/null; then
    ready=true; break
  fi
  sleep 1
done
[[ "${ready}" == true ]]

ID_LIVE_BASE_URL="${proxy_origin}" \
ID_RESET_BROWSER_FIXTURE_OUTPUT="${scratch_dir}/fixture.json" \
ID_RESET_BROWSER_KEY_OUTPUT="${scratch_dir}/key" \
ID_PLAYWRIGHT_MODULE="${playwright_module}" \
ID_CHROMIUM_PATH="${ID_CHROMIUM_PATH:-$(command -v chromium || true)}" \
  node "${workspace_dir}/scripts/check-web-recovery-live.cjs"
touch "${scratch_dir}/done"
wait "${fixture_pid}"
fixture_pid=""
