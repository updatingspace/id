#!/usr/bin/env bash
set -euo pipefail

# Requires migrated disposable local YDB with id_shared_cache, prebuilt binaries and Chromium.
workspace_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin_dir="${ID_RUST_BIN_DIR:-${workspace_dir}/target/debug}"
api_port="${ID_PILOT_API_PORT:-13073}"
web_port="${ID_PILOT_WEB_PORT:-13074}"
proxy_port="${ID_PILOT_PROXY_PORT:-13075}"
proxy_origin="http://127.0.0.1:${proxy_port}"
playwright_module="${ID_PLAYWRIGHT_MODULE:-${workspace_dir}/../../web/id-frontend/node_modules/@playwright/test}"
synthetic_session_key="synthetic-signup-browser-secret-min-32-chars"
synthetic_verify_key="9d45472bb43d42eebef3f4a6f3689b08c1f7c07064a211e5b813b1b92ff28574"
scratch_dir="$(mktemp -d)"
api_pid=""
web_pid=""
proxy_pid=""
cleanup() {
  local status=$?
  trap - EXIT
  for pid in "${proxy_pid}" "${web_pid}" "${api_pid}"; do
    if [[ -n "${pid}" ]]; then kill "${pid}" 2>/dev/null || true; wait "${pid}" 2>/dev/null || true; fi
  done
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
  const target = ['/signup', '/login'].includes(path) || path.startsWith('/_id/') ? web : api;
  const forwarded = http.request({ hostname: '127.0.0.1', port: target, path: incoming.url,
    method: incoming.method, headers: { ...incoming.headers, host: `127.0.0.1:${target}` } },
  response => { outgoing.writeHead(response.statusCode, response.headers); response.pipe(outgoing); });
  forwarded.on('error', () => { if (!outgoing.headersSent) outgoing.writeHead(502); outgoing.end(); });
  incoming.pipe(forwarded);
}).listen(port, '127.0.0.1');
EOF

YDB_ENDPOINT="${YDB_ENDPOINT:-grpc://127.0.0.1:2136}" \
YDB_DATABASE=/local YDB_CREDENTIALS_MODE=anonymous \
  "${bin_dir}/idctl" email-verify-schema

YDB_ENDPOINT="${YDB_ENDPOINT:-grpc://127.0.0.1:2136}" \
YDB_DATABASE=/local YDB_CREDENTIALS_MODE=anonymous \
DJANGO_DEBUG=true DJANGO_SECRET_KEY="${synthetic_session_key}" \
ID_EMAIL_VERIFY_HMAC_KEY="${synthetic_verify_key}" \
ID_AUTH_ME_ENABLED=true ID_AUTH_FORM_TOKEN_ENABLED=true \
ID_AUTH_EMAIL_VERIFY_PILOT_ENABLED=true ID_AUTH_SIGNUP_PILOT_ENABLED=true \
MEDIA_PUBLIC_BASE_URL=https://storage.yandexcloud.net/synthetic-id-media \
SESSION_COOKIE_SECURE=false CSRF_COOKIE_SECURE=false CSRF_TRUSTED_ORIGINS="${proxy_origin}" \
HOST=127.0.0.1 PORT="${api_port}" "${bin_dir}/id-api" >"${scratch_dir}/api.log" 2>&1 &
api_pid=$!
ID_WEB_LOGIN_PILOT_ENABLED=true ID_WEB_SIGNUP_PILOT_ENABLED=true \
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
    curl --silent --fail --max-time 2 "${proxy_origin}/signup" >/dev/null; then
    ready=true; break
  fi
  sleep 1
done
[[ "${ready}" == true ]]

ID_LIVE_BASE_URL="${proxy_origin}" ID_PLAYWRIGHT_MODULE="${playwright_module}" \
ID_CHROMIUM_PATH="${ID_CHROMIUM_PATH:-$(command -v chromium || true)}" \
  node "${workspace_dir}/scripts/check-web-signup-live.cjs"
