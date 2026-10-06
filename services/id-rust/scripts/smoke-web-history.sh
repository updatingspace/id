#!/usr/bin/env bash
set -euo pipefail

workspace_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin_dir="${ID_RUST_BIN_DIR:-${workspace_dir}/target/debug}"
web_port="${ID_PILOT_WEB_PORT:-13058}"
api_port="${ID_PILOT_MOCK_API_PORT:-13059}"
scratch_dir="$(mktemp -d)"
api_pid=""
web_pid=""

cleanup() {
  if [[ -n "${web_pid}" ]]; then kill "${web_pid}" 2>/dev/null || true; wait "${web_pid}" 2>/dev/null || true; fi
  if [[ -n "${api_pid}" ]]; then kill "${api_pid}" 2>/dev/null || true; wait "${api_pid}" 2>/dev/null || true; fi
  rm -rf "${scratch_dir}"
}
trap cleanup EXIT

cat >"${scratch_dir}/mock-api.cjs" <<'EOF'
const http = require('node:http');
const port = Number(process.env.ID_PILOT_MOCK_API_PORT);
http.createServer((request, response) => {
  const valid = request.headers.cookie?.includes('sessionid=valid');
  response.setHeader('content-type', 'application/json');
  if (request.url === '/api/v1/auth/me') {
    response.end(JSON.stringify({ user: valid ? {
      username: 'pilot-user', email: 'pilot@example.invalid',
      email_verified: true, has_2fa: true,
    } : null }));
    return;
  }
  if (request.url === '/api/v1/auth/login-history' && valid) {
    response.end(JSON.stringify({ events: [{
      status: 'success', ip_address: '192.0.2.1', user_agent: '<script>bad</script>',
      device_id: null, is_new_device: true, reason: 'password',
      created_at: '2026-10-05T12:00:00.000Z',
    }] }));
    return;
  }
  response.writeHead(401); response.end(JSON.stringify({ code: 'UNAUTHORIZED' }));
}).listen(port, '127.0.0.1');
EOF

ID_PILOT_MOCK_API_PORT="${api_port}" node "${scratch_dir}/mock-api.cjs" >"${scratch_dir}/api.log" 2>&1 &
api_pid=$!
ID_WEB_ACCOUNT_PILOT_ENABLED=true ID_WEB_LOGIN_HISTORY_PILOT_ENABLED=true \
  ID_WEB_API_ORIGIN="http://127.0.0.1:${api_port}" \
  HOST=127.0.0.1 PORT="${web_port}" "${bin_dir}/id-web" >"${scratch_dir}/web.log" 2>&1 &
web_pid=$!

ready=false
for ((attempt=0; attempt<30; attempt++)); do
  if ! kill -0 "${web_pid}" 2>/dev/null || ! kill -0 "${api_pid}" 2>/dev/null; then
    cat "${scratch_dir}/web.log" "${scratch_dir}/api.log" >&2
    exit 1
  fi
  if curl --silent --fail --max-time 2 -H 'Cookie: sessionid=valid' \
    -D "${scratch_dir}/history.headers" \
    "http://127.0.0.1:${web_port}/account?section=activity" >"${scratch_dir}/history.html"; then
    ready=true; break
  fi
  sleep 1
done
[[ "${ready}" == true ]]

html="$(<"${scratch_dir}/history.html")"
[[ "${html}" == *'История входов'* ]]
[[ "${html}" == *'Успешный вход'* ]]
[[ "${html}" == *'192.0.2.1'* ]]
[[ "${html}" == *'Новое устройство'* ]]
[[ "${html}" == *'&#60;script&#62;bad&#60;/script&#62;'* ]]
[[ "${html}" != *'<script>bad</script>'* ]]
rg -qi '^cache-control: no-store' "${scratch_dir}/history.headers"
guest_status="$(curl --silent --show-error --max-time 5 -o /dev/null -w '%{http_code}' \
  "http://127.0.0.1:${web_port}/account?section=activity")"
[[ "${guest_status}" == 303 ]]
echo "Topcoat login history smoke: owner page, escaped event data and guest redirect"
