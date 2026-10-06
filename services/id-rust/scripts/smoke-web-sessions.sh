#!/usr/bin/env bash
set -euo pipefail

workspace_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin_dir="${ID_RUST_BIN_DIR:-${workspace_dir}/target/debug}"
web_port="${ID_PILOT_WEB_PORT:-13078}"
api_port="${ID_PILOT_MOCK_API_PORT:-13079}"
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
      email_verified: true, has_2fa: false,
    } : null }));
    return;
  }
  if (request.url === '/api/v1/auth/sessions' && valid) {
    response.end(JSON.stringify({ sessions: [
      { id: 'current', user_agent: 'Current device', ip: '192.0.2.1', current: true, revoked: false },
      { id: 'other" onclick="bad', user_agent: '<script>bad()</script>', ip: '192.0.2.2', current: false, revoked: false },
    ] }));
    return;
  }
  response.writeHead(401); response.end(JSON.stringify({ code: 'UNAUTHORIZED' }));
}).listen(port, '127.0.0.1');
EOF

ID_PILOT_MOCK_API_PORT="${api_port}" node "${scratch_dir}/mock-api.cjs" >"${scratch_dir}/api.log" 2>&1 &
api_pid=$!
ID_WEB_ACCOUNT_PILOT_ENABLED=true ID_WEB_SESSIONS_PILOT_ENABLED=true ID_WEB_LOGOUT_PILOT_ENABLED=true \
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
    -D "${scratch_dir}/sessions.headers" \
    "http://127.0.0.1:${web_port}/account?section=sessions" >"${scratch_dir}/sessions.html"; then
    ready=true; break
  fi
  sleep 1
done
[[ "${ready}" == true ]]

html="$(<"${scratch_dir}/sessions.html")"
[[ "${html}" == *'id="session-message"'* ]]
[[ "${html}" == *'id="session-error"'* ]]
[[ "${html}" == *'id="revoke-others"'* ]]
[[ "${html}" == *'data-revoke-session="other&#34; onclick=&#34;bad"'* ]]
[[ "${html}" == *'&#60;script&#62;bad()&#60;/script&#62;'* ]]
[[ "${html}" != *'<script>bad()</script>'* ]]
[[ "${html}" == *'src="/_id/sessions.js"'* ]]
rg -qi '^cache-control: no-store' "${scratch_dir}/sessions.headers"
guest_status="$(curl --silent --show-error --max-time 5 -o /dev/null -w '%{http_code}' \
  "http://127.0.0.1:${web_port}/account?section=sessions")"
[[ "${guest_status}" == 303 ]]
echo "Topcoat sessions smoke: owner controls, escaped device data and guest redirect"
