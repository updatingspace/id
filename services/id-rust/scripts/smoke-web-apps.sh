#!/usr/bin/env bash
set -euo pipefail

workspace_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin_dir="${ID_RUST_BIN_DIR:-${workspace_dir}/target/debug}"
web_port="${ID_PILOT_WEB_PORT:-13018}"
api_port="${ID_PILOT_MOCK_API_PORT:-13019}"
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
const port = Number(process.env.ID_PILOT_MOCK_API_PORT || 13019);
http.createServer((request, response) => {
  const valid = request.headers.cookie?.includes('sessionid=valid');
  response.writeHead(200, {
    'content-type': 'application/json', 'cache-control': 'private, no-store',
    'set-cookie': 'csrftoken=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; Path=/; SameSite=Lax',
  });
  if (request.url === '/api/v1/auth/oauth/apps') {
    response.end(JSON.stringify({ items: valid ? [{
      client_id: 'pilot-client', name: 'Пилотное приложение', scopes: ['openid', 'email'],
      last_used_at: null,
    }] : [] }));
  } else {
    response.end(JSON.stringify({ user: valid ? {
      username: 'pilot-user', email: 'pilot@example.invalid', first_name: '', last_name: '',
      email_verified: true, has_2fa: false,
    } : null }));
  }
}).listen(port, '127.0.0.1');
EOF

ID_PILOT_MOCK_API_PORT="${api_port}" node "${scratch_dir}/mock-api.cjs" >"${scratch_dir}/api.log" 2>&1 &
api_pid=$!
ID_WEB_ACCOUNT_PILOT_ENABLED=true ID_WEB_APPS_PILOT_ENABLED=true \
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
    "http://127.0.0.1:${web_port}/account?section=apps" >"${scratch_dir}/apps.html"; then
    ready=true
    break
  fi
  sleep 1
done
[[ "${ready}" == true ]]

html="$(<"${scratch_dir}/apps.html")"
[[ "${html}" == *'Подключённые приложения'* ]]
[[ "${html}" == *'Пилотное приложение'* ]]
[[ "${html}" == *'data-revoke-app="pilot-client"'* ]]
[[ "${html}" == *'src="/_id/apps.js?'* ]]
curl --silent --show-error --fail --max-time 5 \
  "http://127.0.0.1:${web_port}/_id/apps.js" >"${scratch_dir}/apps.js"
[[ "$(<"${scratch_dir}/apps.js")" == *'/api/v1/auth/oauth/apps/revoke'* ]]
guest_status="$(curl --silent --show-error --max-time 5 -o /dev/null -w '%{http_code}' \
  "http://127.0.0.1:${web_port}/account?section=apps")"
[[ "${guest_status}" == 303 ]]
echo "Topcoat OAuth apps pilot smoke: authenticated SSR list, asset and guest redirect"
