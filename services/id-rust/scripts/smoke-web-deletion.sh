#!/usr/bin/env bash
set -euo pipefail

workspace_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin_dir="${ID_RUST_BIN_DIR:-${workspace_dir}/target/debug}"
web_port="${ID_PILOT_WEB_PORT:-13072}"
api_port="${ID_PILOT_MOCK_API_PORT:-13073}"
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
  response.setHeader('content-type', 'application/json');
  if (request.url === '/api/v1/auth/me') {
    response.setHeader('set-cookie', 'csrftoken=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; Path=/; SameSite=Lax');
    const valid = request.headers.cookie?.includes('sessionid=valid');
    response.end(JSON.stringify({user: valid ? {
      username: 'owner', email: 'owner@example.invalid', email_verified: true, has_2fa: true,
    } : null}));
    return;
  }
  response.writeHead(404); response.end(JSON.stringify({code: 'NOT_FOUND'}));
}).listen(port, '127.0.0.1');
EOF

ID_PILOT_MOCK_API_PORT="${api_port}" node "${scratch_dir}/mock-api.cjs" >"${scratch_dir}/api.log" 2>&1 &
api_pid=$!
ID_WEB_ACCOUNT_PILOT_ENABLED=true ID_WEB_EXPORTS_ENABLED=true ID_WEB_EXPORT_REDEEM_ENABLED=true ID_WEB_DELETION_ENABLED=true \
  ID_WEB_PROFILE_PILOT_ENABLED=true ID_WEB_SESSIONS_PILOT_ENABLED=true ID_WEB_APPS_PILOT_ENABLED=true \
  ID_WEB_PREFERENCES_PILOT_ENABLED=true ID_WEB_SECURITY_PILOT_ENABLED=true ID_WEB_LOGIN_HISTORY_PILOT_ENABLED=true \
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
    "http://127.0.0.1:${web_port}/account?section=delete" >"${scratch_dir}/delete.html"; then
    ready=true; break
  fi
  sleep 1
done
[[ "${ready}" == true ]]
rg -q 'id="delete-account-form"' "${scratch_dir}/delete.html"
rg -q 'id="delete-understood"' "${scratch_dir}/delete.html"
rg -q 'id="delete-mfa"' "${scratch_dir}/delete.html"

ID_PILOT_WEB_PORT="${web_port}" ID_BROWSER_TEST_ROOT="${workspace_dir}/browser-tests" \
  node "${workspace_dir}/scripts/smoke-web-deletion-browser.cjs"
kill "${web_pid}"
wait "${web_pid}" 2>/dev/null || true
web_pid=""
ID_WEB_ACCOUNT_PILOT_ENABLED=true ID_WEB_EXPORTS_ENABLED=true \
  ID_WEB_API_ORIGIN="http://127.0.0.1:${api_port}" \
  HOST=127.0.0.1 PORT="${web_port}" "${bin_dir}/id-web" >"${scratch_dir}/web-disabled.log" 2>&1 &
web_pid=$!
for ((attempt=0; attempt<30; attempt++)); do
  if curl --silent --fail --max-time 2 -H 'Cookie: sessionid=valid' \
    "http://127.0.0.1:${web_port}/account" >"${scratch_dir}/overview.html"; then
    break
  fi
  sleep 1
done
if rg -q 'section=delete' "${scratch_dir}/overview.html"; then
  echo 'deletion link visible while disabled' >&2
  exit 1
fi
disabled_status="$(curl --silent --max-time 2 -o /dev/null -w '%{http_code}' \
  -H 'Cookie: sessionid=valid' "http://127.0.0.1:${web_port}/account?section=delete")"
[[ "${disabled_status}" == 404 ]]
echo "Topcoat deletion smoke: review, confirmation, API payload, accepted and uncertain states"
