#!/usr/bin/env bash
set -euo pipefail

workspace_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin_dir="${ID_RUST_BIN_DIR:-${workspace_dir}/target/debug}"
web_port="${ID_PILOT_WEB_PORT:-13008}"
api_port="${ID_PILOT_MOCK_API_PORT:-13009}"
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
const port = Number(process.env.ID_PILOT_MOCK_API_PORT || 13009);
http.createServer((request, response) => {
  const valid = request.headers.cookie?.includes('sessionid=valid');
  response.writeHead(200, {
    'content-type': 'application/json',
    'cache-control': 'private, no-store',
    'set-cookie': 'csrftoken=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; Path=/; SameSite=Lax',
  });
  response.end(JSON.stringify({ user: valid ? {
    username: 'pilot-user', email: 'pilot@example.invalid', first_name: 'Ada',
    last_name: 'Lovelace', phone_number: '+1 555', birth_date: '1990-01-02',
    email_verified: true, has_2fa: false,
  } : null }));
}).listen(port, '127.0.0.1');
EOF

ID_PILOT_MOCK_API_PORT="${api_port}" node "${scratch_dir}/mock-api.cjs" >"${scratch_dir}/api.log" 2>&1 &
api_pid=$!
ID_WEB_ACCOUNT_PILOT_ENABLED=true ID_WEB_PROFILE_PILOT_ENABLED=true \
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
    "http://127.0.0.1:${web_port}/account?section=profile" >"${scratch_dir}/account.html"; then
    ready=true
    break
  fi
  sleep 1
done
[[ "${ready}" == true ]]

html="$(<"${scratch_dir}/account.html")"
[[ "${html}" == *'id="profile-form"'* ]]
[[ "${html}" == *'value="Ada"'* ]]
[[ "${html}" == *'value="+1 555"'* ]]
[[ "${html}" == *'value="1990-01-02"'* ]]
[[ "${html}" == *'src="/_id/profile.js"'* ]]
curl --silent --show-error --fail --max-time 5 -D "${scratch_dir}/headers" \
  -H 'Cookie: sessionid=valid' "http://127.0.0.1:${web_port}/account?section=profile" > /dev/null
headers="$(<"${scratch_dir}/headers")"
[[ "${headers,,}" == *"content-security-policy: default-src 'none'; script-src 'self'"* ]]
[[ "${headers,,}" == *'cache-control: no-store'* ]]
[[ "${headers,,}" == *'set-cookie: csrftoken='* ]]

curl --silent --show-error --fail --max-time 5 \
  "http://127.0.0.1:${web_port}/_id/profile.js" >"${scratch_dir}/profile.js"
[[ "$(<"${scratch_dir}/profile.js")" == *'"/api/v1/auth/profile"'* ]]

guest_status="$(curl --silent --show-error --max-time 5 -o /dev/null -w '%{http_code}' \
  "http://127.0.0.1:${web_port}/account")"
[[ "${guest_status}" == 303 ]]
echo "Topcoat profile pilot smoke: authenticated SSR form, CSP, asset and guest redirect"
