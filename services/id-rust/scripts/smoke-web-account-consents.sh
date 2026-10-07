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
  const path = new URL(request.url, 'http://localhost').pathname;
  let body;
  if (path === '/api/v1/auth/timezones') body = { timezones: [] };
  else if (!valid) body = { user: null };
  else if (path === '/api/v1/auth/me') body = { user: {
    username: 'pilot-user', email: 'pilot@example.invalid', first_name: 'Ada', last_name: 'Lovelace',
    phone_number: null, birth_date: null, email_verified: true, has_2fa: false,
  } };
  else if (path === '/api/v1/auth/preferences') body = {
    language: 'ru', timezone: '', marketing_opt_in: true, privacy_scope_defaults: {},
  };
  else if (path === '/api/v1/auth/consents') body = { consents: [
    { kind: 'marketing', version: 'v1', granted_at: '2026-10-05T00:00:00Z', revoked_at: null },
    { kind: 'data_processing', version: 'v1', granted_at: '2026-10-05T00:00:00Z', revoked_at: null },
  ] };
  else { response.writeHead(404); response.end(); return; }
  response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'private, no-store',
    'set-cookie': 'csrftoken=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; Path=/; SameSite=Lax' });
  response.end(JSON.stringify(body));
}).listen(port, '127.0.0.1');
EOF

ID_PILOT_MOCK_API_PORT="${api_port}" node "${scratch_dir}/mock-api.cjs" >"${scratch_dir}/api.log" 2>&1 &
api_pid=$!
ID_WEB_ACCOUNT_PILOT_ENABLED=true ID_WEB_PREFERENCES_PILOT_ENABLED=true ID_WEB_CONSENTS_PILOT_ENABLED=true \
  ID_WEB_API_ORIGIN="http://127.0.0.1:${api_port}" HOST=127.0.0.1 PORT="${web_port}" \
  "${bin_dir}/id-web" >"${scratch_dir}/web.log" 2>&1 &
web_pid=$!

ready=false
for ((attempt=0; attempt<30; attempt++)); do
  if ! kill -0 "${web_pid}" 2>/dev/null || ! kill -0 "${api_pid}" 2>/dev/null; then
    cat "${scratch_dir}/web.log" "${scratch_dir}/api.log" >&2
    exit 1
  fi
  if curl --silent --fail --max-time 2 -H 'Cookie: sessionid=valid' \
    "http://127.0.0.1:${web_port}/account?section=privacy" >"${scratch_dir}/privacy.html"; then
    ready=true
    break
  fi
  sleep 1
done
if [[ "${ready}" != true ]]; then
  cat "${scratch_dir}/web.log" "${scratch_dir}/api.log" >&2
  curl --silent --show-error --max-time 2 -i -H 'Cookie: sessionid=valid' \
    "http://127.0.0.1:${web_port}/account?section=privacy" >&2 || true
  exit 1
fi
html="$(<"${scratch_dir}/privacy.html")"
[[ "${html}" == *'id="consents-title"'* ]]
[[ "${html}" == *'data-kind="marketing"'* ]]
[[ "${html}" == *'Обработка персональных данных'* ]]
[[ "${html}" == *'id="consents-error"'* ]]
curl --silent --show-error --fail --max-time 5 \
  "http://127.0.0.1:${web_port}/_id/preferences.js" >"${scratch_dir}/preferences.js"
[[ "$(<"${scratch_dir}/preferences.js")" == *'/api/v1/auth/consents/revoke?kind='* ]]
echo "Topcoat account consents smoke: SSR list, marketing action and local script"
