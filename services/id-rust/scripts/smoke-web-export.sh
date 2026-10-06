#!/usr/bin/env bash
set -euo pipefail

workspace_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin_dir="${ID_RUST_BIN_DIR:-${workspace_dir}/target/debug}"
web_port="${ID_PILOT_WEB_PORT:-13068}"
api_port="${ID_PILOT_MOCK_API_PORT:-13069}"
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
const operation = '0123456789abcdef0123456789abcdef';
http.createServer((request, response) => {
  const valid = request.headers.cookie?.includes('sessionid=valid');
  response.setHeader('content-type', 'application/json');
  if (request.url === '/api/v1/auth/me') {
    response.setHeader('set-cookie', 'csrftoken=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; Path=/; SameSite=Lax');
    response.end(JSON.stringify({ user: valid ? {
      username: 'pilot-user', email: 'pilot@example.invalid', email_verified: true, has_2fa: false,
    } : null }));
    return;
  }
  if (request.url === `/api/v1/auth/data/exports/${operation}` && valid) {
    response.end(JSON.stringify({
      id: operation, status: 'succeeded', expires_at: '2026-10-07T12:00:00Z',
      manifest: { format: 'updspace-id-ndjson-v1', consistency: 'paged-live-read',
        categories: [{ category: '<script>bad</script>', records: 205 }],
        excluded: ['password hashes and salts'] },
    }));
    return;
  }
  if (request.url === '/api/v1/auth/data/exports/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' && valid) {
    response.end(JSON.stringify({ id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', status: 'pending', manifest: null, expires_at: null }));
    return;
  }
  response.writeHead(404); response.end(JSON.stringify({ error: 'NOT_FOUND' }));
}).listen(port, '127.0.0.1');
EOF

ID_PILOT_MOCK_API_PORT="${api_port}" node "${scratch_dir}/mock-api.cjs" >"${scratch_dir}/api.log" 2>&1 &
api_pid=$!
ID_WEB_ACCOUNT_PILOT_ENABLED=true ID_WEB_EXPORTS_ENABLED=true \
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
    -D "${scratch_dir}/export.headers" \
    "http://127.0.0.1:${web_port}/account?section=data&export=0123456789abcdef0123456789abcdef" >"${scratch_dir}/export.html"; then
    ready=true; break
  fi
  sleep 1
done
[[ "${ready}" == true ]]

html="$(<"${scratch_dir}/export.html")"
[[ "${html}" == *'Экспорт данных'* ]]
[[ "${html}" == *'Скачать'* ]]
[[ "${html}" == *'205'* ]]
[[ "${html}" == *'&#60;script&#62;bad&#60;/script&#62;'* ]]
[[ "${html}" != *'<script>bad</script>'* ]]
rg -qi '^cache-control: no-store' "${scratch_dir}/export.headers"
curl --silent --fail --max-time 5 -H 'Cookie: sessionid=valid' \
  "http://127.0.0.1:${web_port}/account?section=data&export=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" >"${scratch_dir}/pending.html"
rg -q 'http-equiv="refresh"' "${scratch_dir}/pending.html"
curl --silent --fail --max-time 5 -H 'Cookie: sessionid=valid' \
  "http://127.0.0.1:${web_port}/account?section=data&export=bad" >"${scratch_dir}/missing.html"
rg -q 'Экспорт не найден' "${scratch_dir}/missing.html"
curl --silent --fail --max-time 5 "http://127.0.0.1:${web_port}/_id/export.js" | rg -q 'Idempotency-Key'
guest_status="$(curl --silent --show-error --max-time 5 -o /dev/null -w '%{http_code}' \
  "http://127.0.0.1:${web_port}/account?section=data")"
[[ "${guest_status}" == 303 ]]
echo "Topcoat export smoke: owner-scoped SSR status, escaping, pending refresh and guest redirect"
