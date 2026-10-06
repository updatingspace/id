#!/usr/bin/env bash
set -euo pipefail

workspace_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin_dir="${ID_RUST_BIN_DIR:-${workspace_dir}/target/debug}"
web_port="${ID_PILOT_WEB_PORT:-13028}"
api_port="${ID_PILOT_MOCK_API_PORT:-13029}"
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
const port = Number(process.env.ID_PILOT_MOCK_API_PORT || 13029);
http.createServer((request, response) => {
  if (!request.url.startsWith('/oauth/authorize/prepare?')) {
    response.writeHead(404); response.end(); return;
  }
  response.writeHead(200, {
    'content-type': 'application/json', 'cache-control': 'no-store',
    'set-cookie': 'csrftoken=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; Path=/; SameSite=Lax',
  });
  if (!request.headers.cookie?.includes('sessionid=valid')) {
    response.end(JSON.stringify({action:'login'})); return;
  }
  response.end(JSON.stringify({action:'consent',request_id:'pilot-request',
    client:{client_id:'pilot-client',name:'Пилотное <script>приложение</script>',logo_url:''},
    scopes:[{name:'openid',description:'Идентификатор пользователя',required:true,granted:true},
      {name:'email',description:'Адрес электронной почты',required:false,granted:true}],
    consent_required:true,state:'pilot-state',redirect_uri:'https://rp.example.invalid/callback'}));
}).listen(port, '127.0.0.1');
EOF

ID_PILOT_MOCK_API_PORT="${api_port}" node "${scratch_dir}/mock-api.cjs" >"${scratch_dir}/api.log" 2>&1 &
api_pid=$!
ID_WEB_CONSENT_PILOT_ENABLED=true ID_WEB_API_ORIGIN="http://127.0.0.1:${api_port}" \
  HOST=127.0.0.1 PORT="${web_port}" "${bin_dir}/id-web" >"${scratch_dir}/web.log" 2>&1 &
web_pid=$!

ready=false
for ((attempt=0; attempt<30; attempt++)); do
  if ! kill -0 "${web_pid}" 2>/dev/null || ! kill -0 "${api_pid}" 2>/dev/null; then
    cat "${scratch_dir}/web.log" "${scratch_dir}/api.log" >&2
    exit 1
  fi
  if curl --silent --fail --max-time 2 -H 'Cookie: sessionid=valid' \
    -D "${scratch_dir}/consent.headers" \
    "http://127.0.0.1:${web_port}/oauth/consent?client_id=pilot-client" >"${scratch_dir}/consent.html"; then
    ready=true
    break
  fi
  sleep 1
done
[[ "${ready}" == true ]]

html="$(<"${scratch_dir}/consent.html")"
[[ "${html}" == *'Разрешить доступ приложению?'* ]]
[[ "${html}" == *'data-request-id="pilot-request"'* ]]
[[ "${html}" == *'/_id/consent.js'* ]]
[[ "${html}" != *'<script>приложение</script>'* ]]
[[ "${html}" == *'&#60;script&#62;'* || "${html}" == *'&lt;script&gt;'* ]]
rg -qi 'set-cookie: csrftoken=' "${scratch_dir}/consent.headers"
rg -q "frame-ancestors 'none'" "${scratch_dir}/consent.headers"
curl --silent --show-error --fail --max-time 5 \
  "http://127.0.0.1:${web_port}/_id/consent.js" >"${scratch_dir}/consent.js"
[[ "$(<"${scratch_dir}/consent.js")" == *'/oauth/authorize/approve'* ]]
guest_location="$(curl --silent --show-error --max-time 5 -D - -o /dev/null \
  "http://127.0.0.1:${web_port}/oauth/consent?client_id=pilot-client" | tr -d '\r' | rg -i '^location:' | head -1)"
[[ "${guest_location}" == *'/login?next='* ]]
echo "Topcoat OIDC consent smoke: escaped SSR, CSRF forwarding, asset and guest redirect"
