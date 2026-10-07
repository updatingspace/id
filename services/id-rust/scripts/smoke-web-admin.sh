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
const port = Number(process.env.ID_PILOT_MOCK_API_PORT || 13069);
http.createServer(async (request, response) => {
  const cookie = request.headers.cookie || '';
  if (!cookie.includes('sessionid=valid')) {
    response.writeHead(cookie.includes('sessionid=notstaff') ? 403 : 401,
      {'content-type':'application/json'});
    response.end('{}');
    return;
  }
  const url = new URL(request.url, `http://127.0.0.1:${port}`);
  if (url.pathname === '/api/v1/auth/admin/me') {
    response.writeHead(200, {'content-type':'application/json'});
    response.end('{"operator":true}');
  } else if (url.pathname === '/api/v1/auth/admin/exports/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') {
    response.writeHead(200, {'content-type':'application/json'});
    response.end(JSON.stringify({operation:{id:'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      status:'cooldown',escrow_state:'sealed',archive_sealed:true,
      release_at:1791400000,expires_at:1791486400}}));
  } else if (url.pathname === '/api/v1/auth/admin/accounts/42') {
    response.writeHead(200, {'content-type':'application/json'});
    response.end(JSON.stringify({account:{id:42,email:'<script>bad()</script>@example.invalid',
      is_active:false,is_staff:false,is_superuser:false,has_mfa:true,
      identity_id:null,public_subject:'subject-42',access_state:'account_disabled'}}));
  } else if (url.pathname === '/api/v1/auth/admin/accounts/43') {
    response.writeHead(200, {'content-type':'application/json'});
    response.end(JSON.stringify({account:{id:43,email:'active@example.invalid',
      is_active:true,is_staff:false,is_superuser:false,has_mfa:false,
      identity_id:'00000000-0000-0000-0000-000000000043',public_subject:'subject-43',access_state:'active'}}));
  } else if (url.pathname === '/api/v1/auth/admin/accounts/search'
    && request.method === 'POST' && !url.search) {
    let raw = '';
    for await (const chunk of request) raw += chunk;
    const email = JSON.parse(raw).email;
    if (email === 'pilot@example.invalid') {
    response.writeHead(200, {'content-type':'application/json'});
    response.end(JSON.stringify({account:{id:42,email:'pilot@example.invalid',
      is_active:false,is_staff:false,is_superuser:false,has_mfa:true,
      identity_id:null,public_subject:'subject-42',access_state:'account_disabled'}}));
    } else if (email === 'ambiguous@example.invalid') {
      response.writeHead(409, {'content-type':'application/json'});
      response.end('{"code":"ACCOUNT_EMAIL_AMBIGUOUS"}');
    } else {
      response.writeHead(404, {'content-type':'application/json'});
      response.end('{"code":"ACCOUNT_NOT_FOUND"}');
    }
  } else {
    response.writeHead(404, {'content-type':'application/json'});
    response.end('{"code":"ACCOUNT_NOT_FOUND"}');
  }
}).listen(port, '127.0.0.1');
EOF

ID_PILOT_MOCK_API_PORT="${api_port}" node "${scratch_dir}/mock-api.cjs" >"${scratch_dir}/api.log" 2>&1 &
api_pid=$!
ID_WEB_ADMIN_ENABLED=true ID_WEB_ADMIN_SUSPEND_ENABLED=true ID_WEB_API_ORIGIN="http://127.0.0.1:${api_port}" \
  HOST=127.0.0.1 PORT="${web_port}" "${bin_dir}/id-web" >"${scratch_dir}/web.log" 2>&1 &
web_pid=$!

ready=false
for ((attempt=0; attempt<30; attempt++)); do
  if ! kill -0 "${web_pid}" 2>/dev/null || ! kill -0 "${api_pid}" 2>/dev/null; then
    cat "${scratch_dir}/web.log" "${scratch_dir}/api.log" >&2
    exit 1
  fi
  if curl --silent --fail --max-time 2 -H 'Cookie: sessionid=valid' \
    "http://127.0.0.1:${web_port}/admin/accounts/?id=42" >"${scratch_dir}/account.html"; then
    ready=true
    break
  fi
  sleep 1
done
[[ "${ready}" == true ]]

html="$(<"${scratch_dir}/account.html")"
[[ "${html}" == *'Аккаунт № 42'* ]]
[[ "${html}" == *'Закрыт: аккаунт отключён'* ]]
[[ "${html}" == *'Связь не найдена'* ]]
[[ "${html}" != *'<script>bad()'* ]]
[[ "${html}" == *'&#60;script&#62;bad()&#60;/script&#62;'* ]]
export_html="$(curl --silent --show-error --fail --max-time 5 -H 'Cookie: sessionid=valid' \
  "http://127.0.0.1:${web_port}/admin/exports/?id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")"
[[ "${export_html}" == *'Ожидание выдачи'* && "${export_html}" == *'24-часовое ожидание'* ]]
[[ "${export_html}" != *'private-recipient-envelope'* && "${export_html}" != *'private-archive'* ]]
export_guest="$(curl --silent --show-error --max-time 5 -o /dev/null -w '%{http_code}' \
  "http://127.0.0.1:${web_port}/admin/exports/")"
export_invalid="$(curl --silent --show-error --max-time 5 -o /dev/null -w '%{http_code}' \
  -H 'Cookie: sessionid=valid' "http://127.0.0.1:${web_port}/admin/exports/?id=bad")"
[[ "${export_guest}" == 303 && "${export_invalid}" == 400 ]]
active_html="$(curl --silent --show-error --fail --max-time 5 -H 'Cookie: sessionid=valid' \
  "http://127.0.0.1:${web_port}/admin/accounts/?id=43")"
[[ "${active_html}" == *'/admin/accounts/suspend?id=43'* ]]
review_html="$(curl --silent --show-error --fail --max-time 5 -H 'Cookie: sessionid=valid' \
  "http://127.0.0.1:${web_port}/admin/accounts/suspend?id=43")"
[[ "${review_html}" == *'Заблокировать вход для аккаунта № 43'* ]]
[[ "${review_html}" == *'data-subject="subject-43"'* ]]
review_guest="$(curl --silent --show-error --max-time 5 -o /dev/null -w '%{http_code}' \
  "http://127.0.0.1:${web_port}/admin/accounts/suspend?id=43")"
[[ "${review_guest}" == 303 ]]

headers="$(curl --silent --show-error --fail --max-time 5 -D - -o /dev/null \
  -H 'Cookie: sessionid=valid' "http://127.0.0.1:${web_port}/admin/accounts/?id=42")"
[[ "${headers,,}" == *'cache-control: no-store'* ]]
[[ "${headers,,}" == *"content-security-policy: default-src 'none'; style-src 'self'"* ]]

email_html="$(curl --silent --show-error --fail --max-time 5 \
  -H 'Cookie: sessionid=valid' -d 'email=pilot%40example.invalid' \
  "http://127.0.0.1:${web_port}/admin/accounts/")"
[[ "${email_html}" == *'Аккаунт № 42'* && "${email_html}" == *'value="pilot@example.invalid"'* ]]
ambiguous_html="$(curl --silent --show-error --fail --max-time 5 \
  -H 'Cookie: sessionid=valid' -d 'email=ambiguous%40example.invalid' \
  "http://127.0.0.1:${web_port}/admin/accounts/")"
[[ "${ambiguous_html}" == *'Поиск требует проверки'* ]]
email_get="$(curl --silent --show-error --max-time 5 -o /dev/null -w '%{http_code}' \
  -H 'Cookie: sessionid=valid' "http://127.0.0.1:${web_port}/admin/accounts/?email=pilot%40example.invalid")"
[[ "${email_get}" == '400' ]]

guest="$(curl --silent --show-error --max-time 5 -o /dev/null -w '%{http_code}' \
  "http://127.0.0.1:${web_port}/admin/accounts/")"
guest_headers="$(curl --silent --show-error --max-time 5 -D - -o /dev/null \
  "http://127.0.0.1:${web_port}/admin/accounts/")"
forbidden="$(curl --silent --show-error --max-time 5 -o /dev/null -w '%{http_code}' \
  -H 'Cookie: sessionid=notstaff' "http://127.0.0.1:${web_port}/admin/accounts/")"
missing="$(curl --silent --show-error --max-time 5 -o /dev/null -w '%{http_code}' \
  -H 'Cookie: sessionid=valid' "http://127.0.0.1:${web_port}/admin/accounts/?id=44")"
invalid="$(curl --silent --show-error --max-time 5 -o /dev/null -w '%{http_code}' \
  -H 'Cookie: sessionid=valid' "http://127.0.0.1:${web_port}/admin/accounts/?id=0")"
[[ "${guest}" == 303 && "${forbidden}" == 403 && "${missing}" == 200 && "${invalid}" == 400 ]]
[[ "${guest_headers,,}" == *'location: /login?next=%2fadmin%2faccounts%2f'* ]]
echo 'Topcoat operator account smoke: SSR, escaping, authorization and lookup outcomes passed'
