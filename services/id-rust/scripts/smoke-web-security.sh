#!/usr/bin/env bash
set -euo pipefail

workspace_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin_dir="${ID_RUST_BIN_DIR:-${workspace_dir}/target/debug}"
web_port="${ID_PILOT_WEB_PORT:-13048}"
api_port="${ID_PILOT_MOCK_API_PORT:-13049}"
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
  const noTotp = request.headers.cookie?.includes('sessionid=valid-no-totp');
  response.setHeader('content-type', 'application/json');
  response.setHeader('cache-control', 'private, no-store');
  if (request.url === '/api/v1/auth/me') {
    response.setHeader('set-cookie', 'csrftoken=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; Path=/; SameSite=Lax');
    response.end(JSON.stringify({ user: valid ? {
      username: 'pilot-user', email: 'pilot@example.invalid', first_name: '', last_name: '',
      email_verified: true, has_2fa: true,
    } : null }));
    return;
  }
  if (request.url === '/api/v1/auth/security' && valid) {
    response.end(JSON.stringify({
      mfa: { has_totp: !noTotp, has_webauthn: !noTotp, has_recovery_codes: !noTotp, recovery_codes_left: noTotp ? 0 : 8 },
      authenticators: noTotp ? [] : [{ id: '42', name: '<script>key</script>', type: 'webauthn',
        created_at: 1, last_used_at: null, is_passwordless: true }],
    }));
    return;
  }
  response.writeHead(401); response.end(JSON.stringify({ code: 'UNAUTHORIZED' }));
}).listen(port, '127.0.0.1');
EOF

ID_PILOT_MOCK_API_PORT="${api_port}" node "${scratch_dir}/mock-api.cjs" >"${scratch_dir}/api.log" 2>&1 &
api_pid=$!
ID_WEB_ACCOUNT_PILOT_ENABLED=true ID_WEB_SECURITY_PILOT_ENABLED=true ID_WEB_TOTP_PILOT_ENABLED=true ID_WEB_PASSWORD_CHANGE_PILOT_ENABLED=true ID_WEB_PASSKEY_REGISTRATION_ENABLED=true \
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
    -D "${scratch_dir}/security.headers" \
    "http://127.0.0.1:${web_port}/account?section=security" >"${scratch_dir}/security.html"; then
    ready=true; break
  fi
  sleep 1
done
[[ "${ready}" == true ]]

html="$(<"${scratch_dir}/security.html")"
[[ "${html}" == *'Безопасность'* ]]
[[ "${html}" == *'Осталось резервных кодов'* ]]
[[ "${html}" == *'Подходит для входа без пароля'* ]]
[[ "${html}" == *'id="totp-disable"'* ]]
[[ "${html}" == *'/_id/totp-disable.js'* ]]
[[ "${html}" == *'id="recovery-rotate"'* ]]
[[ "${html}" == *'/_id/recovery-rotate.js'* ]]
[[ "${html}" == *'/_id/passkeys.js'* ]]
[[ "${html}" == *'id="passkey-register"'* ]]
[[ "${html}" == *'id="password-change-form"'* ]]
[[ "${html}" == *'/_id/password-change.js'* ]]
[[ "${html}" == *'data-passkey-rename="42"'* ]]
[[ "${html}" == *'data-passkey-delete="42"'* ]]
[[ "${html}" == *'&#60;script&#62;key&#60;/script&#62;'* ]]
[[ "${html}" != *'<script>key</script>'* ]]
rg -qi '^cache-control: no-store' "${scratch_dir}/security.headers"
rg -qi "frame-ancestors 'none'" "${scratch_dir}/security.headers"
curl --silent --fail --max-time 5 -H 'Cookie: sessionid=valid-no-totp' \
  -D "${scratch_dir}/totp.headers" \
  "http://127.0.0.1:${web_port}/account?section=security" >"${scratch_dir}/totp.html"
rg -q 'id="totp-begin"' "${scratch_dir}/totp.html"
rg -q 'Ключей доступа нет' "${scratch_dir}/totp.html"
rg -q 'id="passkey-register"' "${scratch_dir}/totp.html"
rg -q '/_id/passkeys.js' "${scratch_dir}/totp.html"
rg -q 'id="totp-confirm-form"' "${scratch_dir}/totp.html"
rg -q '/_id/totp.js' "${scratch_dir}/totp.html"
rg -qi "img-src 'self' data:" "${scratch_dir}/totp.headers"
curl --silent --fail --max-time 5 "http://127.0.0.1:${web_port}/_id/totp.js" | rg -q '/api/v1/auth/mfa/totp/confirm'
curl --silent --fail --max-time 5 "http://127.0.0.1:${web_port}/_id/totp-disable.js" | rg -q '/api/v1/auth/mfa/totp/disable'
curl --silent --fail --max-time 5 "http://127.0.0.1:${web_port}/_id/recovery-rotate.js" | rg -q '/api/v1/auth/mfa/recovery/regenerate'
curl --silent --fail --max-time 5 "http://127.0.0.1:${web_port}/_id/passkeys.js" | rg -q '/api/v1/auth/passkeys/delete'
curl --silent --fail --max-time 5 "http://127.0.0.1:${web_port}/_id/passkeys.js" | rg -q '/api/v1/auth/passkeys/complete'
curl --silent --fail --max-time 5 "http://127.0.0.1:${web_port}/_id/password-change.js" | rg -q '/api/v1/auth/change_password'
guest_status="$(curl --silent --show-error --max-time 5 -o /dev/null -w '%{http_code}' \
  "http://127.0.0.1:${web_port}/account?section=security")"
[[ "${guest_status}" == 303 ]]
echo "Topcoat security pilot smoke: authenticated SSR, escaped key name and guest redirect"
