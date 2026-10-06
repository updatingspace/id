#!/usr/bin/env bash
set -euo pipefail

: "${SMOKE_BASE_URL:?SMOKE_BASE_URL is required}"
base_url="${SMOKE_BASE_URL%/}"
curl_args=(-fsS --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 30)
if [[ -n "${SMOKE_HOST_HEADER:-}" ]]; then
  curl_args+=(-H "Host: ${SMOKE_HOST_HEADER}")
fi

curl "${curl_args[@]}" "${base_url}/healthz" | jq -e '.status == "ok" or .status == "alive"' >/dev/null
curl "${curl_args[@]}" "${base_url}/readyz" | jq -e '.ready == true or .status == "ready"' >/dev/null

home="$(curl "${curl_args[@]}" "${base_url}/")"
login="$(curl "${curl_args[@]}" "${base_url}/login")"
[[ "$home" == *"UpdSpace ID"* ]] || { echo 'Topcoat home unavailable' >&2; exit 1; }
[[ "$login" == *'id="login-form"'* ]] || { echo 'Topcoat login unavailable' >&2; exit 1; }
[[ "$login" == *'id="passkey-login"'* ]] || { echo 'Topcoat passkey control unavailable' >&2; exit 1; }
login_js="$(curl "${curl_args[@]}" "${base_url}/_id/login.js")"
[[ "$login_js" == *'credentials.get'* ]] || { echo 'Topcoat passkey script unavailable' >&2; exit 1; }
curl "${curl_args[@]}" "${base_url}/_id/login.css" >/dev/null

me_headers="$(curl "${curl_args[@]}" -D - -o /dev/null "${base_url}/api/v1/auth/me")"
grep -qi '^cache-control:.*no-store' <<< "$me_headers" || {
  echo 'Rust session response lacks Cache-Control: no-store' >&2
  exit 1
}
curl "${curl_args[@]}" "${base_url}/api/v1/auth/form_token?purpose=login" |
  jq -e '.form_token | type == "string" and length > 20' >/dev/null

echo "Rust API and Topcoat Gateway smoke passed for ${base_url}"
