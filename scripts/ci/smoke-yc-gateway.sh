#!/usr/bin/env bash
set -euo pipefail

: "${SMOKE_BASE_URL:?SMOKE_BASE_URL is required}"

base_url="${SMOKE_BASE_URL%/}"
host_header="${SMOKE_HOST_HEADER:-}"

curl_args=(-fsS --retry 3 --retry-delay 2)
if [[ -n "${host_header}" ]]; then
  curl_args+=(-H "Host: ${host_header}")
fi

curl "${curl_args[@]}" "${base_url}/" >/dev/null
curl "${curl_args[@]}" "${base_url}/health" >/dev/null
curl "${curl_args[@]}" "${base_url}/.well-known/openid-configuration" >/dev/null
curl "${curl_args[@]}" "${base_url}/.well-known/jwks.json" >/dev/null
curl "${curl_args[@]}" "${base_url}/login" >/dev/null

echo "YC gateway smoke checks passed for ${base_url}"
