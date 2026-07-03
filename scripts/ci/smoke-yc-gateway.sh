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

html="$(curl "${curl_args[@]}" "${base_url}/")"
js_path="$(printf '%s' "${html}" | sed -n 's/.*src="\([^"]*\/assets\/[^"]*\.js\)".*/\1/p' | head -n 1)"
css_path="$(printf '%s' "${html}" | sed -n 's/.*href="\([^"]*\/assets\/[^"]*\.css\)".*/\1/p' | head -n 1)"

if [[ -z "${js_path}" || -z "${css_path}" ]]; then
  echo "Could not find Vite JS/CSS assets in ${base_url}/" >&2
  exit 1
fi

js_type="$(curl "${curl_args[@]}" -o /dev/null -D - "${base_url}${js_path}" | awk 'tolower($1)=="content-type:" {print tolower($2); exit}')"
css_type="$(curl "${curl_args[@]}" -o /dev/null -D - "${base_url}${css_path}" | awk 'tolower($1)=="content-type:" {print tolower($2); exit}')"

case "${js_type}" in
  application/javascript*|text/javascript*) ;;
  *)
    echo "Unexpected JS content-type for ${js_path}: ${js_type}" >&2
    exit 1
    ;;
esac

case "${css_type}" in
  text/css*) ;;
  *)
    echo "Unexpected CSS content-type for ${css_path}: ${css_type}" >&2
    exit 1
    ;;
esac

echo "YC gateway smoke checks passed for ${base_url}"
