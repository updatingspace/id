#!/usr/bin/env bash
set -euo pipefail

: "${SMOKE_BASE_URL:?SMOKE_BASE_URL is required}"
base_url="${SMOKE_BASE_URL%/}"
curl_args=(-fsS --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 30)
if [[ -n "${SMOKE_HOST_HEADER:-}" ]]; then
  curl_args+=(-H "Host: ${SMOKE_HOST_HEADER}")
fi

js_path=''
css_path=''
theme_path=''
for page in / /legacy/account; do
  html="$(curl "${curl_args[@]}" "${base_url}${page}" 2>/dev/null || true)"
  js_path="$(printf '%s' "${html}" | sed -n 's/.*src="\([^"]*\/assets\/[^\"]*\.js\)".*/\1/p' | head -n 1)"
  css_path="$(printf '%s' "${html}" | sed -n 's/.*href="\([^"]*\/assets\/[^\"]*\.css\)".*/\1/p' | head -n 1)"
  theme_path="$(printf '%s' "${html}" | sed -n 's/.*src="\([^"]*theme-init\.js[^\"]*\)".*/\1/p' | head -n 1)"
  if [[ -n "${js_path}" && -n "${css_path}" ]]; then
    break
  fi
done
if [[ -z "${js_path}" || -z "${css_path}" ]]; then
  echo "No deployed frontend JS/CSS references found at ${base_url}" >&2
  exit 1
fi

check_type() {
  local path="$1" kind="$2" actual
  actual="$(curl "${curl_args[@]}" -o /dev/null -D - "${base_url}${path}" |
    awk 'tolower($1)=="content-type:" && !found {found=tolower($2)} END {print found}')"
  case "${kind}:${actual}" in
    js:application/javascript*|js:text/javascript*|css:text/css*) ;;
    *) echo "Unexpected Content-Type for ${path}: ${actual}" >&2; return 1 ;;
  esac
}

check_type "${js_path}" js
check_type "${css_path}" css
if [[ -n "${theme_path}" ]]; then
  check_type "${theme_path}" js
fi
echo "Frontend asset MIME smoke passed for ${base_url}"
