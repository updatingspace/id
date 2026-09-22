#!/usr/bin/env bash
set -euo pipefail

: "${YC_BUCKET_NAME:?YC_BUCKET_NAME is required}"
: "${FRONTEND_DIST_DIR:=dist}"
: "${YC_OBJECT_STORAGE_ENDPOINT:=https://storage.yandexcloud.net}"
FRONTEND_DIST_DIR="${FRONTEND_DIST_DIR%/}"

if [[ ! -f "${FRONTEND_DIST_DIR}/index.html" ]]; then
  echo "Frontend index.html not found: ${FRONTEND_DIST_DIR}" >&2
  exit 1
fi

# Publish every dependency before switching the entry document. Keep previous
# assets for open tabs and rollback; cleanup is a separate retention operation.
while IFS= read -r -d '' asset; do
  key="${asset#${FRONTEND_DIST_DIR}/}"
  [[ "${key}" == "index.html" ]] && continue
  cache_control="public,max-age=300"
  if [[ "${key}" =~ ^assets/.+-[a-zA-Z0-9_-]{8,}\.[^.]+$ ]]; then
    cache_control="public,max-age=31536000,immutable"
  fi
  content_type=()
  case "${asset}" in
    *.js) content_type=(--content-type "application/javascript; charset=utf-8") ;;
    *.css) content_type=(--content-type "text/css; charset=utf-8") ;;
    *.svg) content_type=(--content-type "image/svg+xml") ;;
    *.json) content_type=(--content-type "application/json; charset=utf-8") ;;
    *.woff2) content_type=(--content-type "font/woff2") ;;
  esac
  aws --endpoint-url "${YC_OBJECT_STORAGE_ENDPOINT}" \
    s3 cp "${asset}" "s3://${YC_BUCKET_NAME}/${key}" \
    "${content_type[@]}" --cache-control "${cache_control}" --only-show-errors
done < <(find "${FRONTEND_DIST_DIR}" -type f -print0)

aws --endpoint-url "${YC_OBJECT_STORAGE_ENDPOINT}" \
  s3 cp "${FRONTEND_DIST_DIR}/index.html" "s3://${YC_BUCKET_NAME}/index.html" \
  --content-type "text/html; charset=utf-8" \
  --cache-control "no-cache" --only-show-errors
