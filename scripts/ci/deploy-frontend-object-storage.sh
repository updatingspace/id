#!/usr/bin/env bash
set -euo pipefail

: "${YC_BUCKET_NAME:?YC_BUCKET_NAME is required}"
: "${FRONTEND_DIST_DIR:=dist}"
: "${YC_OBJECT_STORAGE_ENDPOINT:=https://storage.yandexcloud.net}"

if [[ ! -d "${FRONTEND_DIST_DIR}" ]]; then
  echo "Frontend dist directory not found: ${FRONTEND_DIST_DIR}" >&2
  exit 1
fi

aws --endpoint-url "${YC_OBJECT_STORAGE_ENDPOINT}" \
  s3 sync "${FRONTEND_DIST_DIR}/" "s3://${YC_BUCKET_NAME}/" \
  --delete \
  --cache-control "public,max-age=300"

if [[ -f "${FRONTEND_DIST_DIR}/index.html" ]]; then
  aws --endpoint-url "${YC_OBJECT_STORAGE_ENDPOINT}" \
    s3 cp "${FRONTEND_DIST_DIR}/index.html" "s3://${YC_BUCKET_NAME}/index.html" \
    --content-type "text/html; charset=utf-8" \
    --cache-control "no-cache"
fi

if [[ -d "${FRONTEND_DIST_DIR}" ]]; then
  while IFS= read -r -d '' asset; do
    key="${asset#${FRONTEND_DIST_DIR}/}"
    case "${asset}" in
      */index.html) continue ;;
      *.js) content_type="application/javascript; charset=utf-8" ;;
      *.css) content_type="text/css; charset=utf-8" ;;
      *.svg) content_type="image/svg+xml" ;;
      *.json) content_type="application/json; charset=utf-8" ;;
      *.woff2) content_type="font/woff2" ;;
      *) continue ;;
    esac

    aws --endpoint-url "${YC_OBJECT_STORAGE_ENDPOINT}" \
      s3 cp "${asset}" "s3://${YC_BUCKET_NAME}/${key}" \
      --content-type "${content_type}" \
      --cache-control "public,max-age=300"
  done < <(find "${FRONTEND_DIST_DIR}" -type f -print0)
fi
