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
    --cache-control "no-cache"
fi
