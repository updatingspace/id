#!/usr/bin/env bash
# Terraform adapter for the existing API Gateway, which the provider cannot import.
set -euo pipefail

: "${YC_GATEWAY_ID:?YC_GATEWAY_ID is required}"
: "${YC_GATEWAY_SPEC:?YC_GATEWAY_SPEC is required}"

umask 077
gateway_spec_file="$(mktemp "${TMPDIR:-/tmp}/id-gateway.XXXXXXXX.yaml")"
trap 'rm -f -- "$gateway_spec_file"' EXIT
printf '%s' "$YC_GATEWAY_SPEC" > "$gateway_spec_file"
yc serverless api-gateway update --id "$YC_GATEWAY_ID" --spec "$gateway_spec_file"
