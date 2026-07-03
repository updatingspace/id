#!/usr/bin/env bash
set -euo pipefail

tf_dir="${YC_TERRAFORM_DIR:-infra/terraform/yandex-cloud}"
tofu_bin="${TOFU_BIN:-tofu}"

if ! command -v "${tofu_bin}" >/dev/null 2>&1; then
  echo "OpenTofu binary not found: ${tofu_bin}" >&2
  exit 127
fi

"${tofu_bin}" fmt -check -recursive "${tf_dir}"
"${tofu_bin}" -chdir="${tf_dir}" init -backend=false
"${tofu_bin}" -chdir="${tf_dir}" validate

echo "OpenTofu local check passed for ${tf_dir}"
