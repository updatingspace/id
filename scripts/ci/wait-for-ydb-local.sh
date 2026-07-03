#!/usr/bin/env bash
set -euo pipefail

container_name="${YDB_CONTAINER_NAME:-ydb-local}"
endpoint="${YDB_LOCAL_ENDPOINT:-grpc://localhost:2136}"
database="${YDB_LOCAL_DATABASE:-/local}"
timeout_seconds="${YDB_WAIT_TIMEOUT_SECONDS:-90}"
start_ts="$(date +%s)"

while true; do
  if docker exec "${container_name}" sh -lc "
    if command -v ydb >/dev/null 2>&1; then
      ydb -e '${endpoint}' -d '${database}' scheme ls >/dev/null 2>&1
    elif [ -x /ydb ]; then
      /ydb -e '${endpoint}' -d '${database}' scheme ls >/dev/null 2>&1
    else
      exit 1
    fi
  "; then
    echo "YDB local is ready at ${endpoint} (${database})"
    exit 0
  fi

  if (( "$(date +%s)" - start_ts >= timeout_seconds )); then
    echo "Timed out waiting for YDB local container ${container_name}" >&2
    docker logs "${container_name}" >&2 || true
    exit 1
  fi

  sleep 2
done
