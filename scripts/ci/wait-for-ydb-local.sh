#!/usr/bin/env bash
set -euo pipefail

container_name="${YDB_CONTAINER_NAME:-ydb-local}"
endpoint="${YDB_LOCAL_ENDPOINT:-grpc://localhost:2136}"
database="${YDB_LOCAL_DATABASE:-/local}"
timeout_seconds="${YDB_WAIT_TIMEOUT_SECONDS:-90}"
start_ts="$(date +%s)"
probe_table="id_ready_$$_${start_ts}"

while true; do
  if docker exec \
    -e YDB_READY_ENDPOINT="${endpoint}" \
    -e YDB_READY_DATABASE="${database}" \
    -e YDB_READY_PROBE="${probe_table}" \
    "${container_name}" sh -lc '
      set -e
      if command -v ydb >/dev/null 2>&1; then
        cli=ydb
      elif [ -x /ydb ]; then
        cli=/ydb
      else
        exit 1
      fi
      "$cli" -e "$YDB_READY_ENDPOINT" -d "$YDB_READY_DATABASE" scheme ls >/dev/null 2>&1
      "$cli" -e "$YDB_READY_ENDPOINT" -d "$YDB_READY_DATABASE" table query execute --type scheme \
        -q "CREATE TABLE IF NOT EXISTS $YDB_READY_PROBE (id Uint64 NOT NULL, PRIMARY KEY (id));" >/dev/null 2>&1
      "$cli" -e "$YDB_READY_ENDPOINT" -d "$YDB_READY_DATABASE" table query execute --type scheme \
        -q "DROP TABLE $YDB_READY_PROBE;" >/dev/null 2>&1
    '; then
    echo "YDB local schema storage is ready at ${endpoint} (${database})"
    exit 0
  fi

  if (( "$(date +%s)" - start_ts >= timeout_seconds )); then
    echo "Timed out waiting for YDB local container ${container_name}" >&2
    docker logs "${container_name}" >&2 || true
    exit 1
  fi

  sleep 2
done
