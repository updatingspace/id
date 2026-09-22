# Shared transient state in the existing serverless database; no dedicated host.
resource "yandex_ydb_table" "cache" {
  connection_string = yandex_ydb_database_serverless.id.ydb_full_endpoint
  path              = "id_shared_cache"
  primary_key       = ["cache_key"]

  column {
    name     = "cache_key"
    type     = "Utf8"
    not_null = true
  }
  column {
    name = "value"
    type = "String"
  }
  column {
    name = "expires_at"
    type = "Uint64"
  }
  ttl {
    column_name     = "expires_at"
    expire_interval = "PT0S"
    unit            = "seconds"
  }
}
