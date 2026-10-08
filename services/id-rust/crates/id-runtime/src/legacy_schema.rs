//! Frozen YDB schema for the transition away from Django migrations.
//! The manifest was collected once from the reviewed Django model graph.

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    time::{Duration, SystemTime},
};
use url::Url;
use ydb::{Bytes, Client, IndexStatus, IndexType, TableDescription, Value};

const MANIFEST: &str = include_str!("../../../schema/legacy-ydb-v1.json");

#[derive(Deserialize)]
struct SchemaManifest {
    version: u8,
    source_sha256: String,
    tables: Vec<TableSpec>,
    indexes: Vec<IndexSpec>,
}

#[derive(Deserialize)]
struct TableSpec {
    name: String,
    sql: String,
    primary_key: Vec<String>,
    columns: Vec<ColumnSpec>,
}

#[derive(Deserialize)]
struct ColumnSpec {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    not_null: bool,
}

#[derive(Deserialize)]
struct IndexSpec {
    table: String,
    name: String,
    columns: Vec<String>,
    sql: String,
}

#[derive(Debug, Default, Serialize)]
pub struct SchemaReport {
    pub checked_tables: usize,
    pub checked_indexes: usize,
    pub create_attempts: usize,
    pub created_indexes: usize,
    pub source_sha256: String,
}

fn identifier(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
        "invalid schema identifier"
    );
    Ok(())
}

fn manifest() -> Result<SchemaManifest> {
    let manifest: SchemaManifest = serde_json::from_str(MANIFEST)?;
    ensure!(manifest.version == 1, "unsupported legacy schema version");
    ensure!(
        manifest.tables.len() == 50 && manifest.indexes.len() == 98,
        "legacy schema inventory is incomplete"
    );
    let ddl = manifest
        .tables
        .iter()
        .map(|table| format!("{};", table.sql))
        .chain(
            manifest
                .indexes
                .iter()
                .map(|index| format!("{};", index.sql)),
        )
        .collect::<Vec<_>>()
        .join("\n");
    ensure!(
        hex::encode(Sha256::digest(ddl.as_bytes())) == manifest.source_sha256,
        "frozen schema SQL checksum mismatch"
    );
    let mut tables = HashSet::new();
    for table in &manifest.tables {
        identifier(&table.name)?;
        ensure!(tables.insert(&table.name), "duplicate schema table");
        ensure!(
            table
                .sql
                .starts_with(&format!("CREATE TABLE `{}` (", table.name)),
            "schema table SQL mismatch"
        );
        for col in &table.columns {
            identifier(&col.name)?;
        }
        for pk in &table.primary_key {
            identifier(pk)?;
        }
    }
    let mut indexes = HashSet::new();
    for index in &manifest.indexes {
        identifier(&index.name)?;
        ensure!(tables.contains(&index.table), "index table not in manifest");
        ensure!(
            indexes.insert((&index.table, &index.name)),
            "duplicate schema index"
        );
        ensure!(
            index.sql.starts_with(&format!(
                "ALTER TABLE `{}` ADD INDEX `{}` GLOBAL ON (",
                index.table, index.name
            )),
            "schema index SQL mismatch"
        );
        for col in &index.columns {
            identifier(col)?;
        }
    }
    Ok(manifest)
}

fn primitive_type_matches(kind: &str, value: &Value) -> bool {
    matches!(
        (kind, value),
        ("Serial" | "Int32", Value::Int32(_))
            | ("BigSerial" | "Int64", Value::Int64(_))
            | ("Utf8", Value::Text(_))
            | ("String", Value::Bytes(_))
            | ("Bool", Value::Bool(_))
            | ("Datetime", Value::DateTime(_))
            | ("Date", Value::Date(_))
            | ("UUID", Value::Uuid(_))
            | ("Json", Value::Json(_))
            | ("Uint16", Value::Uint16(_))
    )
}

#[derive(Default)]
struct DateType;
impl From<DateType> for Value {
    fn from(_: DateType) -> Self {
        Value::Date(SystemTime::UNIX_EPOCH)
    }
}

#[derive(Default)]
struct DateTimeType;
impl From<DateTimeType> for Value {
    fn from(_: DateTimeType) -> Self {
        Value::DateTime(SystemTime::UNIX_EPOCH)
    }
}

#[derive(Default)]
struct JsonType;
impl From<JsonType> for Value {
    fn from(_: JsonType) -> Self {
        Value::Json(String::new())
    }
}

fn expected_optional(kind: &str) -> Result<Value> {
    Ok(match kind {
        "Datetime" => Some(DateTimeType).into(),
        "Date" => Some(DateType).into(),
        "Int32" => Some(i32::default()).into(),
        "Json" => Some(JsonType).into(),
        "String" => Some(Bytes::default()).into(),
        "UUID" => Some(uuid::Uuid::nil()).into(),
        "Utf8" => Some(String::new()).into(),
        _ => bail!("unsupported optional schema type: {kind}"),
    })
}

fn validate_table(spec: &TableSpec, actual: &TableDescription) -> Result<()> {
    ensure!(
        actual.primary_key == spec.primary_key,
        "{} primary key drift",
        spec.name
    );
    for expected in &spec.columns {
        let column = actual
            .columns
            .iter()
            .find(|column| column.name == expected.name)
            .with_context(|| format!("{}.{} column missing", spec.name, expected.name))?;
        let value = column.type_value.as_ref().map_err(|_| {
            anyhow::anyhow!("{}.{} column type unsupported", spec.name, expected.name)
        })?;
        let optional_kind = expected
            .kind
            .strip_prefix("Optional<")
            .and_then(|value| value.strip_suffix('>'));
        ensure!(
            value.is_optional() == !expected.not_null,
            "{}.{} nullability drift",
            spec.name,
            expected.name
        );
        if let Some(kind) = optional_kind {
            let expected_value = expected_optional(kind)?;
            ensure!(
                value == &expected_value,
                "{}.{} optional type drift: actual={value:?}, expected={expected_value:?}",
                spec.name,
                expected.name
            );
        } else {
            ensure!(
                primitive_type_matches(&expected.kind, value),
                "{}.{} type drift",
                spec.name,
                expected.name
            );
        }
    }
    Ok(())
}

fn validate_index(spec: &IndexSpec, description: &TableDescription) -> Result<bool> {
    let Some(actual) = description
        .indexes
        .iter()
        .find(|index| index.name == spec.name)
    else {
        return Ok(false);
    };
    ensure!(
        actual.index_columns == spec.columns
            && actual.data_columns.is_empty()
            && actual.index_type == IndexType::Global
            && actual.status == IndexStatus::Ready,
        "{}.{} index drift or not ready",
        spec.table,
        spec.name
    );
    Ok(true)
}

async fn describe(client: &Client, table: &str) -> Result<TableDescription> {
    client
        .table_client()
        .describe_table(format!("{}/{table}", client.database()))
        .await
        .with_context(|| format!("describe table {table}"))
}

/// Check by default. `apply` adds missing tables and indexes, never drops data.
/// Existing columns, primary keys and indexes are validated before continuing.
pub async fn reconcile(client: &Client, apply: bool) -> Result<SchemaReport> {
    let manifest = manifest()?;
    let mut report = SchemaReport {
        source_sha256: manifest.source_sha256,
        ..SchemaReport::default()
    };
    for spec in &manifest.tables {
        if apply {
            let sql = spec
                .sql
                .replacen("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1);
            client
                .query_client()
                .exec(sql)
                .timeout(Duration::from_secs(30))
                .await
                .with_context(|| format!("create table {}", spec.name))?;
            // CREATE IF NOT EXISTS also succeeds on a pre-existing table.
            report.create_attempts += 1;
        }
        let actual = describe(client, &spec.name).await?;
        validate_table(spec, &actual)?;
        report.checked_tables += 1;
    }
    reconcile_indexes(client, &manifest.indexes, apply, &mut report).await?;
    Ok(report)
}

/// Additive lookup indexes for provider ownership; the frozen Django manifest
/// and its historical checksum remain unchanged. Defaults to read-only check.
pub async fn provider_indexes(client: &Client, apply: bool) -> Result<SchemaReport> {
    let indexes = [
        (
            "socialaccount_socialaccount",
            "social_provider_subject_idx",
            vec!["provider", "uid"],
        ),
        (
            "usid_external_identity",
            "usid_ext_provider_subject_idx",
            vec!["provider", "subject"],
        ),
        (
            "accounts_accountidentity",
            "account_identity_reverse_idx",
            vec!["identity_id"],
        ),
    ]
    .into_iter()
    .map(|(table, name, columns)| IndexSpec {
        table: table.into(),
        name: name.into(),
        columns: columns.iter().map(|column| (*column).to_owned()).collect(),
        sql: format!(
            "ALTER TABLE `{table}` ADD INDEX `{name}` GLOBAL ON ({})",
            columns
                .iter()
                .map(|column| format!("`{column}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    })
    .collect::<Vec<_>>();
    let ddl = indexes
        .iter()
        .map(|index| format!("{};", index.sql))
        .collect::<Vec<_>>()
        .join("\n");
    let mut report = SchemaReport {
        source_sha256: hex::encode(Sha256::digest(ddl.as_bytes())),
        ..SchemaReport::default()
    };
    reconcile_indexes(client, &indexes, apply, &mut report).await?;
    Ok(report)
}

async fn reconcile_indexes(
    client: &Client,
    indexes: &[IndexSpec],
    apply: bool,
    report: &mut SchemaReport,
) -> Result<()> {
    for spec in indexes {
        let actual = describe(client, &spec.table).await?;
        if !validate_index(spec, &actual)? {
            if !apply {
                bail!("{}.{} index missing", spec.table, spec.name);
            }
            client
                .query_client()
                .exec(spec.sql.clone())
                .timeout(Duration::from_secs(30))
                .await
                .with_context(|| format!("create index {}.{}", spec.table, spec.name))?;
            report.created_indexes += 1;
            let actual = describe(client, &spec.table).await?;
            ensure!(
                validate_index(spec, &actual)?,
                "{}.{} index missing after create",
                spec.table,
                spec.name
            );
        }
        report.checked_indexes += 1;
    }
    Ok(())
}

pub fn require_local_ydb_for_pilot() -> Result<()> {
    let endpoint = Url::parse(&std::env::var("YDB_ENDPOINT")?)?;
    ensure!(
        matches!(
            endpoint.host_str(),
            Some("localhost" | "127.0.0.1" | "[::1]")
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "legacy schema bootstrap is restricted to local YDB until verified"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_manifest_is_well_formed() -> Result<()> {
        let schema = manifest()?;
        ensure!(
            schema
                .tables
                .iter()
                .all(|table| !table.primary_key.is_empty())
        );
        ensure!(schema.indexes.iter().all(|index| !index.columns.is_empty()));
        Ok(())
    }
}
