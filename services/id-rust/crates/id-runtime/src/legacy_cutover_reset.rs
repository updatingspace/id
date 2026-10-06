//! Explicit cutover reset for legacy state the owner chose not to migrate.
//! Run only after stopping old writers and before admitting new Rust traffic.
//! One invocation removes a bounded batch from each table and can be repeated.

use anyhow::{Result, bail, ensure};
use serde::Serialize;
use std::time::Duration;
use ydb::Client;

const SEAL_TABLE: &str = "id_legacy_cutover_seal";

async fn ensure_seal_schema(client: &Client) -> Result<()> {
    client.query_client().exec(format!(
        "CREATE TABLE IF NOT EXISTS `{SEAL_TABLE}` (name Utf8 NOT NULL, sealed_at Datetime NOT NULL, PRIMARY KEY (name))"
    )).timeout(Duration::from_secs(15)).await?;
    Ok(())
}

pub async fn is_sealed(client: &Client) -> Result<bool> {
    ensure_seal_schema(client).await?;
    Ok(client
        .query_client()
        .query_row(format!(
            "SELECT name FROM `{SEAL_TABLE}` WHERE name = 'legacy-transient'"
        ))
        .optional()
        .await?
        .is_some())
}

pub async fn seal(client: &Client) -> Result<bool> {
    ensure_seal_schema(client).await?;
    if is_sealed(client).await? {
        return Ok(false);
    }
    let report = reset(client, 1, false).await?;
    ensure!(report.complete, "legacy transient tables are not empty");
    client.query_client().exec(format!(
        "INSERT INTO `{SEAL_TABLE}` (name, sealed_at) VALUES ('legacy-transient', CurrentUtcDatetime())"
    )).timeout(Duration::from_secs(15)).await?;
    Ok(true)
}

const TABLES: &[(&str, &str)] = &[
    ("django_session", "session_key"),
    ("usersessions_usersession", "id"),
    ("core_usersessionmeta", "id"),
    ("core_usersessiontoken", "id"),
    ("usid_application", "id"),
    ("usid_audit_log", "id"),
    ("usid_outbox", "id"),
];

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct TableReset {
    pub table: &'static str,
    pub before: u64,
    pub delete_attempts: u64,
    pub removed: u64,
    pub remaining: u64,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ResetReport {
    pub dry_run: bool,
    pub tables: Vec<TableReset>,
    pub complete: bool,
}

pub async fn reset(client: &Client, batch: u64, apply: bool) -> Result<ResetReport> {
    ensure!(
        (1..=1000).contains(&batch),
        "cutover reset batch must be 1..=1000"
    );
    if apply {
        ensure_seal_schema(client).await?;
        if is_sealed(client).await? {
            bail!("legacy cutover is sealed; reset would erase new sessions");
        }
    }
    let mut tables = Vec::with_capacity(TABLES.len());
    for &(table, key) in TABLES {
        let before = count(client, table).await?;
        let mut delete_attempts = 0;
        if apply && before > 0 {
            if key == "session_key" {
                for value in string_keys(client, table, key, batch).await? {
                    client
                        .query_client()
                        .exec(format!("DELETE FROM `{table}` WHERE `{key}` = $key"))
                        .param("$key", value)
                        .timeout(Duration::from_secs(15))
                        .await?;
                    delete_attempts += 1;
                }
            } else {
                for value in i64_keys(client, table, key, batch).await? {
                    client
                        .query_client()
                        .exec(format!("DELETE FROM `{table}` WHERE `{key}` = $key"))
                        .param("$key", value)
                        .timeout(Duration::from_secs(15))
                        .await?;
                    delete_attempts += 1;
                }
            }
        }
        let remaining = if apply {
            count(client, table).await?
        } else {
            before
        };
        let removed = before.saturating_sub(remaining);
        tables.push(TableReset {
            table,
            before,
            delete_attempts,
            removed,
            remaining,
        });
    }
    let complete = tables.iter().all(|table| table.remaining == 0);
    Ok(ResetReport {
        dry_run: !apply,
        tables,
        complete,
    })
}

async fn count(client: &Client, table: &str) -> Result<u64> {
    let mut row = client
        .query_client()
        .query_row(format!("SELECT COUNT(*) AS n FROM `{table}`"))
        .timeout(Duration::from_secs(15))
        .await?;
    Ok(row.remove_field_by_name("n")?.try_into()?)
}

async fn string_keys(client: &Client, table: &str, key: &str, batch: u64) -> Result<Vec<String>> {
    let mut query_client = client.query_client();
    let mut stream = query_client
        .query(format!(
            "SELECT `{key}` FROM `{table}` ORDER BY `{key}` LIMIT {batch}"
        ))
        .timeout(Duration::from_secs(15))
        .await?;
    let mut keys = Vec::new();
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            keys.push(row.remove_field_by_name(key)?.try_into()?);
        }
    }
    stream.close().await?;
    Ok(keys)
}

async fn i64_keys(client: &Client, table: &str, key: &str, batch: u64) -> Result<Vec<i64>> {
    let mut query_client = client.query_client();
    let mut stream = query_client
        .query(format!(
            "SELECT `{key}` FROM `{table}` ORDER BY `{key}` LIMIT {batch}"
        ))
        .timeout(Duration::from_secs(15))
        .await?;
    let mut keys = Vec::new();
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            keys.push(row.remove_field_by_name(key)?.try_into()?);
        }
    }
    stream.close().await?;
    Ok(keys)
}
