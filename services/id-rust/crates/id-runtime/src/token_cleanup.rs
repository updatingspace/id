//! Bounded-memory cleanup of expired legacy UpdSpace ID one-time tokens.
//! Every candidate is rechecked in a serializable transaction before deletion.

use crate::tx_retry::retry_known_abort;
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::time::{Duration, SystemTime};
use ydb::{Client, Transaction, TxMode, closure};

const TABLES: [TokenTable; 3] = [
    TokenTable::new("usid_activation_token", "token"),
    TokenTable::new("usid_magic_link_token", "token"),
    TokenTable::new("usid_oauth_state", "state"),
];

#[derive(Clone, Copy)]
struct TokenTable {
    table: &'static str,
    key: &'static str,
}

impl TokenTable {
    const fn new(table: &'static str, key: &'static str) -> Self {
        Self { table, key }
    }
}

#[derive(Debug, Default, Serialize)]
pub struct CleanupReport {
    pub dry_run: bool,
    pub scanned: u64,
    pub eligible: u64,
    pub deleted: u64,
    pub activation_deleted: u64,
    pub magic_link_deleted: u64,
    pub oauth_state_deleted: u64,
}

#[derive(Debug)]
struct TokenRow {
    key: String,
    expires_at: SystemTime,
    used_at: Option<SystemTime>,
}

fn due(row: &TokenRow, now: SystemTime, used_cutoff: SystemTime) -> bool {
    row.expires_at <= now || row.used_at.is_some_and(|used_at| used_at <= used_cutoff)
}

async fn page(
    client: &Client,
    table: TokenTable,
    after: &str,
    batch: u64,
) -> Result<Vec<TokenRow>> {
    let sql = format!(
        "SELECT `{key}`, expires_at, used_at FROM `{name}` WHERE `{key}` > $after ORDER BY `{key}` LIMIT {batch}",
        key = table.key,
        name = table.table,
    );
    let mut pager = client.query_client();
    let mut stream = pager
        .query(sql)
        .param("$after", after.to_owned())
        .timeout(Duration::from_secs(15))
        .await
        .with_context(|| format!("page {}", table.table))?;
    let mut rows = Vec::new();
    while let Some(result) = stream.next_result_set().await? {
        for mut row in result {
            rows.push(TokenRow {
                key: row.remove_field_by_name(table.key)?.try_into()?,
                expires_at: row.remove_field_by_name("expires_at")?.try_into()?,
                used_at: row.remove_field_by_name("used_at")?.try_into()?,
            });
        }
    }
    stream.close().await?;
    Ok(rows)
}

async fn delete_if_due(
    client: &Client,
    table: TokenTable,
    key: &str,
    now: SystemTime,
    used_cutoff: SystemTime,
) -> Result<bool> {
    let key = key.to_owned();
    let select = format!(
        "SELECT expires_at, used_at FROM `{name}` WHERE `{field}` = $key",
        name = table.table,
        field = table.key,
    );
    let delete = format!(
        "DELETE FROM `{name}` WHERE `{field}` = $key",
        name = table.table,
        field = table.key,
    );
    retry_known_abort(|| {
        let key = key.clone();
        let select = select.clone();
        let delete = delete.clone();
        async move {
            client
                .query_client()
                .retry_tx(closure!(
                    [key, select, delete],
                    async |tx: &mut Transaction| {
                        let Some(mut row) = tx
                            .query_row(select.clone())
                            .param("$key", key.clone())
                            .optional()
                            .await?
                        else {
                            return Ok(false);
                        };
                        let row = TokenRow {
                            key: key.clone(),
                            expires_at: row.remove_field_by_name("expires_at")?.try_into()?,
                            used_at: row.remove_field_by_name("used_at")?.try_into()?,
                        };
                        if !due(&row, now, used_cutoff) {
                            return Ok(false);
                        }
                        tx.exec(delete.clone()).param("$key", key.clone()).await?;
                        Ok(true)
                    }
                ))
                .isolation(TxMode::SerializableReadWrite)
                .timeout(Duration::from_secs(10))
                .await
        }
    })
    .await
    .with_context(|| format!("delete due token from {}", table.table))
}

/// Scans all rows in primary-key order using bounded pages. A concurrent writer
/// may add a lower key after its page has passed; the next run will find it.
pub async fn cleanup(
    client: &Client,
    now: SystemTime,
    retention_days: u64,
    batch: u64,
    execute: bool,
) -> Result<CleanupReport> {
    ensure!(retention_days <= 365, "retention days must be 0..365");
    ensure!((1..=1000).contains(&batch), "batch must be 1..1000");
    let used_cutoff = now
        .checked_sub(Duration::from_secs(retention_days * 86_400))
        .context("retention cutoff outside supported time range")?;
    let mut report = CleanupReport {
        dry_run: !execute,
        ..CleanupReport::default()
    };
    for (index, table) in TABLES.into_iter().enumerate() {
        let mut after = String::new();
        loop {
            let rows = page(client, table, &after, batch).await?;
            if rows.is_empty() {
                break;
            }
            for row in &rows {
                report.scanned += 1;
                if due(row, now, used_cutoff) {
                    report.eligible += 1;
                    if execute && delete_if_due(client, table, &row.key, now, used_cutoff).await? {
                        report.deleted += 1;
                        match index {
                            0 => report.activation_deleted += 1,
                            1 => report.magic_link_deleted += 1,
                            _ => report.oauth_state_deleted += 1,
                        }
                    }
                }
            }
            if let Some(last) = rows.last() {
                after = last.key.clone();
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn due_rule_matches_legacy_retention() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(20 * 86_400);
        let cutoff = now - Duration::from_secs(7 * 86_400);
        let mut row = TokenRow {
            key: "x".into(),
            expires_at: now + Duration::from_secs(60),
            used_at: None,
        };
        assert!(!due(&row, now, cutoff));
        row.used_at = Some(cutoff + Duration::from_secs(1));
        assert!(!due(&row, now, cutoff));
        row.used_at = Some(cutoff);
        assert!(due(&row, now, cutoff));
        row.used_at = None;
        row.expires_at = now;
        assert!(due(&row, now, cutoff));
    }
}
