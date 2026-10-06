//! Resumable account-email lookup repair after legacy writers are drained.
//! Each row is re-read inside a serializable transaction before mutation.

use crate::{login_email_audit, tx_retry::retry_known_abort};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::time::Duration;
use ydb::{Client, Transaction, TxMode, closure};

#[derive(Debug, Default, Serialize)]
pub struct ReconcileReport {
    pub dry_run: bool,
    pub scanned_accounts: u64,
    pub repaired_lookups: u64,
    pub scanned_lookups: u64,
    pub removed_orphans: u64,
    pub missing_or_stale_before: u64,
    pub orphans_before: u64,
}

async fn page_ids(
    client: &Client,
    table: &str,
    column: &str,
    after: Option<i32>,
    batch: u64,
) -> Result<Vec<i32>> {
    let sql = if after.is_some() {
        format!(
            "SELECT `{column}` FROM `{table}` WHERE `{column}` > $after ORDER BY `{column}` LIMIT {batch}"
        )
    } else {
        format!("SELECT `{column}` FROM `{table}` ORDER BY `{column}` LIMIT {batch}")
    };
    let mut pager = client.query_client();
    let query = pager.query(sql).timeout(Duration::from_secs(15));
    let mut stream = if let Some(after) = after {
        query.param("$after", after).await?
    } else {
        query.await?
    };
    let mut ids = Vec::new();
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            ids.push(row.remove_field_by_name(column)?.try_into()?);
        }
    }
    stream.close().await?;
    Ok(ids)
}

async fn repair_one(client: &Client, id: i32) -> Result<bool> {
    retry_known_abort(|| async {
        client.query_client().retry_tx(closure!([id], async |tx: &mut Transaction| {
            let Some(mut account) = tx.query_row("SELECT email, Unicode::ToLower(Unicode::Strip(email)) AS email_key FROM auth_user WHERE id = $id")
                .param("$id", *id).optional().await? else { return Ok(false); };
            let email: String = account.remove_field_by_name("email")?.try_into()?;
            let ydb_key: String = account.remove_field_by_name("email_key")?.try_into()?;
            let rust_key = email.trim().to_lowercase();
            if rust_key.is_empty() || rust_key != ydb_key {
                return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
                    "email normalization is ambiguous; lookup repair stopped",
                )));
            }
            let existing = tx.query_row("SELECT email_key FROM accounts_accountemaillookup WHERE user_id = $id")
                .param("$id", *id).optional().await?;
            if let Some(mut row) = existing {
                let key: String = row.remove_field_by_name("email_key")?.try_into()?;
                if key == rust_key { return Ok(false); }
            }
            tx.exec("UPSERT INTO accounts_accountemaillookup (user_id, email_key) VALUES ($id, $key)")
                .param("$id", *id).param("$key", rust_key).await?;
            Ok(true)
        })).isolation(TxMode::SerializableReadWrite).timeout(Duration::from_secs(10)).await
    }).await.context("repair email lookup row")
}

async fn remove_orphan(client: &Client, id: i32) -> Result<bool> {
    retry_known_abort(|| async {
        client
            .query_client()
            .retry_tx(closure!([id], async |tx: &mut Transaction| {
                if tx
                    .query_row("SELECT id FROM auth_user WHERE id = $id")
                    .param("$id", *id)
                    .optional()
                    .await?
                    .is_some()
                {
                    return Ok(false);
                }
                if tx
                    .query_row(
                        "SELECT user_id FROM accounts_accountemaillookup WHERE user_id = $id",
                    )
                    .param("$id", *id)
                    .optional()
                    .await?
                    .is_none()
                {
                    return Ok(false);
                }
                tx.exec("DELETE FROM accounts_accountemaillookup WHERE user_id = $id")
                    .param("$id", *id)
                    .await?;
                Ok(true)
            }))
            .isolation(TxMode::SerializableReadWrite)
            .timeout(Duration::from_secs(10))
            .await
    })
    .await
    .context("remove orphan email lookup row")
}

pub async fn reconcile(client: &Client, batch: u64, apply: bool) -> Result<ReconcileReport> {
    ensure!((1..=1000).contains(&batch), "batch must be 1..1000");
    let before = login_email_audit::audit_auth_user(client).await?;
    let mut report = ReconcileReport {
        dry_run: !apply,
        missing_or_stale_before: before.lookup_missing_or_stale,
        orphans_before: before.lookup_orphans,
        ..ReconcileReport::default()
    };
    if !apply {
        return Ok(report);
    }
    ensure!(
        before.collision_groups == 0 && before.empty == 0 && before.normalization_mismatch == 0,
        "account emails contain collisions, empty values or normalization differences"
    );
    let mut after = None;
    loop {
        let ids = page_ids(client, "auth_user", "id", after, batch).await?;
        if ids.is_empty() {
            break;
        }
        for id in &ids {
            report.scanned_accounts += 1;
            if repair_one(client, *id).await? {
                report.repaired_lookups += 1;
            }
        }
        after = ids.last().copied();
    }
    after = None;
    loop {
        let ids = page_ids(
            client,
            "accounts_accountemaillookup",
            "user_id",
            after,
            batch,
        )
        .await?;
        if ids.is_empty() {
            break;
        }
        for id in &ids {
            report.scanned_lookups += 1;
            if remove_orphan(client, *id).await? {
                report.removed_orphans += 1;
            }
        }
        after = ids.last().copied();
    }
    let after_audit = login_email_audit::audit_auth_user(client).await?;
    ensure!(
        after_audit.unambiguous(),
        "email lookup still ambiguous after repair"
    );
    Ok(report)
}
