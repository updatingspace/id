//! Resumable credential-ID index for existing and newly registered passkeys.
//! A verified backfill marker is required before Rust writes new credentials.

use crate::tx_retry::retry_known_abort;
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::time::Duration;
use ydb::{Client, Transaction, TxMode, Value, closure};

pub const TABLE: &str = "id_passkey_credential";
const READY: &str = "ready";

#[derive(Debug, Default, Serialize)]
pub struct IndexReport {
    pub scanned: u64,
    pub inserted: u64,
    pub existing: u64,
    pub stale_removed: u64,
}

enum RowOutcome {
    Skipped,
    Inserted,
    Existing,
}

pub fn digest_of_record(record: &JsonValue) -> Result<String> {
    let raw = record
        .pointer("/credential/rawId")
        .and_then(JsonValue::as_str)
        .context("passkey credential ID missing")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .context("passkey credential ID invalid")?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= 1024,
        "passkey credential ID size invalid"
    );
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub fn digest_of_bytes(bytes: &[u8]) -> Result<String> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= 1024,
        "passkey credential ID size invalid"
    );
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub async fn ensure_schema(client: &Client) -> Result<()> {
    client.query_client().exec(format!(
        "CREATE TABLE IF NOT EXISTS `{TABLE}` (digest Utf8 NOT NULL, authenticator_id Int64 NOT NULL, account_id Int32 NOT NULL, PRIMARY KEY (digest))"
    )).timeout(Duration::from_secs(15)).await?;
    let description = client
        .table_client()
        .describe_table(format!("{}/{TABLE}", client.database()))
        .await?;
    ensure!(
        description.primary_key == ["digest"],
        "passkey index primary key drift"
    );
    ensure!(
        description.columns.len() == 3,
        "passkey index columns drift"
    );
    for (name, expected) in [
        ("digest", "text"),
        ("authenticator_id", "int64"),
        ("account_id", "int32"),
    ] {
        let col = description
            .columns
            .iter()
            .find(|col| col.name == name)
            .context("passkey index column missing")?;
        let correct = matches!(
            (&col.type_value, expected),
            (Ok(Value::Text(_)), "text")
                | (Ok(Value::Int64(_)), "int64")
                | (Ok(Value::Int32(_)), "int32")
        );
        ensure!(correct, "passkey index column type drift: {name}");
    }
    Ok(())
}

pub(crate) async fn lookup_tx(
    tx: &mut Transaction,
    digest: &str,
) -> ydb::YdbResultWithCustomerErr<Option<(i64, i32)>> {
    let Some(mut row) = tx
        .query_row(format!(
            "SELECT authenticator_id, account_id FROM `{TABLE}` WHERE digest = $digest"
        ))
        .param("$digest", digest.to_owned())
        .optional()
        .await?
    else {
        return Ok(None);
    };
    let id: i64 = row.remove_field_by_name("authenticator_id")?.try_into()?;
    let owner: i32 = row.remove_field_by_name("account_id")?.try_into()?;
    Ok(Some((id, owner)))
}

pub(crate) async fn indexed_owner(client: &Client, digest: &str) -> Result<Option<(i64, i32)>> {
    let digest = digest.to_owned();
    Ok(client
        .query_client()
        .retry_tx(closure!([digest], async |tx: &mut Transaction| {
            if lookup_tx(tx, READY).await? != Some((0, 0)) {
                return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
                    "passkey index unavailable",
                )));
            }
            lookup_tx(tx, digest).await
        }))
        .with_mode(TxMode::SnapshotReadOnly)
        .timeout(Duration::from_secs(5))
        .await?)
}

pub(crate) async fn claim_in_tx(
    tx: &mut Transaction,
    digest: &str,
    id: i64,
    owner: i32,
) -> ydb::YdbResultWithCustomerErr<bool> {
    if lookup_tx(tx, READY).await? != Some((0, 0)) {
        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
            "passkey index backfill not verified",
        )));
    }
    if lookup_tx(tx, digest).await?.is_some() {
        return Ok(false);
    }
    tx.exec(format!(
        "INSERT INTO `{TABLE}` (digest, authenticator_id, account_id) VALUES ($digest, $id, $owner)"
    ))
    .param("$digest", digest.to_owned())
    .param("$id", id)
    .param("$owner", owner)
    .await?;
    Ok(true)
}

/// Scans passkeys in primary-key order and re-reads every row before writing.
/// A second pass verifies the forward and reverse mapping before READY is set.
/// Operators must stop legacy writers or deploy a matching dual writer before
/// using the marker for production traffic.
pub async fn backfill(client: &Client) -> Result<IndexReport> {
    ensure_schema(client).await?;
    if let Some((id, owner)) = client
        .query_client()
        .query_row(format!(
            "SELECT authenticator_id, account_id FROM `{TABLE}` WHERE digest = $digest"
        ))
        .param("$digest", READY.to_owned())
        .optional()
        .await?
        .map(|mut row| -> ydb::YdbResult<(i64, i32)> {
            Ok((
                row.remove_field_by_name("authenticator_id")?.try_into()?,
                row.remove_field_by_name("account_id")?.try_into()?,
            ))
        })
        .transpose()?
    {
        ensure!(id == 0 && owner == 0, "passkey index marker drift");
    }
    client
        .query_client()
        .exec(format!("DELETE FROM `{TABLE}` WHERE digest = $digest"))
        .param("$digest", READY.to_owned())
        .await?;
    let mut report = IndexReport::default();
    let mut after: Option<i64> = None;
    loop {
        let sql = if after.is_some() {
            "SELECT id, type FROM mfa_authenticator WHERE id > $after ORDER BY id LIMIT 100"
        } else {
            "SELECT id, type FROM mfa_authenticator ORDER BY id LIMIT 100"
        };
        let mut query = client.query_client();
        let query = query.query(sql).timeout(Duration::from_secs(10));
        let mut stream = if let Some(id) = after {
            query.param("$after", id).await?
        } else {
            query.await?
        };
        let mut page = Vec::new();
        while let Some(rows) = stream.next_result_set().await? {
            for mut row in rows {
                let id: i64 = row.remove_field_by_name("id")?.try_into()?;
                let kind: String = row.remove_field_by_name("type")?.try_into()?;
                page.push((id, kind));
            }
        }
        stream.close().await?;
        if page.is_empty() {
            break;
        }
        for (id, kind) in &page {
            if kind != "webauthn" {
                continue;
            }
            report.scanned += 1;
            match backfill_row(client, *id).await? {
                RowOutcome::Skipped => {}
                RowOutcome::Inserted => report.inserted += 1,
                RowOutcome::Existing => report.existing += 1,
            }
        }
        after = page.last().map(|(id, _)| *id);
        if page.len() < 100 {
            break;
        }
    }
    audit_and_mark(client, &mut report).await?;
    Ok(report)
}

async fn backfill_row(client: &Client, id: i64) -> Result<RowOutcome> {
    retry_known_abort(|| async {
        client.query_client().retry_tx(closure!([id], async |tx: &mut Transaction| {
            let Some(mut row) = tx.query_row("SELECT user_id, type, CAST(data AS Utf8) AS data FROM mfa_authenticator WHERE id = $id")
                .param("$id", *id).optional().await? else { return Ok(RowOutcome::Skipped) };
            let owner: i32 = row.remove_field_by_name("user_id")?.try_into()?;
            let kind: String = row.remove_field_by_name("type")?.try_into()?;
            if kind != "webauthn" { return Ok(RowOutcome::Skipped) }
            let data: String = row.remove_field_by_name("data")?.try_into()?;
            let record: JsonValue = serde_json::from_str(&data).map_err(ydb::YdbOrCustomerError::from_err)?;
            let digest = digest_of_record(&record).map_err(|_| ydb::YdbOrCustomerError::from_err(std::io::Error::other("invalid passkey credential ID")))?;
            if let Some((old_id, old_owner)) = lookup_tx(tx, &digest).await? {
                if old_id != *id || old_owner != owner {
                    return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("duplicate passkey credential ID or index drift")))
                }
                return Ok(RowOutcome::Existing)
            }
            tx.exec(format!("INSERT INTO `{TABLE}` (digest, authenticator_id, account_id) VALUES ($digest, $id, $owner)"))
                .param("$digest", digest).param("$id", *id).param("$owner", owner).await?;
            Ok(RowOutcome::Inserted)
        })).with_mode(TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(10)).await
    }).await
}

async fn audit_and_mark(client: &Client, report: &mut IndexReport) -> Result<()> {
    let mut after: Option<String> = None;
    loop {
        let sql = if after.is_some() {
            format!(
                "SELECT digest, authenticator_id, account_id FROM `{TABLE}` WHERE digest > $after ORDER BY digest LIMIT 100"
            )
        } else {
            format!(
                "SELECT digest, authenticator_id, account_id FROM `{TABLE}` ORDER BY digest LIMIT 100"
            )
        };
        let mut query = client.query_client();
        let query = query.query(sql).timeout(Duration::from_secs(10));
        let mut stream = if let Some(key) = &after {
            query.param("$after", key.clone()).await?
        } else {
            query.await?
        };
        let mut mappings = Vec::new();
        while let Some(rows) = stream.next_result_set().await? {
            for mut row in rows {
                let digest: String = row.remove_field_by_name("digest")?.try_into()?;
                let id: i64 = row.remove_field_by_name("authenticator_id")?.try_into()?;
                let owner: i32 = row.remove_field_by_name("account_id")?.try_into()?;
                mappings.push((digest, id, owner));
            }
        }
        stream.close().await?;
        if mappings.is_empty() {
            break;
        }
        for (digest, id, owner) in &mappings {
            if digest == READY {
                continue;
            }
            let row = client.query_client().query_row("SELECT user_id, type, CAST(data AS Utf8) AS data FROM mfa_authenticator WHERE id = $id")
                .param("$id", *id).optional().await?;
            let Some(mut row) = row else {
                client
                    .query_client()
                    .exec(format!("DELETE FROM `{TABLE}` WHERE digest = $digest"))
                    .param("$digest", digest.clone())
                    .await?;
                report.stale_removed += 1;
                continue;
            };
            let current_owner: i32 = row.remove_field_by_name("user_id")?.try_into()?;
            let kind: String = row.remove_field_by_name("type")?.try_into()?;
            let data: String = row.remove_field_by_name("data")?.try_into()?;
            ensure!(
                kind == "webauthn"
                    && current_owner == *owner
                    && digest_of_record(&serde_json::from_str(&data)?)? == *digest,
                "passkey index ownership or credential drift"
            );
        }
        after = mappings.last().map(|(key, _, _)| key.clone());
        if mappings.len() < 100 {
            break;
        }
    }
    verify_forward(client).await?;
    // The marker is a local migration gate. It is not proof that an old
    // Python writer will keep this table up to date after the audit.
    let marker = client
        .query_client()
        .query_row(format!(
            "SELECT authenticator_id, account_id FROM `{TABLE}` WHERE digest = $digest"
        ))
        .param("$digest", READY.to_owned())
        .optional()
        .await?;
    if let Some(mut marker) = marker {
        let id: i64 = marker
            .remove_field_by_name("authenticator_id")?
            .try_into()?;
        let owner: i32 = marker.remove_field_by_name("account_id")?.try_into()?;
        ensure!(id == 0 && owner == 0, "passkey index marker drift");
    } else {
        client.query_client().exec(format!("INSERT INTO `{TABLE}` (digest, authenticator_id, account_id) VALUES ($digest, 0, 0)"))
            .param("$digest", READY.to_owned()).await?;
    }
    Ok(())
}

async fn verify_forward(client: &Client) -> Result<()> {
    let mut after: Option<i64> = None;
    loop {
        let sql = if after.is_some() {
            "SELECT id, user_id, type, CAST(data AS Utf8) AS data FROM mfa_authenticator WHERE id > $after ORDER BY id LIMIT 100"
        } else {
            "SELECT id, user_id, type, CAST(data AS Utf8) AS data FROM mfa_authenticator ORDER BY id LIMIT 100"
        };
        let mut query = client.query_client();
        let query = query.query(sql).timeout(Duration::from_secs(10));
        let mut stream = if let Some(id) = after {
            query.param("$after", id).await?
        } else {
            query.await?
        };
        let mut rows_seen = 0;
        let mut last = None;
        while let Some(rows) = stream.next_result_set().await? {
            for mut row in rows {
                rows_seen += 1;
                let id: i64 = row.remove_field_by_name("id")?.try_into()?;
                last = Some(id);
                let kind: String = row.remove_field_by_name("type")?.try_into()?;
                if kind != "webauthn" {
                    continue;
                }
                let owner: i32 = row.remove_field_by_name("user_id")?.try_into()?;
                let data: String = row.remove_field_by_name("data")?.try_into()?;
                let digest = digest_of_record(&serde_json::from_str(&data)?)?;
                let Some(mut indexed) = client
                    .query_client()
                    .query_row(format!(
                        "SELECT authenticator_id, account_id FROM `{TABLE}` WHERE digest = $digest"
                    ))
                    .param("$digest", digest)
                    .optional()
                    .await?
                else {
                    anyhow::bail!("passkey index missing a credential");
                };
                let indexed_id: i64 = indexed
                    .remove_field_by_name("authenticator_id")?
                    .try_into()?;
                let indexed_owner: i32 = indexed.remove_field_by_name("account_id")?.try_into()?;
                ensure!(
                    indexed_id == id && indexed_owner == owner,
                    "passkey index forward drift"
                );
            }
        }
        stream.close().await?;
        after = last;
        if rows_seen < 100 {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_credential_id_digest() -> Result<()> {
        let record = json!({"credential":{"rawId":"AQID"}});
        assert_eq!(digest_of_record(&record)?, digest_of_bytes(&[1, 2, 3])?);
        assert!(digest_of_record(&json!({"credential":{"rawId":""}})).is_err());
        assert!(digest_of_record(&json!({"credential":{"rawId":"AQI="}})).is_err());
        Ok(())
    }
}
