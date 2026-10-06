//! Portable, shared YDB cache access for transition-era one-time state.

use crate::tx_retry::retry_known_abort;
use anyhow::{Context, Result, bail, ensure};
use id_compat::cache::{self, CacheValue};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use ydb::{Client, Transaction, TxMode, Value, closure};

fn valid_table_name(table: &str) -> bool {
    !table.is_empty()
        && table
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && (table.as_bytes()[0].is_ascii_alphabetic() || table.as_bytes()[0] == b'_')
}

/// Create the shared one-time-state table without running Django migrations.
/// Keep the legacy column types so existing tokens and rate-limit budgets remain readable.
pub async fn ensure_schema(client: &Client, table: &str) -> Result<()> {
    ensure!(
        valid_table_name(table),
        "invalid YDB cache table identifier"
    );
    client.query_client().exec(format!(
        "CREATE TABLE IF NOT EXISTS `{table}` (cache_key Utf8 NOT NULL, value String, expires_at Uint64, PRIMARY KEY(cache_key)) WITH (TTL=Interval(\"PT0S\") ON expires_at AS SECONDS)"
    )).timeout(Duration::from_secs(15)).await?;
    let description = client
        .table_client()
        .describe_table(format!("{}/{table}", client.database()))
        .await?;
    ensure!(
        description.primary_key == ["cache_key"],
        "cache primary key drift"
    );
    ensure!(description.columns.len() == 3, "cache columns drift");
    for (name, expected) in [
        ("cache_key", Value::Text(String::new())),
        ("value", Some(ydb::Bytes::default()).into()),
        ("expires_at", Some(u64::default()).into()),
    ] {
        let actual = description
            .columns
            .iter()
            .find(|column| column.name == name)
            .with_context(|| format!("cache column missing: {name}"))?;
        let kind = actual
            .type_value
            .as_ref()
            .map_err(|_| anyhow::anyhow!("cache column type unsupported: {name}"))?;
        ensure!(kind == &expected, "cache column type drift: {name}");
    }
    Ok(())
}

#[derive(Clone)]
pub struct CacheStore {
    client: Arc<Client>,
    table: String,
    key_prefix: String,
    version: i64,
    increment_locks: Arc<[Mutex<()>; 64]>,
}

enum TakeOutcome {
    Missing,
    Unsupported,
    Value(CacheValue),
}

enum AddOutcome {
    Existing,
    Unsupported,
    Inserted,
}

enum IncrementOutcome {
    Missing,
    Unsupported,
    Value(i64),
}

enum WindowOutcome {
    Unsupported,
    Value(WindowCounter),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowCounter {
    pub count: i64,
    pub reset_at: i64,
}

#[derive(Debug, Default, Serialize)]
pub struct CacheAudit {
    pub scanned: u64,
    pub portable: u64,
    pub legacy: u64,
    pub expired: u64,
    pub malformed: u64,
}

impl CacheStore {
    pub fn new(client: Arc<Client>, table: &str, key_prefix: &str, version: i64) -> Result<Self> {
        if !valid_table_name(table) {
            bail!("invalid YDB cache table identifier");
        }
        Ok(Self {
            client,
            table: format!("`{table}`"),
            key_prefix: key_prefix.to_owned(),
            version,
            increment_locks: Arc::new(std::array::from_fn(|_| Mutex::new(()))),
        })
    }

    /// Matches Django's default `make_key` followed by YDBCache's SHA-256 key.
    pub fn key(&self, key: &str) -> String {
        let django_key = format!("{}:{}:{key}", self.key_prefix, self.version);
        hex::encode(Sha256::digest(django_key.as_bytes()))
    }

    /// Claim a one-time key as part of a caller's credential-issuance transaction.
    /// Any live row, including an undecodable one, blocks the claim. Callers must
    /// use a serializable write transaction and must not retry an unknown commit.
    pub(crate) async fn claim_in_tx(
        &self,
        tx: &mut Transaction,
        key: &str,
        expiry: SystemTime,
        now: SystemTime,
    ) -> ydb::YdbResultWithCustomerErr<bool> {
        let hashed = self.key(key);
        let select = format!(
            "SELECT expires_at FROM {} WHERE cache_key = $key",
            self.table
        );
        if let Some(mut row) = tx
            .query_row(select)
            .param("$key", hashed.clone())
            .optional()
            .await?
        {
            let old_expiry: Option<u64> = row.remove_field_by_name("expires_at")?.try_into()?;
            if !is_expired(old_expiry, now).unwrap_or(false) {
                return Ok(false);
            }
        }
        let encoded = cache::encode(&CacheValue::String("y".into()))
            .map_err(ydb::YdbOrCustomerError::from_err)?;
        let expiry = expiry
            .duration_since(UNIX_EPOCH)
            .map_err(ydb::YdbOrCustomerError::from_err)?
            .as_secs();
        tx.exec(format!(
            "UPSERT INTO {} (cache_key, value, expires_at) VALUES ($key, $value, $expiry)",
            self.table
        ))
        .param("$key", hashed)
        .param("$value", ydb::Bytes::from(encoded))
        .param("$expiry", expiry)
        .await?;
        Ok(true)
    }

    /// Insert a cryptographically random one-time value in the caller's
    /// serializable transaction. A key collision aborts instead of replacing
    /// an existing credential. The caller must not retry an unknown commit.
    pub(crate) async fn insert_new_in_tx(
        &self,
        tx: &mut Transaction,
        key: &str,
        value: &CacheValue,
        expiry: SystemTime,
    ) -> ydb::YdbResultWithCustomerErr<()> {
        let encoded = cache::encode(value).map_err(ydb::YdbOrCustomerError::from_err)?;
        let expiry = expiry
            .duration_since(UNIX_EPOCH)
            .map_err(ydb::YdbOrCustomerError::from_err)?
            .as_secs();
        tx.exec(format!(
            "INSERT INTO {} (cache_key, value, expires_at) VALUES ($key, $value, $expiry)",
            self.table
        ))
        .param("$key", self.key(key))
        .param("$value", ydb::Bytes::from(encoded))
        .param("$expiry", expiry)
        .await?;
        Ok(())
    }

    pub async fn get(&self, key: &str, now: SystemTime) -> Result<Option<CacheValue>> {
        let hashed = self.key(key);
        let sql = format!(
            "SELECT value, expires_at FROM {} WHERE cache_key = $key",
            self.table
        );
        let Some(mut row) = self
            .client
            .query_client()
            .query_row(sql)
            .param("$key", hashed)
            .optional()
            .timeout(Duration::from_secs(5))
            .await?
        else {
            return Ok(None);
        };
        let value: Option<ydb::Bytes> = row.remove_field_by_name("value")?.try_into()?;
        let expiry: Option<u64> = row.remove_field_by_name("expires_at")?.try_into()?;
        if is_expired(expiry, now)? {
            return Ok(None);
        }
        let Some(value) = value else {
            bail!("cache row has no value");
        };
        Ok(Some(cache::decode(&Vec::<u8>::from(value))?))
    }

    /// Best-effort invalidation for non-credential state such as a successful
    /// account's login penalty. Callers must never clear an IP-wide budget.
    pub async fn delete(&self, key: &str) -> Result<()> {
        let sql = format!("DELETE FROM {} WHERE cache_key = $key", self.table);
        self.client
            .query_client()
            .exec(sql)
            .param("$key", self.key(key))
            .timeout(Duration::from_secs(5))
            .await?;
        Ok(())
    }

    /// Consumes a portable value in one serializable transaction. Unsupported
    /// legacy rows remain untouched so an operator can backfill or inspect them.
    /// Ambiguous commit outcomes are errors; they are never retried as safe.
    pub async fn take(&self, key: &str, now: SystemTime) -> Result<Option<CacheValue>> {
        let hashed = self.key(key);
        let select = format!(
            "SELECT value, expires_at FROM {} WHERE cache_key = $key",
            self.table
        );
        let delete = format!("DELETE FROM {} WHERE cache_key = $key", self.table);
        let result = retry_known_abort(|| {
            let (hashed, select, delete) = (hashed.clone(), select.clone(), delete.clone());
            async move {
                self.client
                    .query_client()
                    .retry_tx(closure!(
                        [hashed, select, delete],
                        async |tx: &mut Transaction| {
                            let Some(mut row) = tx
                                .query_row(select.clone())
                                .param("$key", hashed.clone())
                                .optional()
                                .await?
                            else {
                                return Ok(TakeOutcome::Missing);
                            };
                            let value: Option<ydb::Bytes> =
                                row.remove_field_by_name("value")?.try_into()?;
                            let expiry: Option<u64> =
                                row.remove_field_by_name("expires_at")?.try_into()?;
                            if is_expired(expiry, now).unwrap_or(true) {
                                return Ok(TakeOutcome::Missing);
                            }
                            let Some(value) = value else {
                                return Ok(TakeOutcome::Unsupported);
                            };
                            let Ok(value) = cache::decode(&Vec::<u8>::from(value)) else {
                                return Ok(TakeOutcome::Unsupported);
                            };
                            tx.exec(delete.clone())
                                .param("$key", hashed.clone())
                                .await?;
                            Ok(TakeOutcome::Value(value))
                        }
                    ))
                    .with_mode(TxMode::SerializableReadWrite)
                    .idempotent(false)
                    .timeout(Duration::from_secs(10))
                    .await
            }
        })
        .await?;
        match result {
            TakeOutcome::Missing => Ok(None),
            TakeOutcome::Unsupported => bail!("cache row uses an unsupported format"),
            TakeOutcome::Value(value) => Ok(Some(value)),
        }
    }

    /// Inserts only when no unexpired entry exists. An invalid existing entry
    /// blocks the operation instead of weakening a one-time or rate-limit gate.
    pub async fn add(
        &self,
        key: &str,
        value: &CacheValue,
        expiry: Option<SystemTime>,
        now: SystemTime,
    ) -> Result<bool> {
        let hashed = self.key(key);
        let encoded = cache::encode(value)?;
        let expiry = expiry
            .map(|value| value.duration_since(UNIX_EPOCH).map(|time| time.as_secs()))
            .transpose()?;
        let select = format!(
            "SELECT value, expires_at FROM {} WHERE cache_key = $key",
            self.table
        );
        let upsert = format!(
            "UPSERT INTO {} (cache_key, value, expires_at) VALUES ($key, $value, $expiry)",
            self.table
        );
        let result = retry_known_abort(|| {
            let (hashed, encoded, select, upsert) = (
                hashed.clone(),
                encoded.clone(),
                select.clone(),
                upsert.clone(),
            );
            async move {
                self.client
                    .query_client()
                    .retry_tx(closure!(
                        [hashed, encoded, select, upsert],
                        async |tx: &mut Transaction| {
                            if let Some(mut row) = tx
                                .query_row(select.clone())
                                .param("$key", hashed.clone())
                                .optional()
                                .await?
                            {
                                let old_value: Option<ydb::Bytes> =
                                    row.remove_field_by_name("value")?.try_into()?;
                                let old_expiry: Option<u64> =
                                    row.remove_field_by_name("expires_at")?.try_into()?;
                                if !is_expired(old_expiry, now).unwrap_or(true) {
                                    let Some(old_value) = old_value else {
                                        return Ok(AddOutcome::Unsupported);
                                    };
                                    if cache::decode(&Vec::<u8>::from(old_value)).is_err() {
                                        return Ok(AddOutcome::Unsupported);
                                    }
                                    return Ok(AddOutcome::Existing);
                                }
                            }
                            tx.exec(upsert.clone())
                                .param("$key", hashed.clone())
                                .param("$value", ydb::Bytes::from(encoded.clone()))
                                .param("$expiry", expiry)
                                .await?;
                            Ok(AddOutcome::Inserted)
                        }
                    ))
                    .with_mode(TxMode::SerializableReadWrite)
                    .idempotent(false)
                    .timeout(Duration::from_secs(10))
                    .await
            }
        })
        .await?;
        match result {
            AddOutcome::Existing => Ok(false),
            AddOutcome::Unsupported => bail!("cache row uses an unsupported format"),
            AddOutcome::Inserted => Ok(true),
        }
    }

    /// Increments a signed integer while preserving its original expiry.
    /// Ambiguous commit outcomes are errors, never assumed to be rolled back.
    pub async fn incr(&self, key: &str, delta: i64, now: SystemTime) -> Result<i64> {
        let hashed = self.key(key);
        // Prevent a retry storm for one hot counter within this instance. YDB
        // remains the authority when other instances update the same key.
        let bytes = hashed.as_bytes();
        let stripe = (usize::from(bytes[0]) * 31 + usize::from(bytes[1])) % 64;
        let _guard = self.increment_locks[stripe].lock().await;
        let select = format!(
            "SELECT value, expires_at FROM {} WHERE cache_key = $key",
            self.table
        );
        let upsert = format!(
            "UPSERT INTO {} (cache_key, value, expires_at) VALUES ($key, $value, $expiry)",
            self.table
        );
        let result = retry_known_abort(|| {
            let (hashed, select, upsert) = (hashed.clone(), select.clone(), upsert.clone());
            async move {
                self.client
                    .query_client()
                    .retry_tx(closure!(
                        [hashed, select, upsert],
                        async |tx: &mut Transaction| {
                            let Some(mut row) = tx
                                .query_row(select.clone())
                                .param("$key", hashed.clone())
                                .optional()
                                .await?
                            else {
                                return Ok(IncrementOutcome::Missing);
                            };
                            let value: Option<ydb::Bytes> =
                                row.remove_field_by_name("value")?.try_into()?;
                            let expiry: Option<u64> =
                                row.remove_field_by_name("expires_at")?.try_into()?;
                            if is_expired(expiry, now).unwrap_or(true) {
                                return Ok(IncrementOutcome::Missing);
                            }
                            let Some(value) = value else {
                                return Ok(IncrementOutcome::Unsupported);
                            };
                            let Ok(CacheValue::Int(current)) =
                                cache::decode(&Vec::<u8>::from(value))
                            else {
                                return Ok(IncrementOutcome::Unsupported);
                            };
                            let Some(updated) = current.checked_add(delta) else {
                                return Ok(IncrementOutcome::Unsupported);
                            };
                            let Ok(encoded) = cache::encode(&CacheValue::Int(updated)) else {
                                return Ok(IncrementOutcome::Unsupported);
                            };
                            tx.exec(upsert.clone())
                                .param("$key", hashed.clone())
                                .param("$value", ydb::Bytes::from(encoded))
                                .param("$expiry", expiry)
                                .await?;
                            Ok(IncrementOutcome::Value(updated))
                        }
                    ))
                    .with_mode(TxMode::SerializableReadWrite)
                    .idempotent(false)
                    .timeout(Duration::from_secs(10))
                    .await
            }
        })
        .await?;
        match result {
            IncrementOutcome::Missing => bail!("cache key not found"),
            IncrementOutcome::Unsupported => bail!("cache value cannot be incremented"),
            IncrementOutcome::Value(value) => Ok(value),
        }
    }

    /// Shared transition rate-limit format: {count, reset_at}. Updates are
    /// serializable across Python/Rust instances and preserve the fixed window.
    /// A malformed live row fails closed. Ambiguous commits are never retried.
    pub async fn advance_window(
        &self,
        key: &str,
        window_seconds: u64,
        now: SystemTime,
    ) -> Result<WindowCounter> {
        if !(1..=86_400).contains(&window_seconds) {
            bail!("rate-limit window must be between 1 second and 1 day");
        }
        let now_epoch = now.duration_since(UNIX_EPOCH)?.as_secs();
        let now_seconds = i64::try_from(now_epoch)?;
        let window_seconds = i64::try_from(window_seconds)?;
        let hashed = self.key(key);
        let bytes = hashed.as_bytes();
        let stripe = (usize::from(bytes[0]) * 31 + usize::from(bytes[1])) % 64;
        let _guard = self.increment_locks[stripe].lock().await;
        let select = format!(
            "SELECT value, expires_at FROM {} WHERE cache_key = $key",
            self.table
        );
        let upsert = format!(
            "UPSERT INTO {} (cache_key, value, expires_at) VALUES ($key, $value, $expiry)",
            self.table
        );
        let result = retry_known_abort(|| {
            let (hashed, select, upsert) = (hashed.clone(), select.clone(), upsert.clone());
            async move {
                self.client
                    .query_client()
                    .retry_tx(closure!(
                        [hashed, select, upsert],
                        async |tx: &mut Transaction| {
                            let current = tx
                                .query_row(select.clone())
                                .param("$key", hashed.clone())
                                .optional()
                                .await?;
                            let existing = if let Some(mut row) = current {
                                let raw: Option<ydb::Bytes> =
                                    row.remove_field_by_name("value")?.try_into()?;
                                let expiry: Option<u64> =
                                    row.remove_field_by_name("expires_at")?.try_into()?;
                                if expiry.is_some_and(|expiry| expiry <= now_epoch) {
                                    None
                                } else {
                                    let Some(raw) = raw else {
                                        return Ok(WindowOutcome::Unsupported);
                                    };
                                    match cache::decode(&Vec::<u8>::from(raw)) {
                                        Ok(CacheValue::Map(fields)) => {
                                            let (
                                                Some(CacheValue::Int(count)),
                                                Some(CacheValue::Int(reset_at)),
                                            ) = (fields.get("count"), fields.get("reset_at"))
                                            else {
                                                return Ok(WindowOutcome::Unsupported);
                                            };
                                            if *count < 0 || *reset_at < 0 {
                                                return Ok(WindowOutcome::Unsupported);
                                            }
                                            Some(WindowCounter {
                                                count: *count,
                                                reset_at: *reset_at,
                                            })
                                        }
                                        _ => return Ok(WindowOutcome::Unsupported),
                                    }
                                }
                            } else {
                                None
                            };
                            let updated = if let Some(current) =
                                existing.filter(|value| value.reset_at > now_seconds)
                            {
                                let Some(count) = current.count.checked_add(1) else {
                                    return Ok(WindowOutcome::Unsupported);
                                };
                                WindowCounter {
                                    count,
                                    reset_at: current.reset_at,
                                }
                            } else {
                                let Some(reset_at) = now_seconds.checked_add(window_seconds) else {
                                    return Ok(WindowOutcome::Unsupported);
                                };
                                WindowCounter { count: 1, reset_at }
                            };
                            let value = CacheValue::Map(BTreeMap::from([
                                ("count".into(), CacheValue::Int(updated.count)),
                                ("reset_at".into(), CacheValue::Int(updated.reset_at)),
                            ]));
                            let Ok(encoded) = cache::encode(&value) else {
                                return Ok(WindowOutcome::Unsupported);
                            };
                            let Ok(expiry) = u64::try_from(updated.reset_at) else {
                                return Ok(WindowOutcome::Unsupported);
                            };
                            tx.exec(upsert.clone())
                                .param("$key", hashed.clone())
                                .param("$value", ydb::Bytes::from(encoded))
                                .param("$expiry", Some(expiry))
                                .await?;
                            Ok(WindowOutcome::Value(updated))
                        }
                    ))
                    .with_mode(TxMode::SerializableReadWrite)
                    .idempotent(false)
                    .timeout(Duration::from_secs(10))
                    .await
            }
        })
        .await?;
        match result {
            WindowOutcome::Unsupported => bail!("rate-limit cache value has an unsupported format"),
            WindowOutcome::Value(value) => Ok(value),
        }
    }

    /// Read-only inventory. Page boundaries are independent snapshots; run this
    /// after pre-bridge writers have drained, then repeat before Rust canary.
    pub async fn audit(&self, now: SystemTime) -> Result<CacheAudit> {
        let mut after = String::new();
        let mut counts = CacheAudit::default();
        let sql = format!(
            "SELECT cache_key, value, expires_at FROM {} WHERE cache_key > $after ORDER BY cache_key LIMIT 100",
            self.table
        );
        let mut query_client = self.client.query_client();
        loop {
            let mut stream = query_client
                .query(sql.clone())
                .param("$after", after.clone())
                .timeout(Duration::from_secs(10))
                .await?;
            let mut page = Vec::new();
            while let Some(rows) = stream.next_result_set().await? {
                for mut row in rows {
                    let key: String = row.remove_field_by_name("cache_key")?.try_into()?;
                    let value: Option<ydb::Bytes> =
                        row.remove_field_by_name("value")?.try_into()?;
                    let expiry: Option<u64> = row.remove_field_by_name("expires_at")?.try_into()?;
                    page.push((key, value, expiry));
                }
            }
            stream.close().await?;
            if page.is_empty() {
                return Ok(counts);
            }
            for (_, value, expiry) in &page {
                counts.scanned += 1;
                if is_expired(*expiry, now)? {
                    counts.expired += 1;
                } else if let Some(value) = value {
                    let raw = Vec::<u8>::from(value.clone());
                    if !cache::is_portable(&raw) {
                        counts.legacy += 1;
                    } else if cache::decode(&raw).is_ok() {
                        counts.portable += 1;
                    } else {
                        counts.malformed += 1;
                    }
                } else {
                    counts.malformed += 1;
                }
            }
            after = page
                .last()
                .ok_or_else(|| anyhow::anyhow!("empty page"))?
                .0
                .clone();
        }
    }
}

fn is_expired(expiry: Option<u64>, now: SystemTime) -> Result<bool> {
    let now = now.duration_since(UNIX_EPOCH)?.as_secs();
    Ok(expiry.is_some_and(|time| time <= now))
}
