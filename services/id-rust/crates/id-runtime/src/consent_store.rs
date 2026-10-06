//! Account consent history and atomic revocation of optional consent.

use crate::{
    preferences_domain::default_scope_policies,
    session_store::{LEGACY_BACKENDS, restore_django_session_tx},
    tx_retry::retry_known_abort,
};
use anyhow::Result;
use chrono::{DateTime, SecondsFormat, Utc};
use id_compat::session::SessionCodec;
use serde::Serialize;
use serde_json::Value;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use ydb::{Client, Transaction, TxMode, closure};

const RUST_PREF_ID_PREFIX: i64 = 1 << 61;

#[derive(Debug, Serialize)]
pub struct ConsentRecord {
    pub kind: String,
    pub version: String,
    pub granted_at: String,
    pub revoked_at: Option<String>,
    pub source: String,
    pub meta: Value,
}

#[derive(Clone)]
pub enum ConsentOperation {
    List,
    Revoke(String),
}

pub enum ConsentResult {
    Listed(Vec<ConsentRecord>),
    Revoked(bool),
    Required,
}

pub async fn account_consents(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: &str,
    operation: ConsentOperation,
    now: SystemTime,
) -> Result<Option<ConsentResult>> {
    let token = token.to_owned();
    let backends: Vec<String> = LEGACY_BACKENDS.iter().map(|v| (*v).to_owned()).collect();
    retry_known_abort(|| {
        let token = token.clone();
        let codec = codec.clone();
        let backends = backends.clone();
        let operation = operation.clone();
        async {
            client.query_client().retry_tx(closure!([token, codec, backends, operation], async |tx: &mut Transaction| {
                let Some(session) = restore_django_session_tx(tx, codec.as_ref(), token, backends, now).await? else {
                    return Ok(None);
                };
                let user_id = i32::try_from(session.principal.account_id.get())
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                let has_mfa = tx.query_row("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $user_id LIMIT 1")
                    .param("$user_id", user_id).optional().await?.is_some();
                if has_mfa && !session.mfa_verified { return Ok(None); }

                match operation {
                    ConsentOperation::List => Ok(Some(ConsentResult::Listed(read_history(tx, user_id).await?))),
                    ConsentOperation::Revoke(kind) => {
                        if kind == "data_processing" { return Ok(Some(ConsentResult::Required)); }
                        if kind == "marketing" {
                            let changed = sync_marketing_consent_tx(tx, user_id, false, now, 0, "").await?;
                            if changed == 0 { return Ok(Some(ConsentResult::Revoked(false))); }
                            clear_marketing(tx, user_id, now).await?;
                            return Ok(Some(ConsentResult::Revoked(true)));
                        }
                        let mut row = tx.query_row("SELECT id FROM accounts_userconsent VIEW acct_consent_user_kind_idx WHERE user_id = $user_id AND kind = $kind AND revoked_at IS NULL ORDER BY granted_at DESC, id DESC LIMIT 1")
                            .param("$user_id", user_id).param("$kind", kind.clone()).optional().await?;
                        let Some(ref mut row) = row else { return Ok(Some(ConsentResult::Revoked(false))); };
                        let id: i64 = row.remove_field_by_name("id")?.try_into()?;
                        tx.exec("UPDATE accounts_userconsent SET revoked_at = CAST($now AS Datetime) WHERE id = $id AND revoked_at IS NULL")
                            .param("$now", now).param("$id", id).await?;
                        let meta = serde_json::json!({"kind":kind,"source":"account"}).to_string();
                        tx.exec("INSERT INTO accounts_accountevent (user_id, action, meta, created_at) VALUES ($user_id, 'consent_revoked', Unwrap(CAST($meta AS Json)), CAST($now AS Datetime))")
                            .param("$user_id", user_id).param("$meta", meta).param("$now", now).await?;
                        Ok(Some(ConsentResult::Revoked(true)))
                    }
                }
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
                .timeout(Duration::from_secs(10)).await
        }
    }).await
}

pub(crate) fn new_consent_id() -> i64 {
    ((rand::random::<u64>() & ((1u64 << 62) - 1)) | (1u64 << 62)) as i64
}

/// Keep the marketing switch and consent ledger in the caller's transaction.
/// Returns the number of consent rows granted or revoked. `new_id` is fixed
/// across a known-abort retry; an unknown commit is never retried blindly.
pub(crate) async fn sync_marketing_consent_tx(
    tx: &mut Transaction,
    user_id: i32,
    enabled: bool,
    now: SystemTime,
    new_id: i64,
    version: &str,
) -> ydb::YdbResultWithCustomerErr<usize> {
    let mut stream = tx.query("SELECT id FROM accounts_userconsent VIEW acct_consent_user_kind_idx WHERE user_id = $user_id AND kind = 'marketing' AND revoked_at IS NULL LIMIT 1001")
        .param("$user_id", user_id).await?;
    let mut active: Vec<i64> = Vec::new();
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            active.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    stream.close().await?;
    if active.len() > 1000 {
        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
            "too many active marketing consents",
        )));
    }
    if enabled {
        if !active.is_empty() {
            return Ok(0);
        }
        if new_id <= 0
            || version.is_empty()
            || version.len() > 32
            || version.chars().any(char::is_control)
        {
            return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
                "invalid marketing consent version or ID",
            )));
        }
        if tx
            .query_row("SELECT id FROM accounts_userconsent WHERE id = $id")
            .param("$id", new_id)
            .optional()
            .await?
            .is_some()
        {
            return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
                "consent ID collision",
            )));
        }
        tx.exec("INSERT INTO accounts_userconsent (id, user_id, kind, version, granted_at, source, meta) VALUES ($id, $user_id, 'marketing', $version, CAST($now AS Datetime), 'account', Unwrap(CAST('{}' AS Json)))")
            .param("$id", new_id).param("$user_id", user_id).param("$version", version.to_owned())
            .param("$now", now).await?;
        let meta = serde_json::json!({"kind":"marketing","version":version,"source":"account"})
            .to_string();
        tx.exec("INSERT INTO accounts_accountevent (user_id, action, meta, created_at) VALUES ($user_id, 'consent_granted', Unwrap(CAST($meta AS Json)), CAST($now AS Datetime))")
            .param("$user_id", user_id).param("$meta", meta).param("$now", now).await?;
        return Ok(1);
    }
    for id in &active {
        tx.exec("UPDATE accounts_userconsent SET revoked_at = CAST($now AS Datetime) WHERE id = $id AND revoked_at IS NULL")
            .param("$now", now).param("$id", *id).await?;
    }
    if !active.is_empty() {
        let meta = serde_json::json!({"kind":"marketing","source":"account"}).to_string();
        tx.exec("INSERT INTO accounts_accountevent (user_id, action, meta, created_at) VALUES ($user_id, 'consent_revoked', Unwrap(CAST($meta AS Json)), CAST($now AS Datetime))")
            .param("$user_id", user_id).param("$meta", meta).param("$now", now).await?;
    }
    Ok(active.len())
}

async fn read_history(
    tx: &mut Transaction,
    user_id: i32,
) -> ydb::YdbResultWithCustomerErr<Vec<ConsentRecord>> {
    let mut stream = tx.query("SELECT kind, version, granted_at, revoked_at, source, CAST(meta AS Utf8) AS meta FROM accounts_userconsent VIEW acct_consent_user_kind_idx WHERE user_id = $user_id ORDER BY granted_at DESC, id DESC LIMIT 200")
        .param("$user_id", user_id).await?;
    let mut records = Vec::new();
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            let meta: Option<String> = row.remove_field_by_name("meta")?.try_into()?;
            let meta = meta
                .as_deref()
                .map(serde_json::from_str::<Value>)
                .transpose()
                .map_err(ydb::YdbOrCustomerError::from_err)?
                .unwrap_or_else(|| serde_json::json!({}));
            let granted: SystemTime = row.remove_field_by_name("granted_at")?.try_into()?;
            let revoked: Option<SystemTime> = row.remove_field_by_name("revoked_at")?.try_into()?;
            records.push(ConsentRecord {
                kind: row.remove_field_by_name("kind")?.try_into()?,
                version: row.remove_field_by_name("version")?.try_into()?,
                granted_at: format_time(granted),
                revoked_at: revoked.map(format_time),
                source: row.remove_field_by_name("source")?.try_into()?,
                meta,
            });
        }
    }
    stream.close().await?;
    Ok(records)
}

async fn clear_marketing(
    tx: &mut Transaction,
    user_id: i32,
    now: SystemTime,
) -> ydb::YdbResultWithCustomerErr<()> {
    let mut stream = tx.query("SELECT id, marketing_opt_in FROM accounts_userpreferences VIEW acct_prefs_user_idx WHERE user_id = $user_id LIMIT 2")
        .param("$user_id", user_id).await?;
    let mut rows = Vec::new();
    while let Some(result_set) = stream.next_result_set().await? {
        for mut row in result_set {
            let id: i64 = row.remove_field_by_name("id")?.try_into()?;
            let enabled: bool = row.remove_field_by_name("marketing_opt_in")?.try_into()?;
            rows.push((id, enabled));
        }
    }
    stream.close().await?;
    if rows.len() > 1 {
        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
            "ambiguous preferences owner",
        )));
    }
    match rows.pop() {
        Some((id, true)) => {
            tx.exec("UPDATE accounts_userpreferences SET marketing_opt_in = false, marketing_opt_out_at = CAST($now AS Datetime), updated_at = CAST($now AS Datetime) WHERE id = $id")
                .param("$now", now).param("$id", id).await?;
            let meta = serde_json::json!({"fields":["marketing_opt_in","marketing_opt_out_at","updated_at"],"source":"account"}).to_string();
            tx.exec("INSERT INTO accounts_accountevent (user_id, action, meta, created_at) VALUES ($user_id, 'preferences_updated', Unwrap(CAST($meta AS Json)), CAST($now AS Datetime))")
                .param("$user_id", user_id).param("$meta", meta).param("$now", now).await?;
        }
        Some((_id, false)) => {}
        None => {
            let defaults = serde_json::to_string(&default_scope_policies())
                .map_err(ydb::YdbOrCustomerError::from_err)?;
            tx.exec("INSERT INTO accounts_userpreferences (id, user_id, language, timezone, marketing_opt_in, privacy_scope_defaults, created_at, updated_at) VALUES ($id, $user_id, 'en', '', false, Unwrap(CAST($policies AS Json)), CAST($now AS Datetime), CAST($now AS Datetime))")
                .param("$id", RUST_PREF_ID_PREFIX + i64::from(user_id))
                .param("$user_id", user_id).param("$policies", defaults)
                .param("$now", now).await?;
        }
    }
    Ok(())
}

fn format_time(value: SystemTime) -> String {
    DateTime::<Utc>::from(value).to_rfc3339_opts(SecondsFormat::Secs, true)
}
