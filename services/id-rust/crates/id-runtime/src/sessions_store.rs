//! Legacy allauth session inventory, authorized and touched in one YDB transaction.

use crate::{session_store::restore_django_session_tx, tx_retry::retry_known_abort};
use anyhow::{Context, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use id_compat::session::SessionCodec;
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, SystemTime},
};
use ydb::{Client, Transaction, TxMode, Value, closure};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionRow {
    pub id: String,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
    pub created: Option<String>,
    pub last_seen: Option<String>,
    pub expires: Option<String>,
    pub current: bool,
    pub revoked: bool,
    pub revoked_reason: Option<String>,
    pub revoked_at: Option<String>,
}

#[derive(Clone)]
pub(crate) struct Tracked {
    id: i64,
    user_agent: String,
    ip: String,
    created: SystemTime,
    last_seen: SystemTime,
}

#[derive(Clone)]
pub(crate) struct Metadata {
    pub(crate) id: i64,
    session_token: Option<String>,
    user_agent: String,
    ip: Option<String>,
    first_seen: SystemTime,
    last_seen: Option<SystemTime>,
    pub(crate) revoked_at: Option<SystemTime>,
    pub(crate) revoked_reason: String,
}

pub async fn list_sessions(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: &str,
    x_session_header: bool,
    ip: Option<&str>,
    user_agent: &str,
    now: SystemTime,
) -> Result<Option<Vec<SessionRow>>> {
    let token = token.to_owned();
    let ip = ip.unwrap_or("").to_owned();
    let user_agent: String = user_agent.chars().take(512).collect();
    let backends: Vec<String> = crate::session_store::LEGACY_BACKENDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    let new_meta_id = random_id();
    let new_tracked_id = random_id();
    retry_known_abort(|| {
        let token = token.clone();
        let codec = codec.clone();
        let backends = backends.clone();
        let ip = ip.clone();
        let user_agent = user_agent.clone();
        async {
            client.query_client().retry_tx(closure!([token, codec, backends, ip, user_agent], async |tx: &mut Transaction| {
                let Some(restored) = restore_django_session_tx(tx, codec.as_ref(), token, backends, now).await? else {
                    return Ok(None);
                };
                let user_id = i32::try_from(restored.principal.account_id.get())
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                let has_mfa = tx.query_row("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $user_id LIMIT 1")
                    .param("$user_id", user_id).optional().await?.is_some();
                if has_mfa && !restored.mfa_verified { return Ok(None); }
                let mut tracked = read_tracked(tx, user_id).await?;
                let mut metadata = read_metadata(tx, user_id).await?;
                touch_current(tx, &mut tracked, &mut metadata, user_id, token, x_session_header,
                    ip, user_agent, now, new_meta_id, new_tracked_id).await?;
                let keys: BTreeSet<String> = tracked.keys().chain(metadata.keys()).cloned().collect();
                let mut expiries = BTreeMap::new();
                if !keys.is_empty() {
                    let values = keys.iter().cloned().map(Value::from).collect();
                    let keys_param = Value::list_from(Value::from(String::new()), values)
                        .map_err(ydb::YdbOrCustomerError::from)?;
                    let mut rows = tx.query("SELECT session_key, expire_date FROM django_session WHERE session_key IN $keys")
                        .param("$keys", keys_param).await?;
                    while let Some(set) = rows.next_result_set().await? {
                        for mut row in set {
                            let key: String = row.remove_field_by_name("session_key")?.try_into()?;
                            let expiry: SystemTime = row.remove_field_by_name("expire_date")?.try_into()?;
                            expiries.insert(key, expiry);
                        }
                    }
                    rows.close().await?;
                }
                Ok(Some(compose(keys, &tracked, &metadata, &expiries, token)))
            }))
            .with_mode(TxMode::SerializableReadWrite)
            .idempotent(false)
            .timeout(Duration::from_secs(10)).await
        }
    }).await.context("list legacy sessions")
}

pub(crate) async fn read_tracked(
    tx: &mut Transaction,
    user_id: i32,
) -> ydb::YdbResultWithCustomerErr<BTreeMap<String, Tracked>> {
    let mut query = tx.query("SELECT id, session_key, ip, user_agent, created_at, last_seen_at FROM usersessions_usersession VIEW usersessions_usersession_user_id_af5e0a6d WHERE user_id = $user_id")
        .param("$user_id", user_id).await?;
    let mut result = BTreeMap::new();
    while let Some(set) = query.next_result_set().await? {
        for mut row in set {
            let key: String = row.remove_field_by_name("session_key")?.try_into()?;
            let value = Tracked {
                id: row.remove_field_by_name("id")?.try_into()?,
                ip: row.remove_field_by_name("ip")?.try_into()?,
                user_agent: row.remove_field_by_name("user_agent")?.try_into()?,
                created: row.remove_field_by_name("created_at")?.try_into()?,
                last_seen: row.remove_field_by_name("last_seen_at")?.try_into()?,
            };
            if result.insert(key, value).is_some() {
                return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
                    "duplicate UserSession key",
                )));
            }
        }
    }
    query.close().await?;
    Ok(result)
}

pub(crate) async fn read_metadata(
    tx: &mut Transaction,
    user_id: i32,
) -> ydb::YdbResultWithCustomerErr<BTreeMap<String, Metadata>> {
    let mut query = tx.query("SELECT id, session_key, session_token, user_agent, ip, first_seen, last_seen, revoked_at, revoked_reason FROM core_usersessionmeta VIEW core_usersessionmeta_user_id_9dceac03 WHERE user_id = $user_id")
        .param("$user_id", user_id).await?;
    let mut result = BTreeMap::new();
    while let Some(set) = query.next_result_set().await? {
        for mut row in set {
            let key: String = row.remove_field_by_name("session_key")?.try_into()?;
            let value = Metadata {
                id: row.remove_field_by_name("id")?.try_into()?,
                session_token: row.remove_field_by_name("session_token")?.try_into()?,
                user_agent: row.remove_field_by_name("user_agent")?.try_into()?,
                ip: row.remove_field_by_name("ip")?.try_into()?,
                first_seen: row.remove_field_by_name("first_seen")?.try_into()?,
                last_seen: row.remove_field_by_name("last_seen")?.try_into()?,
                revoked_at: row.remove_field_by_name("revoked_at")?.try_into()?,
                revoked_reason: row.remove_field_by_name("revoked_reason")?.try_into()?,
            };
            if result.insert(key, value).is_some() {
                return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
                    "duplicate UserSessionMeta key",
                )));
            }
        }
    }
    query.close().await?;
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn touch_current(
    tx: &mut Transaction,
    tracked: &mut BTreeMap<String, Tracked>,
    metadata: &mut BTreeMap<String, Metadata>,
    user_id: i32,
    token: &str,
    x_session_header: bool,
    ip: &str,
    user_agent: &str,
    now: SystemTime,
    new_meta_id: i64,
    new_tracked_id: i64,
) -> ydb::YdbResultWithCustomerErr<()> {
    let created = !metadata.contains_key(token);
    let meta = if let Some(meta) = metadata.get_mut(token) {
        meta
    } else {
        tx.exec("INSERT INTO core_usersessionmeta (id, user_id, session_key, session_token, user_agent, ip, first_seen, last_seen, revoked_reason) VALUES ($id, $user_id, $key, $session_token, $ua, $ip, CAST($now AS Datetime), CAST($now AS Datetime), '')")
            .param("$id", new_meta_id).param("$user_id", user_id)
            .param("$key", token.to_owned()).param("$session_token", if x_session_header { Some(token.to_owned()) } else { None })
            .param("$ua", user_agent.to_owned()).param("$ip", ip.to_owned()).param("$now", now).await?;
        metadata.insert(
            token.to_owned(),
            Metadata {
                id: new_meta_id,
                session_token: if x_session_header {
                    Some(token.to_owned())
                } else {
                    None
                },
                user_agent: user_agent.to_owned(),
                ip: Some(ip.to_owned()),
                first_seen: now,
                last_seen: Some(now),
                revoked_at: None,
                revoked_reason: String::new(),
            },
        );
        metadata.get_mut(token).ok_or_else(|| {
            ydb::YdbOrCustomerError::from_err(std::io::Error::other("metadata insert lost"))
        })?
    };
    let due = created
        || meta.last_seen.is_none_or(|last| {
            now.duration_since(last).unwrap_or_default() >= Duration::from_secs(15)
        });
    let token_changed = x_session_header && meta.session_token.as_deref().unwrap_or("").is_empty();
    if !created && (due || token_changed) {
        if due {
            meta.last_seen = Some(now);
            if meta.user_agent.is_empty() {
                meta.user_agent = user_agent.to_owned();
            }
            if meta.ip.as_deref().unwrap_or("").is_empty() {
                meta.ip = Some(ip.to_owned());
            }
        }
        if token_changed {
            meta.session_token = Some(token.to_owned());
        }
        tx.exec("UPDATE core_usersessionmeta SET last_seen = CAST($last_seen AS Datetime), session_token = $session_token, user_agent = $ua, ip = $ip WHERE id = $id")
            .param("$last_seen", meta.last_seen.unwrap_or(now))
            .param("$session_token", meta.session_token.clone())
            .param("$ua", meta.user_agent.clone()).param("$ip", meta.ip.clone())
            .param("$id", meta.id).await?;
    }
    if due {
        if let Some(us) = tracked.get_mut(token) {
            us.last_seen = now;
            if us.user_agent.is_empty() {
                us.user_agent = user_agent.chars().take(200).collect();
            }
            if us.ip.is_empty() {
                us.ip = ip.to_owned();
            }
            tx.exec("UPDATE usersessions_usersession SET last_seen_at = CAST($now AS Datetime), user_agent = $ua, ip = $ip WHERE id = $id")
                .param("$now", now).param("$ua", us.user_agent.clone()).param("$ip", us.ip.clone())
                .param("$id", us.id).await?;
        } else {
            let agent: String = user_agent.chars().take(200).collect();
            tx.exec("INSERT INTO usersessions_usersession (id, user_id, session_key, ip, user_agent, created_at, last_seen_at, data) VALUES ($id, $user_id, $key, $ip, $ua, CAST($now AS Datetime), CAST($now AS Datetime), Unwrap(CAST('{}' AS Json)))")
                .param("$id", new_tracked_id).param("$user_id", user_id)
                .param("$key", token.to_owned()).param("$ip", ip.to_owned())
                .param("$ua", agent.clone()).param("$now", now).await?;
            tracked.insert(
                token.to_owned(),
                Tracked {
                    id: new_tracked_id,
                    user_agent: agent,
                    ip: ip.to_owned(),
                    created: now,
                    last_seen: now,
                },
            );
        }
    }
    Ok(())
}

fn compose(
    keys: BTreeSet<String>,
    tracked: &BTreeMap<String, Tracked>,
    metadata: &BTreeMap<String, Metadata>,
    expiries: &BTreeMap<String, SystemTime>,
    current: &str,
) -> Vec<SessionRow> {
    keys.into_iter()
        .map(|key| {
            let us = tracked.get(&key);
            let meta = metadata.get(&key);
            let expiry = expiries.get(&key);
            let revoked_at = meta.and_then(|row| row.revoked_at);
            SessionRow {
                id: key.clone(),
                user_agent: us
                    .map(|row| row.user_agent.clone())
                    .filter(|value| !value.is_empty())
                    .or_else(|| meta.map(|row| row.user_agent.clone())),
                ip: us
                    .map(|row| row.ip.clone())
                    .filter(|value| !value.is_empty())
                    .or_else(|| meta.and_then(|row| row.ip.clone())),
                created: us
                    .map(|row| format_time(row.created))
                    .or_else(|| meta.map(|row| format_time(row.first_seen))),
                last_seen: us
                    .map(|row| format_time(row.last_seen))
                    .or_else(|| meta.and_then(|row| row.last_seen.map(format_time)))
                    .or_else(|| us.map(|row| format_time(row.created)))
                    .or_else(|| meta.map(|row| format_time(row.first_seen))),
                expires: expiry.map(|value| format_time(*value)),
                current: key == current,
                revoked: revoked_at.is_some() || expiry.is_none(),
                revoked_reason: meta.map(|row| row.revoked_reason.clone()),
                revoked_at: revoked_at.map(format_time),
            }
        })
        .collect()
}

fn format_time(value: SystemTime) -> String {
    DateTime::<Utc>::from(value).to_rfc3339_opts(SecondsFormat::AutoSi, true)
}

fn random_id() -> i64 {
    ((rand::random::<u64>() & ((1u64 << 62) - 1)) | (1u64 << 62)) as i64
}
