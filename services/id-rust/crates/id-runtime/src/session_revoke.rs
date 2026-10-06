//! Owner-scoped single/bulk session revocation on the legacy YDB schema.

use crate::{
    session_store::restore_django_session_tx,
    sessions_store::{read_metadata, read_tracked, touch_current},
    tx_retry::retry_known_abort,
};
use anyhow::{Context, Result};
use id_compat::session::SessionCodec;
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime},
};
use ydb::{Client, Transaction, TxMode, closure};

#[derive(Clone)]
pub enum Selection {
    One(String),
    Bulk {
        ids: Option<Vec<String>>,
        all_except_current: bool,
    },
}

#[derive(Clone, Default)]
pub struct TouchContext {
    pub x_session_header: bool,
    pub ip: String,
    pub user_agent: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Unauthorized,
    Missing,
    One {
        id: String,
        reason: String,
        revoked_at: SystemTime,
    },
    Bulk {
        reason: String,
        current: String,
        revoked_ids: Vec<String>,
        skipped_ids: Vec<String>,
    },
}

#[derive(Clone)]
struct Owned {
    metadata: Option<Metadata>,
    tracked: bool,
}

#[derive(Clone)]
struct Metadata {
    id: i64,
    revoked_at: Option<SystemTime>,
    revoked_reason: String,
}

#[derive(Clone)]
struct Mapping {
    id: i64,
    jti: String,
}

/// The result is returned only after a confirmed commit. A definitive ABORTED
/// transaction may retry; an unknown commit result is surfaced to HTTP as 503.
pub async fn revoke_sessions(
    client: &Client,
    codec: Arc<SessionCodec>,
    actor_token: &str,
    selection: Selection,
    reason: &str,
    touch: TouchContext,
    now: SystemTime,
) -> Result<Outcome> {
    let actor_token = actor_token.to_owned();
    let reason = reason.to_lowercase();
    let backends: Vec<String> = crate::session_store::LEGACY_BACKENDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    let new_meta_id = random_id();
    let new_tracked_id = random_id();
    retry_known_abort(|| {
        let actor_token = actor_token.clone();
        let selection = selection.clone();
        let reason = reason.clone();
        let codec = codec.clone();
        let backends = backends.clone();
        let touch = touch.clone();
        async {
            client.query_client().retry_tx(closure!([actor_token, selection, reason, codec, backends, touch], async |tx: &mut Transaction| {
                let Some(restored) = restore_django_session_tx(tx, codec.as_ref(), actor_token, backends, now).await? else {
                    return Ok(Outcome::Unauthorized);
                };
                let user_id = i32::try_from(restored.principal.account_id.get())
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                let has_mfa = tx.query_row("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $user_id LIMIT 1")
                    .param("$user_id", user_id).optional().await?.is_some();
                if has_mfa && !restored.mfa_verified { return Ok(Outcome::Unauthorized); }
                let mut tracked = read_tracked(tx, user_id).await?;
                let mut metadata = read_metadata(tx, user_id).await?;
                let user_agent: String = touch.user_agent.chars().take(512).collect();
                touch_current(tx, &mut tracked, &mut metadata, user_id, actor_token,
                    touch.x_session_header, &touch.ip, &user_agent, now,
                    new_meta_id, new_tracked_id).await?;
                let mut owned = BTreeMap::new();
                for (key, meta) in metadata {
                    owned.insert(key, Owned { metadata: Some(Metadata {
                        id: meta.id, revoked_at: meta.revoked_at,
                        revoked_reason: meta.revoked_reason,
                    }), tracked: false });
                }
                for key in tracked.into_keys() {
                    owned.entry(key).and_modify(|state| state.tracked = true)
                        .or_insert(Owned { metadata: None, tracked: true });
                }
                let keys: Vec<String> = match selection {
                    Selection::One(id) => {
                        if !owned.contains_key(id) { return Ok(Outcome::Missing); }
                        vec![id.clone()]
                    },
                    Selection::Bulk { ids, all_except_current } => {
                        if let Some(ids) = ids.as_ref().filter(|ids| !ids.is_empty()) {
                            ids.clone()
                        } else {
                            owned.keys().filter(|key| !*all_except_current || *key != actor_token)
                                .cloned().collect()
                        }
                    },
                };
                let mut mappings = read_mappings(tx, user_id).await?;
                let outstanding = read_outstanding(tx, user_id).await?;
                let mut revoked_ids = Vec::new();
                let mut skipped_ids = Vec::new();
                let mut one_result = None;
                for key in keys {
                    let Some(state) = owned.get_mut(&key) else {
                        skipped_ids.push(key);
                        continue;
                    };
                    let old_revoked = state.metadata.as_ref().and_then(|meta| meta.revoked_at);
                    let active_mappings = mappings.remove(&key).unwrap_or_default();
                    let already_revoked = old_revoked.is_some() && active_mappings.is_empty();
                    if already_revoked && !matches!(selection, Selection::One(_)) {
                        skipped_ids.push(key);
                        continue;
                    }
                    let revoked_at = old_revoked.unwrap_or(now);
                    let actual_reason = if let Some(meta) = state.metadata.as_ref() {
                        if old_revoked.is_some() { meta.revoked_reason.clone() } else { reason.clone() }
                    } else { reason.clone() };
                    if let Some(meta) = state.metadata.as_ref() {
                        if old_revoked.is_none() {
                            tx.exec("UPDATE core_usersessionmeta SET revoked_at = CAST($now AS Datetime), revoked_reason = $reason WHERE id = $id")
                                .param("$now", now).param("$reason", reason.clone()).param("$id", meta.id).await?;
                        }
                    } else if state.tracked {
                        let meta_id = random_id();
                        tx.exec("INSERT INTO core_usersessionmeta (id, user_id, session_key, user_agent, first_seen, revoked_at, revoked_reason) VALUES ($id, $user_id, $key, '', CAST($now AS Datetime), CAST($now AS Datetime), $reason)")
                            .param("$id", meta_id).param("$user_id", user_id).param("$key", key.clone())
                            .param("$now", now).param("$reason", reason.clone()).await?;
                    }
                    for mapping in active_mappings {
                        if let Some(outstanding_id) = outstanding.get(&mapping.jti) {
                            let exists = tx.query_row("SELECT id FROM token_blacklist_blacklistedtoken WHERE token_id = $id LIMIT 1")
                                .param("$id", *outstanding_id).optional().await?.is_some();
                            if !exists {
                                tx.exec("INSERT INTO token_blacklist_blacklistedtoken (id, token_id, blacklisted_at) VALUES ($id, $token_id, CAST($now AS Datetime))")
                                    .param("$id", random_id()).param("$token_id", *outstanding_id).param("$now", now).await?;
                            }
                        }
                        tx.exec("UPDATE core_usersessiontoken SET revoked_at = CAST($now AS Datetime) WHERE id = $id")
                            .param("$now", now).param("$id", mapping.id).await?;
                    }
                    tx.exec("DELETE FROM django_session WHERE session_key = $key")
                        .param("$key", key.clone()).await?;
                    if matches!(selection, Selection::One(_)) {
                        one_result = Some(Outcome::One { id: key.clone(), reason: actual_reason, revoked_at });
                    }
                    revoked_ids.push(key);
                }
                Ok(one_result.unwrap_or_else(|| Outcome::Bulk { reason: reason.clone(),
                    current: actor_token.clone(), revoked_ids, skipped_ids }))
            }))
            .with_mode(TxMode::SerializableReadWrite).idempotent(false)
            .timeout(Duration::from_secs(30)).await
        }
    }).await.context("revoke account sessions")
}

async fn read_mappings(
    tx: &mut Transaction,
    user_id: i32,
) -> ydb::YdbResultWithCustomerErr<BTreeMap<String, Vec<Mapping>>> {
    let mut mappings = BTreeMap::<String, Vec<Mapping>>::new();
    let mut query = tx.query("SELECT id, session_key, refresh_jti FROM core_usersessiontoken VIEW core_usersessiontoken_user_id_2e52e0f5 WHERE user_id = $user_id AND revoked_at IS NULL")
        .param("$user_id", user_id).await?;
    while let Some(rows) = query.next_result_set().await? {
        for mut row in rows {
            let key: String = row.remove_field_by_name("session_key")?.try_into()?;
            mappings.entry(key).or_default().push(Mapping {
                id: row.remove_field_by_name("id")?.try_into()?,
                jti: row.remove_field_by_name("refresh_jti")?.try_into()?,
            });
        }
    }
    query.close().await?;
    Ok(mappings)
}

async fn read_outstanding(
    tx: &mut Transaction,
    user_id: i32,
) -> ydb::YdbResultWithCustomerErr<BTreeMap<String, i64>> {
    let mut outstanding = BTreeMap::new();
    let mut query = tx.query("SELECT id, jti FROM token_blacklist_outstandingtoken VIEW token_blacklist_outstandingtoken_user_id_83bc629a WHERE user_id = $user_id")
        .param("$user_id", user_id).await?;
    while let Some(rows) = query.next_result_set().await? {
        for mut row in rows {
            let jti: String = row.remove_field_by_name("jti")?.try_into()?;
            let id: i64 = row.remove_field_by_name("id")?.try_into()?;
            if outstanding.insert(jti, id).is_some() {
                return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
                    "duplicate outstanding JTI",
                )));
            }
        }
    }
    query.close().await?;
    Ok(outstanding)
}

fn random_id() -> i64 {
    ((rand::random::<u64>() & ((1u64 << 62) - 1)) | (1u64 << 62)) as i64
}
