//! Delete a user's current avatar without clearing a concurrently replaced key.

use crate::{
    media_delete::{S3MediaDelete, validate_avatar_key},
    session_store::{LEGACY_BACKENDS, restore_django_session_tx},
    tx_retry::retry_known_abort,
};
use anyhow::Result;
use id_compat::session::SessionCodec;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use ydb::{Client, Transaction, TxMode, closure};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AvatarSnapshot {
    pub account_id: i32,
    pub profile_id: Option<i64>,
    pub key: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DeleteResult {
    Deleted,
    Unauthorized,
    Changed,
}

pub async fn delete(
    client: &Client,
    codec: Arc<SessionCodec>,
    media: &S3MediaDelete,
    token: &str,
    now: SystemTime,
) -> Result<DeleteResult> {
    let token = token.to_owned();
    let backends: Vec<String> = LEGACY_BACKENDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    let snapshot = read(client, codec.clone(), token.clone(), backends.clone(), now).await?;
    let Some(snapshot) = snapshot else {
        return Ok(DeleteResult::Unauthorized);
    };
    if let Some(key) = snapshot.key.as_deref() {
        if validate_avatar_key(snapshot.account_id, key).is_ok() {
            media.delete_avatar(snapshot.account_id, key).await?;
        } else {
            // A legacy or misbound key must never authorize deletion of a
            // foreign object. Clear only this account's pointer.
            tracing::warn!("clearing an unsupported legacy avatar key without object deletion");
        }
    }
    clear(client, codec, token, backends, snapshot, now).await
}

pub(crate) async fn read(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: String,
    backends: Vec<String>,
    now: SystemTime,
) -> Result<Option<AvatarSnapshot>> {
    retry_known_abort(|| {
        let codec = codec.clone();
        let token = token.clone();
        let backends = backends.clone();
        async {
            client
                .query_client()
                .retry_tx(closure!(
                    [codec, token, backends],
                    async |tx: &mut Transaction| {
                        snapshot(tx, codec.as_ref(), token, backends, now).await
                    }
                ))
                .with_mode(TxMode::SerializableReadWrite)
                .idempotent(false)
                .timeout(Duration::from_secs(10))
                .await
        }
    })
    .await
}

async fn clear(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: String,
    backends: Vec<String>,
    prior: AvatarSnapshot,
    now: SystemTime,
) -> Result<DeleteResult> {
    retry_known_abort(|| {
        let codec = codec.clone();
        let token = token.clone();
        let backends = backends.clone();
        let prior = prior.clone();
        async {
            client.query_client().retry_tx(closure!([codec, token, backends, prior], async |tx: &mut Transaction| {
                let Some(current) = snapshot(tx, codec.as_ref(), token, backends, now).await? else {
                    return Ok(DeleteResult::Unauthorized)
                };
                if current != *prior {
                    return Ok(DeleteResult::Changed)
                }
                if let Some(profile_id) = current.profile_id {
                    tx.exec("UPDATE accounts_userprofile SET avatar = NULL, avatar_source = 'none', gravatar_enabled = false, gravatar_checked_at = CAST($now AS Datetime), updated_at = CAST($now AS Datetime) WHERE id = $id")
                        .param("$now", now).param("$id", profile_id).await?;
                } else {
                    tx.exec("INSERT INTO accounts_userprofile (user_id, avatar_source, gravatar_enabled, phone_number, phone_verified, gravatar_checked_at, created_at, updated_at) VALUES ($user_id, 'none', false, '', false, CAST($now AS Datetime), CAST($now AS Datetime), CAST($now AS Datetime))")
                        .param("$user_id", current.account_id).param("$now", now).await?;
                }
                Ok(DeleteResult::Deleted)
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
                .timeout(Duration::from_secs(10)).await
        }
    }).await
}

pub(crate) async fn snapshot(
    tx: &mut Transaction,
    codec: &SessionCodec,
    token: &str,
    backends: &[String],
    now: SystemTime,
) -> ydb::YdbResultWithCustomerErr<Option<AvatarSnapshot>> {
    let Some(session) = restore_django_session_tx(tx, codec, token, backends, now).await? else {
        return Ok(None);
    };
    let account_id = i32::try_from(session.principal.account_id.get())
        .map_err(ydb::YdbOrCustomerError::from_err)?;
    let has_mfa = tx.query_row("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $user_id LIMIT 1")
        .param("$user_id", account_id).optional().await?.is_some();
    if has_mfa && !session.mfa_verified {
        return Ok(None);
    }
    let mut stream = tx.query("SELECT id, CAST(avatar AS Utf8) AS avatar_key FROM accounts_userprofile VIEW acct_profile_user_idx WHERE user_id = $user_id LIMIT 2")
        .param("$user_id", account_id).await?;
    let mut profiles = Vec::with_capacity(2);
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            let id: i64 = row.remove_field_by_name("id")?.try_into()?;
            let key: Option<String> = row.remove_field_by_name("avatar_key")?.try_into()?;
            profiles.push((id, key));
        }
    }
    stream.close().await?;
    if profiles.len() > 1 {
        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
            "ambiguous avatar profile ownership",
        )));
    }
    let (profile_id, key) = profiles
        .pop()
        .map_or((None, None), |(id, key)| (Some(id), key));
    Ok(Some(AvatarSnapshot {
        account_id,
        profile_id,
        key,
    }))
}
