//! Issue a legacy-format account JWT pair from a live Django/allauth session.

use crate::{
    session_store::{LEGACY_BACKENDS, restore_django_session_tx},
    tx_retry::retry_known_abort,
};
use anyhow::{Context, Result};
use id_compat::{
    account_jwt::{AccountJwtCodec, AccountJwtPair},
    session::SessionCodec,
};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use ydb::{Client, Transaction, TxMode, closure};

fn random_bigint_id() -> i64 {
    ((rand::random::<u64>() & ((1u64 << 62) - 1)) | (1u64 << 62)) as i64
}

/// Invalid or revoked sessions yield `None`; an unknown transaction result is
/// an error and must never release the precomputed credentials to the caller.
pub async fn issue_from_session(
    client: &Client,
    codec: Arc<SessionCodec>,
    jwt_codec: Arc<AccountJwtCodec>,
    token: &str,
    now: SystemTime,
) -> Result<Option<AccountJwtPair>> {
    if token.len() != 32
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Ok(None);
    }
    let issued_at = i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?;
    let token = token.to_owned();
    let backends: Vec<String> = LEGACY_BACKENDS
        .iter()
        .map(|backend| (*backend).to_owned())
        .collect();
    let refresh_jti = format!("{:032x}", rand::random::<u128>());
    let access_jti = format!("{:032x}", rand::random::<u128>());
    let meta_id = random_bigint_id();
    let outstanding_id = random_bigint_id();
    let mapping_id = random_bigint_id();
    retry_known_abort(|| {
        let codec = codec.clone();
        let jwt_codec = jwt_codec.clone();
        let token = token.clone();
        let backends = backends.clone();
        let refresh_jti = refresh_jti.clone();
        let access_jti = access_jti.clone();
        async {
            client.query_client().retry_tx(closure!([codec, jwt_codec, token, backends, refresh_jti, access_jti, meta_id, outstanding_id, mapping_id], async |tx: &mut Transaction| {
                let Some(session) = restore_django_session_tx(tx, codec.as_ref(), token, backends, now).await? else {
                    return Ok(None);
                };
                let account_id = i32::try_from(session.principal.account_id.get())
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                let has_mfa = tx.query_row("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $user_id LIMIT 1")
                    .param("$user_id", account_id).optional().await?.is_some();
                if has_mfa && !session.mfa_verified { return Ok(None); }
                let mut stream = tx.query("SELECT id, user_id, revoked_at FROM core_usersessionmeta VIEW core_usersessionmeta_session_key_2f41cf47 WHERE session_key = $key LIMIT 2")
                    .param("$key", token.clone()).await?;
                let mut metadata = Vec::new();
                while let Some(rows) = stream.next_result_set().await? {
                    for mut row in rows {
                        let id: i64 = row.remove_field_by_name("id")?.try_into()?;
                        let owner: i32 = row.remove_field_by_name("user_id")?.try_into()?;
                        let revoked: Option<SystemTime> = row.remove_field_by_name("revoked_at")?.try_into()?;
                        metadata.push((id, owner, revoked.is_some()));
                    }
                }
                stream.close().await?;
                if metadata.len() > 1 || metadata.iter().any(|(_, owner, revoked)| *owner != account_id || *revoked) {
                    return Ok(None);
                }
                let pair = jwt_codec.issue_pair(account_id, token, issued_at, refresh_jti, access_jti)
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                if metadata.is_empty() {
                    tx.exec("INSERT INTO core_usersessionmeta (id, user_id, session_key, session_token, user_agent, first_seen, last_seen, revoked_reason) VALUES ($id, $user_id, $key, $key, '', CAST($now AS Datetime), CAST($now AS Datetime), '')")
                        .param("$id", *meta_id).param("$user_id", account_id)
                        .param("$key", token.clone()).param("$now", now).await?;
                }
                let expires = UNIX_EPOCH.checked_add(Duration::from_secs(u64::try_from(pair.refresh_expires_at)
                    .map_err(ydb::YdbOrCustomerError::from_err)?))
                    .ok_or_else(|| ydb::YdbOrCustomerError::from_err(std::io::Error::other("refresh expiry overflow")))?;
                tx.exec("INSERT INTO token_blacklist_outstandingtoken (id, user_id, jti, token, created_at, expires_at) VALUES ($id, $user_id, $jti, $token, CAST($now AS Datetime), CAST($expiry AS Datetime))")
                    .param("$id", *outstanding_id).param("$user_id", account_id)
                    .param("$jti", refresh_jti.clone()).param("$token", pair.refresh.clone())
                    .param("$now", now).param("$expiry", expires).await?;
                tx.exec("INSERT INTO core_usersessiontoken (id, user_id, session_key, refresh_jti, created_at) VALUES ($id, $user_id, $key, $jti, CAST($now AS Datetime))")
                    .param("$id", *mapping_id).param("$user_id", account_id)
                    .param("$key", token.clone()).param("$jti", refresh_jti.clone())
                    .param("$now", now).await?;
                Ok(Some(pair))
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
                .timeout(Duration::from_secs(10)).await
        }
    }).await.context("issue account JWT from live session")
}
