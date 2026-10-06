//! One-time account JWT refresh rotation against the legacy YDB tables.

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

fn random_id() -> i64 {
    ((rand::random::<u64>() & ((1u64 << 62) - 1)) | (1u64 << 62)) as i64
}

pub enum RefreshOutcome {
    Rotated(AccountJwtPair),
    Invalid,
    ReplayRevoked,
}

/// A known abort may retry the same precomputed credentials. An unknown commit
/// result is an error; the pair is never released to the caller in that case.
pub async fn rotate(
    client: &Client,
    session_codec: Arc<SessionCodec>,
    jwt_codec: Arc<AccountJwtCodec>,
    refresh: &str,
    now: SystemTime,
) -> Result<RefreshOutcome> {
    let issued_at = i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?;
    let Ok(verified) = jwt_codec.verify_refresh(refresh, issued_at) else {
        return Ok(RefreshOutcome::Invalid);
    };
    let refresh = refresh.to_owned();
    let backends: Vec<String> = LEGACY_BACKENDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    let next_refresh_jti = format!("{:032x}", rand::random::<u128>());
    let next_access_jti = format!("{:032x}", rand::random::<u128>());
    let next_outstanding_id = random_id();
    let next_mapping_id = random_id();
    let blacklist_id = random_id();
    retry_known_abort(|| {
        let verified = verified.clone();
        let refresh = refresh.clone();
        let backends = backends.clone();
        let session_codec = session_codec.clone();
        let jwt_codec = jwt_codec.clone();
        let next_refresh_jti = next_refresh_jti.clone();
        let next_access_jti = next_access_jti.clone();
        async move {
            client.query_client().retry_tx(closure!([verified, refresh, backends, session_codec, jwt_codec, next_refresh_jti, next_access_jti, next_outstanding_id, next_mapping_id, blacklist_id], async |tx: &mut Transaction| {
                let mut outstanding = tx.query("SELECT id, token, expires_at FROM token_blacklist_outstandingtoken VIEW token_blacklist_outstandingtoken_user_id_83bc629a WHERE user_id = $user_id AND jti = $jti LIMIT 2")
                    .param("$user_id", verified.account_id).param("$jti", verified.jti.clone()).await?;
                let mut outstanding_rows = Vec::new();
                while let Some(rows) = outstanding.next_result_set().await? { outstanding_rows.extend(rows); }
                outstanding.close().await?;
                let [outstanding] = outstanding_rows.as_mut_slice() else { return Ok(RefreshOutcome::Invalid); };
                let outstanding_id: i64 = outstanding.remove_field_by_name("id")?.try_into()?;
                let saved: String = outstanding.remove_field_by_name("token")?.try_into()?;
                let expires_at: SystemTime = outstanding.remove_field_by_name("expires_at")?.try_into()?;
                if saved != *refresh || expires_at <= now { return Ok(RefreshOutcome::Invalid); }

                let mut mappings = tx.query("SELECT id, session_key, revoked_at FROM core_usersessiontoken VIEW core_usersessiontoken_user_id_2e52e0f5 WHERE user_id = $user_id AND refresh_jti = $jti LIMIT 2")
                    .param("$user_id", verified.account_id).param("$jti", verified.jti.clone()).await?;
                let mut mapping_rows = Vec::new();
                while let Some(rows) = mappings.next_result_set().await? { mapping_rows.extend(rows); }
                mappings.close().await?;
                let [mapping] = mapping_rows.as_mut_slice() else { return Ok(RefreshOutcome::Invalid); };
                let mapping_id: i64 = mapping.remove_field_by_name("id")?.try_into()?;
                let session_key: String = mapping.remove_field_by_name("session_key")?.try_into()?;
                let revoked_at: Option<SystemTime> = mapping.remove_field_by_name("revoked_at")?.try_into()?;
                if session_key != verified.session_key { return Ok(RefreshOutcome::Invalid); }

                let blacklisted = tx.query_row("SELECT id FROM token_blacklist_blacklistedtoken WHERE token_id = $id LIMIT 1")
                    .param("$id", outstanding_id).optional().await?.is_some();
                if revoked_at.is_some() || blacklisted {
                    revoke_replayed_session(tx, verified.account_id, &session_key, now).await?;
                    return Ok(RefreshOutcome::ReplayRevoked);
                }
                let Some(session) = restore_django_session_tx(tx, session_codec.as_ref(), &session_key, backends, now).await? else {
                    return Ok(RefreshOutcome::Invalid);
                };
                if session.principal.account_id.get() != i64::from(verified.account_id) {
                    return Ok(RefreshOutcome::Invalid);
                }
                let has_mfa = tx.query_row("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $user_id LIMIT 1")
                    .param("$user_id", verified.account_id).optional().await?.is_some();
                if has_mfa && !session.mfa_verified { return Ok(RefreshOutcome::Invalid); }

                let pair = jwt_codec.issue_pair(verified.account_id, &session_key, issued_at,
                    next_refresh_jti, next_access_jti)
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                tx.exec("UPDATE core_usersessiontoken SET revoked_at = CAST($now AS Datetime) WHERE id = $id")
                    .param("$now", now).param("$id", mapping_id).await?;
                tx.exec("INSERT INTO token_blacklist_blacklistedtoken (id, token_id, blacklisted_at) VALUES ($id, $token_id, CAST($now AS Datetime))")
                    .param("$id", *blacklist_id).param("$token_id", outstanding_id).param("$now", now).await?;
                let next_expiry = UNIX_EPOCH.checked_add(Duration::from_secs(u64::try_from(pair.refresh_expires_at)
                    .map_err(ydb::YdbOrCustomerError::from_err)?))
                    .ok_or_else(|| ydb::YdbOrCustomerError::from_err(std::io::Error::other("refresh expiry overflow")))?;
                tx.exec("INSERT INTO token_blacklist_outstandingtoken (id, user_id, jti, token, created_at, expires_at) VALUES ($id, $user_id, $jti, $token, CAST($now AS Datetime), CAST($expiry AS Datetime))")
                    .param("$id", *next_outstanding_id).param("$user_id", verified.account_id)
                    .param("$jti", next_refresh_jti.clone()).param("$token", pair.refresh.clone())
                    .param("$now", now).param("$expiry", next_expiry).await?;
                tx.exec("INSERT INTO core_usersessiontoken (id, user_id, session_key, refresh_jti, created_at) VALUES ($id, $user_id, $key, $jti, CAST($now AS Datetime))")
                    .param("$id", *next_mapping_id).param("$user_id", verified.account_id)
                    .param("$key", session_key).param("$jti", next_refresh_jti.clone())
                    .param("$now", now).await?;
                Ok(RefreshOutcome::Rotated(pair))
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
                .timeout(Duration::from_secs(15)).await
        }
    }).await.context("rotate account JWT refresh")
}

async fn revoke_replayed_session(
    tx: &mut Transaction,
    account_id: i32,
    session_key: &str,
    now: SystemTime,
) -> ydb::YdbResultWithCustomerErr<()> {
    // Closing the backing session invalidates every descendant even if an old
    // consumer checks the mapping before this transaction finishes.
    tx.exec("DELETE FROM django_session WHERE session_key = $key")
        .param("$key", session_key.to_owned())
        .await?;
    let mut metadata = tx.query("SELECT id, user_id FROM core_usersessionmeta VIEW core_usersessionmeta_session_key_2f41cf47 WHERE session_key = $key")
        .param("$key", session_key.to_owned()).await?;
    let mut metadata_ids: Vec<i64> = Vec::new();
    while let Some(rows) = metadata.next_result_set().await? {
        for mut row in rows {
            let owner: i32 = row.remove_field_by_name("user_id")?.try_into()?;
            if owner != account_id {
                return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
                    "session metadata owner mismatch",
                )));
            }
            metadata_ids.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    metadata.close().await?;
    for id in metadata_ids {
        tx.exec("UPDATE core_usersessionmeta SET revoked_at = CAST($now AS Datetime), revoked_reason = 'refresh_replay' WHERE id = $id AND revoked_at IS NULL")
            .param("$now", now).param("$id", id).await?;
    }
    let mut mappings = tx.query("SELECT id, user_id, refresh_jti FROM core_usersessiontoken VIEW core_usersessiontoken_session_key_b71d2665 WHERE session_key = $key AND revoked_at IS NULL")
        .param("$key", session_key.to_owned()).await?;
    let mut active = Vec::new();
    while let Some(rows) = mappings.next_result_set().await? {
        for mut row in rows {
            let owner: i32 = row.remove_field_by_name("user_id")?.try_into()?;
            if owner != account_id {
                return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
                    "refresh mapping owner mismatch",
                )));
            }
            let id: i64 = row.remove_field_by_name("id")?.try_into()?;
            let jti: String = row.remove_field_by_name("refresh_jti")?.try_into()?;
            active.push((id, jti));
        }
    }
    mappings.close().await?;
    for (mapping_id, jti) in active {
        tx.exec(
            "UPDATE core_usersessiontoken SET revoked_at = CAST($now AS Datetime) WHERE id = $id",
        )
        .param("$now", now)
        .param("$id", mapping_id)
        .await?;
        let outstanding = tx.query_row("SELECT id FROM token_blacklist_outstandingtoken VIEW token_blacklist_outstandingtoken_user_id_83bc629a WHERE user_id = $user_id AND jti = $jti LIMIT 1")
            .param("$user_id", account_id).param("$jti", jti).optional().await?;
        if let Some(mut outstanding) = outstanding {
            let outstanding_id: i64 = outstanding.remove_field_by_name("id")?.try_into()?;
            let exists = tx
                .query_row(
                    "SELECT id FROM token_blacklist_blacklistedtoken WHERE token_id = $id LIMIT 1",
                )
                .param("$id", outstanding_id)
                .optional()
                .await?
                .is_some();
            if !exists {
                tx.exec("INSERT INTO token_blacklist_blacklistedtoken (id, token_id, blacklisted_at) VALUES ($id, $token_id, CAST($now AS Datetime))")
                    .param("$id", random_id()).param("$token_id", outstanding_id).param("$now", now).await?;
            }
        }
    }
    Ok(())
}
