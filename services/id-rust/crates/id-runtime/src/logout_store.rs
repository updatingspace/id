//! Revoke one legacy Django session and its account refresh tokens atomically.

use crate::{session_store::restore_django_session_tx, tx_retry::retry_known_abort};
use anyhow::{Context, Result};
use id_compat::session::SessionCodec;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use ydb::{Client, Transaction, TxMode, closure};

/// `None` means the supplied session was already invalid. Unknown commit results
/// remain errors: callers must not claim that a logout committed in that case.
pub async fn revoke_current_session(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: &str,
    now: SystemTime,
) -> Result<Option<()>> {
    let token = token.to_owned();
    let backends: Vec<String> = crate::session_store::LEGACY_BACKENDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    retry_known_abort(|| {
        let token = token.clone();
        let codec = codec.clone();
        let backends = backends.clone();
        async {
            client.query_client().retry_tx(closure!([token, codec, backends], async |tx: &mut Transaction| {
                let Some(restored) = restore_django_session_tx(tx, codec.as_ref(), token, backends, now).await? else {
                    return Ok(None);
                };
                let user_id = i32::try_from(restored.principal.account_id.get())
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                // The session-key indexes are global sync indexes from the
                // existing schema. Ownership is checked even after restore.
                let mut metadata = tx.query("SELECT id, user_id FROM core_usersessionmeta VIEW core_usersessionmeta_session_key_2f41cf47 WHERE session_key = $key")
                    .param("$key", token.clone()).await?;
                let mut metadata_ids = Vec::new();
                while let Some(rows) = metadata.next_result_set().await? {
                    for mut row in rows {
                        let owner: i32 = row.remove_field_by_name("user_id")?.try_into()?;
                        if owner != user_id { return Ok(None); }
                        let id: i64 = row.remove_field_by_name("id")?.try_into()?;
                        metadata_ids.push(id);
                    }
                }
                metadata.close().await?;
                for id in metadata_ids {
                    tx.exec("UPDATE core_usersessionmeta SET revoked_at = CAST($now AS Datetime), revoked_reason = 'logout' WHERE id = $id")
                        .param("$now", now).param("$id", id).await?;
                }
                let mut mappings = tx.query("SELECT id, user_id, refresh_jti FROM core_usersessiontoken VIEW core_usersessiontoken_session_key_b71d2665 WHERE session_key = $key AND revoked_at IS NULL")
                    .param("$key", token.clone()).await?;
                let mut mapped = Vec::new();
                while let Some(rows) = mappings.next_result_set().await? {
                    for mut row in rows {
                        let owner: i32 = row.remove_field_by_name("user_id")?.try_into()?;
                        if owner != user_id { return Ok(None); }
                        let id: i64 = row.remove_field_by_name("id")?.try_into()?;
                        let jti: String = row.remove_field_by_name("refresh_jti")?.try_into()?;
                        mapped.push((id, jti));
                    }
                }
                mappings.close().await?;
                for (id, jti) in mapped {
                    // The legacy table only has a user_id index. Filter the
                    // user's rows by JTI without scanning other accounts.
                    let outstanding = tx.query_row("SELECT id FROM token_blacklist_outstandingtoken VIEW token_blacklist_outstandingtoken_user_id_83bc629a WHERE user_id = $user_id AND jti = $jti LIMIT 1")
                        .param("$user_id", user_id).param("$jti", jti).optional().await?;
                    if let Some(mut row) = outstanding {
                        let outstanding_id: i64 = row.remove_field_by_name("id")?.try_into()?;
                        let already = tx.query_row("SELECT id FROM token_blacklist_blacklistedtoken WHERE token_id = $token_id LIMIT 1")
                            .param("$token_id", outstanding_id).optional().await?;
                        if already.is_none() {
                            let blacklist_id = (rand::random::<u64>() & ((1u64 << 62) - 1) | (1u64 << 62)) as i64;
                            tx.exec("INSERT INTO token_blacklist_blacklistedtoken (id, token_id, blacklisted_at) VALUES ($id, $token_id, CAST($now AS Datetime))")
                                .param("$id", blacklist_id).param("$token_id", outstanding_id).param("$now", now).await?;
                        }
                    }
                    tx.exec("UPDATE core_usersessiontoken SET revoked_at = CAST($now AS Datetime) WHERE id = $id")
                        .param("$now", now).param("$id", id).await?;
                }
                let mut tracked = tx.query("SELECT id, session_key FROM usersessions_usersession VIEW usersessions_usersession_user_id_af5e0a6d WHERE user_id = $user_id")
                    .param("$user_id", user_id).await?;
                let mut tracked_ids = Vec::new();
                while let Some(rows) = tracked.next_result_set().await? {
                    for mut row in rows {
                        let key: String = row.remove_field_by_name("session_key")?.try_into()?;
                        if key == *token {
                            let id: i64 = row.remove_field_by_name("id")?.try_into()?;
                            tracked_ids.push(id);
                        }
                    }
                }
                tracked.close().await?;
                for id in tracked_ids {
                    tx.exec("DELETE FROM usersessions_usersession WHERE id = $id")
                        .param("$id", id).await?;
                }
                tx.exec("DELETE FROM django_session WHERE session_key = $key")
                    .param("$key", token.clone()).await?;
                Ok(Some(()))
            }))
            .with_mode(TxMode::SerializableReadWrite)
            .idempotent(false)
            .timeout(Duration::from_secs(10))
            .await
        }
    }).await.context("revoke current Django session")
}
