//! Transactional cancellation of pending secondary email changes.

use crate::{
    email_change,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelResult {
    Unauthorized,
    Cancelled { addresses: usize },
}

pub async fn cancel(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: &str,
    now: SystemTime,
) -> Result<CancelResult> {
    let token = token.to_owned();
    let backends: Vec<String> = LEGACY_BACKENDS.iter().map(|s| (*s).to_owned()).collect();
    retry_known_abort(|| {
        let (codec, token, backends) = (codec.clone(), token.clone(), backends.clone());
        async {
            client.query_client().retry_tx(closure!([codec, token, backends], async |tx: &mut Transaction| {
                let Some(session) = restore_django_session_tx(
                    tx, codec.as_ref(), token, backends, now,
                ).await? else {
                    return Ok(CancelResult::Unauthorized);
                };
                let user_id = i32::try_from(session.principal.account_id.get())
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                let has_mfa = tx.query_row(
                    "SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $user_id LIMIT 1"
                ).param("$user_id", user_id).optional().await?.is_some();
                if has_mfa && !session.mfa_verified {
                    return Ok(CancelResult::Unauthorized);
                }
                let mut stream = tx.query(
                    "SELECT id FROM account_emailaddress VIEW account_emailaddress_user_id_2c513194 WHERE user_id = $user_id AND primary = false AND verified = false LIMIT 101"
                ).param("$user_id", user_id).await?;
                let mut ids = Vec::<i32>::new();
                while let Some(rows) = stream.next_result_set().await? {
                    for mut row in rows {
                        ids.push(row.remove_field_by_name("id")?.try_into()?);
                    }
                }
                stream.close().await?;
                if ids.len() > 100 {
                    return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
                        "too many pending email addresses"
                    )));
                }
                for id in &ids {
                    tx.exec("DELETE FROM account_emailconfirmation WHERE email_address_id = $id")
                        .param("$id", *id).await?;
                    tx.exec("DELETE FROM account_emailaddress WHERE id = $id AND user_id = $user_id AND primary = false AND verified = false")
                        .param("$id", *id).param("$user_id", user_id).await?;
                }
                let had_intent = email_change::cancel_tx(tx, user_id).await?;
                if !ids.is_empty() || had_intent {
                    tx.exec("INSERT INTO accounts_accountevent (user_id, action, meta, created_at) VALUES ($user_id, 'email_change_cancelled', Unwrap(CAST('{}' AS Json)), CAST($now AS Datetime))")
                        .param("$user_id", user_id).param("$now", now).await?;
                }
                Ok(CancelResult::Cancelled { addresses: ids.len() })
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
                .timeout(Duration::from_secs(10)).await
        }
    }).await
}
