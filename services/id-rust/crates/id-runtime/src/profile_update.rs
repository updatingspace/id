//! Transactional update of legacy Django account and optional profile fields.

use crate::{
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

#[derive(Clone, Default)]
pub struct ProfileChanges {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone_number: Option<String>,
    pub birth_date: Option<String>,
    pub ensure_profile: bool,
}

pub async fn update_profile(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: &str,
    changes: ProfileChanges,
    now: SystemTime,
) -> Result<bool> {
    let token = token.to_owned();
    let backends: Vec<String> = LEGACY_BACKENDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    retry_known_abort(|| {
        let codec = codec.clone();
        let token = token.clone();
        let changes = changes.clone();
        let backends = backends.clone();
        async {
            client.query_client().retry_tx(closure!([codec, token, changes, backends], async |tx: &mut Transaction| {
                let Some(session) = restore_django_session_tx(tx, codec.as_ref(), token, backends, now).await? else {
                    return Ok(false);
                };
                let user_id = i32::try_from(session.principal.account_id.get())
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                let has_mfa = tx.query_row("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $user_id LIMIT 1")
                    .param("$user_id", user_id).optional().await?.is_some();
                if has_mfa && !session.mfa_verified { return Ok(false); }

                if let Some(first) = changes.first_name.as_ref() {
                    tx.exec("UPDATE auth_user SET first_name = $first_name WHERE id = $user_id")
                        .param("$first_name", first.to_owned()).param("$user_id", user_id).await?;
                }
                if let Some(last) = changes.last_name.as_ref() {
                    tx.exec("UPDATE auth_user SET last_name = $last_name WHERE id = $user_id")
                        .param("$last_name", last.to_owned()).param("$user_id", user_id).await?;
                }
                if changes.ensure_profile {
                    let mut stream = tx.query("SELECT id FROM accounts_userprofile VIEW acct_profile_user_idx WHERE user_id = $user_id LIMIT 2")
                        .param("$user_id", user_id).await?;
                    let mut profile_ids: Vec<i64> = Vec::with_capacity(2);
                    while let Some(rows) = stream.next_result_set().await? {
                        for mut row in rows {
                            profile_ids.push(row.remove_field_by_name("id")?.try_into()?);
                        }
                    }
                    stream.close().await?;
                    if profile_ids.len() > 1 {
                        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("ambiguous profile ownership")));
                    }
                    if let Some(profile_id) = profile_ids.pop() {
                        if let Some(phone) = changes.phone_number.as_ref() {
                            tx.exec("UPDATE accounts_userprofile SET phone_number = $phone, phone_verified = false, updated_at = CurrentUtcDatetime() WHERE id = $id")
                                .param("$phone", phone.to_owned()).param("$id", profile_id).await?;
                        }
                        if let Some(birth) = changes.birth_date.as_ref() {
                            tx.exec("UPDATE accounts_userprofile SET birth_date = CAST($birth AS Date), updated_at = CurrentUtcDatetime() WHERE id = $id")
                                .param("$birth", birth.to_owned()).param("$id", profile_id).await?;
                        }
                    } else if let Some(birth) = changes.birth_date.as_ref() {
                        tx.exec("INSERT INTO accounts_userprofile (user_id, avatar_source, gravatar_enabled, phone_number, phone_verified, birth_date, created_at, updated_at) VALUES ($user_id, 'none', true, $phone, false, CAST($birth AS Date), CurrentUtcDatetime(), CurrentUtcDatetime())")
                            .param("$user_id", user_id)
                            .param("$phone", changes.phone_number.clone().unwrap_or_default())
                            .param("$birth", birth.to_owned()).await?;
                    } else {
                        tx.exec("INSERT INTO accounts_userprofile (user_id, avatar_source, gravatar_enabled, phone_number, phone_verified, created_at, updated_at) VALUES ($user_id, 'none', true, $phone, false, CurrentUtcDatetime(), CurrentUtcDatetime())")
                            .param("$user_id", user_id)
                            .param("$phone", changes.phone_number.clone().unwrap_or_default()).await?;
                    }
                }
                Ok(true)
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
                .timeout(Duration::from_secs(10)).await
        }
    }).await
}
