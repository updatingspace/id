//! Password changes on the transition YDB schema. The current password is
//! verified off the executor, then its exact stored hash is rechecked before
//! changing it and revoking credentials in one serializable transaction.

use crate::{
    password_policy::{AccountWords, acceptable},
    security_mail,
    session_store::{LEGACY_BACKENDS, restore_django_session_tx},
    tx_retry::retry_known_abort,
};
use anyhow::{Context, Result};
use id_compat::session::SessionCodec;
use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::sync::Semaphore;
use uuid::Uuid;
use ydb::{Client, Transaction, TxMode, closure};

#[derive(Debug, PartialEq, Eq)]
pub enum ChangeResult {
    Unauthorized,
    WrongCurrent,
    WeakNew,
    Stale,
    Changed,
}

pub struct PasswordChanger {
    client: Arc<Client>,
    codec: Arc<SessionCodec>,
    hashing_slots: Arc<Semaphore>,
}

impl PasswordChanger {
    pub fn new(
        client: Arc<Client>,
        codec: Arc<SessionCodec>,
        max_parallel_hashes: usize,
    ) -> Result<Self> {
        anyhow::ensure!(
            (1..=4).contains(&max_parallel_hashes),
            "password hashing parallelism must be 1..=4"
        );
        Ok(Self {
            client,
            codec,
            hashing_slots: Arc::new(Semaphore::new(max_parallel_hashes)),
        })
    }

    pub async fn change(
        &self,
        token: &str,
        current: &str,
        new: &str,
        now: SystemTime,
    ) -> Result<ChangeResult> {
        if token.is_empty() || token.len() > 256 || current.len() > 4096 || new.len() > 4096 {
            return Ok(ChangeResult::Unauthorized);
        }
        let Some((user_id, old_hash, account_words)) =
            read_current_hash(&self.client, self.codec.clone(), token, now).await?
        else {
            return Ok(ChangeResult::Unauthorized);
        };
        let permit = self
            .hashing_slots
            .clone()
            .acquire_owned()
            .await
            .context("password hashing pool closed")?;
        let current = current.to_owned();
        let new = new.to_owned();
        let old_hash_for_hashing = old_hash.clone();
        let prepared = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            if !id_compat::password::verify(&current, &old_hash_for_hashing)? {
                return Ok::<_, id_compat::Error>(Err(ChangeResult::WrongCurrent));
            }
            if !acceptable(&new, &current, &account_words) {
                return Ok(Err(ChangeResult::WeakNew));
            }
            Ok(Ok(id_compat::password::hash_new(&new)?))
        })
        .await
        .context("password hashing task failed")??;
        let new_hash = match prepared {
            Ok(hash) => hash,
            Err(result) => return Ok(result),
        };
        commit_change(
            &self.client,
            self.codec.clone(),
            token,
            user_id,
            &old_hash,
            &new_hash,
            now,
        )
        .await
    }
}

async fn read_current_hash(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: &str,
    now: SystemTime,
) -> Result<Option<(i32, String, AccountWords)>> {
    let token = token.to_owned();
    let backends = LEGACY_BACKENDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    client.query_client().retry_tx(closure!([codec, token, backends], async |tx: &mut Transaction| {
        let Some(session) = restore_django_session_tx(tx, codec.as_ref(), token, backends, now).await? else { return Ok(None); };
        let user_id = i32::try_from(session.principal.account_id.get()).map_err(ydb::YdbOrCustomerError::from_err)?;
        let has_mfa = tx.query_row("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $user_id LIMIT 1")
            .param("$user_id", user_id).optional().await?.is_some();
        if has_mfa && !session.mfa_verified { return Ok(None); }
        let Some(mut account) = tx.query_row("SELECT password, username, email, first_name, last_name FROM auth_user WHERE id = $user_id")
            .param("$user_id", user_id).optional().await? else { return Ok(None); };
        let hash: String = account.remove_field_by_name("password")?.try_into()?;
        let words = AccountWords {
            username: account.remove_field_by_name("username")?.try_into()?,
            email: account.remove_field_by_name("email")?.try_into()?,
            first_name: account.remove_field_by_name("first_name")?.try_into()?,
            last_name: account.remove_field_by_name("last_name")?.try_into()?,
        };
        Ok(Some((user_id, hash, words)))
    })).isolation(TxMode::SerializableReadWrite).timeout(Duration::from_secs(10)).await
        .context("read password change preflight")
}

async fn commit_change(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: &str,
    user_id: i32,
    old_hash: &str,
    new_hash: &str,
    now: SystemTime,
) -> Result<ChangeResult> {
    let token = token.to_owned();
    let old_hash = old_hash.to_owned();
    let new_hash = new_hash.to_owned();
    let mail_id = Uuid::new_v4().to_string();
    let backends = LEGACY_BACKENDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    retry_known_abort(|| {
        let token = token.clone();
        let codec = codec.clone();
        let old_hash = old_hash.clone();
        let new_hash = new_hash.clone();
        let mail_id = mail_id.clone();
        let backends = backends.clone();
        async {
            client.query_client().retry_tx(closure!([token, codec, old_hash, new_hash, backends, mail_id], async |tx: &mut Transaction| {
                let Some(session) = restore_django_session_tx(tx, codec.as_ref(), token, backends, now).await? else { return Ok(ChangeResult::Unauthorized); };
                if session.principal.account_id.get() != i64::from(user_id) { return Ok(ChangeResult::Unauthorized); }
                let has_mfa = tx.query_row("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $user_id LIMIT 1")
                    .param("$user_id", user_id).optional().await?.is_some();
                if has_mfa && !session.mfa_verified { return Ok(ChangeResult::Unauthorized); }
                let Some(mut account) = tx.query_row("SELECT password, email FROM auth_user WHERE id = $user_id")
                    .param("$user_id", user_id).optional().await? else { return Ok(ChangeResult::Unauthorized); };
                let actual: String = account.remove_field_by_name("password")?.try_into()?;
                if actual != old_hash.as_str() { return Ok(ChangeResult::Stale); }
                let recipient: String = account.remove_field_by_name("email")?.try_into()?;
                if !security_mail::valid_recipient(&recipient) {
                    return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("password change notification recipient invalid")));
                }
                tx.exec("UPDATE auth_user SET password = $hash WHERE id = $user_id")
                    .param("$hash", new_hash.clone()).param("$user_id", user_id).await?;
                revoke_credentials(tx, user_id, now, "password_changed").await?;
                security_mail::enqueue_tx(tx, mail_id, user_id, &recipient, "password_changed", now).await?;
                Ok(ChangeResult::Changed)
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
                .timeout(Duration::from_secs(30)).await
        }
    }).await.context("commit password change")
}

async fn ids(
    tx: &mut Transaction,
    statement: &str,
    user_id: i32,
    field: &str,
) -> ydb::YdbResultWithCustomerErr<Vec<i64>> {
    let mut query = tx.query(statement).param("$user_id", user_id).await?;
    let mut result = Vec::new();
    while let Some(rows) = query.next_result_set().await? {
        for mut row in rows {
            result.push(row.remove_field_by_name(field)?.try_into()?);
        }
    }
    query.close().await?;
    Ok(result)
}

async fn strings(
    tx: &mut Transaction,
    statement: &str,
    user_id: i32,
    field: &str,
) -> ydb::YdbResultWithCustomerErr<Vec<String>> {
    let mut query = tx.query(statement).param("$user_id", user_id).await?;
    let mut result = Vec::new();
    while let Some(rows) = query.next_result_set().await? {
        for mut row in rows {
            result.push(row.remove_field_by_name(field)?.try_into()?);
        }
    }
    query.close().await?;
    Ok(result)
}

pub(crate) async fn revoke_credentials(
    tx: &mut Transaction,
    user_id: i32,
    now: SystemTime,
    reason: &str,
) -> ydb::YdbResultWithCustomerErr<()> {
    let mut session_keys = BTreeSet::new();
    let mut metadata = tx.query("SELECT id, session_key, revoked_at FROM core_usersessionmeta VIEW core_usersessionmeta_user_id_9dceac03 WHERE user_id = $user_id")
        .param("$user_id", user_id).await?;
    let mut metadata_ids = Vec::new();
    while let Some(rows) = metadata.next_result_set().await? {
        for mut row in rows {
            let id: i64 = row.remove_field_by_name("id")?.try_into()?;
            let key: String = row.remove_field_by_name("session_key")?.try_into()?;
            let revoked: Option<SystemTime> = row.remove_field_by_name("revoked_at")?.try_into()?;
            session_keys.insert(key);
            if revoked.is_none() {
                metadata_ids.push(id);
            }
        }
    }
    metadata.close().await?;
    for id in metadata_ids {
        tx.exec("UPDATE core_usersessionmeta SET revoked_at = CAST($now AS Datetime), revoked_reason = $reason WHERE id = $id")
            .param("$now", now).param("$reason", reason.to_owned()).param("$id", id).await?;
    }
    let tracked = strings(tx, "SELECT session_key FROM usersessions_usersession VIEW usersessions_usersession_user_id_af5e0a6d WHERE user_id = $user_id", user_id, "session_key").await?;
    session_keys.extend(tracked);
    for key in session_keys {
        tx.exec("DELETE FROM django_session WHERE session_key = $key")
            .param("$key", key)
            .await?;
    }
    for id in ids(tx, "SELECT id FROM usersessions_usersession VIEW usersessions_usersession_user_id_af5e0a6d WHERE user_id = $user_id", user_id, "id").await? {
        tx.exec("DELETE FROM usersessions_usersession WHERE id = $id").param("$id", id).await?;
    }
    for id in ids(tx, "SELECT id FROM core_usersessiontoken VIEW core_usersessiontoken_user_id_2e52e0f5 WHERE user_id = $user_id AND revoked_at IS NULL", user_id, "id").await? {
        tx.exec("UPDATE core_usersessiontoken SET revoked_at = CAST($now AS Datetime) WHERE id = $id")
            .param("$now", now).param("$id", id).await?;
    }
    for id in ids(tx, "SELECT id FROM token_blacklist_outstandingtoken VIEW token_blacklist_outstandingtoken_user_id_83bc629a WHERE user_id = $user_id", user_id, "id").await? {
        let already = tx.query_row("SELECT id FROM token_blacklist_blacklistedtoken WHERE token_id = $id LIMIT 1")
            .param("$id", id).optional().await?.is_some();
        if !already {
            let blacklist_id = ((rand::random::<u64>() & ((1u64 << 62) - 1)) | (1u64 << 62)) as i64;
            tx.exec("INSERT INTO token_blacklist_blacklistedtoken (id, token_id, blacklisted_at) VALUES ($id, $token_id, CAST($now AS Datetime))")
                .param("$id", blacklist_id).param("$token_id", id).param("$now", now).await?;
        }
    }
    for id in ids(
        tx,
        "SELECT id FROM idp_oidctoken VIEW oidc_token_user_client_idx WHERE user_id = $user_id",
        user_id,
        "id",
    )
    .await?
    {
        tx.exec("UPDATE idp_oidctoken SET revoked_at = CAST($now AS Datetime) WHERE id = $id AND revoked_at IS NULL")
            .param("$now", now).param("$id", id).await?;
    }
    for code in strings(tx, "SELECT code FROM idp_oidcauthorizationcode VIEW oidc_code_user_idx WHERE user_id = $user_id", user_id, "code").await? {
        tx.exec("UPDATE idp_oidcauthorizationcode SET used_at = CAST($now AS Datetime) WHERE code = $code AND used_at IS NULL")
            .param("$now", now).param("$code", code).await?;
    }
    for id in strings(tx, "SELECT request_id FROM idp_oidcauthorizationrequest VIEW oidc_req_user_idx WHERE user_id = $user_id", user_id, "request_id").await? {
        tx.exec("DELETE FROM idp_oidcauthorizationrequest WHERE request_id = $id").param("$id", id).await?;
    }
    Ok(())
}
