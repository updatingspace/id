//! Durable account-deletion acceptance: revoke access first, clean data in jobs.

use crate::{
    cache_store::CacheStore,
    password_change::revoke_credentials,
    session_issuer::{MfaVerdict, check_and_consume_mfa},
    session_store::{LEGACY_BACKENDS, restore_django_session_tx},
    tx_retry::retry_known_abort,
};
use anyhow::{Context, Result, ensure};
use hmac::{Hmac, Mac};
use id_compat::{mfa_seal::MfaSealKey, session::SessionCodec};
use serde::Serialize;
use sha2::Sha256;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::sync::Semaphore;
use ydb::{Client, Transaction, TxMode, closure};

#[derive(Debug, PartialEq, Eq)]
pub enum DeletionResult {
    Accepted {
        id: i64,
        status: String,
        existing: bool,
    },
    Unauthorized,
    WrongPassword,
    MfaRequired,
    WrongMfa,
    Stale,
}

#[derive(Debug, Serialize)]
pub struct DeletionStatus {
    pub id: String,
    pub status: String,
    pub cleanup_completed: bool,
}

pub async fn read_status(client: &Client, id: i64) -> Result<Option<DeletionStatus>> {
    let Some(mut row) = client
        .query_client()
        .query_row("SELECT status, executed_at FROM accounts_accountdeletionrequest WHERE id = $id")
        .param("$id", id)
        .optional()
        .await?
    else {
        return Ok(None);
    };
    let status: String = row.remove_field_by_name("status")?.try_into()?;
    let executed_at: Option<SystemTime> = row.remove_field_by_name("executed_at")?.try_into()?;
    Ok(Some(DeletionStatus {
        id: id.to_string(),
        // Legacy Python's `executed` did not prove media or dependent cleanup.
        cleanup_completed: status == "succeeded" && executed_at.is_some(),
        status,
    }))
}

struct CommitInput {
    token: String,
    account_id: i32,
    id: i64,
    old_hash: String,
    code: Option<String>,
    reason: String,
    now: SystemTime,
}

pub struct AccountDeletion {
    client: Arc<Client>,
    codec: Arc<SessionCodec>,
    cache: CacheStore,
    seal_key: Option<Arc<MfaSealKey>>,
    operation_key: Vec<u8>,
    hashing_slots: Arc<Semaphore>,
}

impl AccountDeletion {
    pub fn new(
        client: Arc<Client>,
        codec: Arc<SessionCodec>,
        cache: CacheStore,
        seal_key: Option<Arc<MfaSealKey>>,
        operation_key: &[u8],
        max_parallel_hashes: usize,
    ) -> Result<Self> {
        ensure!(
            operation_key.len() >= 32,
            "account deletion operation key is too short"
        );
        ensure!(
            (1..=4).contains(&max_parallel_hashes),
            "password hashing parallelism must be 1..=4"
        );
        Ok(Self {
            client,
            codec,
            cache,
            seal_key,
            operation_key: operation_key.to_vec(),
            hashing_slots: Arc::new(Semaphore::new(max_parallel_hashes)),
        })
    }

    pub async fn request(
        &self,
        session_key: &str,
        idempotency_key: &str,
        password: &str,
        mfa_code: Option<&str>,
        reason: Option<&str>,
        now: SystemTime,
    ) -> Result<DeletionResult> {
        if session_key.len() != 32
            || !session_key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            || idempotency_key.is_empty()
            || idempotency_key.len() > 128
            || !idempotency_key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || password.is_empty()
            || password.len() > 4096
            || mfa_code.is_some_and(|code| code.len() > 128)
            || reason.is_some_and(|value| value.chars().count() > 256)
        {
            return Ok(DeletionResult::Unauthorized);
        }
        let operation_id = self.operation_id(session_key, idempotency_key)?;
        let Some((account_id, password_hash)) = self.read_hash(session_key, now).await? else {
            return self.existing(session_key, operation_id).await;
        };
        let permit = self
            .hashing_slots
            .clone()
            .acquire_owned()
            .await
            .context("account deletion hashing pool closed")?;
        let password = password.to_owned();
        let stored_hash = password_hash.clone();
        let verified = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            id_compat::password::verify(&password, &stored_hash)
        })
        .await
        .context("account deletion password task failed")??;
        if !verified {
            return Ok(DeletionResult::WrongPassword);
        }
        let result = self
            .commit(CommitInput {
                token: session_key.to_owned(),
                account_id,
                id: operation_id,
                old_hash: password_hash,
                code: mfa_code.map(|value| value.trim().replace(' ', "")),
                reason: reason.unwrap_or("").to_owned(),
                now,
            })
            .await?;
        if result == DeletionResult::Unauthorized {
            self.existing(session_key, operation_id).await
        } else {
            Ok(result)
        }
    }

    fn operation_id(&self, session_key: &str, idempotency_key: &str) -> Result<i64> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.operation_key)?;
        mac.update(b"account-deletion-v1\0");
        mac.update(session_key.as_bytes());
        mac.update(b"\0");
        mac.update(idempotency_key.as_bytes());
        let digest = mac.finalize().into_bytes();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&digest[..8]);
        Ok(((u64::from_be_bytes(bytes) & ((1u64 << 62) - 1)) | (1u64 << 62)) as i64)
    }

    async fn read_hash(&self, token: &str, now: SystemTime) -> Result<Option<(i32, String)>> {
        let token = token.to_owned();
        let codec = self.codec.clone();
        let backends = LEGACY_BACKENDS
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        self.client.query_client().retry_tx(closure!([token, codec, backends], async |tx: &mut Transaction| {
            let Some(session) = restore_django_session_tx(tx, codec.as_ref(), token, backends, now).await? else { return Ok(None); };
            let account_id = i32::try_from(session.principal.account_id.get())
                .map_err(ydb::YdbOrCustomerError::from_err)?;
            let has_mfa = tx.query_row("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $id LIMIT 1")
                .param("$id", account_id).optional().await?.is_some();
            if has_mfa && !session.mfa_verified { return Ok(None); }
            let Some(mut row) = tx.query_row("SELECT password FROM auth_user WHERE id = $id")
                .param("$id", account_id).optional().await? else { return Ok(None); };
            let hash: String = row.remove_field_by_name("password")?.try_into()?;
            Ok(Some((account_id, hash)))
        })).isolation(TxMode::SerializableReadWrite).timeout(Duration::from_secs(10)).await
            .context("read account deletion password hash")
    }

    async fn existing(&self, session_key: &str, id: i64) -> Result<DeletionResult> {
        // The HMAC operation ID already binds this session token and the
        // idempotency key. A finished receipt intentionally has no owner row.
        if let Some(mut receipt) = self
            .client
            .query_client()
            .query_row("SELECT user_id, status FROM accounts_accountdeletionrequest WHERE id = $id")
            .param("$id", id)
            .optional()
            .await?
        {
            let owner: i32 = receipt.remove_field_by_name("user_id")?.try_into()?;
            let status: String = receipt.remove_field_by_name("status")?.try_into()?;
            if owner == 0 && status == "succeeded" {
                return Ok(DeletionResult::Accepted {
                    id,
                    status,
                    existing: true,
                });
            }
        }
        let mut query_client = self.client.query_client();
        let mut meta = query_client.query("SELECT user_id FROM core_usersessionmeta VIEW core_usersessionmeta_session_key_2f41cf47 WHERE session_key = $key LIMIT 2")
            .param("$key", session_key.to_owned()).await?;
        let mut owners: Vec<i32> = Vec::new();
        while let Some(rows) = meta.next_result_set().await? {
            for mut row in rows {
                owners.push(row.remove_field_by_name("user_id")?.try_into()?);
            }
        }
        meta.close().await?;
        let [owner] = owners.as_slice() else {
            return Ok(DeletionResult::Unauthorized);
        };
        let Some(mut request) = self
            .client
            .query_client()
            .query_row("SELECT user_id, status FROM accounts_accountdeletionrequest WHERE id = $id")
            .param("$id", id)
            .optional()
            .await?
        else {
            return Ok(DeletionResult::Unauthorized);
        };
        let user_id: i32 = request.remove_field_by_name("user_id")?.try_into()?;
        let status: String = request.remove_field_by_name("status")?.try_into()?;
        if user_id != *owner || status == "canceled" {
            return Ok(DeletionResult::Unauthorized);
        }
        Ok(DeletionResult::Accepted {
            id,
            status,
            existing: true,
        })
    }

    async fn commit(&self, input: CommitInput) -> Result<DeletionResult> {
        let CommitInput {
            token,
            account_id,
            id,
            old_hash,
            code,
            reason,
            now,
        } = input;
        let codec = self.codec.clone();
        let cache = self.cache.clone();
        let seal_key = self.seal_key.clone();
        let backends = LEGACY_BACKENDS
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        retry_known_abort(|| {
            let token = token.clone();
            let old_hash = old_hash.clone();
            let code = code.clone();
            let reason = reason.clone();
            let codec = codec.clone();
            let cache = cache.clone();
            let seal_key = seal_key.clone();
            let backends = backends.clone();
            async {
                self.client.query_client().retry_tx(closure!([token, old_hash, code, reason, codec, cache, seal_key, backends], async |tx: &mut Transaction| {
                    let Some(session) = restore_django_session_tx(tx, codec.as_ref(), token, backends, now).await? else { return Ok(DeletionResult::Unauthorized); };
                    if session.principal.account_id.get() != i64::from(account_id) { return Ok(DeletionResult::Unauthorized); }
                    let Some(mut account) = tx.query_row("SELECT password FROM auth_user WHERE id = $id")
                        .param("$id", account_id).optional().await? else { return Ok(DeletionResult::Unauthorized); };
                    let actual_hash: String = account.remove_field_by_name("password")?.try_into()?;
                    if actual_hash != *old_hash { return Ok(DeletionResult::Stale); }
                    let verdict = check_and_consume_mfa(tx, account_id, code.as_deref(), Some(cache), seal_key.as_deref(), now).await?;
                    match verdict {
                        MfaVerdict::Reject if code.is_none() => return Ok(DeletionResult::MfaRequired),
                        MfaVerdict::Reject | MfaVerdict::Webauthn => return Ok(DeletionResult::WrongMfa),
                        MfaVerdict::NoMfa | MfaVerdict::Totp | MfaVerdict::Recovery => {},
                    }
                    let existing = tx.query_row("SELECT id FROM accounts_accountdeletionrequest VIEW accounts_accountdeletionrequest_user_id_6a166c52 WHERE user_id = $id AND status != 'canceled' LIMIT 1")
                        .param("$id", account_id).optional().await?.is_some();
                    if existing { return Ok(DeletionResult::Unauthorized); }
                    tx.exec("INSERT INTO accounts_accountdeletionrequest (id, user_id, status, requested_at, reason) VALUES ($id, $user_id, 'pending', CAST($now AS Datetime), $reason)")
                        .param("$id", id).param("$user_id", account_id)
                        .param("$now", now).param("$reason", reason.clone()).await?;
                    tx.exec("UPDATE auth_user SET is_active = false WHERE id = $id")
                        .param("$id", account_id).await?;
                    tx.exec("UPDATE usid_user SET status = 'suspended' WHERE user_id = $id")
                        .param("$id", session.principal.identity_id.get()).await?;
                    revoke_credentials(tx, account_id, now, "account_deleted").await?;
                    Ok(DeletionResult::Accepted { id, status: "pending".into(), existing: false })
                })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
                    .timeout(Duration::from_secs(30)).await
            }
        }).await.context("accept account deletion")
    }
}
