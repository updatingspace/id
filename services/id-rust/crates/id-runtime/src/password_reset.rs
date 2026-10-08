//! One-time password recovery intent. The email contains an HMAC-authenticated
//! row ID; neither YDB nor the mail outbox stores a usable bearer credential.

use crate::{
    new_device_mail::DrainResult,
    password_change::revoke_credentials,
    password_mail,
    password_policy::{AccountWords, acceptable},
    tx_retry::retry_known_abort,
};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentTransferEncoding},
};
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::sync::Semaphore;
use url::Url;
use uuid::Uuid;
use ydb::{Client, IndexStatus, IndexType, Transaction, TxMode, Value, closure};

pub const TABLE: &str = "id_password_reset";
const DUE_INDEX: &str = "id_password_reset_due_idx";
const EXPIRY_INDEX: &str = "id_password_reset_expiry_idx";
const LINK_TTL: Duration = Duration::from_secs(3600);

// Intentionally no Debug implementation: this key is a credential.
#[derive(Clone)]
pub struct ResetKey(Arc<[u8; 32]>);

impl ResetKey {
    pub fn from_env() -> Result<Self> {
        let encoded = std::env::var("ID_PASSWORD_RESET_HMAC_KEY")
            .context("ID_PASSWORD_RESET_HMAC_KEY required")?;
        let bytes = hex::decode(encoded).context("invalid password reset key encoding")?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("password reset key must be 32 bytes"))?;
        Self::new(key)
    }

    pub fn new(bytes: [u8; 32]) -> Result<Self> {
        ensure!(
            bytes.iter().any(|byte| *byte != 0),
            "password reset key cannot be zero"
        );
        Ok(Self(Arc::new(bytes)))
    }

    pub fn issue(&self, id: Uuid) -> Result<String> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.0.as_ref())
            .map_err(|_| anyhow::anyhow!("invalid password reset HMAC key"))?;
        mac.update(b"updspace-id-password-reset-v1:");
        mac.update(id.as_bytes());
        Ok(format!(
            "{}.{}",
            id,
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        ))
    }

    pub fn verify(&self, token: &str) -> Option<Uuid> {
        if token.len() > 128 {
            return None;
        }
        let (id, signature) = token.split_once('.')?;
        let id = Uuid::parse_str(id).ok()?;
        let bytes = URL_SAFE_NO_PAD.decode(signature).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(self.0.as_ref()).ok()?;
        mac.update(b"updspace-id-password-reset-v1:");
        mac.update(id.as_bytes());
        mac.verify_slice(&bytes).ok()?;
        Some(id)
    }
}

fn password_version(hash: &str) -> String {
    hex::encode(Sha256::digest(hash.as_bytes()))
}

/// Additive, repeatable YDB schema step. The due index is also queried to
/// ensure a pre-existing but unready or incorrectly shaped index fails closed.
pub async fn ensure_schema(client: &Client) -> Result<()> {
    client.query_client().exec(format!(
        "CREATE TABLE IF NOT EXISTS `{TABLE}` (id Utf8 NOT NULL, user_id Int32 NOT NULL, recipient Utf8 NOT NULL, password_version Utf8 NOT NULL, expires_at Datetime NOT NULL, consumed_at Datetime, status Utf8 NOT NULL, attempts Int32 NOT NULL, next_attempt_at Datetime NOT NULL, lease_until Datetime, claim_token Utf8 NOT NULL, created_at Datetime NOT NULL, INDEX `{DUE_INDEX}` GLOBAL ON (status, next_attempt_at), INDEX `{EXPIRY_INDEX}` GLOBAL ON (expires_at), PRIMARY KEY (id))"
    )).timeout(Duration::from_secs(15)).await?;
    let description = client
        .table_client()
        .describe_table(format!("{}/{TABLE}", client.database()))
        .await?;
    ensure!(
        description.primary_key == ["id"],
        "password reset primary key drift"
    );
    let columns: std::collections::BTreeSet<_> = description
        .columns
        .iter()
        .map(|column| column.name.as_str())
        .collect();
    ensure!(
        columns
            == [
                "id",
                "user_id",
                "recipient",
                "password_version",
                "expires_at",
                "consumed_at",
                "status",
                "attempts",
                "next_attempt_at",
                "lease_until",
                "claim_token",
                "created_at"
            ]
            .into_iter()
            .collect(),
        "password reset columns drift"
    );
    for (name, kind, nullable) in [
        ("id", "text", false),
        ("user_id", "int32", false),
        ("recipient", "text", false),
        ("password_version", "text", false),
        ("expires_at", "datetime", false),
        ("consumed_at", "datetime", true),
        ("status", "text", false),
        ("attempts", "int32", false),
        ("next_attempt_at", "datetime", false),
        ("lease_until", "datetime", true),
        ("claim_token", "text", false),
        ("created_at", "datetime", false),
    ] {
        let column = description
            .columns
            .iter()
            .find(|column| column.name == name)
            .context("password reset column missing")?;
        let value = column
            .type_value
            .as_ref()
            .map_err(|_| anyhow::anyhow!("password reset column type unsupported: {name}"))?;
        ensure!(
            value.is_optional() == nullable,
            "password reset nullability drift: {name}"
        );
        if !nullable {
            ensure!(
                matches!(
                    (kind, value),
                    ("text", Value::Text(_))
                        | ("int32", Value::Int32(_))
                        | ("datetime", Value::DateTime(_))
                ),
                "password reset column type drift: {name}"
            );
        }
    }
    let index = description
        .indexes
        .iter()
        .find(|index| index.name == DUE_INDEX)
        .context("password reset due index missing")?;
    ensure!(
        index.index_columns == ["status", "next_attempt_at"]
            && index.index_type == IndexType::Global
            && index.status == IndexStatus::Ready,
        "password reset due index drift or not ready"
    );
    let expiry = description
        .indexes
        .iter()
        .find(|index| index.name == EXPIRY_INDEX)
        .context("password reset expiry index missing")?;
    ensure!(
        expiry.index_columns == ["expires_at"]
            && expiry.index_type == IndexType::Global
            && expiry.status == IndexStatus::Ready,
        "password reset expiry index drift or not ready"
    );
    let mut query_client = client.query_client();
    let mut query = query_client.query(format!("SELECT id FROM `{TABLE}` VIEW `{DUE_INDEX}` WHERE status = 'pending' AND next_attempt_at <= CurrentUtcDatetime() LIMIT 1")).await?;
    while query.next_result_set().await?.is_some() {}
    query.close().await?;
    let mut expiry_check = query_client
        .query(format!(
            "SELECT id FROM `{TABLE}` VIEW `{EXPIRY_INDEX}` WHERE expires_at <= CurrentUtcDatetime() LIMIT 1"
        ))
        .await?;
    while expiry_check.next_result_set().await?.is_some() {}
    expiry_check.close().await?;
    Ok(())
}

/// A generic response must be returned regardless of whether the address is
/// known, inactive, unverified or ambiguous. Storage failures are not hidden.
pub async fn request(client: &Client, email: &str, now: SystemTime) -> Result<()> {
    let email = email.trim().to_lowercase();
    ensure!(
        email.len() <= 254 && password_mail::valid_recipient(&email),
        "invalid reset email"
    );
    let id = Uuid::new_v4().to_string();
    let expires = now.checked_add(LINK_TTL).context("reset expiry overflow")?;
    retry_known_abort(|| {
        let email = email.clone();
        let id = id.clone();
        async {
            client.query_client().retry_tx(closure!([email, id], async |tx: &mut Transaction| {
                let mut query = tx.query("SELECT user_id FROM accounts_accountemaillookup VIEW acct_email_key_idx WHERE email_key = $email LIMIT 2")
                    .param("$email", email.clone()).await?;
                let mut ids = Vec::<i32>::new();
                while let Some(rows) = query.next_result_set().await? {
                    for mut row in rows { ids.push(row.remove_field_by_name("user_id")?.try_into()?); }
                }
                query.close().await?;
                if ids.len() != 1 { return Ok(()); }
                let user_id = ids[0];
                let Some(mut account) = tx.query_row("SELECT email, password, is_active FROM auth_user WHERE id = $id")
                    .param("$id", user_id).optional().await? else { return Ok(()); };
                let stored_email: String = account.remove_field_by_name("email")?.try_into()?;
                let hash: String = account.remove_field_by_name("password")?.try_into()?;
                let active: bool = account.remove_field_by_name("is_active")?.try_into()?;
                if !active || stored_email.trim().to_lowercase() != email.as_str() { return Ok(()); }
                let verified = tx.query_row("SELECT id FROM account_emailaddress VIEW account_emailaddress_user_id_2c513194 WHERE user_id = $id AND Unicode::ToLower(email) = $email AND verified = true LIMIT 1")
                    .param("$id", user_id).param("$email", email.clone()).optional().await?.is_some();
                if !verified { return Ok(()); }
                let mut deletion = tx.query_row("SELECT COUNT(*) AS count FROM accounts_accountdeletionrequest VIEW accounts_accountdeletionrequest_user_id_6a166c52 WHERE user_id = $id AND status != 'canceled'")
                    .param("$id", user_id).await?;
                let deletions: u64 = deletion.remove_field_by_name("count")?.try_into()?;
                if deletions != 0 { return Ok(()); }
                tx.exec(format!("INSERT INTO `{TABLE}` (id, user_id, recipient, password_version, expires_at, status, attempts, next_attempt_at, claim_token, created_at) VALUES ($id, $user_id, $recipient, $version, CAST($expires AS Datetime), 'pending', 0, CAST($now AS Datetime), '', CAST($now AS Datetime))"))
                    .param("$id", id.clone()).param("$user_id", user_id).param("$recipient", stored_email)
                    .param("$version", password_version(&hash)).param("$expires", expires).param("$now", now).await?;
                Ok(())
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(15)).await
        }
    }).await.context("create password reset intent")
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConfirmResult {
    Changed,
    Invalid,
    WeakPassword,
}

struct Candidate {
    user_id: i32,
    old_hash: String,
    words: AccountWords,
}

async fn candidate(client: &Client, id: &str, now: SystemTime) -> Result<Option<Candidate>> {
    let id = id.to_owned();
    client.query_client().retry_tx(closure!([id], async |tx: &mut Transaction| {
        let Some(mut reset) = tx.query_row(format!("SELECT user_id, password_version, expires_at, consumed_at, status FROM `{TABLE}` WHERE id = $id"))
            .param("$id", id.clone()).optional().await? else { return Ok(None); };
        let user_id: i32 = reset.remove_field_by_name("user_id")?.try_into()?;
        let version: String = reset.remove_field_by_name("password_version")?.try_into()?;
        let expires: SystemTime = reset.remove_field_by_name("expires_at")?.try_into()?;
        let consumed: Option<SystemTime> = reset.remove_field_by_name("consumed_at")?.try_into()?;
        let status: String = reset.remove_field_by_name("status")?.try_into()?;
        if consumed.is_some() || expires <= now || !matches!(status.as_str(), "pending" | "sent") { return Ok(None); }
        let Some(mut account) = tx.query_row("SELECT password, username, email, first_name, last_name, is_active FROM auth_user WHERE id = $id")
            .param("$id", user_id).optional().await? else { return Ok(None); };
        let old_hash: String = account.remove_field_by_name("password")?.try_into()?;
        if version != password_version(&old_hash) { return Ok(None); }
        let active: bool = account.remove_field_by_name("is_active")?.try_into()?;
        if !active { return Ok(None); }
        let words = AccountWords {
            username: account.remove_field_by_name("username")?.try_into()?,
            email: account.remove_field_by_name("email")?.try_into()?,
            first_name: account.remove_field_by_name("first_name")?.try_into()?,
            last_name: account.remove_field_by_name("last_name")?.try_into()?,
        };
        Ok(Some(Candidate { user_id, old_hash, words }))
    })).isolation(TxMode::SerializableReadWrite).timeout(Duration::from_secs(10)).await
        .context("read password reset intent")
}

pub struct PasswordResetter {
    client: Arc<Client>,
    key: ResetKey,
    hashing_slots: Arc<Semaphore>,
}

impl PasswordResetter {
    pub fn new(client: Arc<Client>, key: ResetKey, max_parallel_hashes: usize) -> Result<Self> {
        ensure!(
            (1..=4).contains(&max_parallel_hashes),
            "password hashing parallelism must be 1..=4"
        );
        Ok(Self {
            client,
            key,
            hashing_slots: Arc::new(Semaphore::new(max_parallel_hashes)),
        })
    }

    pub async fn confirm(
        &self,
        token: &str,
        password: &str,
        now: SystemTime,
    ) -> Result<ConfirmResult> {
        if password.len() > 4096 {
            return Ok(ConfirmResult::WeakPassword);
        }
        let Some(id) = self.key.verify(token) else {
            return Ok(ConfirmResult::Invalid);
        };
        let Some(candidate) = candidate(&self.client, &id.to_string(), now).await? else {
            return Ok(ConfirmResult::Invalid);
        };
        let permit = self
            .hashing_slots
            .clone()
            .acquire_owned()
            .await
            .context("password hashing pool closed")?;
        let password = password.to_owned();
        let old_hash = candidate.old_hash.clone();
        let words = candidate.words;
        let prepared = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            if !acceptable(&password, "", &words)
                || id_compat::password::verify(&password, &old_hash)?
            {
                return Ok::<_, id_compat::Error>(None);
            }
            Ok(Some(id_compat::password::hash_new(&password)?))
        })
        .await
        .context("password hashing task failed")??;
        let Some(new_hash) = prepared else {
            return Ok(ConfirmResult::WeakPassword);
        };
        commit_confirm(
            &self.client,
            id,
            candidate.user_id,
            &candidate.old_hash,
            &new_hash,
            now,
        )
        .await
    }
}

async fn commit_confirm(
    client: &Client,
    id: Uuid,
    user_id: i32,
    old_hash: &str,
    new_hash: &str,
    now: SystemTime,
) -> Result<ConfirmResult> {
    let id = id.to_string();
    let old_version = password_version(old_hash);
    let new_hash = new_hash.to_owned();
    let mail_id = Uuid::new_v4().to_string();
    retry_known_abort(|| {
        let (id, old_version, new_hash, mail_id) = (id.clone(), old_version.clone(), new_hash.clone(), mail_id.clone());
        async {
            client.query_client().retry_tx(closure!([id, old_version, new_hash, mail_id], async |tx: &mut Transaction| {
                let Some(mut reset) = tx.query_row(format!("SELECT user_id, recipient, password_version, expires_at, consumed_at, status FROM `{TABLE}` WHERE id = $id"))
                    .param("$id", id.clone()).optional().await? else { return Ok(ConfirmResult::Invalid); };
                let owner: i32 = reset.remove_field_by_name("user_id")?.try_into()?;
                let recipient: String = reset.remove_field_by_name("recipient")?.try_into()?;
                let version: String = reset.remove_field_by_name("password_version")?.try_into()?;
                let expires: SystemTime = reset.remove_field_by_name("expires_at")?.try_into()?;
                let consumed: Option<SystemTime> = reset.remove_field_by_name("consumed_at")?.try_into()?;
                let status: String = reset.remove_field_by_name("status")?.try_into()?;
                if owner != user_id || version != old_version.as_str() || consumed.is_some() || expires <= now || !matches!(status.as_str(), "pending" | "sent") { return Ok(ConfirmResult::Invalid); }
                let Some(mut account) = tx.query_row("SELECT password, email, is_active FROM auth_user WHERE id = $id")
                    .param("$id", user_id).optional().await? else { return Ok(ConfirmResult::Invalid); };
                let current_hash: String = account.remove_field_by_name("password")?.try_into()?;
                let current_email: String = account.remove_field_by_name("email")?.try_into()?;
                let active: bool = account.remove_field_by_name("is_active")?.try_into()?;
                if !active || password_version(&current_hash) != old_version.as_str() || current_email != recipient { return Ok(ConfirmResult::Invalid); }
                let verified = tx.query_row("SELECT id FROM account_emailaddress VIEW account_emailaddress_user_id_2c513194 WHERE user_id = $id AND Unicode::ToLower(email) = $email AND verified = true LIMIT 1")
                    .param("$id", user_id).param("$email", recipient.to_lowercase()).optional().await?.is_some();
                if !verified { return Ok(ConfirmResult::Invalid); }
                let mut deletion = tx.query_row("SELECT COUNT(*) AS count FROM accounts_accountdeletionrequest VIEW accounts_accountdeletionrequest_user_id_6a166c52 WHERE user_id = $id AND status != 'canceled'")
                    .param("$id", user_id).await?;
                let deletions: u64 = deletion.remove_field_by_name("count")?.try_into()?;
                if deletions != 0 { return Ok(ConfirmResult::Invalid); }
                tx.exec("UPDATE auth_user SET password = $hash WHERE id = $id")
                    .param("$hash", new_hash.clone()).param("$id", user_id).await?;
                tx.exec(format!("UPDATE `{TABLE}` SET consumed_at = CAST($now AS Datetime), status = 'cancelled', recipient = Unwrap(CAST('' AS Utf8)), password_version = Unwrap(CAST('' AS Utf8)), claim_token = Unwrap(CAST('' AS Utf8)), lease_until = NULL WHERE id = $id"))
                    .param("$now", now).param("$id", id.clone()).await?;
                revoke_credentials(tx, user_id, now, "password_changed").await?;
                password_mail::enqueue_tx(tx, mail_id, user_id, &recipient, now).await?;
                Ok(ConfirmResult::Changed)
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(30)).await
        }
    }).await.context("commit password reset")
}

pub struct ResetMailConfig {
    key: ResetKey,
    page: Url,
}

impl ResetMailConfig {
    pub fn from_env() -> Result<Option<Self>> {
        if std::env::var("ID_PASSWORD_RESET_MAIL_ENABLED").as_deref() != Ok("true") {
            return Ok(None);
        }
        Self::new(
            ResetKey::from_env()?,
            &std::env::var("ID_PASSWORD_RESET_URL")?,
        )
        .map(Some)
    }

    pub fn new(key: ResetKey, url: &str) -> Result<Self> {
        let page = Url::parse(url).context("invalid password reset page URL")?;
        let local = matches!(page.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        ensure!(
            (page.scheme() == "https" || (local && page.scheme() == "http"))
                && page.path() == "/reset-password"
                && page.query().is_none()
                && page.fragment().is_none()
                && page.username().is_empty()
                && page.password().is_none(),
            "invalid password reset page URL"
        );
        Ok(Self { key, page })
    }

    fn link(&self, id: Uuid) -> Result<Url> {
        let mut link = self.page.clone();
        link.set_fragment(Some(&format!("key={}", self.key.issue(id)?)));
        Ok(link)
    }
}

pub async fn due_ids(client: &Client, now: SystemTime, limit: u64) -> Result<Vec<String>> {
    if limit == 0 || limit > 100 {
        bail!("password reset mail batch size must be 1..=100");
    }
    let mut query_client = client.query_client();
    let mut query = query_client.query(format!(
        "SELECT id FROM `{TABLE}` VIEW `{DUE_INDEX}` WHERE status = 'pending' AND next_attempt_at <= CAST($now AS Datetime) AND expires_at > CAST($now AS Datetime) AND (lease_until IS NULL OR lease_until <= CAST($now AS Datetime)) ORDER BY next_attempt_at LIMIT $limit"
    )).param("$now", now).param("$limit", limit).await?;
    let mut ids = Vec::new();
    while let Some(rows) = query.next_result_set().await? {
        for mut row in rows {
            ids.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    query.close().await?;
    Ok(ids)
}

pub async fn cleanup_expired(client: &Client, now: SystemTime, limit: u64) -> Result<usize> {
    if limit == 0 || limit > 100 {
        bail!("password reset cleanup batch size must be 1..=100");
    }
    let mut query_client = client.query_client();
    let mut query = query_client.query(format!(
        "SELECT id FROM `{TABLE}` VIEW `{EXPIRY_INDEX}` WHERE expires_at <= CAST($now AS Datetime) ORDER BY expires_at LIMIT $limit"
    )).param("$now", now).param("$limit", limit).await?;
    let mut ids = Vec::<String>::new();
    while let Some(rows) = query.next_result_set().await? {
        for mut row in rows {
            ids.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    query.close().await?;
    for id in &ids {
        client
            .query_client()
            .exec(format!(
                "DELETE FROM `{TABLE}` WHERE id = $id AND expires_at <= CAST($now AS Datetime)"
            ))
            .param("$id", id.clone())
            .param("$now", now)
            .await?;
    }
    Ok(ids.len())
}

async fn claim(client: &Client, id: &str, now: SystemTime) -> Result<Option<String>> {
    ensure!(
        Uuid::parse_str(id).is_ok(),
        "invalid password reset mail ID"
    );
    let id = id.to_owned();
    let claim_token = Uuid::new_v4().to_string();
    let lease_until = now
        .checked_add(Duration::from_secs(120))
        .context("reset mail lease overflow")?;
    let claimed = retry_known_abort(|| {
        let id = id.clone();
        let claim_token = claim_token.clone();
        async {
            client.query_client().retry_tx(closure!([id, claim_token], async |tx: &mut Transaction| {
                let Some(mut row) = tx.query_row(format!("SELECT status, next_attempt_at, expires_at, lease_until, consumed_at FROM `{TABLE}` WHERE id = $id"))
                    .param("$id", id.clone()).optional().await? else { return Ok(false); };
                let status: String = row.remove_field_by_name("status")?.try_into()?;
                let next: SystemTime = row.remove_field_by_name("next_attempt_at")?.try_into()?;
                let expires: SystemTime = row.remove_field_by_name("expires_at")?.try_into()?;
                let lease: Option<SystemTime> = row.remove_field_by_name("lease_until")?.try_into()?;
                let consumed: Option<SystemTime> = row.remove_field_by_name("consumed_at")?.try_into()?;
                if status != "pending" || next > now || expires <= now || consumed.is_some() || lease.is_some_and(|until| until > now) { return Ok(false); }
                tx.exec(format!("UPDATE `{TABLE}` SET claim_token = $token, lease_until = CAST($lease AS Datetime), attempts = attempts + 1 WHERE id = $id"))
                    .param("$id", id.clone()).param("$token", claim_token.clone()).param("$lease", lease_until).await?;
                Ok(true)
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(10)).await
        }
    }).await?;
    Ok(claimed.then_some(claim_token))
}

async fn recipient(client: &Client, id: &str, now: SystemTime) -> Result<Option<String>> {
    let id = id.to_owned();
    client.query_client().retry_tx(closure!([id], async |tx: &mut Transaction| {
        let Some(mut reset) = tx.query_row(format!("SELECT user_id, recipient, password_version, expires_at, consumed_at, status FROM `{TABLE}` WHERE id = $id"))
            .param("$id", id.clone()).optional().await? else { return Ok(None); };
        let user_id: i32 = reset.remove_field_by_name("user_id")?.try_into()?;
        let address: String = reset.remove_field_by_name("recipient")?.try_into()?;
        let version: String = reset.remove_field_by_name("password_version")?.try_into()?;
        let expires: SystemTime = reset.remove_field_by_name("expires_at")?.try_into()?;
        let consumed: Option<SystemTime> = reset.remove_field_by_name("consumed_at")?.try_into()?;
        let status: String = reset.remove_field_by_name("status")?.try_into()?;
        if expires <= now || consumed.is_some() || status != "pending" || !password_mail::valid_recipient(&address) { return Ok(None); }
        let Some(mut account) = tx.query_row("SELECT email, password, is_active FROM auth_user WHERE id = $id")
            .param("$id", user_id).optional().await? else { return Ok(None); };
        let email: String = account.remove_field_by_name("email")?.try_into()?;
        let hash: String = account.remove_field_by_name("password")?.try_into()?;
        let active: bool = account.remove_field_by_name("is_active")?.try_into()?;
        if !active || email != address || version != password_version(&hash) { return Ok(None); }
        let verified = tx.query_row("SELECT id FROM account_emailaddress VIEW account_emailaddress_user_id_2c513194 WHERE user_id = $id AND Unicode::ToLower(email) = $email AND verified = true LIMIT 1")
            .param("$id", user_id).param("$email", address.to_lowercase()).optional().await?.is_some();
        if !verified { return Ok(None); }
        let mut deletion = tx.query_row("SELECT COUNT(*) AS count FROM accounts_accountdeletionrequest VIEW accounts_accountdeletionrequest_user_id_6a166c52 WHERE user_id = $id AND status != 'canceled'")
            .param("$id", user_id).await?;
        let deletions: u64 = deletion.remove_field_by_name("count")?.try_into()?;
        Ok((deletions == 0).then_some(address))
    })).isolation(TxMode::SerializableReadWrite).timeout(Duration::from_secs(10)).await
        .context("read password reset mail recipient")
}

async fn finish(
    client: &Client,
    id: &str,
    token: &str,
    now: SystemTime,
    state: &str,
) -> Result<bool> {
    let id = id.to_owned();
    let token = token.to_owned();
    let state = state.to_owned();
    let next = now
        .checked_add(Duration::from_secs(60))
        .context("reset mail retry overflow")?;
    retry_known_abort(|| {
        let (id, token, state) = (id.clone(), token.clone(), state.clone());
        async {
            client.query_client().retry_tx(closure!([id, token, state], async |tx: &mut Transaction| {
                let Some(mut row) = tx.query_row(format!("SELECT claim_token, status FROM `{TABLE}` WHERE id = $id"))
                    .param("$id", id.clone()).optional().await? else { return Ok(false); };
                let current: String = row.remove_field_by_name("claim_token")?.try_into()?;
                let status: String = row.remove_field_by_name("status")?.try_into()?;
                if current != token.as_str() || status != "pending" { return Ok(false); }
                tx.exec(format!("UPDATE `{TABLE}` SET status = $state, recipient = CASE WHEN $state = 'cancelled' THEN Unwrap(CAST('' AS Utf8)) ELSE recipient END, password_version = CASE WHEN $state = 'cancelled' THEN Unwrap(CAST('' AS Utf8)) ELSE password_version END, claim_token = Unwrap(CAST('' AS Utf8)), lease_until = NULL, next_attempt_at = CAST($next AS Datetime) WHERE id = $id"))
                    .param("$id", id.clone()).param("$state", state.clone()).param("$next", next).await?;
                Ok(true)
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(10)).await
        }
    }).await.context("finalize password reset mail claim")
}

fn render(address: &str, from: &Mailbox, link: &Url) -> Result<Message> {
    Ok(Message::builder().from(from.clone()).to(address.parse()?)
        .subject("Восстановление доступа к UpdSpace ID")
        .header(ContentTransferEncoding::QuotedPrintable)
        .body(format!("Для установки нового пароля откройте ссылку:\n\n{link}\n\nСсылка действует один час. Если вы не запрашивали восстановление, проигнорируйте письмо."))?)
}

pub async fn process_one(
    client: &Client,
    id: &str,
    config: &ResetMailConfig,
    mailer: &AsyncSmtpTransport<Tokio1Executor>,
    from: &Mailbox,
) -> Result<DrainResult> {
    let mut result = DrainResult::default();
    let Some(token) = claim(client, id, SystemTime::now()).await? else {
        return Ok(result);
    };
    result.claimed = 1;
    match recipient(client, id, SystemTime::now()).await {
        Ok(Some(address)) => {
            let uuid = Uuid::parse_str(id)?;
            let delivered = match render(&address, from, &config.link(uuid)?) {
                Ok(message) => tokio::time::timeout(Duration::from_secs(30), mailer.send(message))
                    .await
                    .is_ok_and(|outcome| outcome.is_ok()),
                Err(_) => false,
            };
            if delivered {
                if finish(client, id, &token, SystemTime::now(), "sent").await? {
                    result.sent = 1;
                }
            } else if finish(client, id, &token, SystemTime::now(), "pending").await? {
                result.deferred = 1;
            }
        }
        Ok(None) => {
            if finish(client, id, &token, SystemTime::now(), "cancelled").await? {
                result.cancelled = 1;
            }
        }
        Err(_) => {
            if finish(client, id, &token, SystemTime::now(), "pending").await? {
                result.deferred = 1;
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_reset_link_is_scoped_and_not_forgeable() -> Result<()> {
        let key = ResetKey::new([7; 32])?;
        let other = ResetKey::new([8; 32])?;
        let id = Uuid::new_v4();
        let token = key.issue(id)?;
        assert_eq!(key.verify(&token), Some(id));
        assert_eq!(other.verify(&token), None);
        assert_eq!(key.verify(&token.replace('.', ":")), None);
        let altered = token.replace('A', "B");
        if altered != token {
            assert_eq!(key.verify(&altered), None);
        }
        assert!(ResetKey::new([0; 32]).is_err());
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires migrated local /local YDB; 100 claims across two clients"]
    async fn mail_claim_is_single_owner_and_expiry_is_cleaned() -> Result<()> {
        ensure!(
            matches!(
                std::env::var("YDB_ENDPOINT")?.as_str(),
                "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
            ) && std::env::var("YDB_DATABASE")? == "/local",
            "test requires local YDB"
        );
        let first = Arc::new(crate::connect_ydb().await?);
        let second = Arc::new(crate::connect_ydb().await?);
        ensure_schema(&first).await?;
        let id = Uuid::new_v4().to_string();
        let now = SystemTime::now();
        let expires = now + LINK_TTL;
        first.query_client().exec(format!("INSERT INTO `{TABLE}` (id, user_id, recipient, password_version, expires_at, status, attempts, next_attempt_at, claim_token, created_at) VALUES ($id, -1, 'test@example.invalid', $version, CAST($expires AS Datetime), 'pending', 0, CAST($now AS Datetime), '', CAST($now AS Datetime))"))
            .param("$id", id.clone()).param("$version", "f".repeat(64))
            .param("$expires", expires).param("$now", now).await?;
        let outcome: Result<()> = async {
            ensure!(due_ids(&first, now, 100).await?.contains(&id));
            let mut tasks = tokio::task::JoinSet::new();
            for index in 0..100 {
                let client = if index % 2 == 0 {
                    first.clone()
                } else {
                    second.clone()
                };
                let id = id.clone();
                tasks.spawn(async move { claim(&client, &id, now).await });
            }
            let mut winners = Vec::new();
            while let Some(result) = tasks.join_next().await {
                if let Some(token) = result?? {
                    winners.push(token);
                }
            }
            ensure!(
                winners.len() == 1,
                "{} workers claimed one reset mail",
                winners.len()
            );
            ensure!(!finish(&second, &id, "stale-claim", now, "sent").await?);
            ensure!(finish(&first, &id, &winners[0], now, "pending").await?);
            let later = now + Duration::from_secs(61);
            let retry = claim(&second, &id, later)
                .await?
                .context("retry not claimable")?;
            ensure!(finish(&second, &id, &retry, later, "sent").await?);
            ensure!(claim(&first, &id, later).await?.is_none());
            ensure!(cleanup_expired(&first, expires + Duration::from_secs(1), 100).await? >= 1);
            let row = first
                .query_client()
                .query_row(format!("SELECT id FROM `{TABLE}` WHERE id = $id"))
                .param("$id", id.clone())
                .optional()
                .await?;
            ensure!(row.is_none(), "expired reset intent retained");
            Ok(())
        }
        .await;
        first
            .query_client()
            .exec(format!("DELETE FROM `{TABLE}` WHERE id = $id"))
            .param("$id", id)
            .await?;
        outcome
    }
}
