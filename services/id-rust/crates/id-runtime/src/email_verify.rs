//! New email-verification links for the account's current, unverified address.
//! The link is signed; the YDB row contains no usable bearer credential.

use crate::{
    email_change::{self, ConfirmOutcome},
    new_device_mail::DrainResult,
    password_mail,
    tx_retry::retry_known_abort,
};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentTransferEncoding},
};
use sha2::Sha256;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use url::Url;
use uuid::Uuid;
use ydb::{Client, Transaction, TxMode, Value, closure};

pub const TABLE: &str = "id_email_verification";
const DUE_INDEX: &str = "id_email_verification_due_idx";
const EXPIRY_INDEX: &str = "id_email_verification_expiry_idx";
const LINK_TTL: Duration = Duration::from_secs(24 * 3600);

#[derive(Clone)]
pub struct VerifyKey(Arc<[u8; 32]>);

impl VerifyKey {
    pub fn from_env() -> Result<Self> {
        let encoded = std::env::var("ID_EMAIL_VERIFY_HMAC_KEY")
            .context("ID_EMAIL_VERIFY_HMAC_KEY required")?;
        let bytes: [u8; 32] = hex::decode(encoded)
            .context("invalid email verification key encoding")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("email verification key must be 32 bytes"))?;
        Self::new(bytes)
    }

    pub fn new(bytes: [u8; 32]) -> Result<Self> {
        ensure!(
            bytes.iter().any(|byte| *byte != 0),
            "email verification key cannot be zero"
        );
        Ok(Self(Arc::new(bytes)))
    }

    pub fn issue(&self, id: Uuid) -> Result<String> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.0.as_ref())
            .map_err(|_| anyhow::anyhow!("invalid email verification HMAC key"))?;
        mac.update(b"updspace-id-email-verification-v1:");
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
        let signature = URL_SAFE_NO_PAD.decode(signature).ok()?;
        if signature.len() != 32 {
            return None;
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(self.0.as_ref()).ok()?;
        mac.update(b"updspace-id-email-verification-v1:");
        mac.update(id.as_bytes());
        mac.verify_slice(&signature).ok()?;
        Some(id)
    }
}

pub async fn ensure_schema(client: &Client) -> Result<()> {
    client.query_client().exec(format!(
        "CREATE TABLE IF NOT EXISTS `{TABLE}` (id Utf8 NOT NULL, user_id Int32 NOT NULL, recipient Utf8 NOT NULL, expires_at Datetime NOT NULL, consumed_at Datetime, status Utf8 NOT NULL, attempts Int32 NOT NULL, next_attempt_at Datetime NOT NULL, lease_until Datetime, claim_token Utf8 NOT NULL, created_at Datetime NOT NULL, INDEX `{DUE_INDEX}` GLOBAL ON (status, next_attempt_at), INDEX `{EXPIRY_INDEX}` GLOBAL ON (expires_at), PRIMARY KEY (id))"
    )).timeout(Duration::from_secs(15)).await?;
    let description = client
        .table_client()
        .describe_table(format!("{}/{TABLE}", client.database()))
        .await?;
    ensure!(
        description.primary_key == ["id"],
        "email verification primary key drift"
    );
    let columns: std::collections::BTreeSet<_> = description
        .columns
        .iter()
        .map(|c| c.name.as_str())
        .collect();
    ensure!(
        columns
            == [
                "id",
                "user_id",
                "recipient",
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
        "email verification columns drift"
    );
    for (name, kind, nullable) in [
        ("id", "text", false),
        ("user_id", "int32", false),
        ("recipient", "text", false),
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
            .context("email verification column missing")?;
        let value = column
            .type_value
            .as_ref()
            .map_err(|_| anyhow::anyhow!("email verification column type unsupported: {name}"))?;
        ensure!(
            value.is_optional() == nullable,
            "email verification nullability drift: {name}"
        );
        if !nullable {
            ensure!(
                matches!(
                    (kind, value),
                    ("text", Value::Text(_))
                        | ("int32", Value::Int32(_))
                        | ("datetime", Value::DateTime(_))
                ),
                "email verification column type drift: {name}"
            );
        }
    }
    for (name, columns) in [
        (DUE_INDEX, &["status", "next_attempt_at"][..]),
        (EXPIRY_INDEX, &["expires_at"][..]),
    ] {
        let index = description
            .indexes
            .iter()
            .find(|item| item.name == name)
            .context("email verification index missing")?;
        ensure!(
            index.status == ydb::IndexStatus::Ready
                && index.index_type == ydb::IndexType::Global
                && index.index_columns == columns,
            "email verification index drift or not ready"
        );
    }
    let mut query_client = client.query_client();
    let mut due = query_client.query(format!("SELECT id FROM `{TABLE}` VIEW `{DUE_INDEX}` WHERE status = 'pending' AND next_attempt_at <= CurrentUtcDatetime() LIMIT 1")).await?;
    while due.next_result_set().await?.is_some() {}
    due.close().await?;
    let mut expiry = query_client.query(format!("SELECT id FROM `{TABLE}` VIEW `{EXPIRY_INDEX}` WHERE expires_at <= CurrentUtcDatetime() LIMIT 1")).await?;
    while expiry.next_result_set().await?.is_some() {}
    expiry.close().await?;
    email_change::ensure_schema(client).await?;
    Ok(())
}

async fn eligible(
    tx: &mut Transaction,
    user_id: i32,
    email: &str,
) -> ydb::YdbResultWithCustomerErr<Option<i64>> {
    let Some(mut account) = tx
        .query_row("SELECT email, is_active FROM auth_user WHERE id = $id")
        .param("$id", user_id)
        .optional()
        .await?
    else {
        return Ok(None);
    };
    let stored: String = account.remove_field_by_name("email")?.try_into()?;
    let active: bool = account.remove_field_by_name("is_active")?.try_into()?;
    if !active || stored.trim().to_lowercase() != email {
        return Ok(None);
    }
    let mut owners = tx.query("SELECT user_id FROM accounts_accountemaillookup VIEW acct_email_key_idx WHERE email_key = $email LIMIT 2")
        .param("$email", email.to_owned()).await?;
    let mut owner_ids = Vec::<i32>::new();
    while let Some(rows) = owners.next_result_set().await? {
        for mut row in rows {
            owner_ids.push(row.remove_field_by_name("user_id")?.try_into()?);
        }
    }
    owners.close().await?;
    if owner_ids.as_slice() != [user_id] {
        return Ok(None);
    }
    let mut query = tx.query("SELECT id, verified FROM account_emailaddress VIEW account_emailaddress_user_id_2c513194 WHERE user_id = $id AND Unicode::ToLower(email) = $email LIMIT 2")
        .param("$id", user_id).param("$email", email.to_owned()).await?;
    let mut ids = Vec::new();
    while let Some(rows) = query.next_result_set().await? {
        for mut row in rows {
            let id: i64 = row.remove_field_by_name("id")?.try_into()?;
            let verified: bool = row.remove_field_by_name("verified")?.try_into()?;
            ids.push((id, verified));
        }
    }
    query.close().await?;
    if ids.len() != 1 || ids[0].1 {
        return Ok(None);
    }
    let Some(mut binding) = tx
        .query_row("SELECT identity_id FROM accounts_accountidentity WHERE user_id = $id")
        .param("$id", user_id)
        .optional()
        .await?
    else {
        return Ok(None);
    };
    let identity_id: Option<Uuid> = binding.remove_field_by_name("identity_id")?.try_into()?;
    let Some(identity_id) = identity_id else {
        return Ok(None);
    };
    let Some(mut identity) = tx
        .query_row("SELECT email, email_verified, status FROM usid_user WHERE user_id = $id")
        .param("$id", identity_id)
        .optional()
        .await?
    else {
        return Ok(None);
    };
    let identity_email: String = identity.remove_field_by_name("email")?.try_into()?;
    let identity_verified: bool = identity
        .remove_field_by_name("email_verified")?
        .try_into()?;
    let identity_status: String = identity.remove_field_by_name("status")?.try_into()?;
    if identity_email.trim().to_lowercase() != email
        || identity_verified
        || identity_status != "active"
    {
        return Ok(None);
    }
    let mut deletion = tx.query_row("SELECT COUNT(*) AS count FROM accounts_accountdeletionrequest VIEW accounts_accountdeletionrequest_user_id_6a166c52 WHERE user_id = $id AND status != 'canceled'")
        .param("$id", user_id).await?;
    let count: u64 = deletion.remove_field_by_name("count")?.try_into()?;
    Ok((count == 0).then_some(ids[0].0))
}

/// The caller always returns the same HTTP body for known and unknown emails.
pub async fn request(client: &Client, email: &str, now: SystemTime) -> Result<()> {
    let email = email.trim().to_lowercase();
    ensure!(
        email.len() <= 254 && password_mail::valid_recipient(&email),
        "invalid verification email"
    );
    let id = Uuid::new_v4().to_string();
    let expires = now
        .checked_add(LINK_TTL)
        .context("email verification expiry overflow")?;
    retry_known_abort(|| {
        let (email, id) = (email.clone(), id.clone());
        async {
            client.query_client().retry_tx(closure!([email, id], async |tx: &mut Transaction| {
                let mut query = tx.query("SELECT user_id FROM accounts_accountemaillookup VIEW acct_email_key_idx WHERE email_key = $email LIMIT 2")
                    .param("$email", email.clone()).await?;
                let mut ids = Vec::<i32>::new();
                while let Some(rows) = query.next_result_set().await? {
                    for mut row in rows { ids.push(row.remove_field_by_name("user_id")?.try_into()?); }
                }
                query.close().await?;
                if ids.len() != 1 || eligible(tx, ids[0], email).await?.is_none() { return Ok(()); }
                tx.exec(format!("INSERT INTO `{TABLE}` (id, user_id, recipient, expires_at, status, attempts, next_attempt_at, claim_token, created_at) VALUES ($id, $user_id, $email, CAST($expires AS Datetime), 'pending', 0, CAST($now AS Datetime), '', CAST($now AS Datetime))"))
                    .param("$id", id.clone()).param("$user_id", ids[0]).param("$email", email.clone())
                    .param("$expires", expires).param("$now", now).await?;
                Ok(())
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(15)).await
        }
    }).await.context("create email verification intent")
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConfirmResult {
    Verified,
    Invalid,
}

pub async fn confirm(
    client: &Client,
    key: &VerifyKey,
    token: &str,
    now: SystemTime,
) -> Result<ConfirmResult> {
    let Some(id) = key.verify(token) else {
        return Ok(ConfirmResult::Invalid);
    };
    let id = id.to_string();
    retry_known_abort(|| {
        let id = id.clone();
        async {
            client.query_client().retry_tx(closure!([id], async |tx: &mut Transaction| {
                let Some(mut intent) = tx.query_row(format!("SELECT user_id, recipient, expires_at, consumed_at, status FROM `{TABLE}` WHERE id = $id"))
                    .param("$id", id.clone()).optional().await? else { return Ok(ConfirmResult::Invalid); };
                let user_id: i32 = intent.remove_field_by_name("user_id")?.try_into()?;
                let recipient: String = intent.remove_field_by_name("recipient")?.try_into()?;
                let expires: SystemTime = intent.remove_field_by_name("expires_at")?.try_into()?;
                let consumed: Option<SystemTime> = intent.remove_field_by_name("consumed_at")?.try_into()?;
                let status: String = intent.remove_field_by_name("status")?.try_into()?;
                if consumed.is_some() || expires <= now || !matches!(status.as_str(), "pending" | "sent") { return Ok(ConfirmResult::Invalid); }
                match email_change::confirm_tx(tx, id, user_id, &recipient, now).await? {
                    ConfirmOutcome::Confirmed => return Ok(ConfirmResult::Verified),
                    ConfirmOutcome::Invalid => return Ok(ConfirmResult::Invalid),
                    ConfirmOutcome::NotChange => {}
                }
                let Some(email_id) = eligible(tx, user_id, &recipient.to_lowercase()).await? else { return Ok(ConfirmResult::Invalid); };
                let Some(mut binding) = tx.query_row("SELECT identity_id FROM accounts_accountidentity WHERE user_id = $id")
                    .param("$id", user_id).optional().await? else { return Ok(ConfirmResult::Invalid); };
                let identity_id: Option<Uuid> = binding.remove_field_by_name("identity_id")?.try_into()?;
                let Some(identity_id) = identity_id else { return Ok(ConfirmResult::Invalid); };
                let Some(mut identity) = tx.query_row("SELECT email, status FROM usid_user WHERE user_id = $id")
                    .param("$id", identity_id).optional().await? else { return Ok(ConfirmResult::Invalid); };
                let identity_email: String = identity.remove_field_by_name("email")?.try_into()?;
                let identity_status: String = identity.remove_field_by_name("status")?.try_into()?;
                if identity_email.trim().to_lowercase() != recipient.to_lowercase() || identity_status != "active" { return Ok(ConfirmResult::Invalid); }
                tx.exec("UPDATE account_emailaddress SET verified = true WHERE id = $id AND verified = false")
                    .param("$id", email_id).await?;
                tx.exec("UPDATE usid_user SET email_verified = true WHERE user_id = $id")
                    .param("$id", identity_id).await?;
                tx.exec(format!("UPDATE `{TABLE}` SET consumed_at = CAST($now AS Datetime), status = 'cancelled', recipient = Unwrap(CAST('' AS Utf8)), claim_token = Unwrap(CAST('' AS Utf8)), lease_until = NULL WHERE id = $id"))
                    .param("$now", now).param("$id", id.clone()).await?;
                Ok(ConfirmResult::Verified)
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(15)).await
        }
    }).await.context("confirm email verification")
}

pub struct VerifyMailConfig {
    key: VerifyKey,
    page: Url,
}

impl VerifyMailConfig {
    pub fn from_env() -> Result<Option<Self>> {
        if std::env::var("ID_EMAIL_VERIFY_MAIL_ENABLED").as_deref() != Ok("true") {
            return Ok(None);
        }
        Self::new(
            VerifyKey::from_env()?,
            &std::env::var("ID_EMAIL_VERIFY_URL")?,
        )
        .map(Some)
    }

    pub fn new(key: VerifyKey, url: &str) -> Result<Self> {
        let page = Url::parse(url).context("invalid email verification page URL")?;
        let local = matches!(page.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        ensure!(
            (page.scheme() == "https" || (local && page.scheme() == "http"))
                && page.path() == "/verify-email"
                && page.query().is_none()
                && page.fragment().is_none()
                && page.username().is_empty()
                && page.password().is_none(),
            "invalid email verification page URL"
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
        bail!("email verification mail batch size must be 1..=100");
    }
    let mut query_client = client.query_client();
    let mut rows = query_client.query(format!(
        "SELECT id FROM `{TABLE}` VIEW `{DUE_INDEX}` WHERE status = 'pending' AND next_attempt_at <= CAST($now AS Datetime) AND expires_at > CAST($now AS Datetime) AND (lease_until IS NULL OR lease_until <= CAST($now AS Datetime)) ORDER BY next_attempt_at LIMIT $limit"
    )).param("$now", now).param("$limit", limit).await?;
    let mut ids = Vec::new();
    while let Some(set) = rows.next_result_set().await? {
        for mut row in set {
            ids.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    rows.close().await?;
    Ok(ids)
}

pub async fn cleanup_expired(client: &Client, now: SystemTime, limit: u64) -> Result<usize> {
    if limit == 0 || limit > 100 {
        bail!("email verification cleanup batch size must be 1..=100");
    }
    let mut query_client = client.query_client();
    let mut rows = query_client.query(format!(
        "SELECT id FROM `{TABLE}` VIEW `{EXPIRY_INDEX}` WHERE expires_at <= CAST($now AS Datetime) ORDER BY expires_at LIMIT $limit"
    )).param("$now", now).param("$limit", limit).await?;
    let mut ids = Vec::<String>::new();
    while let Some(set) = rows.next_result_set().await? {
        for mut row in set {
            ids.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    rows.close().await?;
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
        "invalid email verification intent ID"
    );
    let id = id.to_owned();
    let token = Uuid::new_v4().to_string();
    let lease = now
        .checked_add(Duration::from_secs(120))
        .context("email mail lease overflow")?;
    let claimed = retry_known_abort(|| {
        let (id, token) = (id.clone(), token.clone());
        async {
            client.query_client().retry_tx(closure!([id, token], async |tx: &mut Transaction| {
                let Some(mut row) = tx.query_row(format!("SELECT status, next_attempt_at, expires_at, lease_until, consumed_at FROM `{TABLE}` WHERE id = $id"))
                    .param("$id", id.clone()).optional().await? else { return Ok(false); };
                let status: String = row.remove_field_by_name("status")?.try_into()?;
                let next: SystemTime = row.remove_field_by_name("next_attempt_at")?.try_into()?;
                let expires: SystemTime = row.remove_field_by_name("expires_at")?.try_into()?;
                let existing_lease: Option<SystemTime> = row.remove_field_by_name("lease_until")?.try_into()?;
                let consumed: Option<SystemTime> = row.remove_field_by_name("consumed_at")?.try_into()?;
                if status != "pending" || next > now || expires <= now || consumed.is_some() || existing_lease.is_some_and(|until| until > now) { return Ok(false); }
                tx.exec(format!("UPDATE `{TABLE}` SET claim_token = $token, lease_until = CAST($lease AS Datetime), attempts = attempts + 1 WHERE id = $id"))
                    .param("$id", id.clone()).param("$token", token.clone()).param("$lease", lease).await?;
                Ok(true)
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(10)).await
        }
    }).await?;
    Ok(claimed.then_some(token))
}

async fn recipient(client: &Client, id: &str, now: SystemTime) -> Result<Option<String>> {
    let id = id.to_owned();
    client.query_client().retry_tx(closure!([id], async |tx: &mut Transaction| {
        let Some(mut intent) = tx.query_row(format!("SELECT user_id, recipient, expires_at, consumed_at, status FROM `{TABLE}` WHERE id = $id"))
            .param("$id", id.clone()).optional().await? else { return Ok(None); };
        let user_id: i32 = intent.remove_field_by_name("user_id")?.try_into()?;
        let email: String = intent.remove_field_by_name("recipient")?.try_into()?;
        let expires: SystemTime = intent.remove_field_by_name("expires_at")?.try_into()?;
        let consumed: Option<SystemTime> = intent.remove_field_by_name("consumed_at")?.try_into()?;
        let status: String = intent.remove_field_by_name("status")?.try_into()?;
        if status != "pending" || consumed.is_some() || expires <= now || !password_mail::valid_recipient(&email) { return Ok(None); }
        if email_change::eligible_tx(tx, id, user_id, &email, now).await? {
            return Ok(Some(email));
        }
        Ok(eligible(tx, user_id, &email.to_lowercase()).await?.map(|_| email))
    })).isolation(TxMode::SerializableReadWrite).timeout(Duration::from_secs(10)).await
        .context("read email verification recipient")
}

async fn finish(
    client: &Client,
    id: &str,
    token: &str,
    now: SystemTime,
    state: &str,
) -> Result<bool> {
    let (id, token, state) = (id.to_owned(), token.to_owned(), state.to_owned());
    let next = now
        .checked_add(Duration::from_secs(60))
        .context("email mail retry overflow")?;
    retry_known_abort(|| {
        let (id, token, state) = (id.clone(), token.clone(), state.clone());
        async {
            client.query_client().retry_tx(closure!([id, token, state], async |tx: &mut Transaction| {
                let Some(mut row) = tx.query_row(format!("SELECT claim_token, status FROM `{TABLE}` WHERE id = $id"))
                    .param("$id", id.clone()).optional().await? else { return Ok(false); };
                let current: String = row.remove_field_by_name("claim_token")?.try_into()?;
                let status: String = row.remove_field_by_name("status")?.try_into()?;
                if current != token.as_str() || status != "pending" { return Ok(false); }
                tx.exec(format!("UPDATE `{TABLE}` SET status = $state, recipient = CASE WHEN $state = 'cancelled' THEN Unwrap(CAST('' AS Utf8)) ELSE recipient END, claim_token = Unwrap(CAST('' AS Utf8)), lease_until = NULL, next_attempt_at = CAST($next AS Datetime) WHERE id = $id"))
                    .param("$id", id.clone()).param("$state", state.clone()).param("$next", next).await?;
                Ok(true)
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(10)).await
        }
    }).await.context("finalize email verification mail claim")
}

pub async fn process_one(
    client: &Client,
    id: &str,
    config: &VerifyMailConfig,
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
            let link = config.link(Uuid::parse_str(id)?)?;
            let message = Message::builder().from(from.clone()).to(address.parse()?)
                .subject("Подтвердите email UpdSpace ID")
                .header(ContentTransferEncoding::QuotedPrintable)
                .body(format!("Чтобы подтвердить адрес, откройте ссылку:\n\n{link}\n\nСсылка действует 24 часа. Если вы не регистрировались, проигнорируйте письмо."))?;
            let delivered = tokio::time::timeout(Duration::from_secs(30), mailer.send(message))
                .await
                .is_ok_and(|outcome| outcome.is_ok());
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
    fn signature_is_purpose_and_key_bound() -> Result<()> {
        let key = VerifyKey::new([7; 32])?;
        let id = Uuid::new_v4();
        let token = key.issue(id)?;
        assert_eq!(key.verify(&token), Some(id));
        assert_eq!(VerifyKey::new([8; 32])?.verify(&token), None);
        assert_eq!(
            crate::password_reset::ResetKey::new([7; 32])?.verify(&token),
            None
        );
        assert!(VerifyKey::new([0; 32]).is_err());
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
        first.query_client().exec(format!("INSERT INTO `{TABLE}` (id, user_id, recipient, expires_at, status, attempts, next_attempt_at, claim_token, created_at) VALUES ($id, -1, 'test@example.invalid', CAST($expires AS Datetime), 'pending', 0, CAST($now AS Datetime), '', CAST($now AS Datetime))"))
            .param("$id", id.clone()).param("$expires", expires).param("$now", now).await?;
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
                "{} workers claimed one verification mail",
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
            ensure!(row.is_none(), "expired verification intent retained");
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
