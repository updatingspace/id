//! Durable magic-link issuance. The mail row has no usable bearer token: a
//! worker derives it from the row ID and the same HMAC key as the API.

use crate::new_device_mail::DrainResult;
use crate::tx_retry::retry_known_abort;
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentTransferEncoding},
};
use sha2::Sha256;
use std::time::{Duration, SystemTime};
use url::Url;
use uuid::Uuid;
use ydb::{Client, IndexStatus, IndexType, Transaction, TxMode, closure};

pub const TABLE: &str = "id_magic_link_mail";
const DUE_INDEX: &str = "id_magic_link_mail_due_idx";
const LINK_TTL: Duration = Duration::from_secs(15 * 60);

#[derive(Clone)]
pub struct Request {
    pub email: String,
    pub tenant_id: Uuid,
    pub tenant_slug: String,
    pub redirect_to: String,
}

pub async fn ensure_schema(client: &Client) -> Result<()> {
    client.query_client().exec(format!(
        "CREATE TABLE IF NOT EXISTS `{TABLE}` (id Utf8 NOT NULL, user_id UUID NOT NULL, tenant_id UUID NOT NULL, tenant_slug Utf8 NOT NULL, recipient Utf8 NOT NULL, redirect_to Utf8 NOT NULL, expires_at Datetime NOT NULL, status Utf8 NOT NULL, attempts Int32 NOT NULL, next_attempt_at Datetime NOT NULL, lease_until Datetime, claim_token Utf8 NOT NULL, created_at Datetime NOT NULL, INDEX `{DUE_INDEX}` GLOBAL ON (status, next_attempt_at), PRIMARY KEY (id))"
    )).timeout(Duration::from_secs(15)).await?;
    let description = client
        .table_client()
        .describe_table(format!("{}/{TABLE}", client.database()))
        .await?;
    ensure!(
        description.primary_key == ["id"],
        "magic-link mail primary key drift"
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
                "tenant_id",
                "tenant_slug",
                "recipient",
                "redirect_to",
                "expires_at",
                "status",
                "attempts",
                "next_attempt_at",
                "lease_until",
                "claim_token",
                "created_at"
            ]
            .into_iter()
            .collect(),
        "magic-link mail columns drift"
    );
    let index = description
        .indexes
        .iter()
        .find(|index| index.name == DUE_INDEX)
        .context("magic-link mail due index missing")?;
    ensure!(
        index.index_columns == ["status", "next_attempt_at"]
            && index.index_type == IndexType::Global
            && index.status == IndexStatus::Ready,
        "magic-link mail due index drift or not ready"
    );
    Ok(())
}

pub fn token_for_id(secret: &[u8], id: Uuid) -> Result<String> {
    ensure!(secret.len() >= 32, "magic-link key is too short");
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)?;
    mac.update(b"updspace-id-magic-link-v1:");
    mac.update(id.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn token_hash(secret: &[u8], token: &str) -> Result<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)?;
    mac.update(token.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Unknown, ambiguous, inactive and unverified addresses produce the same
/// success response at the HTTP boundary and create no mail intent.
pub async fn request(
    client: &Client,
    secret: &[u8],
    input: Request,
    now: SystemTime,
) -> Result<()> {
    ensure!(secret.len() >= 32, "magic-link key is too short");
    ensure!(
        input.email.len() <= 254 && crate::password_mail::valid_recipient(&input.email),
        "invalid magic-link email"
    );
    ensure!(
        !input.tenant_slug.is_empty() && input.tenant_slug.len() <= 64,
        "invalid tenant slug"
    );
    ensure!(input.redirect_to.len() <= 2048, "invalid redirect");
    let email = input.email.trim().to_lowercase();
    let id = Uuid::new_v4();
    let token = token_for_id(secret, id)?;
    let hash = token_hash(secret, &token)?;
    let expires = now
        .checked_add(LINK_TTL)
        .context("magic-link expiry overflow")?;
    retry_known_abort(|| {
        let (input, email, hash) = (input.clone(), email.clone(), hash.clone());
        let id = id.to_string();
        async {
            client.query_client().retry_tx(closure!([input, email, hash, id], async |tx: &mut Transaction| {
                let Some(mut tenant) = tx.query_row("SELECT slug FROM usid_tenant WHERE id = $id")
                    .param("$id", input.tenant_id).optional().await? else { return Ok(()); };
                let slug: String = tenant.remove_field_by_name("slug")?.try_into()?;
                if slug != input.tenant_slug { return Ok(()); }
                let mut lookup = tx.query("SELECT user_id FROM usid_user VIEW usid_user_email_idx WHERE email = $email LIMIT 2")
                    .param("$email", email.clone()).await?;
                let mut ids = Vec::<Uuid>::new();
                while let Some(rows) = lookup.next_result_set().await? {
                    for mut row in rows { ids.push(row.remove_field_by_name("user_id")?.try_into()?); }
                }
                lookup.close().await?;
                if ids.len() != 1 { return Ok(()); }
                let user_id = ids[0];
                let Some(mut user) = tx.query_row("SELECT email_verified, status, email FROM usid_user WHERE user_id = $id")
                    .param("$id", user_id).optional().await? else { return Ok(()); };
                let verified: bool = user.remove_field_by_name("email_verified")?.try_into()?;
                let status: String = user.remove_field_by_name("status")?.try_into()?;
                let actual_email: String = user.remove_field_by_name("email")?.try_into()?;
                if !verified || status != "active" || actual_email != *email { return Ok(()); }
                let mut memberships = tx.query("SELECT status FROM usid_tenant_membership WHERE user_id = $user AND tenant_id = $tenant LIMIT 2")
                    .param("$user", user_id).param("$tenant", input.tenant_id).await?;
                let mut states = Vec::<String>::new();
                while let Some(rows) = memberships.next_result_set().await? {
                    for mut row in rows { states.push(row.remove_field_by_name("status")?.try_into()?); }
                }
                memberships.close().await?;
                if states.as_slice() != ["active"] { return Ok(()); }
                tx.exec("INSERT INTO usid_magic_link_token (token, user_id, expires_at, ip_hash, ua_hash, skip_context_validation, created_at) VALUES ($hash, $user, CAST($expires AS Datetime), '', '', true, CAST($now AS Datetime))")
                    .param("$hash", hash.clone()).param("$user", user_id).param("$expires", expires).param("$now", now).await?;
                tx.exec(format!("INSERT INTO `{TABLE}` (id, user_id, tenant_id, tenant_slug, recipient, redirect_to, expires_at, status, attempts, next_attempt_at, claim_token, created_at) VALUES ($id, $user, $tenant, $slug, $email, $redirect, CAST($expires AS Datetime), 'pending', 0, CAST($now AS Datetime), '', CAST($now AS Datetime))"))
                    .param("$id", id.clone()).param("$user", user_id).param("$tenant", input.tenant_id)
                    .param("$slug", input.tenant_slug.clone()).param("$email", email.clone())
                    .param("$redirect", input.redirect_to.clone()).param("$expires", expires).param("$now", now).await?;
                Ok(())
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(15)).await
        }
    }).await.context("create magic-link mail intent")
}

pub async fn due_ids(client: &Client, now: SystemTime, limit: u64) -> Result<Vec<String>> {
    if limit == 0 || limit > 100 {
        bail!("magic-link mail batch size must be 1..=100");
    }
    let mut query_client = client.query_client();
    let mut query = query_client.query(format!("SELECT id FROM `{TABLE}` VIEW `{DUE_INDEX}` WHERE status = 'pending' AND next_attempt_at <= CAST($now AS Datetime) AND expires_at > CAST($now AS Datetime) AND (lease_until IS NULL OR lease_until <= CAST($now AS Datetime)) ORDER BY next_attempt_at LIMIT $limit"))
        .param("$now", now).param("$limit", limit).await?;
    let mut ids = Vec::new();
    while let Some(rows) = query.next_result_set().await? {
        for mut row in rows {
            ids.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    query.close().await?;
    Ok(ids)
}

/// Remove expired mail metadata and its unusable legacy token in bounded
/// batches. A partial cleanup is harmless and resumes on the next timer run.
pub async fn cleanup_expired(
    client: &Client,
    secret: &[u8],
    now: SystemTime,
    limit: u64,
) -> Result<usize> {
    if limit == 0 || limit > 100 {
        bail!("magic-link cleanup batch size must be 1..=100");
    }
    let mut query_client = client.query_client();
    let mut query = query_client
        .query(format!(
            "SELECT id FROM `{TABLE}` WHERE expires_at <= CAST($now AS Datetime) LIMIT $limit"
        ))
        .param("$now", now)
        .param("$limit", limit)
        .await?;
    let mut ids = Vec::<String>::new();
    while let Some(rows) = query.next_result_set().await? {
        for mut row in rows {
            ids.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    query.close().await?;
    for id in &ids {
        let token = token_for_id(secret, Uuid::parse_str(id)?)?;
        let hash = token_hash(secret, &token)?;
        client.query_client().exec("DELETE FROM usid_magic_link_token WHERE token = $hash AND expires_at <= CAST($now AS Datetime)")
            .param("$hash", hash).param("$now", now).await?;
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

pub struct MailConfig {
    secret: Vec<u8>,
    public_url: Url,
}

impl MailConfig {
    pub fn from_env() -> Result<Option<Self>> {
        if std::env::var("ID_MAGIC_LINK_MAIL_ENABLED").as_deref() != Ok("true") {
            return Ok(None);
        }
        let secret = std::env::var("ID_TOKEN_HASH_SECRET")
            .or_else(|_| std::env::var("DJANGO_SECRET_KEY"))?;
        Self::new(
            secret.into_bytes(),
            &std::env::var("ID_MAGIC_LINK_PUBLIC_URL")?,
        )
        .map(Some)
    }

    pub fn new(secret: Vec<u8>, url: &str) -> Result<Self> {
        ensure!(secret.len() >= 32, "magic-link key is too short");
        let public_url = Url::parse(url)?;
        let local = matches!(public_url.host_str(), Some("localhost" | "127.0.0.1"));
        ensure!(
            (public_url.scheme() == "https" || (local && public_url.scheme() == "http"))
                && public_url.path() == "/api/v1/auth/magic-link/consume"
                && public_url.query().is_none()
                && public_url.fragment().is_none()
                && public_url.username().is_empty()
                && public_url.password().is_none(),
            "invalid magic-link public URL"
        );
        Ok(Self { secret, public_url })
    }

    fn link(&self, id: Uuid, row: &MailRow) -> Result<Url> {
        let token = token_for_id(&self.secret, id)?;
        let signature = crate::magic_link_http::link_signature(
            &self.secret,
            &token,
            row.tenant_id,
            &row.tenant_slug,
            &row.redirect_to,
        )?;
        let mut link = self.public_url.clone();
        link.query_pairs_mut()
            .append_pair("token", &token)
            .append_pair("redirect_to", &row.redirect_to)
            .append_pair("tenant_id", &row.tenant_id.to_string())
            .append_pair("tenant_slug", &row.tenant_slug)
            .append_pair("tenant_sig", &signature);
        Ok(link)
    }

    pub fn secret(&self) -> &[u8] {
        &self.secret
    }
}

struct MailRow {
    recipient: String,
    tenant_id: Uuid,
    tenant_slug: String,
    redirect_to: String,
}

async fn claim(client: &Client, id: &str, now: SystemTime) -> Result<Option<String>> {
    ensure!(Uuid::parse_str(id).is_ok(), "invalid magic-link mail ID");
    let id = id.to_owned();
    let claim_token = Uuid::new_v4().to_string();
    let lease_until = now
        .checked_add(Duration::from_secs(120))
        .context("magic-link mail lease overflow")?;
    let claimed = retry_known_abort(|| {
        let (id, claim_token) = (id.clone(), claim_token.clone());
        async {
            client.query_client().retry_tx(closure!([id, claim_token], async |tx: &mut Transaction| {
                let Some(mut row) = tx.query_row(format!("SELECT status, next_attempt_at, expires_at, lease_until FROM `{TABLE}` WHERE id = $id"))
                    .param("$id", id.clone()).optional().await? else { return Ok(false); };
                let status: String = row.remove_field_by_name("status")?.try_into()?;
                let next: SystemTime = row.remove_field_by_name("next_attempt_at")?.try_into()?;
                let expires: SystemTime = row.remove_field_by_name("expires_at")?.try_into()?;
                let lease: Option<SystemTime> = row.remove_field_by_name("lease_until")?.try_into()?;
                if status != "pending" || next > now || expires <= now || lease.is_some_and(|until| until > now) { return Ok(false); }
                tx.exec(format!("UPDATE `{TABLE}` SET claim_token = $token, lease_until = CAST($lease AS Datetime), attempts = attempts + 1 WHERE id = $id"))
                    .param("$id", id.clone()).param("$token", claim_token.clone()).param("$lease", lease_until).await?;
                Ok(true)
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(10)).await
        }
    }).await?;
    Ok(claimed.then_some(claim_token))
}

async fn mail_row(
    client: &Client,
    secret: &[u8],
    id: &str,
    now: SystemTime,
) -> Result<Option<MailRow>> {
    let id = id.to_owned();
    let hash = token_hash(secret, &token_for_id(secret, Uuid::parse_str(&id)?)?)?;
    client.query_client().retry_tx(closure!([id, hash], async |tx: &mut Transaction| {
        let Some(mut row) = tx.query_row(format!("SELECT user_id, recipient, tenant_id, tenant_slug, redirect_to, expires_at, status FROM `{TABLE}` WHERE id = $id"))
            .param("$id", id.clone()).optional().await? else { return Ok(None); };
        let user_id: Uuid = row.remove_field_by_name("user_id")?.try_into()?;
        let recipient: String = row.remove_field_by_name("recipient")?.try_into()?;
        let tenant_id: Uuid = row.remove_field_by_name("tenant_id")?.try_into()?;
        let tenant_slug: String = row.remove_field_by_name("tenant_slug")?.try_into()?;
        let redirect_to: String = row.remove_field_by_name("redirect_to")?.try_into()?;
        let expires: SystemTime = row.remove_field_by_name("expires_at")?.try_into()?;
        let status: String = row.remove_field_by_name("status")?.try_into()?;
        if status != "pending" || expires <= now || !crate::password_mail::valid_recipient(&recipient) { return Ok(None); }
        let Some(mut token) = tx.query_row("SELECT user_id, expires_at, used_at FROM usid_magic_link_token WHERE token = $hash")
            .param("$hash", hash.clone()).optional().await? else { return Ok(None); };
        let owner: Uuid = token.remove_field_by_name("user_id")?.try_into()?;
        let token_expiry: SystemTime = token.remove_field_by_name("expires_at")?.try_into()?;
        let used: Option<SystemTime> = token.remove_field_by_name("used_at")?.try_into()?;
        if owner != user_id || token_expiry <= now || used.is_some() { return Ok(None); }
        let Some(mut user) = tx.query_row("SELECT email, email_verified, status FROM usid_user WHERE user_id = $id")
            .param("$id", user_id).optional().await? else { return Ok(None); };
        let email: String = user.remove_field_by_name("email")?.try_into()?;
        let verified: bool = user.remove_field_by_name("email_verified")?.try_into()?;
        let state: String = user.remove_field_by_name("status")?.try_into()?;
        if email != recipient || !verified || state != "active" { return Ok(None); }
        let Some(mut tenant) = tx.query_row("SELECT slug FROM usid_tenant WHERE id = $id")
            .param("$id", tenant_id).optional().await? else { return Ok(None); };
        let slug: String = tenant.remove_field_by_name("slug")?.try_into()?;
        if slug != tenant_slug { return Ok(None); }
        let mut membership = tx.query_row("SELECT COUNT(*) AS n FROM usid_tenant_membership WHERE user_id = $user AND tenant_id = $tenant AND status = 'active'")
            .param("$user", user_id).param("$tenant", tenant_id).await?;
        let count: u64 = membership.remove_field_by_name("n")?.try_into()?;
        if count != 1 { return Ok(None); }
        Ok(Some(MailRow { recipient, tenant_id, tenant_slug, redirect_to }))
    })).with_mode(TxMode::SerializableReadWrite).idempotent(true).timeout(Duration::from_secs(10)).await
        .context("read magic-link mail recipient")
}

async fn finish(
    client: &Client,
    id: &str,
    claim_token: &str,
    now: SystemTime,
    status: &str,
) -> Result<bool> {
    let next = now
        .checked_add(Duration::from_secs(60))
        .context("magic-link retry overflow")?;
    let (id, claim_token, status) = (id.to_owned(), claim_token.to_owned(), status.to_owned());
    retry_known_abort(|| {
        let (id, claim_token, status) = (id.clone(), claim_token.clone(), status.clone());
        async {
            client.query_client().retry_tx(closure!([id, claim_token, status], async |tx: &mut Transaction| {
                let Some(mut row) = tx.query_row(format!("SELECT claim_token FROM `{TABLE}` WHERE id = $id"))
                    .param("$id", id.clone()).optional().await? else { return Ok(false); };
                let current: String = row.remove_field_by_name("claim_token")?.try_into()?;
                if current != *claim_token { return Ok(false); }
                tx.exec(format!("UPDATE `{TABLE}` SET status = $status, claim_token = '', lease_until = NULL, next_attempt_at = CAST($next AS Datetime) WHERE id = $id"))
                    .param("$id", id.clone()).param("$status", status.clone()).param("$next", next).await?;
                Ok(true)
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(10)).await
        }
    }).await.context("finalize magic-link mail claim")
}

pub async fn process_one(
    client: &Client,
    id: &str,
    config: &MailConfig,
    mailer: &AsyncSmtpTransport<Tokio1Executor>,
    from: &Mailbox,
) -> Result<DrainResult> {
    let mut result = DrainResult::default();
    let Some(claim_token) = claim(client, id, SystemTime::now()).await? else {
        return Ok(result);
    };
    result.claimed = 1;
    match mail_row(client, &config.secret, id, SystemTime::now()).await {
        Ok(Some(row)) => {
            let delivered = match config.link(Uuid::parse_str(id)?, &row).and_then(|link| {
                Ok(Message::builder().from(from.clone()).to(row.recipient.parse()?)
                    .subject("Вход в UpdSpace ID")
                    .header(ContentTransferEncoding::QuotedPrintable)
                    .body(format!("Чтобы войти, откройте ссылку:\n\n{link}\n\nСсылка действует 15 минут и работает один раз. Если вы не запрашивали вход, проигнорируйте письмо."))?)
            }) {
                Ok(message) => tokio::time::timeout(Duration::from_secs(30), mailer.send(message))
                    .await.is_ok_and(|outcome| outcome.is_ok()),
                Err(_) => false,
            };
            if delivered {
                if finish(client, id, &claim_token, SystemTime::now(), "sent").await? {
                    result.sent = 1;
                }
            } else if finish(client, id, &claim_token, SystemTime::now(), "pending").await? {
                result.deferred = 1;
            }
        }
        Ok(None) => {
            if finish(client, id, &claim_token, SystemTime::now(), "cancelled").await? {
                result.cancelled = 1;
            }
        }
        Err(_) => {
            if finish(client, id, &claim_token, SystemTime::now(), "pending").await? {
                result.deferred = 1;
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    #[test]
    fn token_is_stable_for_retry_and_bound_to_id() -> Result<()> {
        let secret = [7u8; 32];
        let id = Uuid::new_v4();
        let first = token_for_id(&secret, id)?;
        assert_eq!(first, token_for_id(&secret, id)?);
        assert_ne!(first, token_for_id(&secret, Uuid::new_v4())?);
        assert_eq!(first.len(), 43);
        assert_eq!(token_hash(&secret, &first)?.len(), 64);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires local YDB; 100 competing mail claims across two connections"]
    async fn mail_claim_has_one_owner_and_retry_after_lease() -> Result<()> {
        ensure!(
            matches!(
                std::env::var("YDB_ENDPOINT")?.as_str(),
                "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
            ) && std::env::var("YDB_DATABASE")? == "/local",
            "local YDB required"
        );
        let first = Arc::new(crate::connect_ydb().await?);
        let second = Arc::new(crate::connect_ydb().await?);
        ensure_schema(&first).await?;
        let id = Uuid::new_v4().to_string();
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let now = SystemTime::now();
        first.query_client().exec(format!("INSERT INTO `{TABLE}` (id, user_id, tenant_id, tenant_slug, recipient, redirect_to, expires_at, status, attempts, next_attempt_at, claim_token, created_at) VALUES ($id, $user, $tenant, 'test', 'test@example.invalid', 'https://portal.example.invalid/callback', CAST($expires AS Datetime), 'pending', 0, CAST($now AS Datetime), '', CAST($now AS Datetime))"))
            .param("$id", id.clone()).param("$user", user_id).param("$tenant", tenant_id)
            .param("$expires", now + LINK_TTL).param("$now", now).await?;
        let result: Result<()> = async {
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
            while let Some(done) = tasks.join_next().await {
                if let Some(token) = done?? {
                    winners.push(token);
                }
            }
            ensure!(
                winners.len() == 1,
                "{} workers claimed one mail",
                winners.len()
            );
            ensure!(!finish(&second, &id, "stale", now, "sent").await?);
            ensure!(finish(&first, &id, &winners[0], now, "pending").await?);
            let later = now + Duration::from_secs(61);
            let retry = claim(&second, &id, later)
                .await?
                .context("retry not claimable")?;
            ensure!(finish(&second, &id, &retry, later, "sent").await?);
            ensure!(claim(&first, &id, later).await?.is_none());
            Ok(())
        }
        .await;
        first
            .query_client()
            .exec(format!("DELETE FROM `{TABLE}` WHERE id = $id"))
            .param("$id", id)
            .await?;
        result
    }
}
