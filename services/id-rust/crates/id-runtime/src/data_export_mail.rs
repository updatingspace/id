//! Durable notices for delayed exports. SMTP can acknowledge ambiguously;
//! retries deliberately send the same operation-bound capability.

use crate::{data_export_escrow::ExportEscrowKey, tx_retry::retry_known_abort};
use anyhow::{Context, Result, bail, ensure};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentTransferEncoding},
};
use std::time::{Duration, SystemTime};
use url::Url;
use uuid::Uuid;
use ydb::{Client, Transaction, TxMode, closure};

const TABLE: &str = "id_data_export_mail";
const DUE_INDEX: &str = "id_export_mail_due_idx";
const LEASE: Duration = Duration::from_secs(120);
const RETRY: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Notice,
    Delivery,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Notice => "notice",
            Self::Delivery => "delivery",
        }
    }
}

fn mail_id(export_id: &str, kind: Kind) -> String {
    format!("{export_id}:{}", kind.name())
}

fn valid_export_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub struct MailConfig {
    pub key: ExportEscrowKey,
    pub public_origin: Url,
}

impl MailConfig {
    pub fn from_env() -> Result<Option<Self>> {
        let pilot = crate::me_http::env_flag("ID_EXPORT_ESCROW_MAIL_PILOT_ENABLED", false)?;
        let rollout = crate::me_http::env_flag("ID_EXPORT_ESCROW_MAIL_ROLLOUT_ENABLED", false)?;
        if !pilot && !rollout {
            return Ok(None);
        }
        let endpoint = Url::parse(&std::env::var("YDB_ENDPOINT")?)?;
        let local_ydb = crate::me_http::env_flag("DJANGO_DEBUG", false)?
            && matches!(
                endpoint.host_str(),
                Some("localhost" | "127.0.0.1" | "[::1]")
            )
            && std::env::var("YDB_DATABASE")? == "/local";
        ensure!(
            !pilot || local_ydb,
            "export escrow mail pilot requires local debug YDB"
        );
        let key = ExportEscrowKey::from_base64(&std::env::var("ID_EXPORT_ESCROW_KEY")?)?;
        Ok(Some(Self::new(
            key,
            &std::env::var("ID_EXPORT_PUBLIC_ORIGIN")?,
        )?))
    }

    pub fn new(key: ExportEscrowKey, public_origin: &str) -> Result<Self> {
        let origin = Url::parse(public_origin)?;
        let loopback = matches!(origin.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        ensure!(
            (origin.scheme() == "https" || (origin.scheme() == "http" && loopback))
                && origin.path() == "/"
                && origin.query().is_none()
                && origin.fragment().is_none()
                && origin.username().is_empty()
                && origin.password().is_none(),
            "invalid export public origin"
        );
        Ok(Self {
            key,
            public_origin: origin,
        })
    }

    fn link(&self, id: &str) -> Result<String> {
        ensure!(valid_export_id(id), "invalid export ID");
        let mut url = self.public_origin.join("/data/export")?;
        url.query_pairs_mut().append_pair("id", id);
        url.set_fragment(Some(&self.key.capability(id)?));
        Ok(url.to_string())
    }

    fn cancel_link(&self, id: &str) -> Result<String> {
        ensure!(valid_export_id(id), "invalid export ID");
        let mut url = self.public_origin.join("/data/export/cancel")?;
        url.query_pairs_mut().append_pair("id", id);
        url.set_fragment(Some(&self.key.cancel_capability(id)?));
        Ok(url.to_string())
    }
}

pub async fn ensure_schema(client: &Client) -> Result<()> {
    client.query_client().exec(format!(
        "CREATE TABLE IF NOT EXISTS `{TABLE}` (id Utf8 NOT NULL, export_id Utf8 NOT NULL, kind Utf8 NOT NULL, state Utf8 NOT NULL, next_attempt_at Datetime NOT NULL, lease_until Datetime, claim_token Utf8 NOT NULL, attempts Int32 NOT NULL, created_at Datetime NOT NULL, sent_at Datetime, INDEX `{DUE_INDEX}` GLOBAL ON (state, next_attempt_at), PRIMARY KEY (id))"
    )).timeout(Duration::from_secs(15)).await?;
    let description = client
        .table_client()
        .describe_table(format!("{}/{TABLE}", client.database()))
        .await?;
    ensure!(
        description.primary_key == ["id"],
        "export mail primary key drift"
    );
    let expected = [
        "id",
        "export_id",
        "kind",
        "state",
        "next_attempt_at",
        "lease_until",
        "claim_token",
        "attempts",
        "created_at",
        "sent_at",
    ];
    let actual: std::collections::BTreeSet<_> = description
        .columns
        .iter()
        .map(|column| column.name.as_str())
        .collect();
    ensure!(
        actual == expected.into_iter().collect(),
        "export mail column drift"
    );
    let index = description
        .indexes
        .iter()
        .find(|index| index.name == DUE_INDEX)
        .context("export mail due index missing")?;
    ensure!(
        index.index_columns == ["state", "next_attempt_at"]
            && index.index_type == ydb::IndexType::Global
            && index.status == ydb::IndexStatus::Ready,
        "export mail due index drift"
    );
    Ok(())
}

pub async fn insert_request_tx(
    tx: &mut Transaction,
    export_id: &str,
    now: SystemTime,
) -> ydb::YdbResultWithCustomerErr<()> {
    if !valid_export_id(export_id) {
        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
            "invalid export mail ID",
        )));
    }
    let release_at = now + crate::data_export_escrow::COOLDOWN;
    for (kind, due) in [(Kind::Notice, now), (Kind::Delivery, release_at)] {
        tx.exec(format!("INSERT INTO `{TABLE}` (id, export_id, kind, state, next_attempt_at, claim_token, attempts, created_at) VALUES ($id, $export, $kind, 'pending', CAST($due AS Datetime), '', 0, CAST($now AS Datetime))"))
            .param("$id", mail_id(export_id, kind)).param("$export", export_id.to_owned())
            .param("$kind", kind.name().to_owned()).param("$due", due).param("$now", now).await?;
    }
    Ok(())
}

pub async fn intents_exist_tx(
    tx: &mut Transaction,
    export_id: &str,
) -> ydb::YdbResultWithCustomerErr<bool> {
    for kind in [Kind::Notice, Kind::Delivery] {
        if tx
            .query_row(format!("SELECT id FROM `{TABLE}` WHERE id = $id"))
            .param("$id", mail_id(export_id, kind))
            .optional()
            .await?
            .is_none()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

pub async fn due_ids(client: &Client, now: SystemTime, limit: u64) -> Result<Vec<String>> {
    ensure!((1..=10).contains(&limit), "invalid export mail batch size");
    let mut found = Vec::new();
    for state in ["pending", "running"] {
        let mut query_client = client.query_client();
        let mut query = query_client.query(format!("SELECT id FROM `{TABLE}` VIEW `{DUE_INDEX}` WHERE state = $state AND next_attempt_at <= CAST($now AS Datetime) ORDER BY next_attempt_at LIMIT $limit"))
            .param("$state", state.to_owned()).param("$now", now).param("$limit", limit).await?;
        while let Some(set) = query.next_result_set().await? {
            for mut row in set {
                found.push(row.remove_field_by_name("id")?.try_into()?);
            }
        }
        query.close().await?;
    }
    found.truncate(limit as usize);
    Ok(found)
}

struct Claimed {
    token: String,
    export_id: String,
    kind: Kind,
    envelope: String,
    release_at: SystemTime,
    snapshot_failed: bool,
}

async fn claim(client: &Client, id: &str, now: SystemTime) -> Result<Option<Claimed>> {
    let (export_id, kind) = if let Some(id) = id.strip_suffix(":notice") {
        (id, Kind::Notice)
    } else if let Some(id) = id.strip_suffix(":delivery") {
        (id, Kind::Delivery)
    } else {
        bail!("invalid export mail kind");
    };
    ensure!(valid_export_id(export_id), "invalid export mail ID");
    let id = id.to_owned();
    let export_id = export_id.to_owned();
    let token = Uuid::new_v4().to_string();
    let lease_until = now + LEASE;
    retry_known_abort(|| {
        let id = id.clone(); let export_id = export_id.clone(); let token = token.clone();
        async move {
            client.query_client().retry_tx(closure!([id, export_id, token], async |tx: &mut Transaction| {
                let Some(mut row) = tx.query_row(format!("SELECT state, next_attempt_at FROM `{TABLE}` WHERE id = $id"))
                    .param("$id", id.clone()).optional().await? else { return Ok(None); };
                let state: String = row.remove_field_by_name("state")?.try_into()?;
                let due: SystemTime = row.remove_field_by_name("next_attempt_at")?.try_into()?;
                if !matches!(state.as_str(), "pending" | "running") || due > now { return Ok(None); }
                let Some(mut escrow) = tx.query_row("SELECT encrypted_email, state, release_at, expires_at, object_key FROM id_data_export_escrow WHERE id = $id")
                    .param("$id", export_id.clone()).optional().await? else { return Ok(None); };
                let envelope: String = escrow.remove_field_by_name("encrypted_email")?.try_into()?;
                let escrow_state: String = escrow.remove_field_by_name("state")?.try_into()?;
                let release_at: SystemTime = escrow.remove_field_by_name("release_at")?.try_into()?;
                let expiry: SystemTime = escrow.remove_field_by_name("expires_at")?.try_into()?;
                let object_key: String = escrow.remove_field_by_name("object_key")?.try_into()?;
                if expiry <= now || envelope.is_empty() || matches!(escrow_state.as_str(), "expired" | "cancelled") {
                    tx.exec(format!("UPDATE `{TABLE}` SET state = 'cancelled', claim_token = '', lease_until = NULL WHERE id = $id"))
                        .param("$id", id.clone()).await?;
                    return Ok(None);
                }
                if kind == Kind::Delivery && (!matches!(escrow_state.as_str(), "sealed" | "released" | "failed")
                    || (escrow_state != "failed" && object_key.is_empty()) || release_at > now) {
                    let next = now + Duration::from_secs(300);
                    tx.exec(format!("UPDATE `{TABLE}` SET state = 'pending', next_attempt_at = CAST($next AS Datetime), claim_token = '', lease_until = NULL WHERE id = $id"))
                        .param("$id", id.clone()).param("$next", next).await?;
                    return Ok(None);
                }
                tx.exec(format!("UPDATE `{TABLE}` SET state = 'running', attempts = attempts + 1, claim_token = $token, lease_until = CAST($until AS Datetime), next_attempt_at = CAST($until AS Datetime) WHERE id = $id"))
                    .param("$id", id.clone()).param("$token", token.clone()).param("$until", lease_until).await?;
                Ok(Some(Claimed { token: token.clone(), export_id: export_id.clone(), kind, envelope, release_at, snapshot_failed: escrow_state == "failed" }))
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(10)).await
        }
    }).await.context("claim export mail")
}

async fn finish(
    client: &Client,
    id: &str,
    token: &str,
    sent: bool,
    now: SystemTime,
) -> Result<bool> {
    let id = id.to_owned();
    let token = token.to_owned();
    retry_known_abort(|| {
        let id = id.clone(); let token = token.clone();
        async move {
            client.query_client().retry_tx(closure!([id, token], async |tx: &mut Transaction| {
                let Some(mut row) = tx.query_row(format!("SELECT state, claim_token, export_id, kind FROM `{TABLE}` WHERE id = $id"))
                    .param("$id", id.clone()).optional().await? else { return Ok(false); };
                let state: String = row.remove_field_by_name("state")?.try_into()?;
                let current: String = row.remove_field_by_name("claim_token")?.try_into()?;
                let export_id: String = row.remove_field_by_name("export_id")?.try_into()?;
                let kind: String = row.remove_field_by_name("kind")?.try_into()?;
                if state != "running" || current != *token { return Ok(false); }
                let next = now + RETRY;
                let next_state = if sent { "sent" } else { "pending" };
                tx.exec(format!("UPDATE `{TABLE}` SET state = $state, next_attempt_at = CAST($next AS Datetime), claim_token = '', lease_until = NULL, sent_at = CASE WHEN $sent THEN CAST($now AS Datetime) ELSE NULL END WHERE id = $id"))
                    .param("$id", id.clone()).param("$state", next_state.to_owned()).param("$next", next)
                    .param("$sent", sent).param("$now", now).await?;
                if sent {
                    let field = if kind == "notice" { "notice_state" } else { "delivery_state" };
                    tx.exec(format!("UPDATE id_data_export_escrow SET {field} = 'sent' WHERE id = $id"))
                        .param("$id", export_id).await?;
                }
                Ok(true)
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(10)).await
        }
    }).await.context("finish export mail")
}

fn render(
    claimed: &Claimed,
    recipient: &str,
    config: &MailConfig,
    from: &Mailbox,
) -> Result<Message> {
    let (subject, body) = match claimed.kind {
        Kind::Notice if claimed.snapshot_failed => (
            "Не удалось подготовить копию данных UpdSpace ID",
            "Запрошенную копию данных подготовить не удалось. Архив и ссылка для скачивания не созданы. Если аккаунт ещё доступен, вы можете создать новый запрос. Если запрос сделали не вы, обратитесь в поддержку UpdSpace ID.\n".to_owned(),
        ),
        Kind::Notice => (
            "Запрошена копия данных UpdSpace ID",
            format!(
                "Для вашего аккаунта принят запрос на копию данных. Мы подготовим архив; ссылка для получения будет отправлена на этот адрес не раньше {}. Номер запроса: {}.\n\nЕсли запрос сделали не вы или вы передумали, отмените его по ссылке:\n{}\n\nОтмена работает и после удаления аккаунта. Эта ссылка не открывает архив. Не пересылайте письмо другим людям.\n",
                chrono::DateTime::<chrono::Utc>::from(claimed.release_at).to_rfc3339(),
                claimed.export_id,
                config.cancel_link(&claimed.export_id)?,
            ),
        ),
        Kind::Delivery if claimed.snapshot_failed => (
            "Копия данных UpdSpace ID не подготовлена",
            "Не удалось подготовить ранее запрошенную копию данных. Ссылка для скачивания не выдавалась. Если аккаунт ещё доступен, создайте новый запрос. Если аккаунт удалён, обратитесь в поддержку UpdSpace ID.\n".to_owned(),
        ),
        Kind::Delivery => (
            "Ваша копия данных UpdSpace ID готова",
            format!(
                "Откройте ссылку, чтобы получить ранее запрошенную копию данных:\n\n{}\n\nСсылка действует ограниченное время и остаётся доступной после удаления аккаунта. Не пересылайте это письмо другим людям.\n",
                config.link(&claimed.export_id)?
            ),
        ),
    };
    Ok(Message::builder()
        .from(from.clone())
        .to(recipient.parse()?)
        .subject(subject)
        .header(ContentTransferEncoding::QuotedPrintable)
        .body(body)?)
}

pub async fn process_one(
    client: &Client,
    id: &str,
    config: &MailConfig,
    mailer: &AsyncSmtpTransport<Tokio1Executor>,
    from: &Mailbox,
) -> Result<crate::new_device_mail::DrainResult> {
    let mut result = crate::new_device_mail::DrainResult::default();
    let Some(claimed) = claim(client, id, SystemTime::now()).await? else {
        return Ok(result);
    };
    result.claimed = 1;
    let sent = match config
        .key
        .unseal_recipient(&claimed.export_id, &claimed.envelope)
        .and_then(|recipient| render(&claimed, &recipient, config, from))
    {
        Ok(message) => tokio::time::timeout(Duration::from_secs(30), mailer.send(message))
            .await
            .is_ok_and(|response| response.is_ok()),
        Err(error) => {
            tracing::warn!(operation_id = %claimed.export_id, error = %error, "export mail composition deferred");
            false
        }
    };
    if finish(client, id, &claimed.token, sent, SystemTime::now()).await? {
        if sent {
            result.sent = 1;
        } else {
            result.deferred = 1;
        }
    }
    Ok(result)
}

pub async fn drain_due(
    client: &Client,
    limit: u64,
    config: &MailConfig,
    mailer: &AsyncSmtpTransport<Tokio1Executor>,
    from: &Mailbox,
) -> Result<crate::new_device_mail::DrainResult> {
    let mut result = crate::new_device_mail::DrainResult::default();
    for id in due_ids(client, SystemTime::now(), limit).await? {
        let one = process_one(client, &id, config, mailer, from).await?;
        result.claimed += one.claimed;
        result.sent += one.sent;
        result.deferred += one.deferred;
        result.cancelled += one.cancelled;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};

    #[test]
    fn delivery_link_keeps_capability_in_fragment() -> Result<()> {
        let key = ExportEscrowKey::from_base64(&STANDARD.encode([0x37; 32]))?;
        let config = MailConfig::new(key, "https://id.example.invalid/")?;
        let link = Url::parse(&config.link("0123456789abcdef0123456789abcdef")?)?;
        ensure!(link.path() == "/data/export");
        ensure!(
            link.query() == Some("id=0123456789abcdef0123456789abcdef")
                && link.fragment().is_some()
        );
        let cancel = Url::parse(&config.cancel_link("0123456789abcdef0123456789abcdef")?)?;
        ensure!(cancel.path() == "/data/export/cancel");
        ensure!(cancel.query() == link.query());
        ensure!(cancel.fragment().is_some() && cancel.fragment() != link.fragment());
        ensure!(MailConfig::new(config.key, "https://other.invalid/path").is_err());
        Ok(())
    }
}
