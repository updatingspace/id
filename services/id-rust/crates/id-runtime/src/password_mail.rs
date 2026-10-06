//! Durable password-change notification. The password transaction inserts one
//! intent; SMTP delivery is retried by the private jobs service. SMTP's final
//! acknowledgement can be ambiguous, so duplicate email remains possible.

use crate::{new_device_mail::DrainResult, tx_retry::retry_known_abort};
use anyhow::{Context, Result, bail, ensure};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentTransferEncoding},
};
use std::time::{Duration, SystemTime};
use uuid::Uuid;
use ydb::{Client, IndexStatus, IndexType, Transaction, TxMode, Value, closure};

pub const TABLE: &str = "id_password_mail";
const DUE_INDEX: &str = "id_password_mail_due_idx";
const LEASE: Duration = Duration::from_secs(120);
const SMTP_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) fn valid_recipient(value: &str) -> bool {
    !value.is_empty() && value.parse::<Mailbox>().is_ok()
}

/// Additive schema step, repeated safely by `idctl password-mail-schema`.
pub async fn ensure_schema(client: &Client) -> Result<()> {
    client.query_client().exec(format!(
        "CREATE TABLE IF NOT EXISTS `{TABLE}` (id Utf8 NOT NULL, user_id Int32 NOT NULL, recipient Utf8 NOT NULL, status Utf8 NOT NULL, attempts Int32 NOT NULL, next_attempt_at Datetime NOT NULL, lease_until Datetime, claim_token Utf8 NOT NULL, sent_at Datetime, created_at Datetime NOT NULL, INDEX `{DUE_INDEX}` GLOBAL ON (status, next_attempt_at), PRIMARY KEY (id))"
    )).timeout(Duration::from_secs(15)).await?;
    let description = client
        .table_client()
        .describe_table(format!("{}/{TABLE}", client.database()))
        .await?;
    ensure!(
        description.primary_key == ["id"],
        "password mail primary key drift"
    );
    let actual: std::collections::BTreeSet<_> = description
        .columns
        .iter()
        .map(|column| column.name.as_str())
        .collect();
    let expected = [
        "id",
        "user_id",
        "recipient",
        "status",
        "attempts",
        "next_attempt_at",
        "lease_until",
        "claim_token",
        "sent_at",
        "created_at",
    ];
    ensure!(
        actual == expected.into_iter().collect(),
        "password mail columns drift"
    );
    for (name, kind, nullable) in [
        ("id", "text", false),
        ("user_id", "int32", false),
        ("recipient", "text", false),
        ("status", "text", false),
        ("attempts", "int32", false),
        ("next_attempt_at", "datetime", false),
        ("lease_until", "datetime", true),
        ("claim_token", "text", false),
        ("sent_at", "datetime", true),
        ("created_at", "datetime", false),
    ] {
        let column = description
            .columns
            .iter()
            .find(|column| column.name == name)
            .context("password mail column missing")?;
        let value = column
            .type_value
            .as_ref()
            .map_err(|_| anyhow::anyhow!("password mail column type unsupported: {name}"))?;
        if nullable {
            ensure!(
                value.is_optional(),
                "password mail nullability drift: {name}"
            );
            continue;
        }
        ensure!(
            !value.is_optional(),
            "password mail nullability drift: {name}"
        );
        let valid = matches!(
            (kind, value),
            ("text", Value::Text(_))
                | ("int32", Value::Int32(_))
                | ("datetime", Value::DateTime(_))
        );
        ensure!(valid, "password mail column type drift: {name}");
    }
    let index = description
        .indexes
        .iter()
        .find(|index| index.name == DUE_INDEX)
        .context("password mail due index missing")?;
    ensure!(
        index.index_columns == ["status", "next_attempt_at"]
            && index.index_type == IndexType::Global
            && index.status == IndexStatus::Ready,
        "password mail due index drift or not ready"
    );
    // IF NOT EXISTS does not validate an existing index; this query does.
    let mut query_client = client.query_client();
    let mut check = query_client.query(format!(
        "SELECT id FROM `{TABLE}` VIEW `{DUE_INDEX}` WHERE status = 'pending' AND next_attempt_at <= CurrentUtcDatetime() LIMIT 1"
    )).await?;
    while check.next_result_set().await?.is_some() {}
    check.close().await?;
    Ok(())
}

pub(crate) async fn enqueue_tx(
    tx: &mut Transaction,
    id: &str,
    user_id: i32,
    recipient: &str,
    now: SystemTime,
) -> ydb::YdbResultWithCustomerErr<()> {
    tx.exec(format!("INSERT INTO `{TABLE}` (id, user_id, recipient, status, attempts, next_attempt_at, claim_token, created_at) VALUES ($id, $user_id, $recipient, 'pending', 0, CAST($now AS Datetime), '', CAST($now AS Datetime))"))
        .param("$id", id.to_owned()).param("$user_id", user_id)
        .param("$recipient", recipient.to_owned()).param("$now", now).await?;
    Ok(())
}

pub async fn due_ids(client: &Client, now: SystemTime, limit: u64) -> Result<Vec<String>> {
    if limit == 0 || limit > 100 {
        bail!("password mail batch size must be 1..=100");
    }
    let mut query_client = client.query_client();
    let mut query = query_client.query(format!(
        "SELECT id FROM `{TABLE}` VIEW `{DUE_INDEX}` WHERE status = 'pending' AND next_attempt_at <= CAST($now AS Datetime) AND (lease_until IS NULL OR lease_until <= CAST($now AS Datetime)) ORDER BY next_attempt_at LIMIT $limit"
    )).param("$now", now).param("$limit", limit).await?;
    let mut ids = Vec::new();
    while let Some(set) = query.next_result_set().await? {
        for mut row in set {
            ids.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    query.close().await?;
    Ok(ids)
}

async fn claim(client: &Client, id: &str, now: SystemTime) -> Result<Option<String>> {
    ensure!(Uuid::parse_str(id).is_ok(), "invalid password mail ID");
    let id = id.to_owned();
    let token = Uuid::new_v4().to_string();
    let lease_until = now.checked_add(LEASE).context("mail lease overflow")?;
    let claimed = retry_known_abort(|| {
        let id = id.clone();
        let token = token.clone();
        async move {
            client.query_client().retry_tx(closure!([id, token], async |tx: &mut Transaction| {
                let Some(mut row) = tx.query_row(format!("SELECT status, next_attempt_at, lease_until FROM `{TABLE}` WHERE id = $id"))
                    .param("$id", id.clone()).optional().await? else { return Ok(false); };
                let status: String = row.remove_field_by_name("status")?.try_into()?;
                let next: SystemTime = row.remove_field_by_name("next_attempt_at")?.try_into()?;
                let lease: Option<SystemTime> = row.remove_field_by_name("lease_until")?.try_into()?;
                if status != "pending" || next > now || lease.is_some_and(|until| until > now) {
                    return Ok(false);
                }
                tx.exec(format!("UPDATE `{TABLE}` SET claim_token = $token, lease_until = CAST($lease AS Datetime), attempts = attempts + 1 WHERE id = $id"))
                    .param("$id", id.clone()).param("$token", token.clone()).param("$lease", lease_until).await?;
                Ok(true)
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
                .timeout(Duration::from_secs(10)).await
        }
    }).await?;
    Ok(claimed.then_some(token))
}

async fn recipient(client: &Client, id: &str) -> Result<Option<String>> {
    let mut row = client
        .query_client()
        .query_row(format!(
            "SELECT user_id, recipient FROM `{TABLE}` WHERE id = $id"
        ))
        .param("$id", id.to_owned())
        .await?;
    let user_id: i32 = row.remove_field_by_name("user_id")?.try_into()?;
    let recipient: String = row.remove_field_by_name("recipient")?.try_into()?;
    let account = client
        .query_client()
        .query_row("SELECT id FROM auth_user WHERE id = $id")
        .param("$id", user_id)
        .optional()
        .await?;
    if account.is_none() || recipient.is_empty() {
        return Ok(None);
    }
    let mut deletion = client.query_client().query_row(
        "SELECT COUNT(*) AS count FROM accounts_accountdeletionrequest VIEW accounts_accountdeletionrequest_user_id_6a166c52 WHERE user_id = $id AND status != 'canceled'"
    ).param("$id", user_id).await?;
    let count: u64 = deletion.remove_field_by_name("count")?.try_into()?;
    Ok((count == 0).then_some(recipient))
}

fn render(recipient: &str, from: &Mailbox) -> Result<Message> {
    Ok(Message::builder().from(from.clone()).to(recipient.parse()?)
        .subject("Пароль аккаунта изменён")
        .header(ContentTransferEncoding::QuotedPrintable)
        .body("Пароль вашего аккаунта UpdSpace ID изменён.\n\nЕсли это были не вы, обратитесь в поддержку и проверьте безопасность своей почты.".to_owned())?)
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
        .context("mail retry overflow")?;
    retry_known_abort(|| {
        let id = id.clone(); let token = token.clone(); let state = state.clone();
        async move {
            client.query_client().retry_tx(closure!([id, token, state], async |tx: &mut Transaction| {
                let Some(mut row) = tx.query_row(format!("SELECT claim_token FROM `{TABLE}` WHERE id = $id"))
                    .param("$id", id.clone()).optional().await? else { return Ok(false); };
                let current: String = row.remove_field_by_name("claim_token")?.try_into()?;
                if current != token.as_str() { return Ok(false); }
                tx.exec(format!("UPDATE `{TABLE}` SET status = $state, user_id = CASE WHEN $state = 'pending' THEN user_id ELSE 0 END, recipient = CASE WHEN $state = 'pending' THEN recipient ELSE Unwrap(CAST('' AS Utf8)) END, claim_token = Unwrap(CAST('' AS Utf8)), lease_until = NULL, sent_at = CASE WHEN $state = 'sent' THEN CAST($now AS Datetime) ELSE NULL END, next_attempt_at = CAST($next AS Datetime) WHERE id = $id"))
                    .param("$id", id.clone()).param("$state", state.clone())
                    .param("$now", now).param("$next", next).await?;
                Ok(true)
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
                .timeout(Duration::from_secs(10)).await
        }
    }).await.context("finalize password mail claim")
}

pub async fn process_one(
    client: &Client,
    id: &str,
    mailer: &AsyncSmtpTransport<Tokio1Executor>,
    from: &Mailbox,
) -> Result<DrainResult> {
    let mut result = DrainResult::default();
    let Some(token) = claim(client, id, SystemTime::now()).await? else {
        return Ok(result);
    };
    result.claimed = 1;
    match recipient(client, id).await {
        Ok(Some(address)) => {
            let delivered = match render(&address, from) {
                Ok(message) => tokio::time::timeout(SMTP_TIMEOUT, mailer.send(message))
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

pub async fn drain_due(
    client: &Client,
    limit: u64,
    mailer: &AsyncSmtpTransport<Tokio1Executor>,
    from: &Mailbox,
) -> Result<DrainResult> {
    let mut result = DrainResult::default();
    for id in due_ids(client, SystemTime::now(), limit).await? {
        let next = process_one(client, &id, mailer, from).await?;
        result.claimed += next.claimed;
        result.sent += next.sent;
        result.deferred += next.deferred;
        result.cancelled += next.cancelled;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tower::ServiceExt;

    #[test]
    fn mail_contains_no_credentials() -> Result<()> {
        assert!(!valid_recipient(""));
        assert!(!valid_recipient("invalid\nBcc: other@example.invalid"));
        assert!(valid_recipient("person@example.invalid"));
        let from: Mailbox = "no-reply@example.invalid".parse()?;
        let message = render("person@example.invalid", &from)?;
        let raw = String::from_utf8(message.formatted())?;
        assert!(raw.contains("person@example.invalid"));
        assert!(!raw.to_lowercase().contains("password="));
        Ok(())
    }

    async fn local_client() -> Result<Arc<Client>> {
        ensure!(
            matches!(
                std::env::var("YDB_ENDPOINT")?.as_str(),
                "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
            ) && std::env::var("YDB_DATABASE")? == "/local",
            "password mail test requires local YDB"
        );
        let client = Arc::new(crate::connect_ydb().await?);
        ensure_schema(&client).await?;
        crate::security_mail::ensure_schema(&client).await?;
        Ok(client)
    }

    #[tokio::test]
    #[ignore = "requires local /local YDB and a loopback SMTP fixture"]
    async fn sends_once_from_durable_intent() -> Result<()> {
        let client = local_client().await?;
        let id = Uuid::new_v4().to_string();
        let account_id = -i32::try_from(rand::random::<u32>() % 1_000_000_000 + 1)?;
        let recipient = "password-mail@example.invalid";
        let now = SystemTime::now();
        client.query_client().exec("INSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, '', true, $name, '', '', $email, false, false, CAST($now AS Datetime))")
            .param("$id", account_id).param("$name", format!("mail-{id}"))
            .param("$email", recipient).param("$now", now).await?;
        let outcome: Result<()> = async {
            client.query_client().exec(format!("INSERT INTO `{TABLE}` (id, user_id, recipient, status, attempts, next_attempt_at, claim_token, created_at) VALUES ($id, $user, $recipient, 'pending', 0, CAST($now AS Datetime), '', CAST($now AS Datetime))"))
                .param("$id", id.clone()).param("$user", account_id).param("$recipient", recipient)
                .param("$now", now).await?;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let port = listener.local_addr()?.port();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await?;
                let mut io = BufReader::new(stream);
                io.get_mut().write_all(b"220 localhost ESMTP\r\n").await?;
                let mut body = String::new();
                loop {
                    let mut line = String::new();
                    if io.read_line(&mut line).await? == 0 { bail!("SMTP client disconnected"); }
                    if line.starts_with("DATA") {
                        io.get_mut().write_all(b"354 send data\r\n").await?;
                        loop {
                            line.clear();
                            if io.read_line(&mut line).await? == 0 { bail!("SMTP body truncated"); }
                            if line == ".\r\n" { break; }
                            body.push_str(&line);
                        }
                        io.get_mut().write_all(b"250 queued\r\n").await?;
                        return Ok::<String, anyhow::Error>(body);
                    }
                    io.get_mut().write_all(b"250 ok\r\n").await?;
                }
            });
            let from: Mailbox = "no-reply@example.invalid".parse()?;
            let mailer = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("127.0.0.1")
                .port(port).timeout(Some(Duration::from_secs(5))).build();
            let worker = Arc::new(crate::new_device_mail::MailWorker::for_test(client.clone(), mailer, from));
            ensure!(worker.ready().await, "mail worker not ready after schema migration");
            let app = crate::jobs_http::router(worker);
            let queue_body = serde_json::json!({"messages":[{"event_metadata":{"event_type":"yandex.cloud.events.messagequeue.QueueMessage"},
                "details":{"message":{"body":serde_json::json!({"version":1,"kind":"password_changed_mail","event_id":id}).to_string()}}}]});
            let request = || Request::builder().method("POST").uri("/internal/jobs/mail")
                .body(Body::from(queue_body.to_string()));
            let timer_body = serde_json::json!({"messages":[{"event_metadata":{"event_type":"yandex.cloud.events.serverless.triggers.TimerMessage"},"details":{"payload":""}}]});
            let timer_request = Request::builder().method("POST").uri("/internal/jobs/recover-mail")
                .body(Body::from(timer_body.to_string()))?;
            let response = app.clone().oneshot(timer_request).await?;
            ensure!(response.status() == StatusCode::OK, "password mail timer dispatch failed");
            let first: serde_json::Value = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
            ensure!(first["claimed"] == 1 && first["sent"] == 1, "password alert not sent");
            let body = tokio::time::timeout(Duration::from_secs(5), server).await???;
            ensure!(body.contains("UpdSpace ID") && !body.contains("password="));
            // A delayed queue wakeup must not send the already delivered alert again.
            let response = app.oneshot(request()?).await?;
            ensure!(response.status() == StatusCode::OK);
            let second: serde_json::Value = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
            ensure!(second["claimed"] == 0 && second["sent"] == 0, "sent alert was claimed twice");
            let mut row = client.query_client().query_row(format!("SELECT status, attempts, sent_at, recipient, user_id FROM `{TABLE}` WHERE id = $id"))
                .param("$id", id.clone()).await?;
            let status: String = row.remove_field_by_name("status")?.try_into()?;
            let attempts: i32 = row.remove_field_by_name("attempts")?.try_into()?;
            let sent_at: Option<SystemTime> = row.remove_field_by_name("sent_at")?.try_into()?;
            let recipient_after: String = row.remove_field_by_name("recipient")?.try_into()?;
            let user_after: i32 = row.remove_field_by_name("user_id")?.try_into()?;
            ensure!(status == "sent" && attempts == 1 && sent_at.is_some() && recipient_after.is_empty() && user_after == 0);
            Ok(())
        }.await;
        client
            .query_client()
            .exec(format!("DELETE FROM `{TABLE}` WHERE id = $id"))
            .param("$id", id)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM auth_user WHERE id = $id")
            .param("$id", account_id)
            .await?;
        outcome
    }

    #[tokio::test]
    #[ignore = "requires local /local YDB; races 100 claims across two clients"]
    async fn two_clients_claim_one_password_mail() -> Result<()> {
        let first = local_client().await?;
        let second = local_client().await?;
        let id = Uuid::new_v4().to_string();
        let now = SystemTime::now();
        first.query_client().exec(format!("INSERT INTO `{TABLE}` (id, user_id, recipient, status, attempts, next_attempt_at, claim_token, created_at) VALUES ($id, -1, 'test@example.invalid', 'pending', 0, CAST($now AS Datetime), '', CAST($now AS Datetime))"))
            .param("$id", id.clone()).param("$now", now).await?;
        let outcome: Result<()> = async {
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
            while let Some(outcome) = tasks.join_next().await {
                if let Some(token) = outcome?? {
                    winners.push(token);
                }
            }
            ensure!(
                winners.len() == 1,
                "password mail had {} claim winners",
                winners.len()
            );
            ensure!(!finish(&second, &id, "stale", now, "sent").await?);
            ensure!(finish(&first, &id, &winners[0], now, "sent").await?);
            ensure!(claim(&second, &id, now).await?.is_none());
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

    #[tokio::test]
    #[ignore = "requires local /local YDB; cancels mail for a deleted account"]
    async fn deleted_account_cancels_and_scrubs_pending_mail() -> Result<()> {
        let client = local_client().await?;
        let id = Uuid::new_v4().to_string();
        let now = SystemTime::now();
        client.query_client().exec(format!("INSERT INTO `{TABLE}` (id, user_id, recipient, status, attempts, next_attempt_at, claim_token, created_at) VALUES ($id, -1, 'deleted@example.invalid', 'pending', 0, CAST($now AS Datetime), '', CAST($now AS Datetime))"))
            .param("$id", id.clone()).param("$now", now).await?;
        let outcome: Result<()> = async {
            let from: Mailbox = "no-reply@example.invalid".parse()?;
            let mailer = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("127.0.0.1")
                .port(9)
                .timeout(Some(Duration::from_secs(1)))
                .build();
            let result = process_one(&client, &id, &mailer, &from).await?;
            ensure!(result.claimed == 1 && result.cancelled == 1 && result.sent == 0);
            let mut row = client
                .query_client()
                .query_row(format!(
                    "SELECT status, recipient, user_id FROM `{TABLE}` WHERE id = $id"
                ))
                .param("$id", id.clone())
                .await?;
            let status: String = row.remove_field_by_name("status")?.try_into()?;
            let recipient: String = row.remove_field_by_name("recipient")?.try_into()?;
            let user_id: i32 = row.remove_field_by_name("user_id")?.try_into()?;
            ensure!(status == "cancelled" && recipient.is_empty() && user_id == 0);
            Ok(())
        }
        .await;
        client
            .query_client()
            .exec(format!("DELETE FROM `{TABLE}` WHERE id = $id"))
            .param("$id", id)
            .await?;
        outcome
    }
}
