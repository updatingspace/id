#![recursion_limit = "256"]
//! Real YDB proof that a replaced email link cannot change the account and
//! that confirmation updates login and identity ownership only once.

use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use id_compat::session::SessionCodec;
use id_runtime::{
    email_change::{self, StageResult},
    email_verify::{self, ConfirmResult, VerifyKey, VerifyMailConfig},
};
use lettre::{AsyncSmtpTransport, Tokio1Executor, message::Mailbox};
use serde_json::json;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tower::ServiceExt;
use uuid::Uuid;
use ydb::Client;

// The expiry test sweeps the whole local table with a future clock.
static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn change_request(
    app: &Router,
    token: Option<&str>,
    csrf: bool,
    email: &str,
) -> Result<(StatusCode, serde_json::Value)> {
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/email/change")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        request = request.header(
            header::COOKIE,
            format!("sessionid={token}; csrftoken=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        );
    }
    if csrf {
        request = request
            .header(header::ORIGIN, "http://id.localhost")
            .header("x-csrftoken", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(json!({"new_email":email}).to_string()))?)
        .await?;
    let status = response.status();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
    Ok((status, body))
}

async fn cancel_request(app: &Router, token: &str) -> Result<(StatusCode, serde_json::Value)> {
    let request = Request::builder()
        .method("DELETE")
        .uri("/api/v1/auth/email/change")
        .header(
            header::COOKIE,
            format!("sessionid={token}; csrftoken=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        )
        .header(header::ORIGIN, "http://id.localhost")
        .header("x-csrftoken", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .body(Body::empty())?;
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
    Ok((status, body))
}

async fn seed(
    client: &Client,
    codec: &SessionCodec,
    user_id: i32,
    identity_id: Uuid,
    token: &str,
    old: &str,
    recent: bool,
) -> Result<()> {
    let now = SystemTime::now();
    let password = "pbkdf2_sha256$1000000$synthetic$synthetic";
    let seconds = now.duration_since(UNIX_EPOCH)?.as_secs();
    let data = json!({
        "_auth_user_id": user_id.to_string(),
        "_auth_user_backend": "django.contrib.auth.backends.ModelBackend",
        "_auth_user_hash": codec.auth_hash(password)?,
        "account_authentication_methods": [{"method":"password", "at": if recent { seconds } else { seconds - 400 }}]
    });
    let signed = codec.encode(
        data.as_object().context("session object")?,
        i64::try_from(seconds)?,
        true,
    )?;
    client.query_client().exec("INSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $password, true, $name, '', '', $email, false, false, CAST($now AS Datetime))")
        .param("$id", user_id).param("$password", password).param("$name", format!("emailchange{user_id}"))
        .param("$email", old.to_owned()).param("$now", now).await?;
    client.query_client().exec("INSERT INTO django_session (session_key, session_data, expire_date) VALUES ($token, $signed, CAST($expires AS Datetime))")
        .param("$token", token.to_owned()).param("$signed", signed).param("$expires", now + Duration::from_secs(3600)).await?;
    client
        .query_client()
        .exec("INSERT INTO accounts_accountemaillookup (user_id, email_key) VALUES ($id, $email)")
        .param("$id", user_id)
        .param("$email", old.to_owned())
        .await?;
    client.query_client().exec("INSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($id, $user_id, $email, true, true)")
        .param("$id", user_id).param("$user_id", user_id).param("$email", old.to_owned()).await?;
    client.query_client().exec("INSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($identity, $name, $name, $email, true, 'active', false, CAST($now AS Datetime))")
        .param("$identity", identity_id).param("$name", format!("emailchange{user_id}"))
        .param("$email", old.to_owned()).param("$now", now).await?;
    client.query_client().exec("INSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($id, $identity, $subject, CAST($now AS Datetime))")
        .param("$id", user_id).param("$identity", identity_id)
        .param("$subject", format!("email-change-subject-{user_id}")) .param("$now", now).await?;
    Ok(())
}

async fn latest_intent(client: &Client, user_id: i32) -> Result<String> {
    let mut row = client
        .query_client()
        .query_row("SELECT intent_id FROM id_email_change WHERE user_id = $id")
        .param("$id", user_id)
        .await?;
    Ok(row.remove_field_by_name("intent_id")?.try_into()?)
}

async fn cleanup(
    client: &Client,
    user_id: i32,
    identity_id: Uuid,
    token: &str,
    addresses: &[String],
) -> Result<()> {
    for email in addresses {
        client
            .query_client()
            .exec("DELETE FROM id_email_claim WHERE email_key = $email")
            .param("$email", email.clone())
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM id_email_change WHERE user_id = $id")
        .param("$id", user_id)
        .await?;
    let mut query_client = client.query_client();
    let mut rows = query_client.query("SELECT id FROM account_emailaddress VIEW account_emailaddress_user_id_2c513194 WHERE user_id = $id")
        .param("$id", user_id).await?;
    let mut ids = Vec::<i32>::new();
    while let Some(set) = rows.next_result_set().await? {
        for mut row in set {
            ids.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    rows.close().await?;
    for id in ids {
        client
            .query_client()
            .exec("DELETE FROM account_emailaddress WHERE id = $id")
            .param("$id", id)
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM id_email_verification WHERE user_id = $id")
        .param("$id", user_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM id_security_mail WHERE user_id = $id")
        .param("$id", user_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountevent WHERE user_id = $id")
        .param("$id", user_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountemaillookup WHERE user_id = $id")
        .param("$id", user_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountidentity WHERE user_id = $id")
        .param("$id", user_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM usid_user WHERE user_id = $id")
        .param("$id", identity_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM django_session WHERE session_key = $token")
        .param("$token", token.to_owned())
        .await?;
    client
        .query_client()
        .exec("DELETE FROM auth_user WHERE id = $id")
        .param("$id", user_id)
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires migrated isolated local YDB"]
async fn latest_email_link_claims_identity_once_and_notifies_both_addresses() -> Result<()> {
    let _guard = TEST_LOCK.lock().await;
    ensure!(
        std::env::var("YDB_DATABASE")? == "/local",
        "isolated local YDB required"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    email_verify::ensure_schema(&client).await?;
    id_runtime::security_mail::ensure_schema(&client).await?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let user_id = -i32::try_from(stamp % 800_000_000 + 10_000)?;
    let other_id = user_id - 1;
    let identity_id = Uuid::new_v4();
    let other_identity = Uuid::new_v4();
    let token = format!("emailchange{stamp:032x}session");
    let other_token = format!("emailchangeother{stamp:032x}session");
    let old = format!("old-{stamp}@example.invalid");
    let other_old = format!("other-{stamp}@example.invalid");
    let new = format!("new-{stamp}@example.invalid");
    let codec = Arc::new(SessionCodec::new(
        std::env::var("DJANGO_SECRET_KEY")?.as_bytes(),
        &[],
    )?);
    let now = SystemTime::now();
    seed(&client, &codec, user_id, identity_id, &token, &old, true).await?;
    seed(
        &client,
        &codec,
        other_id,
        other_identity,
        &other_token,
        &other_old,
        true,
    )
    .await?;
    let outcome: Result<()> = async {
        ensure!(
            email_change::stage(&client, codec.clone(), &token, &new, now).await?
                == StageResult::Staged,
            "initial stage failed"
        );
        let first_id = latest_intent(&client, user_id).await?;
        ensure!(
            email_change::stage(&client, codec.clone(), &other_token, &new, now).await?
                == StageResult::EmailExists,
            "second account claimed reserved address"
        );
        ensure!(
            email_change::stage(&client, codec.clone(), &token, &new, now).await?
                == StageResult::Staged,
            "replacement failed"
        );
        let second_id = latest_intent(&client, user_id).await?;
        ensure!(first_id != second_id, "replacement reused link");
        let key = VerifyKey::new([8; 32])?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut io = BufReader::new(stream);
            io.get_mut().write_all(b"220 localhost ESMTP\r\n").await?;
            let mut body = String::new();
            loop {
                let mut line = String::new();
                if io.read_line(&mut line).await? == 0 {
                    anyhow::bail!("SMTP client disconnected");
                }
                if line.starts_with("DATA") {
                    io.get_mut().write_all(b"354 send data\r\n").await?;
                    loop {
                        line.clear();
                        if io.read_line(&mut line).await? == 0 {
                            anyhow::bail!("SMTP body truncated");
                        }
                        if line == ".\r\n" {
                            break;
                        }
                        body.push_str(&line);
                    }
                    io.get_mut().write_all(b"250 queued\r\n").await?;
                    return Ok::<String, anyhow::Error>(body);
                }
                io.get_mut().write_all(b"250 ok\r\n").await?;
            }
        });
        let mailer = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("127.0.0.1")
            .port(port)
            .timeout(Some(Duration::from_secs(5)))
            .build();
        let mail_config = VerifyMailConfig::new(key.clone(), "http://localhost/verify-email")?;
        let from: Mailbox = "no-reply@example.invalid".parse()?;
        let sent =
            email_verify::process_one(&client, &second_id, &mail_config, &mailer, &from).await?;
        ensure!(
            sent.claimed == 1 && sent.sent == 1,
            "email change confirmation mail not sent"
        );
        let message = tokio::time::timeout(Duration::from_secs(5), server).await???;
        ensure!(
            message.contains("verify-email") && message.contains("new-"),
            "mail destination/link incorrect"
        );
        ensure!(
            email_verify::process_one(&client, &first_id, &mail_config, &mailer, &from)
                .await?
                .claimed
                == 0,
            "replaced email intent was still queued"
        );
        ensure!(
            email_verify::confirm(&client, &key, &key.issue(Uuid::parse_str(&first_id)?)?, now)
                .await?
                == ConfirmResult::Invalid,
            "replaced link succeeded"
        );
        let second_token = key.issue(Uuid::parse_str(&second_id)?)?;
        let mut attempts = tokio::task::JoinSet::new();
        for _ in 0..100 {
            let client = client.clone();
            let key = key.clone();
            let token = second_token.clone();
            attempts.spawn(async move { email_verify::confirm(&client, &key, &token, now).await });
        }
        let mut verified = 0;
        while let Some(outcome) = attempts.join_next().await {
            if outcome?? == ConfirmResult::Verified {
                verified += 1;
            }
        }
        ensure!(verified == 1, "confirmation succeeded {verified} times");
        for (table, id_column, id) in [
            ("auth_user", "id", user_id.to_string()),
            ("usid_user", "user_id", identity_id.to_string()),
        ] {
            let mut row = client
                .query_client()
                .query_row(format!("SELECT email FROM {table} WHERE {id_column} = $id"))
                .param(
                    "$id",
                    if table == "auth_user" {
                        ydb::Value::from(user_id)
                    } else {
                        ydb::Value::from(identity_id)
                    },
                )
                .await?;
            let stored: String = row.remove_field_by_name("email")?.try_into()?;
            ensure!(stored == new, "{table} email not updated for {id}");
        }
        let mut lookup = client
            .query_client()
            .query_row("SELECT email_key FROM accounts_accountemaillookup WHERE user_id = $id")
            .param("$id", user_id)
            .await?;
        let key: String = lookup.remove_field_by_name("email_key")?.try_into()?;
        ensure!(key == new, "login lookup not updated");
        let mut notices = client
            .query_client()
            .query_row("SELECT COUNT(*) AS total FROM id_security_mail WHERE user_id = $id")
            .param("$id", user_id)
            .await?;
        let total: u64 = notices.remove_field_by_name("total")?.try_into()?;
        ensure!(total == 2, "missing durable old/new address notices");
        ensure!(
            email_verify::confirm(&client, &VerifyKey::new([8; 32])?, &second_token, now).await?
                == ConfirmResult::Invalid,
            "replay succeeded"
        );
        Ok(())
    }
    .await;
    cleanup(
        &client,
        user_id,
        identity_id,
        &token,
        std::slice::from_ref(&new),
    )
    .await?;
    cleanup(&client, other_id, other_identity, &other_token, &[]).await?;
    outcome
}

#[tokio::test]
#[ignore = "requires migrated isolated local YDB and email-change HTTP flag"]
async fn http_request_enforces_session_csrf_and_recent_auth() -> Result<()> {
    let _guard = TEST_LOCK.lock().await;
    ensure!(
        std::env::var("YDB_DATABASE")? == "/local"
            && std::env::var("ID_AUTH_EMAIL_CHANGE_PILOT_ENABLED")? == "true",
        "isolated local YDB and pilot flag required"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    email_verify::ensure_schema(&client).await?;
    let config = id_runtime::email_cancel_http::EmailCancelHttpConfig::from_env(client.clone())?
        .context("email change pilot disabled")?;
    let app = id_runtime::email_cancel_http::router(config);
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let user_id = -i32::try_from(stamp % 800_000_000 + 900_000_000)?;
    let stale_id = user_id - 1;
    let identity_id = Uuid::new_v4();
    let stale_identity = Uuid::new_v4();
    let token = format!("emailhttprecent{stamp:032x}");
    let stale_token = format!("emailhttpstale{stamp:032x}");
    let old = format!("email-http-old-{stamp}@example.invalid");
    let stale_old = format!("email-http-stale-{stamp}@example.invalid");
    let new = format!("email-http-new-{stamp}@example.invalid");
    let codec = Arc::new(SessionCodec::new(
        std::env::var("DJANGO_SECRET_KEY")?.as_bytes(),
        &[],
    )?);
    let now = SystemTime::now();
    seed(&client, &codec, user_id, identity_id, &token, &old, true).await?;
    seed(
        &client,
        &codec,
        stale_id,
        stale_identity,
        &stale_token,
        &stale_old,
        false,
    )
    .await?;
    let outcome: Result<()> = async {
        let (status, _) = change_request(&app, None, true, &new).await?;
        ensure!(
            status == StatusCode::UNAUTHORIZED,
            "anonymous change accepted"
        );
        let (status, _) = change_request(&app, Some(&token), false, &new).await?;
        ensure!(
            status == StatusCode::FORBIDDEN,
            "cookie change bypassed CSRF"
        );
        let (status, body) = change_request(&app, Some(&stale_token), true, &new).await?;
        ensure!(
            status == StatusCode::UNAUTHORIZED && body["code"] == "REAUTH_REQUIRED",
            "stale authentication was accepted or misclassified: {body}"
        );
        let (status, body) = change_request(&app, Some(&token), true, &new).await?;
        ensure!(
            status == StatusCode::OK && body["ok"] == true,
            "valid change request failed: {body}"
        );
        let intent_id = latest_intent(&client, user_id).await?;
        let mut mail = client
            .query_client()
            .query_row("SELECT status, recipient FROM id_email_verification WHERE id = $id")
            .param("$id", intent_id.clone())
            .await?;
        let mail_status: String = mail.remove_field_by_name("status")?.try_into()?;
        let recipient: String = mail.remove_field_by_name("recipient")?.try_into()?;
        ensure!(
            mail_status == "pending" && recipient == new,
            "durable mail was not queued"
        );
        let (status, body) = cancel_request(&app, &token).await?;
        ensure!(
            status == StatusCode::OK && body["ok"] == true,
            "email cancellation failed: {body}"
        );
        ensure!(
            client
                .query_client()
                .query_row("SELECT user_id FROM id_email_change WHERE user_id = $id")
                .param("$id", user_id)
                .optional()
                .await?
                .is_none(),
            "cancel left change intent"
        );
        ensure!(
            client
                .query_client()
                .query_row("SELECT user_id FROM id_email_claim WHERE email_key = $email")
                .param("$email", new.clone())
                .optional()
                .await?
                .is_none(),
            "cancel left address claim"
        );
        let mut cancelled = client
            .query_client()
            .query_row("SELECT status, recipient FROM id_email_verification WHERE id = $id")
            .param("$id", intent_id)
            .await?;
        let state: String = cancelled.remove_field_by_name("status")?.try_into()?;
        let recipient: String = cancelled.remove_field_by_name("recipient")?.try_into()?;
        ensure!(
            state == "cancelled" && recipient.is_empty(),
            "cancel left a sendable email"
        );
        ensure!(
            email_change::stage(&client, codec.clone(), &token, &new, now).await?
                == StageResult::Staged,
            "could not restage after cancellation"
        );
        ensure!(
            email_change::cleanup_expired(&client, now + Duration::from_secs(25 * 3600), 100)
                .await?
                >= 1,
            "expired email change was not cleaned"
        );
        ensure!(
            client
                .query_client()
                .query_row("SELECT user_id FROM id_email_claim WHERE email_key = $email")
                .param("$email", new.clone())
                .optional()
                .await?
                .is_none(),
            "expired address claim remained"
        );
        Ok(())
    }
    .await;
    cleanup(&client, user_id, identity_id, &token, &[new]).await?;
    cleanup(&client, stale_id, stale_identity, &stale_token, &[]).await?;
    outcome
}
