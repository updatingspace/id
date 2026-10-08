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

// Serialize the lifecycle scenarios while keeping every mutation fixture-owned.
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
            .exec("DELETE FROM id_email_claim WHERE email_key = $email AND user_id = $owner")
            .param("$email", email.clone())
            .param("$owner", user_id)
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
            .exec("DELETE FROM account_emailconfirmation WHERE email_address_id=$id")
            .param("$id", id)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM account_emailaddress WHERE id = $id")
            .param("$id", id)
            .await?;
    }
    for table in ["mfa_authenticator", "accounts_accountdeletionrequest"] {
        client
            .query_client()
            .exec(format!("DELETE FROM `{table}` WHERE user_id=$id"))
            .param("$id", user_id)
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
        let now = SystemTime::now();
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
        let now = SystemTime::now();
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
        let expired_id = latest_intent(&client, user_id).await?;
        client.query_client().exec("UPDATE id_email_change SET expires_at=CAST($past AS Datetime) WHERE user_id=$id AND intent_id=$intent")
            .param("$past",now-Duration::from_secs(1)).param("$id",user_id).param("$intent",expired_id.clone()).await?;
        let key = VerifyKey::new([9;32])?;
        ensure!(email_verify::confirm(&client,&key,&key.issue(Uuid::parse_str(&expired_id)?)?,now).await? == ConfirmResult::Invalid,
            "expired email intent confirmed");
        let (status, body) = cancel_request(&app, &token).await?;
        ensure!(status == StatusCode::OK && body["ok"] == true, "owner could not cancel expired intent");
        ensure!(client.query_client().query_row("SELECT user_id FROM id_email_claim WHERE email_key=$email")
            .param("$email",new.clone()).optional().await?.is_none(), "expired address claim remained");
        ensure!(client.query_client().query_row("SELECT user_id FROM id_email_change WHERE user_id=$id")
            .param("$id",user_id).optional().await?.is_none(), "expired intent remained");
        let mut remaining = client.query_client().query_row("SELECT COUNT(*) AS total FROM account_emailaddress WHERE user_id=$id")
            .param("$id",user_id).await?;
        let remaining: u64 = remaining.remove_field_by_name("total")?.try_into()?;
        ensure!(remaining == 1, "cancel did not preserve exactly the primary address");
        assert_emails(&client,user_id,identity_id,&old).await?;
        Ok(())
    }
    .await;
    cleanup(&client, user_id, identity_id, &token, &[new]).await?;
    cleanup(&client, stale_id, stale_identity, &stale_token, &[]).await?;
    outcome
}

async fn assert_emails(
    client: &Client,
    user_id: i32,
    identity_id: Uuid,
    expected: &str,
) -> Result<()> {
    for (sql, id) in [
        (
            "SELECT email AS value FROM auth_user WHERE id=$id",
            ydb::Value::from(user_id),
        ),
        (
            "SELECT email AS value FROM usid_user WHERE user_id=$id",
            ydb::Value::from(identity_id),
        ),
        (
            "SELECT email_key AS value FROM accounts_accountemaillookup WHERE user_id=$id",
            ydb::Value::from(user_id),
        ),
    ] {
        let mut row = client
            .query_client()
            .query_row(sql)
            .param("$id", id)
            .await?;
        let actual: String = row.remove_field_by_name("value")?.try_into()?;
        ensure!(
            actual == expected,
            "email stores disagree: {sql}: expected {expected}, got {actual}"
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires migrated local YDB; fixture-owned writes only"]
async fn mixed_case_legacy_email_confirmation_updates_all_owners_atomically() -> Result<()> {
    let _guard = TEST_LOCK.lock().await;
    ensure!(
        std::env::var("YDB_DATABASE")? == "/local",
        "local YDB required"
    );
    let client = id_runtime::connect_ydb().await?;
    email_verify::ensure_schema(&client).await?;
    id_runtime::security_mail::ensure_schema(&client).await?;
    let suffix = Uuid::new_v4().simple().to_string();
    let user_id = 700_000_000 + i32::try_from(rand::random::<u32>() % 100_000_000)?;
    let identity = Uuid::new_v4();
    let token = format!("email-case-{suffix}");
    let old = format!("MixedCase-{suffix}@Example.Invalid");
    let new = format!("changed-{suffix}@example.invalid");
    let codec = Arc::new(SessionCodec::new(
        b"synthetic-email-case-session-secret",
        &[],
    )?);
    seed(&client, &codec, user_id, identity, &token, &old, true).await?;
    let outcome: Result<()> = async {
        client
            .query_client()
            .exec("UPDATE usid_user SET email=$email WHERE user_id=$id")
            .param("$email", format!(" {} ", old.to_uppercase()))
            .param("$id", identity)
            .await?;
        let now = SystemTime::now();
        ensure!(
            email_change::stage(&client, codec.clone(), &token, &new, now).await?
                == StageResult::Staged
        );
        let intent = latest_intent(&client, user_id).await?;
        let key = VerifyKey::new([9; 32])?;
        let link = key.issue(Uuid::parse_str(&intent)?)?;
        ensure!(email_verify::confirm(&client, &key, &link, now).await? == ConfirmResult::Verified);
        assert_emails(&client, user_id, identity, &new).await?;
        ensure!(email_verify::confirm(&client, &key, &link, now).await? == ConfirmResult::Invalid);
        Ok(())
    }
    .await;
    cleanup(&client, user_id, identity, &token, &[new]).await?;
    outcome
}

#[tokio::test]
#[ignore = "requires migrated local YDB; fixture-owned writes only"]
async fn confirmation_rechecks_claim_address_account_and_identity_ownership() -> Result<()> {
    let _guard = TEST_LOCK.lock().await;
    ensure!(
        std::env::var("YDB_DATABASE")? == "/local",
        "local YDB required"
    );
    let client = id_runtime::connect_ydb().await?;
    email_verify::ensure_schema(&client).await?;
    id_runtime::security_mail::ensure_schema(&client).await?;
    let suffix = Uuid::new_v4().simple().to_string();
    let user_id = 700_000_000 + i32::try_from(rand::random::<u32>() % 100_000_000)?;
    let identity = Uuid::new_v4();
    let other = user_id + 1;
    let other_identity = Uuid::new_v4();
    let token = format!("email-owner-{suffix}");
    let other_token = format!("email-other-{suffix}");
    let old = format!("owner-{suffix}@example.invalid");
    let other_old = format!("other-{suffix}@example.invalid");
    let new = format!("target-{suffix}@example.invalid");
    let codec = Arc::new(SessionCodec::new(
        b"synthetic-email-owner-session-secret",
        &[],
    )?);
    seed(&client, &codec, user_id, identity, &token, &old, true).await?;
    seed(
        &client,
        &codec,
        other,
        other_identity,
        &other_token,
        &other_old,
        true,
    )
    .await?;
    let outcome: Result<()> = async {
        let now = SystemTime::now();
        ensure!(email_change::stage(&client, codec.clone(), &token, &new, now).await? == StageResult::Staged);
        let intent = latest_intent(&client, user_id).await?;
        let key = VerifyKey::new([9;32])?;
        let link = key.issue(Uuid::parse_str(&intent)?)?;
        let mut row = client.query_client().query_row("SELECT address_id FROM id_email_change WHERE user_id=$id")
            .param("$id",user_id).await?;
        let address: i32 = row.remove_field_by_name("address_id")?.try_into()?;

        // A later claim by another owner and reassignment of the address invalidate the old capability.
        client.query_client().exec("UPDATE id_email_claim SET user_id=$other WHERE email_key=$email")
            .param("$other",other).param("$email",new.clone()).await?;
        ensure!(email_verify::confirm(&client,&key,&link,now).await? == ConfirmResult::Invalid, "foreign claim accepted");
        client.query_client().exec("UPDATE id_email_claim SET user_id=$owner WHERE email_key=$email")
            .param("$owner",user_id).param("$email",new.clone()).await?;
        client.query_client().exec("UPDATE account_emailaddress SET user_id=$other WHERE id=$id")
            .param("$other",other).param("$id",address).await?;
        ensure!(email_verify::confirm(&client,&key,&link,now).await? == ConfirmResult::Invalid, "foreign address accepted");
        client.query_client().exec("UPDATE account_emailaddress SET user_id=$owner WHERE id=$id")
            .param("$owner",user_id).param("$id",address).await?;

        client.query_client().exec("UPDATE auth_user SET is_active=false WHERE id=$id").param("$id",user_id).await?;
        ensure!(email_verify::confirm(&client,&key,&link,now).await? == ConfirmResult::Invalid, "disabled account confirmed");
        client.query_client().exec("UPDATE auth_user SET is_active=true WHERE id=$id").param("$id",user_id).await?;
        client.query_client().exec("UPDATE usid_user SET status='banned' WHERE user_id=$id").param("$id",identity).await?;
        ensure!(email_verify::confirm(&client,&key,&link,now).await? == ConfirmResult::Invalid, "inactive identity confirmed");
        client.query_client().exec("UPDATE usid_user SET status='active' WHERE user_id=$id").param("$id",identity).await?;
        client.query_client().exec("INSERT INTO accounts_accountdeletionrequest (id,user_id,status,requested_at,reason) VALUES ($id,$owner,'pending',CurrentUtcDatetime(),'synthetic email regression')")
            .param("$id",i64::from(user_id)).param("$owner",user_id).await?;
        ensure!(email_verify::confirm(&client,&key,&link,now).await? == ConfirmResult::Invalid, "deleting account confirmed");
        client.query_client().exec("DELETE FROM accounts_accountdeletionrequest WHERE id=$id").param("$id",i64::from(user_id)).await?;

        // A newly verified secondary address also owns an email, even without a login lookup for it.
        client.query_client().exec("INSERT INTO account_emailaddress (id,user_id,email,verified,primary) VALUES ($id,$owner,$email,true,false)")
            .param("$id",-other).param("$owner",other).param("$email",new.clone()).await?;
        ensure!(email_verify::confirm(&client,&key,&link,now).await? == ConfirmResult::Invalid, "late verified owner bypassed conflict check");
        ensure!(email_change::stage(&client,codec.clone(),&token,&new,now).await? == StageResult::EmailExists);
        client.query_client().exec("DELETE FROM account_emailaddress WHERE id=$id AND user_id=$owner")
            .param("$id",-other).param("$owner",other).await?;

        assert_emails(&client,user_id,identity,&old).await?;
        assert_emails(&client,other,other_identity,&other_old).await?;
        let mut mail = client.query_client().query_row("SELECT consumed_at, status FROM id_email_verification WHERE id=$id")
            .param("$id",intent.clone()).await?;
        let consumed: Option<SystemTime> = mail.remove_field_by_name("consumed_at")?.try_into()?;
        let status: String = mail.remove_field_by_name("status")?.try_into()?;
        ensure!(consumed.is_none() && status == "pending", "rejected confirmation changed mail intent");
        let mut notices = client.query_client().query_row("SELECT COUNT(*) AS total FROM id_security_mail WHERE user_id=$id")
            .param("$id",user_id).await?;
        let notices: u64 = notices.remove_field_by_name("total")?.try_into()?;
        ensure!(notices == 0, "rejected confirmation queued security mail");

        // An expired address claim can be acquired by a different account; the old link stays invalid.
        client.query_client().exec("UPDATE id_email_claim SET expires_at=CAST($past AS Datetime) WHERE email_key=$email AND user_id=$id")
            .param("$past",now-Duration::from_secs(1)).param("$email",new.clone()).param("$id",user_id).await?;
        ensure!(email_verify::confirm(&client,&key,&link,now).await? == ConfirmResult::Invalid, "expired claim accepted");
        ensure!(email_change::stage(&client,codec.clone(),&other_token,&new,now).await? == StageResult::Staged);
        ensure!(email_verify::confirm(&client,&key,&link,now).await? == ConfirmResult::Invalid, "replaced owner accepted");
        let other_intent = latest_intent(&client,other).await?;
        let other_link = key.issue(Uuid::parse_str(&other_intent)?)?;
        ensure!(email_verify::confirm(&client,&key,&other_link,now).await? == ConfirmResult::Verified);
        assert_emails(&client,user_id,identity,&old).await?;
        assert_emails(&client,other,other_identity,&new).await?;
        Ok(())
    }.await;
    cleanup(
        &client,
        user_id,
        identity,
        &token,
        std::slice::from_ref(&new),
    )
    .await?;
    cleanup(&client, other, other_identity, &other_token, &[new]).await?;
    outcome
}

#[tokio::test]
#[ignore = "requires migrated local YDB; fixture-owned writes only"]
async fn stage_requires_mfa_and_rolls_back_replacement_when_address_limit_fails() -> Result<()> {
    let _guard = TEST_LOCK.lock().await;
    ensure!(
        std::env::var("YDB_DATABASE")? == "/local",
        "local YDB required"
    );
    let client = id_runtime::connect_ydb().await?;
    email_verify::ensure_schema(&client).await?;
    id_runtime::security_mail::ensure_schema(&client).await?;
    let suffix = Uuid::new_v4().simple().to_string();
    let user_id = 700_000_000 + i32::try_from(rand::random::<u32>() % 100_000_000)?;
    let identity = Uuid::new_v4();
    let token = format!("email-rollback-{suffix}");
    let old = format!("rollback-{suffix}@example.invalid");
    let new = format!("first-{suffix}@example.invalid");
    let replacement = format!("replacement-{suffix}@example.invalid");
    let codec = Arc::new(SessionCodec::new(
        b"synthetic-email-rollback-session-secret",
        &[],
    )?);
    seed(&client, &codec, user_id, identity, &token, &old, true).await?;
    let outcome: Result<()> = async {
        let now = SystemTime::now();
        ensure!(email_change::stage(&client,codec.clone(),"",&new,now).await? == StageResult::Unauthorized);
        ensure!(email_change::stage(&client,codec.clone(),"unknown-session",&new,now).await? == StageResult::Unauthorized);
        ensure!(email_change::stage(&client,codec.clone(),&token,"invalid recipient",now).await? == StageResult::InvalidEmail);
        ensure!(email_change::stage(&client,codec.clone(),&token,&old.to_uppercase(),now).await? == StageResult::NoChange);
        client.query_client().exec("INSERT INTO mfa_authenticator (id,user_id,type,data,created_at) VALUES ($id,$owner,'webauthn',Unwrap(CAST('{}' AS Json)),CurrentUtcDatetime())")
            .param("$id",i64::from(user_id)).param("$owner",user_id).await?;
        ensure!(email_change::stage(&client,codec.clone(),&token,&new,now).await? == StageResult::Unauthorized,
            "session without account-bound MFA staged a change");
        client.query_client().exec("DELETE FROM mfa_authenticator WHERE id=$id").param("$id",i64::from(user_id)).await?;
        ensure!(client.query_client().query_row("SELECT user_id FROM id_email_change WHERE user_id=$id")
            .param("$id",user_id).optional().await?.is_none(), "rejected/no-op stage persisted an intent");
        ensure!(email_change::stage(&client,codec.clone(),&token,&new,now).await? == StageResult::Staged);
        let intent = latest_intent(&client,user_id).await?;
        // This legacy data anomaly is detected after replacement has scheduled writes to old mail/claim.
        for index in 0..100 {
            client.query_client().exec("INSERT INTO account_emailaddress (id,user_id,email,verified,primary) VALUES ($id,$owner,$email,false,false)")
                .param("$id",-user_id-index).param("$owner",user_id)
                .param("$email",format!("extra-{index}-{suffix}@example.invalid")).await?;
        }
        ensure!(email_change::stage(&client,codec.clone(),&token,&replacement,now).await.is_err(),
            "oversized address set was accepted");
        ensure!(latest_intent(&client,user_id).await? == intent, "failed replacement changed current intent");
        let mut mail = client.query_client().query_row("SELECT status,recipient FROM id_email_verification WHERE id=$id")
            .param("$id",intent.clone()).await?;
        let status: String = mail.remove_field_by_name("status")?.try_into()?;
        let recipient: String = mail.remove_field_by_name("recipient")?.try_into()?;
        ensure!(status == "pending" && recipient == new, "failed transaction canceled prior mail");
        let mut claim = client.query_client().query_row("SELECT intent_id FROM id_email_claim WHERE email_key=$email")
            .param("$email",new.clone()).await?;
        let claim: String = claim.remove_field_by_name("intent_id")?.try_into()?;
        ensure!(claim == intent, "failed transaction lost previous address claim");
        ensure!(client.query_client().query_row("SELECT user_id FROM id_email_claim WHERE email_key=$email")
            .param("$email",replacement.clone()).optional().await?.is_none(), "failed transaction claimed replacement email");
        assert_emails(&client,user_id,identity,&old).await?;
        let key = VerifyKey::new([9;32])?;
        ensure!(email_verify::confirm(&client,&key,&key.issue(Uuid::parse_str(&intent)?)?,now).await? == ConfirmResult::Verified,
            "failed replacement invalidated the previously issued link");
        assert_emails(&client,user_id,identity,&new).await?;
        Ok(())
    }.await;
    cleanup(&client, user_id, identity, &token, &[new, replacement]).await?;
    outcome
}
