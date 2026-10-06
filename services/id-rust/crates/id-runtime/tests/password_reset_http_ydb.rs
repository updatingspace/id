#![recursion_limit = "256"]
//! Public recovery and SMTP job against the migrated local YDB.

use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use cookie::SameSite;
use id_runtime::{
    cache_store::CacheStore,
    password_reset::{self, ResetKey, ResetMailConfig},
};
use lettre::{AsyncSmtpTransport, Tokio1Executor, message::Mailbox};
use serde_json::{Value, json};
use std::{
    sync::{Arc, LazyLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tower::ServiceExt;
use uuid::Uuid;

static TEST_IP: LazyLock<String> = LazyLock::new(|| {
    let id = Uuid::new_v4();
    let bytes = id.as_bytes();
    format!("10.{}.{}.{}", bytes[0], bytes[1], bytes[2])
});

async fn form_token(app: &Router) -> Result<(String, String)> {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/form_token?purpose=password_reset")
                .body(Body::empty())?,
        )
        .await?;
    ensure!(response.status() == StatusCode::OK);
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .context("missing CSRF cookie")?
        .to_str()?;
    let secret = cookie::Cookie::parse(cookie.to_owned())?.value().to_owned();
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
    Ok((
        body["form_token"]
            .as_str()
            .context("missing form token")?
            .to_owned(),
        secret,
    ))
}

async fn post(
    app: &Router,
    path: &str,
    payload: Value,
    csrf: &str,
    include_csrf: bool,
) -> Result<(StatusCode, Value)> {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, "http://localhost:5175")
        .header("x-forwarded-for", TEST_IP.as_str())
        .header(header::COOKIE, format!("csrftoken={csrf}"));
    if include_csrf {
        request = request.header("x-csrftoken", csrf);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(payload.to_string()))?)
        .await?;
    let status = response.status();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
    Ok((status, body))
}

#[tokio::test]
#[ignore = "requires migrated local YDB and enabled Rust recovery pilot"]
async fn request_mail_and_single_use_confirmation() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local"
            && std::env::var("DJANGO_DEBUG")? == "true"
            && std::env::var("ID_AUTH_PASSWORD_RESET_PILOT_ENABLED")? == "true",
        "test requires opt-in local YDB"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    password_reset::ensure_schema(&client).await?;
    password_reset::ensure_schema(&client).await?;
    id_runtime::password_mail::ensure_schema(&client).await?;
    client.query_client().exec("CREATE TABLE IF NOT EXISTS id_shared_cache (cache_key Utf8 NOT NULL, value String, expires_at Uint64, PRIMARY KEY (cache_key))").await?;
    let table = std::env::var("YDB_CACHE_TABLE").unwrap_or_else(|_| "id_shared_cache".into());
    let cache = CacheStore::new(client.clone(), &table, "", 1)?;
    let form = id_runtime::form_token_http::FormTokenConfig::new(
        cache,
        "csrftoken".into(),
        false,
        SameSite::Lax,
        None,
    )?;
    let reset = id_runtime::password_reset_http::PasswordResetHttpConfig::from_env(client.clone())?
        .context("reset pilot disabled")?;
    let app = id_runtime::form_token_http::router(Arc::new(form))
        .merge(id_runtime::password_reset_http::router(reset));
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let user_id = -i32::try_from(stamp % 1_000_000_000 + 1)?;
    let meta_id = i64::from(user_id).abs() + 9_000_000_000;
    let mapping_id = meta_id + 1;
    let email = format!("rust-reset-{stamp}@example.invalid");
    let old = "synthetic current reset password";
    let new = "Velvet orchard lantern 4827!";
    let old_hash = id_compat::password::hash_new(old)?;
    let session = format!("rustreset{stamp:032x}");
    let now = SystemTime::now();
    client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $hash, true, $name, '', '', $email, false, false, CurrentUtcDatetime())")
        .param("$id", user_id).param("$hash", old_hash.clone()).param("$name", format!("rust-reset-{stamp}"))
        .param("$email", email.clone()).await?;
    let outcome: Result<()> = async {
        client.query_client().exec("UPSERT INTO accounts_accountemaillookup (user_id, email_key) VALUES ($id, $email)")
            .param("$id", user_id).param("$email", email.clone()).await?;
        client.query_client().exec("UPSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($id, $id, $email, true, true)")
            .param("$id", user_id).param("$email", email.clone()).await?;
        client.query_client().exec("UPSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, '', CAST($expires AS Datetime))")
            .param("$key", session.clone()).param("$expires", now + Duration::from_secs(3600)).await?;
        client.query_client().exec("INSERT INTO core_usersessionmeta (id, user_id, session_key, user_agent, revoked_reason, first_seen) VALUES ($id, $user, $key, '', '', CAST($now AS Datetime))")
            .param("$id", meta_id).param("$user", user_id).param("$key", session.clone()).param("$now", now).await?;
        client.query_client().exec("INSERT INTO core_usersessiontoken (id, user_id, session_key, refresh_jti, created_at) VALUES ($id, $user, $key, $jti, CAST($now AS Datetime))")
            .param("$id", mapping_id).param("$user", user_id).param("$key", session.clone()).param("$jti", format!("rust-reset-jti-{stamp}")).param("$now", now).await?;

        let (token, csrf) = form_token(&app).await?;
        let body = json!({"email":email,"form_token":token});
        let (status, _) = post(&app, "/api/v1/auth/password/reset/request", body.clone(), &csrf, false).await?;
        ensure!(status == StatusCode::FORBIDDEN, "missing CSRF accepted");
        let (status, requested) = post(&app, "/api/v1/auth/password/reset/request", body, &csrf, true).await?;
        ensure!(status == StatusCode::OK && requested["ok"] == true, "reset request failed: {requested}");
        let (unknown_token, unknown_csrf) = form_token(&app).await?;
        let (unknown_status, unknown) = post(&app, "/api/v1/auth/password/reset/request",
            json!({"email":"missing@example.invalid","form_token":unknown_token}), &unknown_csrf, true).await?;
        ensure!(unknown_status == status && unknown == requested, "account existence leaked through response");
        let mut query_client = client.query_client();
        let mut rows = query_client.query("SELECT id FROM id_password_reset WHERE user_id = $id")
            .param("$id", user_id).await?;
        let mut ids = Vec::<String>::new();
        while let Some(set) = rows.next_result_set().await? {
            for mut row in set { ids.push(row.remove_field_by_name("id")?.try_into()?); }
        }
        rows.close().await?;
        ensure!(ids.len() == 1, "expected one recovery intent");
        let id = ids[0].clone();
        let key = ResetKey::from_env()?.issue(Uuid::parse_str(&id)?)?;
        ensure!(!id.contains(&key), "bearer token stored in row ID");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut io = BufReader::new(stream);
            io.get_mut().write_all(b"220 localhost ESMTP\r\n").await?;
            let mut body = String::new();
            loop {
                let mut line = String::new();
                if io.read_line(&mut line).await? == 0 { anyhow::bail!("SMTP client disconnected"); }
                if line.starts_with("DATA") {
                    io.get_mut().write_all(b"354 send data\r\n").await?;
                    loop {
                        line.clear();
                        if io.read_line(&mut line).await? == 0 { anyhow::bail!("SMTP body truncated"); }
                        if line == ".\r\n" { break; }
                        body.push_str(&line);
                    }
                    io.get_mut().write_all(b"250 queued\r\n").await?;
                    return Ok::<String, anyhow::Error>(body);
                }
                io.get_mut().write_all(b"250 ok\r\n").await?;
            }
        });
        let mailer = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("127.0.0.1")
            .port(port).timeout(Some(Duration::from_secs(5))).build();
        let config = ResetMailConfig::new(ResetKey::from_env()?, "http://localhost/reset-password")?;
        let from: Mailbox = "no-reply@example.invalid".parse()?;
        let sent = password_reset::process_one(&client, &id, &config, &mailer, &from).await?;
        ensure!(sent.claimed == 1 && sent.sent == 1, "reset email was not sent");
        let mail = tokio::time::timeout(Duration::from_secs(5), server).await???;
        ensure!(mail.contains("reset-password") && !mail.contains(&old_hash), "unsafe recovery email");
        let again = password_reset::process_one(&client, &id, &config, &mailer, &from).await?;
        ensure!(again.claimed == 0, "sent mail claimed twice");

        let payload = json!({"key":key,"password":new});
        let (status, _) = post(&app, "/api/v1/auth/password/reset/confirm", payload.clone(), &csrf, false).await?;
        ensure!(status == StatusCode::FORBIDDEN, "confirmation ignored CSRF");
        let (status, weak) = post(&app, "/api/v1/auth/password/reset/confirm", json!({"key":key,"password":"short"}), &csrf, true).await?;
        ensure!(status == StatusCode::BAD_REQUEST && weak["code"] == "VALIDATION_ERROR", "weak password accepted");
        let ((first, first_body), (second, second_body)) = tokio::try_join!(
            post(&app, "/api/v1/auth/password/reset/confirm", payload.clone(), &csrf, true),
            post(&app, "/api/v1/auth/password/reset/confirm", payload, &csrf, true),
        )?;
        let successes = usize::from(first == StatusCode::OK) + usize::from(second == StatusCode::OK);
        ensure!(successes == 1, "concurrent recovery had {successes} successes: {first_body}, {second_body}");
        let (status, repeated) = post(&app, "/api/v1/auth/password/reset/confirm", json!({"key":key,"password":"another strong password"}), &csrf, true).await?;
        ensure!(status == StatusCode::BAD_REQUEST && repeated["code"] == "INVALID_RECOVERY_LINK", "reset key replay accepted");
        let mut row = client.query_client().query_row("SELECT password FROM auth_user WHERE id = $id").param("$id", user_id).await?;
        let changed: String = row.remove_field_by_name("password")?.try_into()?;
        ensure!(id_compat::password::verify(new, &changed)? && !id_compat::password::verify(old, &changed)?);
        let session_row = client.query_client().query_row("SELECT session_key FROM django_session WHERE session_key = $key")
            .param("$key", session.clone()).optional().await?;
        ensure!(session_row.is_none(), "old session survived recovery");
        let mut row = client.query_client().query_row("SELECT revoked_at FROM core_usersessiontoken WHERE id = $id")
            .param("$id", mapping_id).await?;
        let revoked: Option<SystemTime> = row.remove_field_by_name("revoked_at")?.try_into()?;
        ensure!(revoked.is_some(), "account refresh survived recovery");
        let mut row = client.query_client().query_row("SELECT consumed_at, recipient FROM id_password_reset WHERE id = $id")
            .param("$id", id.clone()).await?;
        let consumed: Option<SystemTime> = row.remove_field_by_name("consumed_at")?.try_into()?;
        let recipient: String = row.remove_field_by_name("recipient")?.try_into()?;
        ensure!(consumed.is_some() && recipient.is_empty(), "reset row was not consumed and scrubbed");
        Ok(())
    }.await;
    let mut query_client = client.query_client();
    for table in ["id_password_reset", "id_password_mail"] {
        let mut rows = query_client
            .query(format!("SELECT id FROM `{table}` WHERE user_id = $id"))
            .param("$id", user_id)
            .await?;
        let mut ids = Vec::<String>::new();
        while let Some(set) = rows.next_result_set().await? {
            for mut row in set {
                ids.push(row.remove_field_by_name("id")?.try_into()?);
            }
        }
        rows.close().await?;
        for id in ids {
            client
                .query_client()
                .exec(format!("DELETE FROM `{table}` WHERE id = $id"))
                .param("$id", id)
                .await?;
        }
    }
    client
        .query_client()
        .exec("DELETE FROM core_usersessiontoken WHERE id = $id")
        .param("$id", mapping_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM core_usersessionmeta WHERE id = $id")
        .param("$id", meta_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM django_session WHERE session_key = $key")
        .param("$key", session)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM account_emailaddress WHERE id = $id")
        .param("$id", user_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountemaillookup WHERE user_id = $id")
        .param("$id", user_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM auth_user WHERE id = $id")
        .param("$id", user_id)
        .await?;
    outcome
}
