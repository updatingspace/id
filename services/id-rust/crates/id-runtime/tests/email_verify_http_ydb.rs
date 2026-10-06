#![recursion_limit = "256"]
//! Email-verification HTTP, durable SMTP intent and single-use confirmation on local YDB.

use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use cookie::SameSite;
use id_compat::session::SessionCodec;
use id_runtime::{
    cache_store::CacheStore,
    email_verify::{self, VerifyKey, VerifyMailConfig},
};
use lettre::{AsyncSmtpTransport, Tokio1Executor, message::Mailbox};
use serde_json::{Value, json};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tower::ServiceExt;
use uuid::Uuid;

async fn token(app: &Router) -> Result<(String, String)> {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/form_token?purpose=email_verification")
                .body(Body::empty())?,
        )
        .await?;
    ensure!(response.status() == StatusCode::OK);
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .context("missing CSRF cookie")?
        .to_str()?;
    let csrf = cookie::Cookie::parse(cookie.to_owned())?.value().to_owned();
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
    Ok((
        body["form_token"]
            .as_str()
            .context("missing form token")?
            .to_owned(),
        csrf,
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
        .header(
            "x-forwarded-for",
            format!("10.{}.{}.{}", std::process::id() % 255, 34, 88),
        )
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

async fn resend(
    app: &Router,
    session: Option<&str>,
    csrf: Option<&str>,
    explicit: Option<&str>,
) -> Result<(StatusCode, Value)> {
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/email/resend")
        .header(header::ORIGIN, "http://localhost:5175");
    if let Some(session) = session {
        request = request.header(
            header::COOKIE,
            format!("sessionid={session}; csrftoken={}", csrf.unwrap_or("a")),
        );
    }
    if let Some(csrf) = csrf {
        request = request.header("x-csrftoken", csrf);
    }
    if let Some(explicit) = explicit {
        request = request.header("x-session-token", explicit);
    }
    let response = app.clone().oneshot(request.body(Body::empty())?).await?;
    let status = response.status();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
    Ok((status, body))
}

#[tokio::test]
#[ignore = "requires migrated local YDB and enabled email verification pilot"]
async fn request_mail_and_single_use_confirmation() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("id_runtime=error")
        .try_init();
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local"
            && std::env::var("DJANGO_DEBUG")? == "true"
            && std::env::var("ID_AUTH_EMAIL_VERIFY_PILOT_ENABLED")? == "true"
            && std::env::var("ID_AUTH_EMAIL_RESEND_ENABLED")? == "true",
        "test requires opt-in local YDB"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    email_verify::ensure_schema(&client).await?;
    email_verify::ensure_schema(&client).await?;
    let table = std::env::var("YDB_CACHE_TABLE").unwrap_or_else(|_| "id_shared_cache".into());
    let cache = CacheStore::new(client.clone(), &table, "", 1)?;
    let form = id_runtime::form_token_http::FormTokenConfig::new(
        cache,
        "csrftoken".into(),
        false,
        SameSite::Lax,
        None,
    )?;
    let verify = id_runtime::email_verify_http::EmailVerifyHttpConfig::from_env(client.clone())?
        .context("email verify pilot disabled")?;
    let app = id_runtime::form_token_http::router(Arc::new(form))
        .merge(id_runtime::email_verify_http::router(verify));
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let account_id = -i32::try_from(stamp % 1_000_000_000 + 1)?;
    let identity_id = Uuid::new_v4();
    let email = format!("verify-http-{stamp}@example.invalid");
    let name = format!("verify-http-{stamp}");
    let hash = id_compat::password::hash_new("Original verification password 123!")?;
    let session = format!("rustverify{stamp:032x}session");
    let codec = SessionCodec::new(std::env::var("DJANGO_SECRET_KEY")?.as_bytes(), &[])?;
    let now = SystemTime::now();
    let session_payload = json!({
        "_auth_user_id": account_id.to_string(),
        "_auth_user_backend": "django.contrib.auth.backends.ModelBackend",
        "_auth_user_hash": codec.auth_hash(&hash)?,
    });
    let signed_session = codec.encode(
        session_payload.as_object().context("session payload")?,
        i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?,
        true,
    )?;
    client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $hash, true, $name, '', '', $email, false, false, CurrentUtcDatetime())")
        .param("$id", account_id).param("$hash", hash).param("$name", name.clone()).param("$email", email.clone()).await?;
    let outcome: Result<()> = async {
        client.query_client().exec("UPSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, $data, CAST($expires AS Datetime))")
            .param("$key", session.clone()).param("$data", signed_session)
            .param("$expires", now + Duration::from_secs(3600)).await?;
        client.query_client().exec("UPSERT INTO accounts_accountemaillookup (user_id, email_key) VALUES ($id, $email)")
            .param("$id", account_id).param("$email", email.clone()).await?;
        client.query_client().exec("UPSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($id, $id, $email, false, true)")
            .param("$id", account_id).param("$email", email.clone()).await?;
        client.query_client().exec("UPSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, $name, $name, $email, false, 'active', false, CurrentUtcDatetime())")
            .param("$id", identity_id).param("$name", name).param("$email", email.clone()).await?;
        client.query_client().exec("UPSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($id, $identity, $subject, CurrentUtcDatetime())")
            .param("$id", account_id).param("$identity", identity_id).param("$subject", format!("verify-sub-{stamp}")).await?;

        let (anonymous, _) = resend(&app, None, None, None).await?;
        ensure!(anonymous == StatusCode::UNAUTHORIZED, "anonymous resend accepted");
        let (csrf_denied, _) = resend(&app, Some(&session), None, None).await?;
        ensure!(csrf_denied == StatusCode::FORBIDDEN, "cookie resend without CSRF accepted");
        let (invalid_header, _) = resend(&app, Some(&session), None, Some("invalid")).await?;
        ensure!(invalid_header == StatusCode::UNAUTHORIZED, "invalid header fell back to cookie");
        let (resent, response) = resend(&app, Some(&session), Some(&"a".repeat(32)), None).await?;
        ensure!(resent == StatusCode::OK && response["ok"] == true, "authenticated resend failed: {response}");

        let (form_token, csrf) = token(&app).await?;
        let body = json!({"email":email,"form_token":form_token});
        let (denied, _) = post(&app, "/api/v1/auth/email/verification/request", body.clone(), &csrf, false).await?;
        ensure!(denied == StatusCode::FORBIDDEN, "request without CSRF was accepted");
        let (status, requested) = post(&app, "/api/v1/auth/email/verification/request", body, &csrf, true).await?;
        ensure!(status == StatusCode::OK && requested["ok"] == true, "verification request failed: {requested}");
        let (unknown_token, unknown_csrf) = token(&app).await?;
        let (unknown_status, unknown) = post(&app, "/api/v1/auth/email/verification/request",
            json!({"email":"nobody@example.invalid","form_token":unknown_token}), &unknown_csrf, true).await?;
        ensure!(unknown_status == status && unknown == requested, "account existence leaked through response");

        let mut query = client.query_client();
        let mut rows = query.query("SELECT id FROM id_email_verification WHERE user_id = $id")
            .param("$id", account_id).await?;
        let mut ids = Vec::<String>::new();
        while let Some(set) = rows.next_result_set().await? {
            for mut row in set { ids.push(row.remove_field_by_name("id")?.try_into()?); }
        }
        rows.close().await?;
        ensure!(ids.len() == 2, "expected public and authenticated verification intents");
        let id = ids[1].clone();
        let key = VerifyKey::from_env()?.issue(Uuid::parse_str(&id)?)?;

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
        let config = VerifyMailConfig::new(VerifyKey::from_env()?, "http://localhost/verify-email")?;
        let from: Mailbox = "no-reply@example.invalid".parse()?;
        let sent = email_verify::process_one(&client, &id, &config, &mailer, &from).await?;
        ensure!(sent.claimed == 1 && sent.sent == 1, "verification email was not sent");
        let mail = tokio::time::timeout(Duration::from_secs(5), server).await???;
        ensure!(mail.contains("verify-email") && !mail.contains("Original verification password"));
        ensure!(email_verify::process_one(&client, &id, &config, &mailer, &from).await?.claimed == 0);

        let (forged_status, forged) = post(&app, "/api/v1/auth/email/verification/confirm",
            json!({"key":VerifyKey::new([9; 32])?.issue(Uuid::parse_str(&id)?)?}), &csrf, true).await?;
        ensure!(forged_status == StatusCode::BAD_REQUEST && forged["code"] == "INVALID_RECOVERY_LINK");
        ensure!(email_verify::confirm(&client, &VerifyKey::from_env()?, &key,
            SystemTime::now() + Duration::from_secs(25 * 3600)).await? == email_verify::ConfirmResult::Invalid,
            "expired verification link was accepted");
        let collision_id = account_id - 1;
        client.query_client().exec("UPSERT INTO accounts_accountemaillookup (user_id, email_key) VALUES ($id, $email)")
            .param("$id", collision_id).param("$email", email.clone()).await?;
        let collision = post(&app, "/api/v1/auth/email/verification/confirm", json!({"key":key}), &csrf, true).await;
        client.query_client().exec("DELETE FROM accounts_accountemaillookup WHERE user_id = $id")
            .param("$id", collision_id).await?;
        let (collision_status, collision_body) = collision?;
        ensure!(collision_status == StatusCode::BAD_REQUEST && collision_body["code"] == "INVALID_RECOVERY_LINK",
            "new email collision did not block confirmation");

        let ((first, first_body), (second, second_body)) = tokio::try_join!(
            post(&app, "/api/v1/auth/email/verification/confirm", json!({"key":key}), &csrf, true),
            post(&app, "/api/v1/auth/email/verification/confirm", json!({"key":key}), &csrf, true),
        )?;
        let successes = usize::from(first == StatusCode::OK) + usize::from(second == StatusCode::OK);
        ensure!(successes == 1, "concurrent confirmation had {successes} successes: {first_body}, {second_body}");
        let (replay, payload) = post(&app, "/api/v1/auth/email/verification/confirm", json!({"key":key}), &csrf, true).await?;
        ensure!(replay == StatusCode::BAD_REQUEST && payload["code"] == "INVALID_RECOVERY_LINK");
        let mut address = client.query_client().query_row("SELECT verified FROM account_emailaddress WHERE id = $id")
            .param("$id", account_id).await?;
        let verified: bool = address.remove_field_by_name("verified")?.try_into()?;
        ensure!(verified, "email address not verified");
        let mut identity = client.query_client().query_row("SELECT email_verified FROM usid_user WHERE user_id = $id")
            .param("$id", identity_id).await?;
        let master_verified: bool = identity.remove_field_by_name("email_verified")?.try_into()?;
        ensure!(master_verified, "master identity not verified");
        let (verified_token, verified_csrf) = token(&app).await?;
        let (verified_status, verified_response) = post(&app, "/api/v1/auth/email/verification/request",
            json!({"email":email,"form_token":verified_token}), &verified_csrf, true).await?;
        ensure!(verified_status == status && verified_response == requested,
            "verified account leaked through request response");
        Ok(())
    }.await;
    let mut query = client.query_client();
    let mut rows = query
        .query("SELECT id FROM id_email_verification WHERE user_id = $id")
        .param("$id", account_id)
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
            .exec("DELETE FROM id_email_verification WHERE id = $id")
            .param("$id", id)
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM account_emailaddress WHERE id = $id")
        .param("$id", account_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountemaillookup WHERE user_id = $id")
        .param("$id", account_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountidentity WHERE user_id = $id")
        .param("$id", account_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM usid_user WHERE user_id = $id")
        .param("$id", identity_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM auth_user WHERE id = $id")
        .param("$id", account_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM django_session WHERE session_key = $key")
        .param("$key", session)
        .await?;
    outcome
}
