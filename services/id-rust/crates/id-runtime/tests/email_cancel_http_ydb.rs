#![recursion_limit = "256"]
//! Email-change cancellation and confirmation cleanup on local YDB.

use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use id_compat::session::SessionCodec;
use serde_json::{Value, json};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;
use uuid::Uuid;

async fn delete(
    app: &Router,
    cookie: Option<&str>,
    token: Option<&str>,
    csrf: bool,
) -> Result<(StatusCode, Value)> {
    let mut request = Request::builder()
        .method("DELETE")
        .uri("/api/v1/auth/email/change");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    if let Some(token) = token {
        request = request.header("x-session-token", token);
    }
    if csrf {
        request = request
            .header(header::ORIGIN, "http://id.localhost")
            .header("x-csrftoken", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    }
    let response = app.clone().oneshot(request.body(Body::empty())?).await?;
    let status = response.status();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
    Ok((status, body))
}

#[tokio::test]
#[ignore = "requires migrated local YDB and opt-in Rust email cancellation"]
async fn cancellation_cleans_confirmations_without_touching_primary_or_verified_email() -> Result<()>
{
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local"
            && std::env::var("ID_AUTH_EMAIL_CANCEL_PILOT_ENABLED")? == "true",
        "test requires opt-in local YDB"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    let app = id_runtime::email_cancel_http::router(
        id_runtime::email_cancel_http::EmailCancelHttpConfig::from_env(client.clone())?
            .context("email cancellation disabled")?,
    );
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let user_id = -i32::try_from(stamp % 1_000_000_000 + 1)?;
    let primary_id = user_id - 5000;
    let pending_id = primary_id - 1;
    let verified_id = primary_id - 2;
    let pending_confirmation_id = primary_id - 3;
    let verified_confirmation_id = primary_id - 4;
    let identity_id = Uuid::from_u128((stamp << 32) | u128::from(std::process::id()));
    let token = format!("rustemailcancel{stamp:032x}session");
    let codec = SessionCodec::new(std::env::var("DJANGO_SECRET_KEY")?.as_bytes(), &[])?;
    let password = "pbkdf2_sha256$1000000$synthetic$synthetic";
    let now = SystemTime::now();
    let data = json!({"_auth_user_id":user_id.to_string(),
        "_auth_user_backend":"django.contrib.auth.backends.ModelBackend",
        "_auth_user_hash":codec.auth_hash(password)?});
    let signed = codec.encode(
        data.as_object().context("session object")?,
        i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?,
        true,
    )?;
    client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $password, true, $name, '', '', $email, false, false, CurrentUtcDatetime())")
        .param("$id", user_id).param("$password", password)
        .param("$name", format!("rust-email-cancel-{stamp}"))
        .param("$email", format!("rust-email-cancel-{stamp}@example.invalid")).await?;
    let outcome: Result<()> = async {
        client.query_client().exec("UPSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, $data, CAST($expires AS Datetime))")
            .param("$key", token.clone()).param("$data", signed)
            .param("$expires", now + Duration::from_secs(3600)).await?;
        client.query_client().exec("UPSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, $name, $name, $email, true, 'active', false, CurrentUtcDatetime())")
            .param("$id", identity_id).param("$name", format!("rust-email-cancel-{stamp}"))
            .param("$email", format!("rust-email-cancel-{stamp}@example.invalid")).await?;
        client.query_client().exec("UPSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($id, $identity, $subject, CurrentUtcDatetime())")
            .param("$id", user_id).param("$identity", identity_id)
            .param("$subject", format!("rust-email-cancel-sub-{stamp}")).await?;
        for (id, label, verified, primary) in [
            (primary_id, "primary", true, true),
            (pending_id, "pending", false, false),
            (verified_id, "verified", true, false),
        ] {
            client.query_client().exec("UPSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($id, $user_id, $email, $verified, $primary)")
                .param("$id", id).param("$user_id", user_id)
                .param("$email", format!("{label}-{stamp}@example.invalid"))
                .param("$verified", verified).param("$primary", primary).await?;
        }
        for (id, email_id) in [(pending_confirmation_id, pending_id), (verified_confirmation_id, verified_id)] {
            client.query_client().exec("UPSERT INTO account_emailconfirmation (id, email_address_id, created, key) VALUES ($id, $email_id, CurrentUtcDatetime(), $key)")
                .param("$id", id).param("$email_id", email_id)
                .param("$key", format!("rust-email-cancel-{stamp}-{id}")).await?;
        }
        let cookie = format!("sessionid={token}; csrftoken=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let (status, _) = delete(&app, None, None, false).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "anonymous cancellation succeeded");
        let (status, _) = delete(&app, Some(&cookie), None, false).await?;
        ensure!(status == StatusCode::FORBIDDEN, "cookie cancellation bypassed CSRF");
        let (status, _) = delete(&app, Some(&cookie), Some("invalid"), true).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "invalid header fell back to cookie");
        let mut attempts = tokio::task::JoinSet::new();
        for attempt in 0..10 {
            let app = app.clone();
            let cookie = cookie.clone();
            let token = token.clone();
            attempts.spawn(async move {
                if attempt == 0 {
                    delete(&app, Some(&cookie), None, true).await
                } else {
                    delete(&app, None, Some(&token), false).await
                }
            });
        }
        while let Some(result) = attempts.join_next().await {
            let (status, body) = result??;
            ensure!(status == StatusCode::OK && body["ok"] == true,
                "concurrent email cancellation failed: {body}");
        }
        let (status, body) = delete(&app, Some(&cookie), Some(&token), false).await?;
        ensure!(status == StatusCode::OK && body["ok"] == true, "idempotent retry failed: {body}");
        for (id, exists) in [(primary_id, true), (pending_id, false), (verified_id, true)] {
            let row = client.query_client().query_row("SELECT id FROM account_emailaddress WHERE id = $id")
                .param("$id", id).optional().await?;
            ensure!(row.is_some() == exists, "email address preservation mismatch");
        }
        for (id, exists) in [(pending_confirmation_id, false), (verified_confirmation_id, true)] {
            let row = client.query_client().query_row("SELECT id FROM account_emailconfirmation WHERE id = $id")
                .param("$id", id).optional().await?;
            ensure!(row.is_some() == exists, "email confirmation preservation mismatch");
        }
        let mut count = client.query_client().query_row("SELECT COUNT(*) AS total FROM accounts_accountevent WHERE user_id = $user_id AND action = 'email_change_cancelled'")
            .param("$user_id", user_id).await?;
        let total: u64 = count.remove_field_by_name("total")?.try_into()?;
        ensure!(total == 1, "retry created a second audit event");
        client.query_client().exec("UPDATE auth_user SET is_active = false WHERE id = $id")
            .param("$id", user_id).await?;
        let (status, _) = delete(&app, Some(&cookie), Some(&token), false).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "disabled account cancelled email");
        Ok(())
    }.await;
    for id in [pending_confirmation_id, verified_confirmation_id] {
        client
            .query_client()
            .exec("DELETE FROM account_emailconfirmation WHERE id = $id")
            .param("$id", id)
            .await?;
    }
    for id in [primary_id, pending_id, verified_id] {
        client
            .query_client()
            .exec("DELETE FROM account_emailaddress WHERE id = $id")
            .param("$id", id)
            .await?;
    }
    client.query_client().exec("DELETE FROM accounts_accountevent WHERE user_id = $id AND action = 'email_change_cancelled'")
        .param("$id", user_id).await?;
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
        .exec("DELETE FROM django_session WHERE session_key = $key")
        .param("$key", token)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM auth_user WHERE id = $id")
        .param("$id", user_id)
        .await?;
    outcome
}
