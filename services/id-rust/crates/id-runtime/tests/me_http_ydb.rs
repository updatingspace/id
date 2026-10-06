#![recursion_limit = "256"]
//! End-to-end Axum route with synthetic Django session rows in local YDB.

use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
};
use id_compat::session::SessionCodec;
use serde_json::{Value, json};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;
use uuid::Uuid;

const BACKEND: &str = "django.contrib.auth.backends.ModelBackend";

async fn request(
    app: &Router,
    cookie: Option<&str>,
    header_token: Option<&str>,
) -> Result<(StatusCode, HeaderMap, Value)> {
    let mut builder = Request::builder().uri("/api/v1/auth/me").method("GET");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    if let Some(token) = header_token {
        builder = builder.header("x-session-token", token);
    }
    let response = app.clone().oneshot(builder.body(Body::empty())?).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await?)?;
    Ok((status, headers, body))
}

#[tokio::test]
#[ignore = "requires local YDB after migrate_ydb and opt-in Rust /me environment"]
async fn me_route_preserves_guest_header_and_cookie_contract() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local"
            && std::env::var("ID_AUTH_ME_ENABLED")? == "true",
        "HTTP test requires opt-in local YDB on port 2136"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    let config = id_runtime::me_http::MeHttpConfig::from_env(client.clone())?
        .context("Rust /me route was not enabled")?;
    let app = id_runtime::me_http::router(config);
    let (guest_status, guest_headers, guest_body) = request(&app, None, None).await?;
    ensure!(guest_status == StatusCode::OK && guest_body == json!({"user": null}));
    ensure!(guest_headers[header::CACHE_CONTROL] == "private, no-store");
    ensure!(guest_headers[header::PRAGMA] == "no-cache");
    ensure!(guest_headers[header::VARY] == "Cookie, origin");
    let csrf = guest_headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("csrftoken="))
        .context("guest response did not issue CSRF cookie")?;
    ensure!(!csrf.contains("HttpOnly") && csrf.contains("SameSite=Lax"));

    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let id = -i32::try_from(stamp % 1_000_000_000 + 1)?;
    let identity_id = Uuid::from_u128((stamp << 32) | u128::from(std::process::id()));
    let audit_prefix = format!("rustme{stamp:032x}");
    let token = format!("{audit_prefix}session");
    let secret = std::env::var("DJANGO_SECRET_KEY")?;
    let codec = Arc::new(SessionCodec::new(secret.as_bytes(), &[])?);
    let password = "pbkdf2_sha256$1000000$synthetic$synthetic";
    let now = SystemTime::now();
    let payload = json!({
        "_auth_user_id": id.to_string(),
        "_auth_user_backend": BACKEND,
        "_auth_user_hash": codec.auth_hash(password)?,
    });
    let encoded = codec.encode(
        payload
            .as_object()
            .context("synthetic session payload is not an object")?,
        i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?,
        true,
    )?;
    client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $password, true, $username, 'Ada', 'Lovelace', $email, false, false, CurrentUtcDatetime())")
        .param("$id", id).param("$password", password)
        .param("$username", format!("rust-me-{stamp}"))
        .param("$email", format!("rust-me-{stamp}@example.invalid"))
        .await?;
    let result: Result<()> = async {
        client.query_client().exec("UPSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, $data, CAST($expires AS Datetime))")
            .param("$key", token.clone()).param("$data", encoded)
            .param("$expires", now + Duration::from_secs(3600)).await?;
        client.query_client().exec("UPSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($identity_id, $name, $name, $email, true, 'active', false, CurrentUtcDatetime())")
            .param("$identity_id", identity_id)
            .param("$name", format!("rust-me-{stamp}"))
            .param("$email", format!("rust-me-{stamp}@example.invalid"))
            .await?;
        client.query_client().exec("UPSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($user_id, $identity_id, $subject, CurrentUtcDatetime())")
            .param("$user_id", id).param("$identity_id", identity_id)
            .param("$subject", format!("stable-me-subject-{stamp}"))
            .await?;
        client.query_client().exec("UPSERT INTO accounts_userprofile (id, user_id, avatar, avatar_source, gravatar_enabled, phone_number, phone_verified, created_at, updated_at) VALUES ($row_id, $user_id, CAST('avatars/saved.jpg' AS String), 'upload', false, '', false, CurrentUtcDatetime(), CurrentUtcDatetime())")
            .param("$row_id", i64::from(id)).param("$user_id", id).await?;

        let (status, headers, body) = request(&app, None, Some(&token)).await?;
        ensure!(status == StatusCode::OK && body["user"]["username"] == format!("rust-me-{stamp}"));
        ensure!(body["user"]["first_name"] == "Ada" && body["user"]["language"] == "en");
        ensure!(body["user"]["avatar_url"] == "https://storage.yandexcloud.net/synthetic-id-media/avatars/saved.jpg");
        let session_cookie = headers.get_all(header::SET_COOKIE).iter()
            .filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with("sessionid="))
            .context("valid header did not establish browser session cookie")?;
        ensure!(session_cookie.contains("HttpOnly") && session_cookie.contains("SameSite=Lax"));
        let browser_cookie = format!("sessionid={token}");

        let (status, headers, body) = request(&app, Some(&browser_cookie), None).await?;
        ensure!(status == StatusCode::OK && body["user"]["username"] == format!("rust-me-{stamp}"));
        ensure!(!headers.get_all(header::SET_COOKIE).iter()
            .filter_map(|value| value.to_str().ok())
            .any(|value| value.starts_with("sessionid=")), "cookie restore rewrote session cookie");

        let (status, _, body) = request(&app, Some(&browser_cookie), Some("invalid")).await?;
        ensure!(status == StatusCode::UNAUTHORIZED && body["code"] == "INVALID_OR_EXPIRED_TOKEN");
        ensure!(body["status"] == 401 && body["details"].is_null());

        client.query_client().exec("UPSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($row_id, $user_id, 'totp', Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime())")
            .param("$row_id", i64::from(id)).param("$user_id", id).await?;
        let (status, _, _) = request(&app, None, Some(&token)).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "MFA account without bound proof was accepted");
        let (status, _, body) = request(&app, Some(&browser_cookie), None).await?;
        ensure!(status == StatusCode::OK && body == json!({"user": null}), "MFA cookie without proof was accepted");
        let audit = id_runtime::session_audit::audit_mfa_sessions_with_prefix(
            &client, codec.clone(), &[BACKEND], now, &audit_prefix).await?;
        ensure!(audit.scanned == 1 && audit.eligible_mfa_unproven == 1,
            "audit missed an unproven active MFA session");

        let mut unfinished_allauth = payload.clone();
        unfinished_allauth["account_authentication_methods"] = json!([
            {"method": "password", "at": 1}, {"method": "mfa", "type": "totp", "at": 2}
        ]);
        let signed = codec.encode(unfinished_allauth.as_object().context("allauth payload is not an object")?,
            i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?, true)?;
        client.query_client().exec("UPDATE django_session SET session_data = $data WHERE session_key = $key")
            .param("$data", signed).param("$key", token.clone()).await?;
        let (status, _, _) = request(&app, None, Some(&token)).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "allauth method log alone was accepted as MFA proof");

        let mut wrong_proof = payload.clone();
        wrong_proof["id_mfa_verified_user_id"] = json!((id - 1).to_string());
        let signed = codec.encode(wrong_proof.as_object().context("proof payload is not an object")?,
            i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?, true)?;
        client.query_client().exec("UPDATE django_session SET session_data = $data WHERE session_key = $key")
            .param("$data", signed).param("$key", token.clone()).await?;
        let (status, _, _) = request(&app, None, Some(&token)).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "proof for another account was accepted");

        let mut verified = payload.clone();
        verified["id_mfa_verified_user_id"] = json!(id.to_string());
        let signed = codec.encode(verified.as_object().context("proof payload is not an object")?,
            i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?, true)?;
        client.query_client().exec("UPDATE django_session SET session_data = $data WHERE session_key = $key")
            .param("$data", signed).param("$key", token.clone()).await?;
        let (status, _, body) = request(&app, None, Some(&token)).await?;
        ensure!(status == StatusCode::OK && body["user"]["has_2fa"] == true,
            "verified MFA session was not restored");
        let audit = id_runtime::session_audit::audit_mfa_sessions_with_prefix(
            &client, codec.clone(), &[BACKEND], now, &audit_prefix).await?;
        ensure!(audit.scanned == 1 && audit.eligible_mfa_proven == 1
            && audit.eligible_mfa_unproven == 0,
            "audit did not recognize bound MFA proof");

        client.query_client().exec("UPDATE auth_user SET is_active = false WHERE id = $id")
            .param("$id", id).await?;
        let (status, _, body) = request(&app, Some(&browser_cookie), None).await?;
        ensure!(status == StatusCode::OK && body == json!({"user": null}));
        let (status, _, _) = request(&app, None, Some(&token)).await?;
        ensure!(status == StatusCode::UNAUTHORIZED);
        Ok(())
    }.await;

    client
        .query_client()
        .exec("DELETE FROM mfa_authenticator WHERE id = $id")
        .param("$id", i64::from(id))
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountidentity WHERE user_id = $id")
        .param("$id", id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_userprofile WHERE id = $id")
        .param("$id", i64::from(id))
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
        .param("$id", id)
        .await?;
    result
}
