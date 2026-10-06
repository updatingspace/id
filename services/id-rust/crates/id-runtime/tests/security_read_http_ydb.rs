#![recursion_limit = "256"]
//! Authenticated MFA/passkey inventory against the real local YDB schema.

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

async fn request(
    app: &Router,
    path: &str,
    cookie: Option<&str>,
    token: Option<&str>,
) -> Result<(StatusCode, Value)> {
    let mut builder = Request::builder().uri(path).method("GET");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    if let Some(token) = token {
        builder = builder.header("x-session-token", token);
    }
    let response = app.clone().oneshot(builder.body(Body::empty())?).await?;
    let status = response.status();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await?)?;
    Ok((status, body))
}

#[tokio::test]
#[ignore = "requires migrated local YDB and opt-in Rust MFA inventory"]
async fn mfa_and_passkeys_require_current_bound_mfa_session() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local"
            && std::env::var("ID_AUTH_SECURITY_READ_PILOT_ENABLED")? == "true",
        "test requires opt-in local YDB"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    let app = id_runtime::security_http::router(
        id_runtime::security_http::SecurityReadHttpConfig::from_env(client.clone())?
            .context("MFA read pilot disabled")?,
    );
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let user_id = -i32::try_from(stamp % 1_000_000_000 + 1)?;
    let identity_id = Uuid::from_u128((stamp << 32) | u128::from(std::process::id()));
    let row_id = -i64::try_from(stamp % 1_000_000_000 + 10_000_000_000)?;
    let email_id = user_id - 5000;
    let token = format!("rustsecurity{stamp:032x}session");
    let codec = SessionCodec::new(std::env::var("DJANGO_SECRET_KEY")?.as_bytes(), &[])?;
    let password = "pbkdf2_sha256$1000000$synthetic$synthetic";
    let now = SystemTime::now();
    let mut session = json!({"_auth_user_id":user_id.to_string(),
        "_auth_user_backend":"django.contrib.auth.backends.ModelBackend",
        "_auth_user_hash":codec.auth_hash(password)?});
    let signed = codec.encode(
        session.as_object().context("session data")?,
        i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?,
        true,
    )?;
    client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $password, true, $name, '', '', $email, false, false, CurrentUtcDatetime())")
        .param("$id", user_id).param("$password", password)
        .param("$name", format!("rust-security-{stamp}"))
        .param("$email", format!("rust-security-{stamp}@example.invalid")).await?;
    let outcome: Result<()> = async {
        client.query_client().exec("UPSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, $data, CAST($expires AS Datetime))")
            .param("$key", token.clone()).param("$data", signed).param("$expires", now + Duration::from_secs(3600)).await?;
        client.query_client().exec("UPSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, $name, $name, $email, true, 'active', false, CurrentUtcDatetime())")
            .param("$id", identity_id).param("$name", format!("rust-security-{stamp}"))
            .param("$email", format!("rust-security-{stamp}@example.invalid")).await?;
        client.query_client().exec("UPSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($id, $identity, $subject, CurrentUtcDatetime())")
            .param("$id", user_id).param("$identity", identity_id)
            .param("$subject", format!("rust-security-sub-{stamp}")).await?;
        client.query_client().exec("UPSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($id, $user_id, $email, true, true)")
            .param("$id", email_id).param("$user_id", user_id)
            .param("$email", format!("primary-{stamp}@example.invalid")).await?;
        for (offset, label) in [(2, "older"), (1, "pending")] {
            client.query_client().exec("UPSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($id, $user_id, $email, false, false)")
                .param("$id", email_id - offset).param("$user_id", user_id)
                .param("$email", format!("{label}-{stamp}@example.invalid")).await?;
        }
        client.query_client().exec("UPSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $user_id, 'totp', Unwrap(CAST($data AS Json)), CurrentUtcDatetime())")
            .param("$id", row_id).param("$user_id", user_id)
            .param("$data", json!({"secret":"encrypted-test-secret"}).to_string()).await?;
        client.query_client().exec("UPSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $user_id, 'recovery_codes', Unwrap(CAST($data AS Json)), CurrentUtcDatetime())")
            .param("$id", row_id - 1).param("$user_id", user_id)
            .param("$data", json!({"seed":"encrypted-test-seed","used_mask":5}).to_string()).await?;
        client.query_client().exec("UPSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $user_id, 'webauthn', Unwrap(CAST($data AS Json)), CurrentUtcDatetime())")
            .param("$id", row_id - 2).param("$user_id", user_id)
            .param("$data", json!({"name":"Security key","credential":{"clientExtensionResults":{"credProps":{"rk":true}}}}).to_string()).await?;
        for offset in 0..101u64 {
            client.query_client().exec("UPSERT INTO accounts_loginevent (id, user_id, status, ip_address, ip_hash, user_agent, device_id, location, is_new_device, reason, meta, created_at) VALUES ($id, $user_id, 'success', $ip, '', 'Test browser', '', '', false, $reason, Unwrap(CAST('{}' AS Json)), CAST($created AS Datetime))")
                .param("$id", row_id - 100 - i64::try_from(offset)?)
                .param("$user_id", user_id)
                .param("$ip", format!("192.0.2.{}", offset % 200 + 1))
                .param("$reason", format!("event-{offset:03}"))
                .param("$created", now - Duration::from_secs(offset * 60)).await?;
        }
        client.query_client().exec("UPSERT INTO accounts_loginevent (id, user_id, status, ip_address, ip_hash, user_agent, device_id, location, is_new_device, reason, meta, created_at) VALUES ($id, $user_id, 'failure', '203.0.113.1', '', 'Other browser', '', '', false, 'foreign-event', Unwrap(CAST('{}' AS Json)), CAST($created AS Datetime))")
            .param("$id", row_id - 1000).param("$user_id", user_id - 1).param("$created", now).await?;
        let cookie = format!("sessionid={token}");
        let (status, _) = request(&app, "/api/v1/auth/mfa/status", Some(&cookie), None).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "unproven MFA session was accepted");
        let (status, _) = request(&app, "/api/v1/auth/login-history", Some(&cookie), None).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "unproven MFA session read login history");
        let (status, _) = request(&app, "/api/v1/auth/email", Some(&cookie), None).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "unproven MFA session read email status");
        session["id_mfa_verified_user_id"] = json!(user_id.to_string());
        let signed = codec.encode(session.as_object().context("bound session")?,
            i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?, true)?;
        client.query_client().exec("UPDATE django_session SET session_data = $data WHERE session_key = $key")
            .param("$data", signed).param("$key", token.clone()).await?;

        let (status, body) = request(&app, "/api/v1/auth/mfa/status", Some(&cookie), None).await?;
        ensure!(status == StatusCode::OK && body == json!({"has_totp":true,"has_webauthn":true,
            "has_recovery_codes":true,"recovery_codes_left":8}), "MFA status: {body}");
        let (status, body) = request(&app, "/api/v1/auth/passkeys", Some(&cookie), None).await?;
        ensure!(status == StatusCode::OK && body["authenticators"].as_array().is_some_and(|rows| rows.len() == 1), "passkeys: {body}");
        let passkey_id = (row_id - 2).to_string();
        ensure!(body["authenticators"][0]["id"].as_str() == Some(passkey_id.as_str())
            && body["authenticators"][0]["name"] == "Security key"
            && body["authenticators"][0]["is_passwordless"] == true
            && body["authenticators"][0]["created_at"].as_u64().is_some(), "passkey fields: {body}");
        ensure!(!body.to_string().contains("encrypted-test"), "passkey inventory disclosed MFA data");
        let (status, combined) = request(&app, "/api/v1/auth/security", Some(&cookie), None).await?;
        ensure!(status == StatusCode::OK && combined["mfa"]["recovery_codes_left"] == 8
            && combined["authenticators"][0]["id"].as_str() == Some(passkey_id.as_str()),
            "combined security snapshot: {combined}");
        let (status, email) = request(&app, "/api/v1/auth/email", Some(&cookie), None).await?;
        ensure!(status == StatusCode::OK && email == json!({
            "email":format!("primary-{stamp}@example.invalid"),
            "verified":true,
            "pending_email":format!("pending-{stamp}@example.invalid")
        }), "email status: {email}");
        let (status, history) = request(&app, "/api/v1/auth/login-history", Some(&cookie), None).await?;
        ensure!(status == StatusCode::OK, "login history response: {history}");
        let events = history["events"].as_array().context("login events missing")?;
        ensure!(events.len() == 100 && events[0]["reason"] == "event-000"
            && events[99]["reason"] == "event-099", "history cap/order is wrong");
        ensure!(events.iter().all(|event| event["reason"] != "foreign-event")
            && events[0]["ip_address"] == "192.0.2.1"
            && events[0]["created_at"].as_str().is_some(), "history leaked another account or dropped fields");
        let (status, body) = request(&app, "/api/v1/auth/login-history", Some(&cookie), Some("invalid")).await?;
        ensure!(status == StatusCode::UNAUTHORIZED && body["code"] == "INVALID_OR_EXPIRED_TOKEN",
            "invalid header fell back to cookie for history");
        let (status, body) = request(&app, "/api/v1/auth/passkeys", Some(&cookie), Some("invalid")).await?;
        ensure!(status == StatusCode::UNAUTHORIZED && body["code"] == "INVALID_OR_EXPIRED_TOKEN",
            "invalid header fell back to cookie");
        let (status, body) = request(&app, "/api/v1/auth/email", Some(&cookie), Some("invalid")).await?;
        ensure!(status == StatusCode::UNAUTHORIZED && body["code"] == "INVALID_OR_EXPIRED_TOKEN",
            "invalid header fell back to cookie for email");

        client.query_client().exec("UPDATE mfa_authenticator SET data = Unwrap(CAST($data AS Json)) WHERE id = $id")
            .param("$id", row_id - 1)
            .param("$data", json!({"migrated_codes":["encrypted-one","encrypted-two"]}).to_string()).await?;
        let (status, body) = request(&app, "/api/v1/auth/mfa/status", Some(&cookie), None).await?;
        ensure!(status == StatusCode::OK && body["recovery_codes_left"] == 2,
            "migrated recovery status: {body}");
        client.query_client().exec("UPDATE auth_user SET is_active = false WHERE id = $id")
            .param("$id", user_id).await?;
        let (status, _) = request(&app, "/api/v1/auth/passkeys", Some(&cookie), None).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "disabled user read passkeys");
        let (status, _) = request(&app, "/api/v1/auth/login-history", Some(&cookie), None).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "disabled user read history");
        let (status, _) = request(&app, "/api/v1/auth/email", Some(&cookie), None).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "disabled user read email status");
        Ok(())
    }.await;
    for id in [row_id, row_id - 1, row_id - 2] {
        client
            .query_client()
            .exec("DELETE FROM mfa_authenticator WHERE id = $id")
            .param("$id", id)
            .await?;
    }
    for id in [email_id, email_id - 1, email_id - 2] {
        client
            .query_client()
            .exec("DELETE FROM account_emailaddress WHERE id = $id")
            .param("$id", id)
            .await?;
    }
    for offset in 0..101i64 {
        client
            .query_client()
            .exec("DELETE FROM accounts_loginevent WHERE id = $id")
            .param("$id", row_id - 100 - offset)
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM accounts_loginevent WHERE id = $id")
        .param("$id", row_id - 1000)
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
