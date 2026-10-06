#![recursion_limit = "256"]
//! Password change and credential revocation against a migrated local YDB.

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

async fn change(
    app: &Router,
    token: Option<&str>,
    cookie: Option<&str>,
    csrf: bool,
    current: &str,
    new: &str,
) -> Result<(StatusCode, Value)> {
    let mut request = Request::builder()
        .uri("/api/v1/auth/change_password")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        request = request.header("x-session-token", token);
    }
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    if csrf {
        request = request
            .header("origin", "http://localhost:5175")
            .header("x-csrftoken", "a".repeat(32));
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(
            json!({"current_password":current,"new_password":new}).to_string(),
        ))?)
        .await?;
    let status = response.status();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await?)?;
    Ok((status, body))
}

#[tokio::test]
#[ignore = "requires migrated local YDB and ID_AUTH_PASSWORD_CHANGE_PILOT_ENABLED=true"]
async fn password_change_invalidates_all_sessions_and_refresh_mapping() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local"
            && std::env::var("DJANGO_DEBUG")? == "true"
            && std::env::var("ID_AUTH_PASSWORD_CHANGE_PILOT_ENABLED")? == "true",
        "test requires opt-in local YDB"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    id_runtime::security_mail::ensure_schema(&client).await?;
    let config =
        id_runtime::password_change_http::PasswordChangeHttpConfig::from_env(client.clone())?
            .context("password change pilot disabled")?;
    let app = id_runtime::password_change_http::router(config);
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let user_id = -i32::try_from(stamp % 1_000_000_000 + 1)?;
    let identity_id = Uuid::from_u128((stamp << 32) | u128::from(std::process::id()));
    let token = format!("rustpassword{stamp:032x}a");
    let other = format!("rustpassword{stamp:032x}b");
    let metadata_id = i64::from(user_id).abs() + 9_000_000_000;
    let mapping_id = metadata_id + 1;
    let oidc_token_id = metadata_id + 2;
    let oidc_client_id = metadata_id + 3;
    let oidc_code = format!("rust-password-code-{stamp}");
    let oidc_request = format!("rust-password-request-{stamp}");
    let mfa_id = metadata_id + 4;
    let current = "synthetic current passphrase";
    let new = "synthetic changed passphrase";
    let hash = id_compat::password::hash_new(current)?;
    let codec = SessionCodec::new(std::env::var("DJANGO_SECRET_KEY")?.as_bytes(), &[])?;
    let now = SystemTime::now();
    let payload = json!({
        "_auth_user_id": user_id.to_string(),
        "_auth_user_backend": "django.contrib.auth.backends.ModelBackend",
        "_auth_user_hash": codec.auth_hash(&hash)?,
    });
    let encoded = codec.encode(
        payload.as_object().context("session payload")?,
        i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?,
        true,
    )?;
    client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $hash, true, $name, '', '', $email, false, false, CurrentUtcDatetime())")
        .param("$id", user_id).param("$hash", hash.clone()).param("$name", format!("rust-password-{stamp}"))
        .param("$email", format!("rust-password-{stamp}@example.invalid")).await?;
    let result: Result<()> = async {
        client.query_client().exec("UPSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, $name, $name, $email, true, 'active', false, CurrentUtcDatetime())")
            .param("$id", identity_id).param("$name", format!("rust-password-{stamp}"))
            .param("$email", format!("rust-password-{stamp}@example.invalid")).await?;
        client.query_client().exec("UPSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($user, $id, $subject, CurrentUtcDatetime())")
            .param("$user", user_id).param("$id", identity_id).param("$subject", format!("rust-password-subject-{stamp}")).await?;
        for key in [&token, &other] {
            client.query_client().exec("UPSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, $data, CAST($expires AS Datetime))")
                .param("$key", key.clone()).param("$data", encoded.clone()).param("$expires", now + Duration::from_secs(3600)).await?;
        }
        client.query_client().exec("INSERT INTO core_usersessionmeta (id, user_id, session_key, user_agent, revoked_reason, first_seen) VALUES ($id, $user, $key, '', '', CAST($now AS Datetime))")
            .param("$id", metadata_id).param("$user", user_id).param("$key", other.clone()).param("$now", now).await?;
        client.query_client().exec("INSERT INTO core_usersessiontoken (id, user_id, session_key, refresh_jti, created_at) VALUES ($id, $user, $key, $jti, CAST($now AS Datetime))")
            .param("$id", mapping_id).param("$user", user_id).param("$key", other.clone())
            .param("$jti", format!("rust-password-jti-{stamp}")).param("$now", now).await?;
        client.query_client().exec("INSERT INTO idp_oidctoken (id, user_id, client_id, access_jti, id_jti, refresh_token_hash, scope, created_at, access_expires_at) VALUES ($id, $user, $client, $jti, '', $refresh, 'openid', CAST($now AS Datetime), CAST($expiry AS Datetime))")
            .param("$id", oidc_token_id).param("$user", user_id).param("$client", oidc_client_id)
            .param("$jti", format!("rust-password-access-{stamp}"))
            .param("$refresh", format!("rust-password-refresh-{stamp}"))
            .param("$now", now).param("$expiry", now + Duration::from_secs(3600)).await?;
        client.query_client().exec("INSERT INTO idp_oidcauthorizationcode (code, client_id, user_id, redirect_uri, scope, nonce, code_challenge, code_challenge_method, created_at, expires_at) VALUES ($code, $client, $user, 'https://example.invalid/callback', 'openid', '', '', '', CAST($now AS Datetime), CAST($expiry AS Datetime))")
            .param("$code", oidc_code.clone()).param("$client", oidc_client_id).param("$user", user_id)
            .param("$now", now).param("$expiry", now + Duration::from_secs(3600)).await?;
        client.query_client().exec("INSERT INTO idp_oidcauthorizationrequest (request_id, client_id, user_id, redirect_uri, scope, state, nonce, code_challenge, code_challenge_method, prompt, created_at, expires_at) VALUES ($request, $client, $user, 'https://example.invalid/callback', 'openid', '', '', '', '', '', CAST($now AS Datetime), CAST($expiry AS Datetime))")
            .param("$request", oidc_request.clone()).param("$client", oidc_client_id).param("$user", user_id)
            .param("$now", now).param("$expiry", now + Duration::from_secs(3600)).await?;

        let cookie = format!("sessionid={token}; csrftoken={}", "a".repeat(32));
        let (status, _) = change(&app, None, Some(&cookie), false, current, new).await?;
        ensure!(status == StatusCode::FORBIDDEN, "missing CSRF allowed");
        let (status, _) = change(&app, Some("invalid"), Some(&cookie), true, current, new).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "invalid explicit token fell back to cookie");
        let (status, _) = change(&app, Some(&token), None, false, "wrong current", new).await?;
        ensure!(status == StatusCode::BAD_REQUEST, "wrong current password allowed");
        let (status, _) = change(&app, Some(&token), None, false, current, "short").await?;
        ensure!(status == StatusCode::BAD_REQUEST, "weak new password allowed");
        let account_derived = format!("rust-password-{stamp}-new");
        for weak in ["password123", account_derived.as_str()] {
            let (status, _) = change(&app, Some(&token), None, false, current, weak).await?;
            ensure!(status == StatusCode::BAD_REQUEST, "common or account-derived password allowed");
        }
        client.query_client().exec("UPDATE auth_user SET email = $email WHERE id = $id")
            .param("$email", "invalid-email").param("$id", user_id).await?;
        let (status, _) = change(&app, Some(&token), None, false, current, new).await?;
        ensure!(status == StatusCode::SERVICE_UNAVAILABLE, "password changed without a deliverable notification address");
        let mut row = client.query_client().query_row("SELECT password FROM auth_user WHERE id = $id")
            .param("$id", user_id).await?;
        let unchanged: String = row.remove_field_by_name("password")?.try_into()?;
        ensure!(unchanged == hash, "failed mail preflight changed the password");
        client.query_client().exec("UPDATE auth_user SET email = $email WHERE id = $id")
            .param("$email", format!("rust-password-{stamp}@example.invalid"))
            .param("$id", user_id).await?;
        client.query_client().exec("INSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $user, 'totp', Unwrap(CAST('{}' AS Json)), CAST($now AS Datetime))")
            .param("$id", mfa_id).param("$user", user_id).param("$now", now).await?;
        let (status, _) = change(&app, Some(&token), None, false, current, new).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "MFA-unproven session changed password");
        client.query_client().exec("DELETE FROM mfa_authenticator WHERE id = $id").param("$id", mfa_id).await?;
        let ((first_status, first_body), (second_status, second_body)) = tokio::try_join!(
            change(&app, Some(&token), None, false, current, new),
            change(&app, Some(&other), None, false, current, new),
        )?;
        let successes = usize::from(first_status == StatusCode::OK) + usize::from(second_status == StatusCode::OK);
        ensure!(successes == 1, "concurrent password changes: {first_status} {first_body}; {second_status} {second_body}");
        let loser = if first_status == StatusCode::OK { second_status } else { first_status };
        ensure!(matches!(loser, StatusCode::UNAUTHORIZED | StatusCode::CONFLICT), "unexpected concurrent result: {loser}");
        let (status, _) = change(&app, Some(&token), None, false, current, "another strong passphrase").await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "old session survived password change");
        let mut row = client.query_client().query_row("SELECT password FROM auth_user WHERE id = $id").param("$id", user_id).await?;
        let changed: String = row.remove_field_by_name("password")?.try_into()?;
        ensure!(id_compat::password::verify(new, &changed)?);
        ensure!(!id_compat::password::verify(current, &changed)?);
        let mut row = client.query_client().query_row("SELECT revoked_at FROM core_usersessionmeta WHERE id = $id").param("$id", metadata_id).await?;
        let revoked: Option<SystemTime> = row.remove_field_by_name("revoked_at")?.try_into()?;
        ensure!(revoked.is_some(), "session metadata was not revoked");
        let mut row = client.query_client().query_row("SELECT revoked_at FROM core_usersessiontoken WHERE id = $id").param("$id", mapping_id).await?;
        let revoked: Option<SystemTime> = row.remove_field_by_name("revoked_at")?.try_into()?;
        ensure!(revoked.is_some(), "refresh mapping was not revoked");
        let row = client.query_client().query_row("SELECT session_key FROM django_session WHERE session_key = $key").param("$key", other.clone()).optional().await?;
        ensure!(row.is_none(), "second session survived password change");
        let mut row = client.query_client().query_row("SELECT revoked_at FROM idp_oidctoken WHERE id = $id").param("$id", oidc_token_id).await?;
        let revoked: Option<SystemTime> = row.remove_field_by_name("revoked_at")?.try_into()?;
        ensure!(revoked.is_some(), "OIDC token was not revoked");
        let mut row = client.query_client().query_row("SELECT used_at FROM idp_oidcauthorizationcode WHERE code = $code").param("$code", oidc_code.clone()).await?;
        let used: Option<SystemTime> = row.remove_field_by_name("used_at")?.try_into()?;
        ensure!(used.is_some(), "pending OIDC code was not consumed");
        let row = client.query_client().query_row("SELECT request_id FROM idp_oidcauthorizationrequest WHERE request_id = $id").param("$id", oidc_request.clone()).optional().await?;
        ensure!(row.is_none(), "pending OIDC request survived password change");
        let mut query_client = client.query_client();
        let mut mail = query_client.query("SELECT id, status, recipient, kind FROM id_security_mail WHERE user_id = $user_id")
            .param("$user_id", user_id).await?;
        let mut intents = Vec::new();
        while let Some(set) = mail.next_result_set().await? {
            for mut row in set {
                let id: String = row.remove_field_by_name("id")?.try_into()?;
                let status: String = row.remove_field_by_name("status")?.try_into()?;
                let recipient: String = row.remove_field_by_name("recipient")?.try_into()?;
                let kind: String = row.remove_field_by_name("kind")?.try_into()?;
                intents.push((id, status, recipient, kind));
            }
        }
        mail.close().await?;
        ensure!(intents.len() == 1, "concurrent password changes created {} mail intents", intents.len());
        ensure!(intents[0].1 == "pending" && intents[0].2 == format!("rust-password-{stamp}@example.invalid") && intents[0].3 == "password_changed");
        Ok(())
    }.await;
    let mut query_client = client.query_client();
    let mut mail = query_client
        .query("SELECT id FROM id_security_mail WHERE user_id = $user_id")
        .param("$user_id", user_id)
        .await?;
    let mut mail_ids: Vec<String> = Vec::new();
    while let Some(set) = mail.next_result_set().await? {
        for mut row in set {
            mail_ids.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    mail.close().await?;
    for id in mail_ids {
        client
            .query_client()
            .exec("DELETE FROM id_security_mail WHERE id = $id")
            .param("$id", id)
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM core_usersessiontoken WHERE id = $id")
        .param("$id", mapping_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM core_usersessionmeta WHERE id = $id")
        .param("$id", metadata_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM mfa_authenticator WHERE id = $id")
        .param("$id", mfa_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM idp_oidctoken WHERE id = $id")
        .param("$id", oidc_token_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM idp_oidcauthorizationcode WHERE code = $code")
        .param("$code", oidc_code)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM idp_oidcauthorizationrequest WHERE request_id = $id")
        .param("$id", oidc_request)
        .await?;
    for key in [&token, &other] {
        client
            .query_client()
            .exec("DELETE FROM django_session WHERE session_key = $key")
            .param("$key", key.clone())
            .await?;
    }
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
        .exec("DELETE FROM auth_user WHERE id = $id")
        .param("$id", user_id)
        .await?;
    result
}
