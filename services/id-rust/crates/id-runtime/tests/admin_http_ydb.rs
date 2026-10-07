#![recursion_limit = "256"]
//! Authorization and privacy contract for the first operator HTTP route.

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

const BACKEND: &str = "django.contrib.auth.backends.ModelBackend";

async fn get(
    app: &Router,
    path: &str,
    cookie: Option<&str>,
    header_token: Option<&str>,
) -> Result<(StatusCode, Value)> {
    let mut request = Request::builder().uri(path).method("GET");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    if let Some(token) = header_token {
        request = request.header("x-session-token", token);
    }
    let response = app.clone().oneshot(request.body(Body::empty())?).await?;
    ensure!(response.headers()[header::CACHE_CONTROL] == "no-store");
    let status = response.status();
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 16 * 1024).await?)?;
    Ok((status, body))
}

#[tokio::test]
#[ignore = "requires disposable local YDB on port 2137"]
async fn operator_lookup_requires_role_and_bound_mfa() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2137" | "grpc://127.0.0.1:2137"
        ) && std::env::var("YDB_DATABASE")? == "/local"
            && std::env::var("ID_DISPOSABLE_YDB")? == "true"
            && std::env::var("ID_AUTH_ADMIN_READ_ENABLED")? == "true",
        "operator HTTP test requires disposable YDB and explicit opt-in"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    let config = id_runtime::admin_http::AdminReadConfig::from_env(client.clone())?
        .context("operator route not enabled")?;
    let app = id_runtime::admin_http::router(config);
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let account_id = -i32::try_from(stamp % 1_000_000_000 + 1)?;
    let target_id = 1_500_000_000 + i32::try_from(stamp % 500_000_000)?;
    let target_email = format!("target-test-{stamp}@example.invalid");
    let email_id = target_id - 1_000_000_000;
    let deletion_id = i64::try_from(stamp % 1_000_000_000_000 + 1)?;
    let identity_id = Uuid::from_u128((stamp << 32) | u128::from(std::process::id()));
    let target_identity_id = Uuid::from_u128(identity_id.as_u128() + 1);
    let token = format!("admin-test-{stamp}");
    let secret = std::env::var("DJANGO_SECRET_KEY")?;
    let codec = SessionCodec::new(secret.as_bytes(), &[])?;
    let password = "pbkdf2_sha256$1000000$synthetic$synthetic";
    let now = SystemTime::now();
    let payload = json!({
        "_auth_user_id": account_id.to_string(),
        "_auth_user_backend": BACKEND,
        "_auth_user_hash": codec.auth_hash(password)?,
        "id_mfa_verified_user_id": account_id.to_string(),
    });
    let encoded = codec.encode(
        payload
            .as_object()
            .context("session payload is not an object")?,
        i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?,
        true,
    )?;
    client.query_client().exec("INSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $password, true, $name, '', '', $email, false, false, CurrentUtcDatetime())")
        .param("$id", account_id).param("$password", password)
        .param("$name", format!("admin-test-{stamp}"))
        .param("$email", format!("admin-test-{stamp}@example.invalid")).await?;
    let result: Result<()> = async {
        client.query_client().exec("INSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, $name, $name, $email, true, 'active', false, CurrentUtcDatetime())")
            .param("$id", identity_id).param("$name", format!("admin-test-{stamp}"))
            .param("$email", format!("admin-test-{stamp}@example.invalid")).await?;
        client.query_client().exec("INSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($user, $identity, $subject, CurrentUtcDatetime())")
            .param("$user", account_id).param("$identity", identity_id)
            .param("$subject", format!("admin-test-subject-{stamp}")).await?;
        client.query_client().exec("INSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $password, false, $name, '', '', $email, false, false, CurrentUtcDatetime())")
            .param("$id", target_id).param("$password", password)
            .param("$name", format!("target-test-{stamp}"))
            .param("$email", target_email.clone()).await?;
        client.query_client().exec("INSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($user, $identity, $subject, CurrentUtcDatetime())")
            .param("$user", target_id).param("$identity", target_identity_id)
            .param("$subject", format!("target-subject-{stamp}")).await?;
        client.query_client().exec("INSERT INTO accounts_accountemaillookup (user_id, email_key) VALUES ($id, $email)")
            .param("$id", target_id).param("$email", target_email.clone()).await?;
        client.query_client().exec("INSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($id, $user_id, $email, true, true)")
            .param("$id", email_id).param("$user_id", target_id)
            .param("$email", target_email.clone()).await?;
        client.query_client().exec("INSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, $data, CAST($expires AS Datetime))")
            .param("$key", token.clone()).param("$data", encoded)
            .param("$expires", now + Duration::from_secs(3600)).await?;
        client.query_client().exec("INSERT INTO accounts_accountdeletionrequest (id, user_id, status, requested_at, reason) VALUES ($id, $user, 'pending', CurrentUtcDatetime(), 'private test reason')")
            .param("$id", deletion_id).param("$user", target_id).await?;

        let path = format!("/api/v1/auth/admin/deletions/{deletion_id}");
        let account_path = format!("/api/v1/auth/admin/accounts/{target_id}");
        let email_path = format!("/api/v1/auth/admin/accounts/search?email={target_email}");
        let cookie = format!("sessionid={token}");
        let (status, _) = get(&app, &path, None, None).await?;
        ensure!(status == StatusCode::UNAUTHORIZED);
        let (status, _) = get(&app, &path, Some(&cookie), None).await?;
        ensure!(status == StatusCode::FORBIDDEN);
        let (status, _) = get(&app, &account_path, Some(&cookie), None).await?;
        ensure!(status == StatusCode::FORBIDDEN);
        let (status, _) = get(&app, &email_path, Some(&cookie), None).await?;
        ensure!(status == StatusCode::FORBIDDEN);
        client.query_client().exec("UPDATE auth_user SET is_staff = true WHERE id = $id")
            .param("$id", account_id).await?;
        let (status, _) = get(&app, &path, Some(&cookie), None).await?;
        ensure!(status == StatusCode::FORBIDDEN);
        client.query_client().exec("UPDATE auth_user SET is_superuser = true WHERE id = $id")
            .param("$id", account_id).await?;
        let (status, _) = get(&app, &path, Some(&cookie), None).await?;
        ensure!(status == StatusCode::FORBIDDEN, "operator was accepted without MFA");
        client.query_client().exec("INSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $user, 'totp', Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime())")
            .param("$id", i64::from(account_id)).param("$user", account_id).await?;
        let (status, body) = get(&app, "/api/v1/auth/admin/me", Some(&cookie), None).await?;
        ensure!(status == StatusCode::OK && body == json!({"operator":true}));
        let (status, body) = get(&app, &path, Some(&cookie), None).await?;
        ensure!(status == StatusCode::OK && body["operation"]["status"] == "pending");
        ensure!(body["operation"]["cleanup_completed"] == false);
        ensure!(!body.to_string().contains("private test reason") && !body.to_string().contains("admin-test-"));
        let (status, body) = get(&app, &account_path, Some(&cookie), None).await?;
        ensure!(status == StatusCode::OK && body["account"]["id"] == target_id
            && body["account"]["is_active"] == false
            && body["account"]["identity_id"] == target_identity_id.to_string()
            && body["account"]["public_subject"] == format!("target-subject-{stamp}")
            && body["account"]["has_mfa"] == false, "operator account lookup: {body}");
        ensure!(!body.to_string().contains(password), "password hash exposed to operator UI");
        let (status, body) = get(&app, &email_path, Some(&cookie), None).await?;
        ensure!(status == StatusCode::OK && body["account"]["id"] == target_id,
            "verified email lookup: {body}");
        let (status, _) = get(&app, &email_path, Some(&cookie), Some("invalid")).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "invalid header fell back to cookie for email lookup");
        let (status, _) = get(&app, "/api/v1/auth/admin/accounts/search?email=bad", Some(&cookie), None).await?;
        ensure!(status == StatusCode::BAD_REQUEST);
        client.query_client().exec("UPDATE account_emailaddress SET verified = false WHERE id = $id")
            .param("$id", email_id).await?;
        let (status, _) = get(&app, &email_path, Some(&cookie), None).await?;
        ensure!(status == StatusCode::NOT_FOUND, "unverified email returned an account");
        client.query_client().exec("UPDATE account_emailaddress SET verified = true WHERE id = $id")
            .param("$id", email_id).await?;
        client.query_client().exec("INSERT INTO accounts_accountemaillookup (user_id, email_key) VALUES ($id, $email)")
            .param("$id", target_id + 1).param("$email", target_email.clone()).await?;
        let (status, body) = get(&app, &email_path, Some(&cookie), None).await?;
        ensure!(status == StatusCode::CONFLICT && body["code"] == "ACCOUNT_EMAIL_AMBIGUOUS",
            "ambiguous email selected an account: {body}");
        let (status, _) = get(&app, &account_path, Some(&cookie), Some("invalid")).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "invalid header fell back to cookie for account lookup");
        let (status, _) = get(&app, "/api/v1/auth/admin/accounts/0", Some(&cookie), None).await?;
        ensure!(status == StatusCode::BAD_REQUEST);
        let (status, _) = get(&app, "/api/v1/auth/admin/accounts/2147483648", Some(&cookie), None).await?;
        ensure!(status == StatusCode::BAD_REQUEST);
        let (status, _) = get(&app, "/api/v1/auth/admin/accounts/2147483647", Some(&cookie), None).await?;
        ensure!(status == StatusCode::NOT_FOUND);
        let (status, _) = get(&app, &path, Some(&cookie), Some("invalid")).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "invalid header fell back to cookie");
        let (status, _) = get(&app, "/api/v1/auth/admin/deletions/0", Some(&cookie), None).await?;
        ensure!(status == StatusCode::BAD_REQUEST);
        let (status, _) = get(&app, "/api/v1/auth/admin/deletions/999999999999999999", Some(&cookie), None).await?;
        ensure!(status == StatusCode::NOT_FOUND);
        client.query_client().exec("UPDATE auth_user SET is_active = false WHERE id = $id")
            .param("$id", account_id).await?;
        let (status, _) = get(&app, &path, Some(&cookie), None).await?;
        ensure!(status == StatusCode::UNAUTHORIZED);
        Ok(())
    }.await;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountdeletionrequest WHERE id = $id")
        .param("$id", deletion_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM mfa_authenticator WHERE id = $id")
        .param("$id", i64::from(account_id))
        .await?;
    client
        .query_client()
        .exec("DELETE FROM django_session WHERE session_key = $key")
        .param("$key", token)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountidentity WHERE user_id = $id")
        .param("$id", account_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountidentity WHERE user_id = $id")
        .param("$id", target_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountemaillookup WHERE user_id = $id")
        .param("$id", target_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountemaillookup WHERE user_id = $id")
        .param("$id", target_id + 1)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM account_emailaddress WHERE id = $id")
        .param("$id", email_id)
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
        .exec("DELETE FROM auth_user WHERE id = $id")
        .param("$id", target_id)
        .await?;
    result
}
