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

async fn search_email(
    app: &Router,
    cookie: Option<&str>,
    header_token: Option<&str>,
    email: &str,
) -> Result<(StatusCode, Value)> {
    let mut request = Request::builder()
        .uri("/api/v1/auth/admin/accounts/search")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    if let Some(token) = header_token {
        request = request.header("x-session-token", token);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(json!({"email":email}).to_string()))?)
        .await?;
    ensure!(response.headers()[header::CACHE_CONTROL] == "no-store");
    let status = response.status();
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 16 * 1024).await?)?;
    Ok((status, body))
}

async fn search_client(
    app: &Router,
    cookie: Option<&str>,
    header_token: Option<&str>,
    client_id: &str,
) -> Result<(StatusCode, Value)> {
    let mut request = Request::builder()
        .uri("/api/v1/auth/admin/clients/search")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    if let Some(token) = header_token {
        request = request.header("x-session-token", token);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(json!({"client_id":client_id}).to_string()))?)
        .await?;
    ensure!(response.headers()[header::CACHE_CONTROL] == "no-store");
    let status = response.status();
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 16 * 1024).await?)?;
    Ok((status, body))
}

async fn edit_client_redirects(
    app: &Router,
    cookie: &str,
    csrf: Option<&str>,
    client_id: &str,
    revision: &str,
    redirects: Value,
    password: &str,
) -> Result<(StatusCode, Value)> {
    let mut request = Request::builder()
        .uri("/api/v1/auth/admin/clients/redirects")
        .method("POST")
        .header(header::COOKIE, cookie)
        .header(header::ORIGIN, "http://id.localhost")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(csrf) = csrf {
        request = request.header("x-csrftoken", csrf);
    }
    let response = app
        .clone()
        .oneshot(
            request.body(Body::from(
                json!({
                    "client_id": client_id, "expected_revision": revision,
                    "redirect_uris": redirects, "current_password": password,
                })
                .to_string(),
            ))?,
        )
        .await?;
    ensure!(response.headers()[header::CACHE_CONTROL] == "no-store");
    let status = response.status();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 16 * 1024).await?)?;
    Ok((status, body))
}

async fn suspend(
    app: &Router,
    target_id: i32,
    cookie: &str,
    csrf: Option<&str>,
    subject: &str,
    password: &str,
) -> Result<(StatusCode, Value)> {
    let mut request = Request::builder()
        .uri(format!("/api/v1/auth/admin/accounts/{target_id}/suspend"))
        .method("POST")
        .header(header::COOKIE, cookie)
        .header(header::ORIGIN, "http://id.localhost")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(csrf) = csrf {
        request = request.header("x-csrftoken", csrf);
    }
    let response = app
        .clone()
        .oneshot(
            request.body(Body::from(
                json!({
                    "expected_subject": subject,
                    "current_password": password,
                    "reason": "security_incident",
                })
                .to_string(),
            ))?,
        )
        .await?;
    ensure!(response.headers()[header::CACHE_CONTROL] == "no-store");
    let status = response.status();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 16 * 1024).await?)?;
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
            && std::env::var("ID_AUTH_ADMIN_READ_ENABLED")? == "true"
            && std::env::var("ID_AUTH_ADMIN_SUSPEND_ENABLED")? == "true"
            && std::env::var("ID_AUTH_ADMIN_CLIENT_REDIRECTS_ENABLED")? == "true",
        "operator HTTP test requires disposable YDB and explicit opt-in"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    let config = id_runtime::admin_http::AdminReadConfig::from_env(client.clone())?
        .context("operator route not enabled")?;
    let app = id_runtime::admin_http::router(config);
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let account_id = 1_000_000_000 + i32::try_from(stamp % 400_000_000)?;
    let target_id = 1_500_000_000 + i32::try_from(stamp % 400_000_000)?;
    let target_email = format!("target-test-{stamp}@example.invalid");
    let email_id = target_id - 1_000_000_000;
    let deletion_id = i64::try_from(stamp % 1_000_000_000_000 + 1)?;
    let export_id = format!("{stamp:032x}");
    let oidc_client_id = format!("operator-client-{stamp}");
    let oidc_row_id = i64::try_from(stamp)?;
    let identity_id = Uuid::from_u128((stamp << 32) | u128::from(std::process::id()));
    let target_identity_id = Uuid::from_u128(identity_id.as_u128() + 1);
    let token = format!("admin-test-{stamp}");
    let secret = std::env::var("DJANGO_SECRET_KEY")?;
    let codec = SessionCodec::new(secret.as_bytes(), &[])?;
    let password =
        tokio::task::spawn_blocking(|| id_compat::password::hash_new("admin-test-password"))
            .await??;
    let now = SystemTime::now();
    let payload = json!({
        "_auth_user_id": account_id.to_string(),
        "_auth_user_backend": BACKEND,
        "_auth_user_hash": codec.auth_hash(&password)?,
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
        .param("$id", account_id).param("$password", password.clone())
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
            .param("$id", target_id).param("$password", password.clone())
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
        client.query_client().exec("INSERT INTO id_data_export_operation (id, user_id, status, attempts, next_attempt_at, claim_token, object_key, manifest, created_at) VALUES ($id, 0, 'cooldown', 1, CurrentUtcDatetime(), '', '', '', CurrentUtcDatetime())")
            .param("$id", export_id.clone()).await?;
        client.query_client().exec("INSERT INTO id_data_export_escrow (id, user_id, encrypted_email, state, release_at, expires_at, object_key, manifest, notice_state, delivery_state, created_at) VALUES ($id, 0, 'private-recipient-envelope', 'sealed', CAST($release AS Datetime), CAST($expiry AS Datetime), 'exports/escrow/private-archive', '{}', 'sent', 'pending', CurrentUtcDatetime())")
            .param("$id", export_id.clone())
            .param("$release", now + Duration::from_secs(86400))
            .param("$expiry", now + Duration::from_secs(172800)).await?;
        client.query_client().exec("INSERT INTO idp_oidcclient (id, client_id, client_secret_hash, name, description, logo_url, redirect_uris, allowed_scopes, grant_types, response_types, is_public, is_first_party, created_at, updated_at) VALUES ($id, $client_id, 'never-expose-this-secret-hash', '<script>client</script>', 'Test service', '', Unwrap(CAST($redirects AS Json)), Unwrap(CAST('[\"openid\"]' AS Json)), Unwrap(CAST('[\"authorization_code\"]' AS Json)), Unwrap(CAST('[\"code\"]' AS Json)), true, false, CurrentUtcDatetime(), CurrentUtcDatetime())")
            .param("$id", oidc_row_id).param("$client_id", oidc_client_id.clone())
            .param("$redirects", json!(["https://client.example.invalid/callback?x=<script>"]).to_string()).await?;

        let path = format!("/api/v1/auth/admin/deletions/{deletion_id}");
        let export_path = format!("/api/v1/auth/admin/exports/{export_id}");
        let account_path = format!("/api/v1/auth/admin/accounts/{target_id}");
        let cookie = format!("sessionid={token}");
        let (status, _) = get(&app, &path, None, None).await?;
        ensure!(status == StatusCode::UNAUTHORIZED);
        let (status, _) = get(&app, &export_path, None, None).await?;
        ensure!(status == StatusCode::UNAUTHORIZED);
        let (status, _) = get(&app, &path, Some(&cookie), None).await?;
        ensure!(status == StatusCode::FORBIDDEN);
        let (status, _) = get(&app, &export_path, Some(&cookie), None).await?;
        ensure!(status == StatusCode::FORBIDDEN);
        let (status, _) = get(&app, &account_path, Some(&cookie), None).await?;
        ensure!(status == StatusCode::FORBIDDEN);
        let (status, _) = search_email(&app, Some(&cookie), None, &target_email).await?;
        ensure!(status == StatusCode::FORBIDDEN);
        let (status, _) = search_client(&app, Some(&cookie), None, &oidc_client_id).await?;
        ensure!(status == StatusCode::FORBIDDEN);
        client.query_client().exec("UPDATE auth_user SET is_staff = true WHERE id = $id")
            .param("$id", account_id).await?;
        let (status, _) = get(&app, &path, Some(&cookie), None).await?;
        ensure!(status == StatusCode::FORBIDDEN);
        client.query_client().exec("UPDATE auth_user SET is_superuser = true WHERE id = $id")
            .param("$id", account_id).await?;
        let (status, _) = get(&app, &path, Some(&cookie), None).await?;
        ensure!(status == StatusCode::FORBIDDEN, "operator was accepted without MFA");
        let csrf = "abcdefghijklmnopqrstuvwxyzABCDEF";
        let csrf_cookie = format!("{cookie}; csrftoken={csrf}");
        let (status, body) = suspend(&app, target_id, &csrf_cookie, Some(csrf),
            &format!("target-subject-{stamp}"), "admin-test-password").await?;
        ensure!(status == StatusCode::FORBIDDEN && body["code"] == "OPERATOR_ACCESS_REQUIRED",
            "operator suspension accepted without bound MFA: {body}");
        client.query_client().exec("INSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $user, 'totp', Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime())")
            .param("$id", i64::from(account_id)).param("$user", account_id).await?;
        let (status, body) = get(&app, "/api/v1/auth/admin/me", Some(&cookie), None).await?;
        ensure!(status == StatusCode::OK && body == json!({"operator":true}));
        let (status, body) = search_client(&app, Some(&cookie), None, &oidc_client_id).await?;
        ensure!(status == StatusCode::OK && body["client"]["client_id"] == oidc_client_id
            && body["client"]["name"] == "<script>client</script>"
            && body["client"]["redirect_uris"][0] == "https://client.example.invalid/callback?x=<script>"
            && body["client"]["is_public"] == true,
            "operator client lookup: {body}");
        ensure!(!body.to_string().contains("never-expose-this-secret-hash"), "OIDC secret hash exposed");
        let revision = body["client"]["redirect_revision"].as_str().context("client redirect revision")?.to_owned();
        ensure!(revision.len() == 64, "client revision missing");
        client.query_client().exec("INSERT INTO idp_oidcclient (id, client_id, client_secret_hash, name, description, logo_url, redirect_uris, allowed_scopes, grant_types, response_types, is_public, is_first_party, created_at, updated_at) VALUES ($id, $client_id, 'second-private-secret', 'Duplicate', '', '', Unwrap(CAST('[]' AS Json)), Unwrap(CAST('[]' AS Json)), Unwrap(CAST('[]' AS Json)), Unwrap(CAST('[]' AS Json)), true, false, CurrentUtcDatetime(), CurrentUtcDatetime())")
            .param("$id", oidc_row_id + 1).param("$client_id", oidc_client_id.clone()).await?;
        let (status, body) = search_client(&app, Some(&cookie), None, &oidc_client_id).await?;
        ensure!(status == StatusCode::CONFLICT && body["code"] == "CLIENT_ID_AMBIGUOUS",
            "duplicate OIDC client was selected: {body}");
        client.query_client().exec("DELETE FROM idp_oidcclient WHERE id = $id")
            .param("$id", oidc_row_id + 1).await?;
        let (status, _) = search_client(&app, Some(&cookie), Some("invalid"), &oidc_client_id).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "invalid header fell back to cookie for client lookup");
        let (status, _) = search_client(&app, Some(&cookie), None, "bad\nclient").await?;
        ensure!(status == StatusCode::BAD_REQUEST);
        let (status, _) = search_client(&app, Some(&cookie), None, "missing-client").await?;
        ensure!(status == StatusCode::NOT_FOUND);
        let changed = json!(["https://new.example.invalid/callback"]);
        let (status, body) = edit_client_redirects(&app, &csrf_cookie, None, &oidc_client_id,
            &revision, changed.clone(), "admin-test-password").await?;
        ensure!(status == StatusCode::FORBIDDEN && body["code"] == "CSRF_FAILED");
        let (status, body) = edit_client_redirects(&app, &csrf_cookie, Some(csrf), &oidc_client_id,
            &revision, json!(["http://evil.example.invalid/callback"]), "admin-test-password").await?;
        ensure!(status == StatusCode::BAD_REQUEST && body["code"] == "INVALID_REDIRECT_UPDATE");
        let (status, body) = edit_client_redirects(&app, &csrf_cookie, Some(csrf), &oidc_client_id,
            &revision, changed.clone(), "wrong-password").await?;
        ensure!(status == StatusCode::BAD_REQUEST && body["code"] == "INVALID_PASSWORD");
        let (status, body) = edit_client_redirects(&app, &csrf_cookie, Some(csrf), &oidc_client_id,
            &revision, changed.clone(), "admin-test-password").await?;
        ensure!(status == StatusCode::OK && body["status"] == "updated"
            && body["redirect_revision"].as_str().is_some_and(|value| value != revision),
            "OIDC redirect edit failed: {body}");
        let updated_revision = body["redirect_revision"].as_str().context("updated redirect revision")?.to_owned();
        let (status, client_after) = search_client(&app, Some(&cookie), None, &oidc_client_id).await?;
        ensure!(status == StatusCode::OK && client_after["client"]["redirect_uris"] == changed
            && client_after["client"]["redirect_revision"] == body["redirect_revision"],
            "OIDC redirect edit not visible: {client_after}");
        let (status, body) = edit_client_redirects(&app, &csrf_cookie, Some(csrf), &oidc_client_id,
            &revision, json!(["https://another.example.invalid/callback"]), "admin-test-password").await?;
        ensure!(status == StatusCode::CONFLICT && body["code"] == "REVIEW_STALE",
            "stale OIDC redirect edit was accepted: {body}");
        let mut audit = client.query_client().query_row("SELECT CAST(meta_json AS Utf8) AS meta FROM usid_audit_log WHERE action = 'oidc_client.redirects_updated' AND target_id = $id LIMIT 1")
            .param("$id", oidc_client_id.clone()).await?;
        let meta: String = audit.remove_field_by_name("meta")?.try_into()?;
        ensure!(meta.contains("new_revision") && !meta.contains("new.example.invalid")
            && !meta.contains("admin-test-password"), "OIDC redirect audit exposes private input");
        let mut concurrent = tokio::task::JoinSet::new();
        for uri in ["https://one.example.invalid/callback", "https://two.example.invalid/callback"] {
            let app = app.clone();
            let cookie = csrf_cookie.clone();
            let client_id = oidc_client_id.clone();
            let revision = updated_revision.clone();
            let csrf = csrf.to_owned();
            concurrent.spawn(async move {
                edit_client_redirects(&app, &cookie, Some(&csrf), &client_id, &revision,
                    json!([uri]), "admin-test-password").await
            });
        }
        let mut statuses = Vec::new();
        while let Some(result) = concurrent.join_next().await {
            statuses.push(result??.0);
        }
        statuses.sort();
        ensure!(statuses == [StatusCode::OK, StatusCode::CONFLICT],
            "concurrent redirect changes did not serialize: {statuses:?}");
        let url_search = Request::builder().uri(format!("/api/v1/auth/admin/clients/search?client_id={oidc_client_id}"))
            .method("GET").header(header::COOKIE, &cookie).body(Body::empty())?;
        ensure!(app.clone().oneshot(url_search).await?.status() == StatusCode::METHOD_NOT_ALLOWED,
            "client lookup exposed through GET URL");
        let (status, body) = get(&app, &path, Some(&cookie), None).await?;
        ensure!(status == StatusCode::OK && body["operation"]["status"] == "pending");
        ensure!(body["operation"]["cleanup_completed"] == false);
        ensure!(!body.to_string().contains("private test reason") && !body.to_string().contains("admin-test-"));
        let (status, body) = get(&app, &export_path, Some(&cookie), None).await?;
        ensure!(status == StatusCode::OK
            && body["operation"]["id"] == export_id
            && body["operation"]["status"] == "cooldown"
            && body["operation"]["escrow_state"] == "sealed"
            && body["operation"]["archive_sealed"] == true
            && body["operation"]["release_at"].as_u64().is_some()
            && body["operation"]["expires_at"].as_u64().is_some(),
            "operator export lifecycle: {body}");
        ensure!(!body.to_string().contains("private-recipient-envelope")
            && !body.to_string().contains("private-archive")
            && !body.to_string().contains("manifest"),
            "operator export response leaked private data");
        client.query_client().exec("UPDATE id_data_export_escrow SET delivery_state = 'sent', release_at = CAST($release AS Datetime) WHERE id = $id")
            .param("$id", export_id.clone())
            .param("$release", now - Duration::from_secs(1)).await?;
        let (status, body) = get(&app, &export_path, Some(&cookie), None).await?;
        ensure!(status == StatusCode::OK && body["operation"]["status"] == "ready",
            "delivered export still looked in cooldown: {body}");
        let (status, _) = get(&app, &export_path, Some(&cookie), Some("invalid")).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "invalid header fell back to cookie for export lookup");
        let (status, _) = get(&app, "/api/v1/auth/admin/exports/bad", Some(&cookie), None).await?;
        ensure!(status == StatusCode::BAD_REQUEST);
        let (status, _) = get(&app, "/api/v1/auth/admin/exports/00000000000000000000000000000000", Some(&cookie), None).await?;
        ensure!(status == StatusCode::NOT_FOUND);
        let (status, body) = get(&app, &account_path, Some(&cookie), None).await?;
        ensure!(status == StatusCode::OK && body["account"]["id"] == target_id
            && body["account"]["is_active"] == false
            && body["account"]["access_state"] == "deletion_pending"
            && body["account"]["identity_id"] == target_identity_id.to_string()
            && body["account"]["public_subject"] == format!("target-subject-{stamp}")
            && body["account"]["has_mfa"] == false, "operator account lookup: {body}");
        ensure!(!body.to_string().contains(password.as_str()), "password hash exposed to operator UI");
        client.query_client().exec("DELETE FROM accounts_accountdeletionrequest WHERE id = $id")
            .param("$id", deletion_id).await?;
        let (_, body) = get(&app, &account_path, Some(&cookie), None).await?;
        ensure!(body["account"]["access_state"] == "account_disabled");
        client.query_client().exec("UPDATE auth_user SET is_active = true WHERE id = $id")
            .param("$id", target_id).await?;
        let (_, body) = get(&app, &account_path, Some(&cookie), None).await?;
        ensure!(body["account"]["access_state"] == "needs_review", "missing identity allowed: {body}");
        client.query_client().exec("INSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, $name, $name, $email, true, 'active', false, CurrentUtcDatetime())")
            .param("$id", target_identity_id).param("$name", format!("target-test-{stamp}"))
            .param("$email", target_email.clone()).await?;
        let (_, body) = get(&app, &account_path, Some(&cookie), None).await?;
        ensure!(body["account"]["access_state"] == "active", "active identity misreported: {body}");
        client.query_client().exec("UPDATE usid_user SET status = 'suspended' WHERE user_id = $id")
            .param("$id", target_identity_id).await?;
        let (_, body) = get(&app, &account_path, Some(&cookie), None).await?;
        ensure!(body["account"]["access_state"] == "identity_inactive", "suspended identity misreported: {body}");
        client.query_client().exec("INSERT INTO accounts_accountdeletionrequest (id, user_id, status, requested_at, reason) VALUES ($id, $user, 'pending', CurrentUtcDatetime(), 'private test reason')")
            .param("$id", deletion_id).param("$user", target_id).await?;
        let (status, body) = search_email(&app, Some(&cookie), None, &target_email).await?;
        ensure!(status == StatusCode::OK && body["account"]["id"] == target_id,
            "verified email lookup: {body}");
        let (status, _) = search_email(&app, Some(&cookie), Some("invalid"), &target_email).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "invalid header fell back to cookie for email lookup");
        let (status, _) = search_email(&app, Some(&cookie), None, "bad").await?;
        ensure!(status == StatusCode::BAD_REQUEST);
        let url_search = Request::builder()
            .uri("/api/v1/auth/admin/accounts/search?email=bad")
            .method("GET")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())?;
        let response = app.clone().oneshot(url_search).await?;
        ensure!(response.status() == StatusCode::METHOD_NOT_ALLOWED, "email search leaked into URL");
        client.query_client().exec("UPDATE account_emailaddress SET verified = false WHERE id = $id")
            .param("$id", email_id).await?;
        let (status, _) = search_email(&app, Some(&cookie), None, &target_email).await?;
        ensure!(status == StatusCode::NOT_FOUND, "unverified email returned an account");
        client.query_client().exec("UPDATE account_emailaddress SET verified = true WHERE id = $id")
            .param("$id", email_id).await?;
        client.query_client().exec("INSERT INTO accounts_accountemaillookup (user_id, email_key) VALUES ($id, $email)")
            .param("$id", target_id + 1).param("$email", target_email.clone()).await?;
        let (status, body) = search_email(&app, Some(&cookie), None, &target_email).await?;
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
        client.query_client().exec("DELETE FROM accounts_accountdeletionrequest WHERE id = $id")
            .param("$id", deletion_id).await?;
        client.query_client().exec("UPDATE usid_user SET status = 'active' WHERE user_id = $id")
            .param("$id", target_identity_id).await?;
        let target_token = format!("target-session-{stamp}");
        let target_payload = json!({
            "_auth_user_id": target_id.to_string(),
            "_auth_user_backend": BACKEND,
            "_auth_user_hash": codec.auth_hash(&password)?,
        });
        let target_encoded = codec.encode(target_payload.as_object().context("target session payload")?,
            i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?, true)?;
        client.query_client().exec("INSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, $data, CAST($expires AS Datetime))")
            .param("$key", target_token.clone()).param("$data", target_encoded)
            .param("$expires", now + Duration::from_secs(3600)).await?;
        let target_meta_id = i64::from(target_id) + 1_000_000_000;
        client.query_client().exec("INSERT INTO core_usersessionmeta (id, user_id, session_key, user_agent, first_seen, revoked_reason) VALUES ($id, $user, $key, '', CAST($now AS Datetime), '')")
            .param("$id", target_meta_id).param("$user", target_id)
            .param("$key", target_token.clone()).param("$now", now).await?;
        let subject = format!("target-subject-{stamp}");
        let (status, body) = suspend(&app, target_id, &csrf_cookie, None, &subject, "admin-test-password").await?;
        ensure!(status == StatusCode::FORBIDDEN && body["code"] == "CSRF_FAILED");
        let (status, body) = suspend(&app, target_id, &csrf_cookie, Some(csrf), &subject, "wrong-password").await?;
        ensure!(status == StatusCode::BAD_REQUEST && body["code"] == "INVALID_PASSWORD");
        let (status, body) = suspend(&app, account_id, &csrf_cookie, Some(csrf), &subject, "admin-test-password").await?;
        ensure!(status == StatusCode::FORBIDDEN && body["code"] == "SELF_SUSPENSION_FORBIDDEN");
        client.query_client().exec("UPDATE auth_user SET is_staff = true WHERE id = $id")
            .param("$id", target_id).await?;
        let (status, body) = suspend(&app, target_id, &csrf_cookie, Some(csrf), &subject, "admin-test-password").await?;
        ensure!(status == StatusCode::FORBIDDEN && body["code"] == "PROTECTED_ACCOUNT");
        client.query_client().exec("UPDATE auth_user SET is_staff = false WHERE id = $id")
            .param("$id", target_id).await?;
        client.query_client().exec("INSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($user, $identity, $subject, CurrentUtcDatetime())")
            .param("$user", target_id + 1).param("$identity", target_identity_id)
            .param("$subject", format!("other-subject-{stamp}")).await?;
        let (status, body) = suspend(&app, target_id, &csrf_cookie, Some(csrf), &subject, "admin-test-password").await?;
        ensure!(status == StatusCode::CONFLICT && body["code"] == "REVIEW_STALE", "ambiguous identity suspended: {body}");
        client.query_client().exec("DELETE FROM accounts_accountidentity WHERE user_id = $id")
            .param("$id", target_id + 1).await?;
        let (status, body) = suspend(&app, target_id, &csrf_cookie, Some(csrf), "wrong-subject", "admin-test-password").await?;
        ensure!(status == StatusCode::CONFLICT && body["code"] == "REVIEW_STALE");
        let (status, body) = suspend(&app, target_id, &csrf_cookie, Some(csrf), &subject, "admin-test-password").await?;
        ensure!(status == StatusCode::OK && body["status"] == "suspended", "suspension failed: {body}");
        let (_, body) = get(&app, &account_path, Some(&cookie), None).await?;
        ensure!(body["account"]["access_state"] == "account_disabled", "suspended account looked active: {body}");
        let target_session = client.query_client().query_row("SELECT session_key FROM django_session WHERE session_key = $key")
            .param("$key", target_token).optional().await?;
        ensure!(target_session.is_none(), "target session survived suspension");
        let mut meta = client.query_client().query_row("SELECT revoked_at, revoked_reason FROM core_usersessionmeta WHERE id = $id")
            .param("$id", target_meta_id).await?;
        let revoked_at: Option<SystemTime> = meta.remove_field_by_name("revoked_at")?.try_into()?;
        let reason: String = meta.remove_field_by_name("revoked_reason")?.try_into()?;
        ensure!(revoked_at.is_some() && reason == "operator_suspended");
        let mut audit = client.query_client().query_row("SELECT action, CAST(meta_json AS Utf8) AS meta_json FROM usid_audit_log WHERE target_id = $id LIMIT 1")
            .param("$id", target_identity_id.to_string()).await?;
        let action: String = audit.remove_field_by_name("action")?.try_into()?;
        let meta_json: String = audit.remove_field_by_name("meta_json")?.try_into()?;
        ensure!(action == "account.suspended" && serde_json::from_str::<Value>(&meta_json)?["reason"] == "security_incident");
        client.query_client().exec("DELETE FROM core_usersessionmeta WHERE id = $id")
            .param("$id", target_meta_id).await?;
        client.query_client().exec("UPDATE auth_user SET is_active = false WHERE id = $id")
            .param("$id", account_id).await?;
        let (status, _) = get(&app, &path, Some(&cookie), None).await?;
        ensure!(status == StatusCode::UNAUTHORIZED);
        let (status, _) = get(&app, &export_path, Some(&cookie), None).await?;
        ensure!(status == StatusCode::UNAUTHORIZED);
        Ok(())
    }.await;
    client
        .query_client()
        .exec("DELETE FROM idp_oidcclient WHERE id = $id")
        .param("$id", oidc_row_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountdeletionrequest WHERE id = $id")
        .param("$id", deletion_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM id_data_export_escrow WHERE id = $id")
        .param("$id", export_id.clone())
        .await?;
    client
        .query_client()
        .exec("DELETE FROM id_data_export_operation WHERE id = $id")
        .param("$id", export_id)
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
        .exec("DELETE FROM accounts_accountidentity WHERE user_id = $id")
        .param("$id", target_id + 1)
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
        .exec("DELETE FROM usid_user WHERE user_id = $id")
        .param("$id", target_identity_id)
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
