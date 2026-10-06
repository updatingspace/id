#![recursion_limit = "256"]
//! Preferences HTTP, legacy schema, and concurrent get-or-create on local YDB.

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

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    token: Option<&str>,
    csrf: Option<&str>,
    body: Option<Value>,
) -> Result<(StatusCode, Value)> {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    if let Some(token) = token {
        builder = builder.header("x-session-token", token);
    }
    if let Some(csrf) = csrf {
        builder = builder.header("x-csrftoken", csrf);
    }
    let body = if let Some(body) = body {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
        Body::from(body.to_string())
    } else {
        Body::empty()
    };
    let response = app.clone().oneshot(builder.body(body)?).await?;
    let status = response.status();
    let value = serde_json::from_slice(&to_bytes(response.into_body(), 2_000_000).await?)?;
    Ok((status, value))
}

#[tokio::test]
#[ignore = "requires migrated local YDB and opt-in preferences route"]
async fn preferences_roundtrip_and_single_owner_under_concurrent_reads() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local"
            && std::env::var("ID_AUTH_PREFERENCES_PILOT_ENABLED")? == "true",
        "test requires opt-in local YDB"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    let app = id_runtime::preferences_http::router(
        id_runtime::preferences_http::PreferencesHttpConfig::from_env(client.clone())?
            .context("preferences pilot disabled")?,
    );
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let id = -i32::try_from(stamp % 1_000_000_000 + 1)?;
    let identity_id = Uuid::from_u128((stamp << 32) | u128::from(std::process::id()));
    let token = format!("rustprefs{stamp:032x}session");
    let password = "pbkdf2_sha256$1000000$synthetic$synthetic";
    let codec = SessionCodec::new(std::env::var("DJANGO_SECRET_KEY")?.as_bytes(), &[])?;
    let now = SystemTime::now();
    let payload = json!({
        "_auth_user_id": id.to_string(),
        "_auth_user_backend": "django.contrib.auth.backends.ModelBackend",
        "_auth_user_hash": codec.auth_hash(password)?,
    });
    let encoded = codec.encode(
        payload.as_object().context("session payload")?,
        i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?,
        true,
    )?;
    client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $password, true, $name, '', '', $email, false, false, CurrentUtcDatetime())")
        .param("$id", id).param("$password", password)
        .param("$name", format!("rust-prefs-{stamp}"))
        .param("$email", format!("rust-prefs-{stamp}@example.invalid")).await?;
    let result: Result<()> = async {
        client.query_client().exec("UPSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, $data, CAST($expires AS Datetime))")
            .param("$key", token.clone()).param("$data", encoded)
            .param("$expires", now + Duration::from_secs(3600)).await?;
        client.query_client().exec("UPSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($identity_id, $name, $name, $email, true, 'active', false, CurrentUtcDatetime())")
            .param("$identity_id", identity_id).param("$name", format!("rust-prefs-{stamp}"))
            .param("$email", format!("rust-prefs-{stamp}@example.invalid")).await?;
        client.query_client().exec("UPSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($user_id, $identity_id, $subject, CurrentUtcDatetime())")
            .param("$user_id", id).param("$identity_id", identity_id)
            .param("$subject", format!("rust-prefs-subject-{stamp}")).await?;

        let (status, zones) = call(&app, "GET", "/api/v1/auth/timezones", None, None, None, None).await?;
        ensure!(status == StatusCode::OK && zones["timezones"].as_array().is_some_and(|value| value.len() == 433));
        ensure!(zones["timezones"].as_array().context("timezones list")?.iter().any(|value| value["name"] == "Europe/Moscow"));

        let mut concurrent = tokio::task::JoinSet::new();
        for _ in 0..20 {
            let app = app.clone(); let token = token.clone();
            concurrent.spawn(async move {
                call(&app, "GET", "/api/v1/auth/preferences", None, Some(&token), None, None).await
            });
        }
        let mut success = 0;
        while let Some(result) = concurrent.join_next().await {
            let (status, value) = result??;
            if status == StatusCode::OK {
                ensure!(value["language"] == "en" && value["marketing_opt_in"] == false);
                success += 1;
            } else {
                ensure!(status == StatusCode::SERVICE_UNAVAILABLE, "unexpected concurrent response: {status} {value}");
            }
        }
        ensure!(success > 0);
        let mut query_client = client.query_client();
        let mut stream = query_client.query("SELECT id FROM accounts_userpreferences VIEW acct_prefs_user_idx WHERE user_id = $id")
            .param("$id", id).await?;
        let mut count = 0;
        while let Some(rows) = stream.next_result_set().await? { for _ in rows { count += 1; } }
        stream.close().await?;
        ensure!(count == 1, "concurrent GET created {count} preference rows");

        let csrf = "a".repeat(32);
        let cookie = format!("sessionid={token}; csrftoken={csrf}");
        let (status, body) = call(&app, "PATCH", "/api/v1/auth/preferences", Some(&cookie), None, None,
            Some(json!({"language":"ru"}))).await?;
        ensure!(status == StatusCode::FORBIDDEN && body["code"] == "CSRF_FAILED");
        let (status, _) = call(&app, "PATCH", "/api/v1/auth/preferences", Some(&cookie), Some("invalid"), Some(&csrf),
            Some(json!({"language":"ru"}))).await?;
        ensure!(status == StatusCode::UNAUTHORIZED);

        let (status, body) = call(&app, "PATCH", "/api/v1/auth/preferences", Some(&cookie), None, Some(&csrf),
            Some(json!({"language":" ru ", "timezone":" Europe/Moscow ", "marketing_opt_in":true,
                "privacy_scope_defaults":{"email":"deny","phone":"invalid","custom":"allow"}}))).await?;
        ensure!(status == StatusCode::OK, "{body}");
        ensure!(body["language"] == "ru" && body["timezone"] == "Europe/Moscow");
        ensure!(body["marketing_opt_in"] == true && body["marketing_opt_in_at"].is_string());
        let (status, consents) = call(&app, "GET", "/api/v1/auth/consents", None, Some(&token), None, None).await?;
        ensure!(status == StatusCode::OK && consents["consents"].as_array().is_some_and(|rows|
            rows.len() == 1 && rows[0]["kind"] == "marketing" && rows[0]["revoked_at"].is_null()),
            "opt-in did not grant marketing consent: {consents}");
        ensure!(body["privacy_scope_defaults"]["email"] == "deny"
            && body["privacy_scope_defaults"]["phone"] == "ask"
            && body["privacy_scope_defaults"]["custom"] == "allow");
        let (status, body) = call(&app, "GET", "/api/v1/auth/preferences", None, Some(&token), None, None).await?;
        ensure!(status == StatusCode::OK && body["language"] == "ru" && body["marketing_opt_in"] == true);
        let (status, body) = call(&app, "PATCH", "/api/v1/auth/preferences", None, Some(&token), None,
            Some(json!({"timezone":"Invalid/Zone", "marketing_opt_in":false}))).await?;
        ensure!(status == StatusCode::OK && body["timezone"] == "" && body["marketing_opt_in"] == false);
        ensure!(body["marketing_opt_in_at"].is_string() && body["marketing_opt_out_at"].is_string());
        let processing_id = i64::from(id) - 1;
        client.query_client().exec("UPSERT INTO accounts_userconsent (id, user_id, kind, version, granted_at, revoked_at, source, meta) VALUES ($id, $user_id, 'data_processing', 'v1', CurrentUtcDatetime(), NULL, 'test', Unwrap(CAST('{}' AS Json)))")
            .param("$id", processing_id).param("$user_id", id).await?;
        let (status, body) = call(&app, "GET", "/api/v1/auth/consents", None, Some(&token), None, None).await?;
        ensure!(status == StatusCode::OK && body["consents"].as_array().is_some_and(|rows| rows.len() == 2),
            "consent history: {body}");
        let (status, _) = call(&app, "PATCH", "/api/v1/auth/preferences", None, Some(&token), None,
            Some(json!({"marketing_opt_in":true}))).await?;
        ensure!(status == StatusCode::OK);
        let (status, consents) = call(&app, "GET", "/api/v1/auth/consents", None, Some(&token), None, None).await?;
        ensure!(status == StatusCode::OK && consents["consents"].as_array().is_some_and(|rows|
            rows.len() == 3 && rows.iter().filter(|row| row["kind"] == "marketing" && row["revoked_at"].is_null()).count() == 1),
            "re-opt-in did not record a new consent: {consents}");
        let (status, body) = call(&app, "POST", "/api/v1/auth/consents/revoke?kind=marketing", Some(&cookie), None, None, None).await?;
        ensure!(status == StatusCode::FORBIDDEN && body["code"] == "CSRF_FAILED");
        let (status, body) = call(&app, "POST", "/api/v1/auth/consents/revoke?kind=data_processing", Some(&cookie), None, Some(&csrf), None).await?;
        ensure!(status == StatusCode::BAD_REQUEST && body["code"] == "CONSENT_REQUIRED");
        let (first, second) = tokio::join!(
            call(&app, "POST", "/api/v1/auth/consents/revoke?kind=marketing", Some(&cookie), None, Some(&csrf), None),
            call(&app, "POST", "/api/v1/auth/consents/revoke?kind=marketing", Some(&cookie), None, Some(&csrf), None),
        );
        let responses = [first?, second?];
        ensure!(responses.iter().filter(|(status, body)| *status == StatusCode::OK && body["ok"] == true).count() == 1
            && responses.iter().filter(|(status, body)| *status == StatusCode::BAD_REQUEST && body["code"] == "CONSENT_NOT_FOUND").count() == 1,
            "concurrent revoke: {responses:?}");
        let (status, body) = call(&app, "POST", "/api/v1/auth/consents/revoke?kind=marketing", None, Some(&token), None, None).await?;
        ensure!(status == StatusCode::BAD_REQUEST && body["code"] == "CONSENT_NOT_FOUND");
        let (status, body) = call(&app, "GET", "/api/v1/auth/consents", None, Some(&token), None, None).await?;
        ensure!(status == StatusCode::OK && body["consents"].as_array().is_some_and(|rows|
            rows.iter().filter(|row| row["kind"] == "marketing" && row["revoked_at"].is_string()).count() == 2
            && rows.iter().any(|row| row["kind"] == "data_processing" && row["revoked_at"].is_null())));
        let (status, body) = call(&app, "GET", "/api/v1/auth/preferences", None, Some(&token), None, None).await?;
        ensure!(status == StatusCode::OK && body["marketing_opt_in"] == false && body["marketing_opt_out_at"].is_string());
        let mut audit = client.query_client().query_row("SELECT action FROM accounts_accountevent VIEW acct_event_user_idx WHERE user_id = $id AND action = 'consent_revoked' LIMIT 1")
            .param("$id", id).await?;
        let action: String = audit.remove_field_by_name("action")?.try_into()?;
        ensure!(action == "consent_revoked");
        let mut audit = client.query_client().query_row("SELECT action, CAST(meta AS Utf8) AS meta FROM accounts_accountevent VIEW acct_event_user_idx WHERE user_id = $id AND action = 'preferences_updated' LIMIT 1")
            .param("$id", id).await?;
        let action: String = audit.remove_field_by_name("action")?.try_into()?;
        ensure!(action == "preferences_updated");

        client.query_client().exec("UPSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $user_id, 'totp', Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime())")
            .param("$id", i64::from(id)).param("$user_id", id).await?;
        let (status, _) = call(&app, "GET", "/api/v1/auth/preferences", None, Some(&token), None, None).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "MFA-unproven session read preferences");
        Ok(())
    }.await;
    client
        .query_client()
        .exec("DELETE FROM mfa_authenticator WHERE id = $id")
        .param("$id", i64::from(id))
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_userconsent WHERE user_id = $id")
        .param("$id", id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountevent WHERE user_id = $id")
        .param("$id", id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_userpreferences WHERE user_id = $id")
        .param("$id", id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountidentity WHERE user_id = $id")
        .param("$id", id)
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
