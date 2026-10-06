#![recursion_limit = "256"]
//! Real-YDB owner checks and atomic application access revocation.

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
    let mut request = Request::builder().method(method).uri(path);
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    if let Some(token) = token {
        request = request.header("x-session-token", token);
    }
    if let Some(csrf) = csrf {
        request = request.header("x-csrftoken", csrf);
    }
    let body = if let Some(body) = body {
        request = request.header(header::CONTENT_TYPE, "application/json");
        Body::from(body.to_string())
    } else {
        Body::empty()
    };
    let response = app.clone().oneshot(request.body(body)?).await?;
    let status = response.status();
    Ok((
        status,
        serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await?)?,
    ))
}

#[tokio::test]
#[ignore = "requires migrated local YDB and opt-in OAuth application route"]
async fn app_revoke_closes_tokens_codes_requests_and_only_selected_grant() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local"
            && std::env::var("ID_AUTH_APPS_PILOT_ENABLED")? == "true",
        "test requires opt-in local YDB"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    let app = id_runtime::authorized_apps_http::router(
        id_runtime::authorized_apps_http::AuthorizedAppsHttpConfig::from_env(client.clone())?
            .context("OAuth apps pilot disabled")?,
    );
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let user_id = -i32::try_from(stamp % 1_000_000_000 + 1)?;
    let identity_id = Uuid::from_u128((stamp << 32) | u128::from(std::process::id()));
    let first_pk = -i64::try_from(stamp % 1_000_000_000 + 10_000_000_000)?;
    let second_pk = first_pk - 1;
    let first_client = format!("rust-app-one-{stamp}");
    let second_client = format!("rust-app-two-{stamp}");
    let code = format!("rust-code-{stamp}");
    let request_id = format!("rust-request-{stamp}");
    let token = format!("rustapps{stamp:032x}session");
    let password = "pbkdf2_sha256$1000000$synthetic$synthetic";
    let codec = SessionCodec::new(std::env::var("DJANGO_SECRET_KEY")?.as_bytes(), &[])?;
    let now = SystemTime::now();
    let payload = json!({
        "_auth_user_id": user_id.to_string(),
        "_auth_user_backend": "django.contrib.auth.backends.ModelBackend",
        "_auth_user_hash": codec.auth_hash(password)?,
    });
    let encoded = codec.encode(
        payload.as_object().context("session payload")?,
        i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?,
        true,
    )?;
    client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $password, true, $name, '', '', $email, false, false, CurrentUtcDatetime())")
        .param("$id", user_id).param("$password", password).param("$name", format!("rust-apps-{stamp}"))
        .param("$email", format!("rust-apps-{stamp}@example.invalid")).await?;
    let result: Result<()> = async {
        client.query_client().exec("UPSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, $data, CAST($expires AS Datetime))")
            .param("$key", token.clone()).param("$data", encoded).param("$expires", now + Duration::from_secs(3600)).await?;
        client.query_client().exec("UPSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($identity_id, $name, $name, $email, true, 'active', false, CurrentUtcDatetime())")
            .param("$identity_id", identity_id).param("$name", format!("rust-apps-{stamp}"))
            .param("$email", format!("rust-apps-{stamp}@example.invalid")).await?;
        client.query_client().exec("UPSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($user_id, $identity_id, $subject, CurrentUtcDatetime())")
            .param("$user_id", user_id).param("$identity_id", identity_id).param("$subject", format!("rust-apps-subject-{stamp}")).await?;
        for (pk, client_id, name) in [(first_pk, &first_client, "Первое"), (second_pk, &second_client, "Второе")] {
            client.query_client().exec("UPSERT INTO idp_oidcclient (id, client_id, name, logo_url, description, client_secret_hash, redirect_uris, allowed_scopes, grant_types, response_types, is_public, is_first_party, created_at, updated_at) VALUES ($id, $client_id, $name, '', '', '', Unwrap(CAST('[]' AS Json)), Unwrap(CAST('[]' AS Json)), Unwrap(CAST('[]' AS Json)), Unwrap(CAST('[]' AS Json)), true, false, CurrentUtcDatetime(), CurrentUtcDatetime())")
                .param("$id", pk).param("$client_id", client_id.clone()).param("$name", name).await?;
            client.query_client().exec("UPSERT INTO idp_oidcconsent (id, user_id, client_id, scopes, created_at, updated_at) VALUES ($id, $user_id, $client_id, Unwrap(CAST($scopes AS Json)), CurrentUtcDatetime(), CurrentUtcDatetime())")
                .param("$id", pk).param("$user_id", user_id).param("$client_id", pk).param("$scopes", r#"["openid","email"]"#).await?;
            client.query_client().exec("UPSERT INTO idp_oidctoken (id, user_id, client_id, access_jti, id_jti, refresh_token_hash, scope, created_at, access_expires_at) VALUES ($id, $user_id, $client_id, $jti, '', $hash, 'openid email', CurrentUtcDatetime(), CAST($expires AS Datetime))")
                .param("$id", pk).param("$user_id", user_id).param("$client_id", pk)
                .param("$jti", format!("jti-{pk}")).param("$hash", format!("hash-{pk}"))
                .param("$expires", now + Duration::from_secs(3600)).await?;
        }
        client.query_client().exec("UPSERT INTO idp_oidcauthorizationcode (code, client_id, user_id, redirect_uri, scope, nonce, code_challenge, code_challenge_method, created_at, expires_at) VALUES ($code, $client_id, $user_id, 'https://example.invalid/callback', 'openid', '', '', '', CurrentUtcDatetime(), CAST($expires AS Datetime))")
            .param("$code", code.clone()).param("$client_id", first_pk).param("$user_id", user_id)
            .param("$expires", now + Duration::from_secs(3600)).await?;
        client.query_client().exec("UPSERT INTO idp_oidcauthorizationrequest (request_id, client_id, user_id, redirect_uri, scope, state, nonce, code_challenge, code_challenge_method, prompt, created_at, expires_at) VALUES ($request_id, $client_id, $user_id, 'https://example.invalid/callback', 'openid', '', '', '', '', '', CurrentUtcDatetime(), CAST($expires AS Datetime))")
            .param("$request_id", request_id.clone()).param("$client_id", first_pk).param("$user_id", user_id)
            .param("$expires", now + Duration::from_secs(3600)).await?;

        let (status, listed) = call(&app, "GET", "/api/v1/auth/oauth/apps", None, Some(&token), None, None).await?;
        ensure!(status == StatusCode::OK, "{listed}");
        ensure!(listed["items"].as_array().is_some_and(|items| items.len() == 2));
        let csrf = "a".repeat(32);
        let cookie = format!("sessionid={token}; csrftoken={csrf}");
        let body = json!({"client_id":first_client});
        let (status, response) = call(&app, "POST", "/api/v1/auth/oauth/apps/revoke", Some(&cookie), None, None, Some(body.clone())).await?;
        ensure!(status == StatusCode::FORBIDDEN && response["code"] == "CSRF_FAILED");
        let (status, _) = call(&app, "POST", "/api/v1/auth/oauth/apps/revoke", Some(&cookie), Some("invalid"), Some(&csrf), Some(body.clone())).await?;
        ensure!(status == StatusCode::UNAUTHORIZED);
        let (status, response) = call(&app, "POST", "/api/v1/auth/oauth/apps/revoke", Some(&cookie), None, Some(&csrf), Some(body.clone())).await?;
        ensure!(status == StatusCode::OK, "{response}");
        let (status, listed) = call(&app, "GET", "/api/v1/auth/oauth/apps", None, Some(&token), None, None).await?;
        ensure!(status == StatusCode::OK && listed["items"].as_array().is_some_and(|items| items.len() == 1));
        ensure!(listed["items"][0]["client_id"] == second_client);
        let mut first_token = client.query_client().query_row("SELECT revoked_at FROM idp_oidctoken WHERE id = $id").param("$id", first_pk).await?;
        let revoked: Option<SystemTime> = first_token.remove_field_by_name("revoked_at")?.try_into()?;
        ensure!(revoked.is_some());
        let mut second_token = client.query_client().query_row("SELECT revoked_at FROM idp_oidctoken WHERE id = $id").param("$id", second_pk).await?;
        let still_valid: Option<SystemTime> = second_token.remove_field_by_name("revoked_at")?.try_into()?;
        ensure!(still_valid.is_none());
        ensure!(client.query_client().query_row("SELECT code FROM idp_oidcauthorizationcode WHERE code = $code")
            .param("$code", code.clone()).optional().await?.is_none());
        ensure!(client.query_client().query_row("SELECT request_id FROM idp_oidcauthorizationrequest WHERE request_id = $id")
            .param("$id", request_id.clone()).optional().await?.is_none());
        let mut event = client.query_client().query_row("SELECT action, CAST(meta AS Utf8) AS meta FROM accounts_accountevent VIEW acct_event_user_idx WHERE user_id = $id LIMIT 1")
            .param("$id", user_id).await?;
        let action: String = event.remove_field_by_name("action")?.try_into()?;
        let meta: String = event.remove_field_by_name("meta")?.try_into()?;
        ensure!(action == "oauth_app_revoked" && serde_json::from_str::<Value>(&meta)?["client_pk"] == first_pk);
        let (status, _) = call(&app, "POST", "/api/v1/auth/oauth/apps/revoke", Some(&cookie), None, Some(&csrf), Some(body)).await?;
        ensure!(status == StatusCode::BAD_REQUEST);
        Ok(())
    }.await;
    for pk in [first_pk, second_pk] {
        client
            .query_client()
            .exec("DELETE FROM idp_oidctoken WHERE id = $id")
            .param("$id", pk)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM idp_oidcconsent WHERE id = $id")
            .param("$id", pk)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM idp_oidcclient WHERE id = $id")
            .param("$id", pk)
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM idp_oidcauthorizationcode WHERE code = $code")
        .param("$code", code)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM idp_oidcauthorizationrequest WHERE request_id = $id")
        .param("$id", request_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountevent WHERE user_id = $id")
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
        .exec("DELETE FROM django_session WHERE session_key = $key")
        .param("$key", token)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM auth_user WHERE id = $id")
        .param("$id", user_id)
        .await?;
    result
}
