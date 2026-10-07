#![recursion_limit = "256"]
//! Real-YDB remembered-consent authorization with a synthetic legacy session.

use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use id_compat::session::SessionCodec;
use id_runtime::{
    oidc_code_exchange::{CodeExchange, exchange_code},
    oidc_keys::OidcKeyRing,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

async fn get(
    app: &Router,
    uri: &str,
    cookie: Option<&str>,
    explicit: Option<&str>,
) -> Result<(StatusCode, Option<String>)> {
    let mut req = Request::builder().uri(uri).method("GET");
    if let Some(cookie) = cookie {
        req = req.header(header::COOKIE, cookie);
    }
    if let Some(token) = explicit {
        req = req.header("x-session-token", token);
    }
    let response = app.clone().oneshot(req.body(Body::empty())?).await?;
    Ok((
        response.status(),
        response
            .headers()
            .get(header::LOCATION)
            .map(|v| v.to_str().map(str::to_owned))
            .transpose()?,
    ))
}

async fn post_form(
    app: &Router,
    form: &str,
    cookie: Option<&str>,
    content_type: &str,
) -> Result<(StatusCode, Option<String>)> {
    let mut req = Request::builder()
        .uri("/oauth/authorize")
        .method("POST")
        .header(header::CONTENT_TYPE, content_type);
    if let Some(cookie) = cookie {
        req = req.header(header::COOKIE, cookie);
    }
    let response = app
        .clone()
        .oneshot(req.body(Body::from(form.to_owned()))?)
        .await?;
    Ok((
        response.status(),
        response
            .headers()
            .get(header::LOCATION)
            .map(|v| v.to_str().map(str::to_owned))
            .transpose()?,
    ))
}

async fn call_json(
    app: &Router,
    method: &str,
    uri: &str,
    cookie: &str,
    csrf: Option<&str>,
    body: Option<Value>,
) -> Result<(StatusCode, HeaderMap, Value)> {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::COOKIE, cookie);
    if let Some(csrf) = csrf {
        request = request.header("x-csrftoken", csrf);
    }
    let payload = if let Some(body) = body {
        request = request.header(header::CONTENT_TYPE, "application/json");
        Body::from(body.to_string())
    } else {
        Body::empty()
    };
    let response = app.clone().oneshot(request.body(payload)?).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await?)?;
    Ok((status, headers, body))
}

fn keyset() -> Result<OidcKeyRing> {
    let private = Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
        ])
        .output()?;
    ensure!(private.status.success(), "test RSA generation failed");
    let mut child = Command::new("openssl")
        .args(["pkey", "-pubout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    child
        .stdin
        .take()
        .context("openssl stdin")?
        .write_all(&private.stdout)?;
    let public = child.wait_with_output()?;
    ensure!(public.status.success(), "test public key export failed");
    OidcKeyRing::from_json(
        &json!({"private_key_pem":String::from_utf8(private.stdout)?,
        "public_key_pem":String::from_utf8(public.stdout)?,"kid":"authorize-local-test"})
        .to_string(),
    )
}

#[tokio::test]
#[ignore = "requires migrated local YDB and opt-in OIDC authorization route"]
async fn remembered_consent_issues_only_bound_single_use_codes() -> Result<()> {
    let endpoint = std::env::var("YDB_ENDPOINT")?;
    let fixed_local = matches!(
        endpoint.as_str(),
        "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
    );
    let disposable_local = std::env::var("ID_DISPOSABLE_YDB").as_deref() == Ok("true")
        && (endpoint.starts_with("grpc://localhost:") || endpoint.starts_with("grpc://127.0.0.1:"));
    ensure!(
        (fixed_local || disposable_local)
            && std::env::var("YDB_DATABASE")? == "/local"
            && std::env::var("ID_OIDC_AUTHORIZE_PILOT_ENABLED")? == "true"
            && std::env::var("ID_OIDC_TOKEN_PILOT_ENABLED")? == "true",
        "local pilot required"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    let app = id_runtime::oidc_authorize_http::router(
        id_runtime::oidc_authorize_http::OidcAuthorizeHttpConfig::from_env(client.clone())?
            .context("OIDC authorization pilot disabled")?,
    );
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let user_id = -i32::try_from(stamp % 1_000_000_000 + 1)?;
    let client_pk = -i64::try_from(stamp % 1_000_000_000 + 10_000_000_000)?;
    let identity_id = Uuid::from_u128((stamp << 32) | u128::from(std::process::id()));
    let client_id = format!("rust-authorize-{stamp}");
    let session = format!("rustauthorize{stamp:032x}session");
    let password = "pbkdf2_sha256$1000000$synthetic$synthetic";
    let codec = SessionCodec::new(std::env::var("DJANGO_SECRET_KEY")?.as_bytes(), &[])?;
    let now = SystemTime::now();
    let payload = json!({"_auth_user_id":user_id.to_string(),
        "_auth_user_backend":"django.contrib.auth.backends.ModelBackend",
        "_auth_user_hash":codec.auth_hash(password)?});
    let encoded = codec.encode(
        payload.as_object().context("session payload")?,
        i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?,
        true,
    )?;
    let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let authorize_uri = format!(
        "/oauth/authorize?client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example.invalid%2Fcallback&response_type=code&scope=openid%20email&state=state-123&code_challenge={challenge}&code_challenge_method=S256&prompt=none"
    );
    client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $password, true, $name, '', '', $email, false, false, CurrentUtcDatetime())")
        .param("$id", user_id).param("$password", password).param("$name", format!("rust-authorize-{stamp}"))
        .param("$email", format!("rust-authorize-{stamp}@example.invalid")).await?;
    let result: Result<()> = async {
        client.query_client().exec("UPSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, $data, CAST($expires AS Datetime))")
            .param("$key", session.clone()).param("$data", encoded)
            .param("$expires", now + Duration::from_secs(3600)).await?;
        client.query_client().exec("UPSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, $name, $name, $email, true, 'active', false, CurrentUtcDatetime())")
            .param("$id", identity_id).param("$name", format!("rust-authorize-{stamp}"))
            .param("$email", format!("rust-authorize-{stamp}@example.invalid")).await?;
        client.query_client().exec("UPSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($user_id, $identity_id, $subject, CurrentUtcDatetime())")
            .param("$user_id", user_id).param("$identity_id", identity_id)
            .param("$subject", format!("rust-authorize-subject-{stamp}")).await?;
        client.query_client().exec("UPSERT INTO idp_oidcclient (id, client_id, name, logo_url, description, client_secret_hash, redirect_uris, allowed_scopes, grant_types, response_types, is_public, is_first_party, created_at, updated_at) VALUES ($id, $client_id, 'OIDC pilot', '', '', '', Unwrap(CAST($redirects AS Json)), Unwrap(CAST('[\"openid\",\"email\"]' AS Json)), Unwrap(CAST('[\"authorization_code\"]' AS Json)), Unwrap(CAST('[\"code\"]' AS Json)), true, false, CurrentUtcDatetime(), CurrentUtcDatetime())")
            .param("$id", client_pk).param("$client_id", client_id.clone())
            .param("$redirects", r#"["https://rp.example.invalid/callback"]"#).await?;
        let duplicate_pk = client_pk - 100;
        client.query_client().exec("UPSERT INTO idp_oidcclient (id, client_id, name, logo_url, description, client_secret_hash, redirect_uris, allowed_scopes, grant_types, response_types, is_public, is_first_party, created_at, updated_at) VALUES ($id, $client_id, 'Ambiguous OIDC client', '', '', '', Unwrap(CAST($redirects AS Json)), Unwrap(CAST('[\"openid\",\"email\"]' AS Json)), Unwrap(CAST('[\"authorization_code\"]' AS Json)), Unwrap(CAST('[\"code\"]' AS Json)), true, false, CurrentUtcDatetime(), CurrentUtcDatetime())")
            .param("$id", duplicate_pk).param("$client_id", client_id.clone())
            .param("$redirects", r#"["https://rp.example.invalid/callback"]"#).await?;
        let (status, location) = get(&app, &authorize_uri, Some(&format!("sessionid={session}")), None).await?;
        ensure!(status == StatusCode::NOT_FOUND && location.is_none(), "ambiguous client issued an authorization response");
        client.query_client().exec("DELETE FROM idp_oidcclient WHERE id = $id")
            .param("$id", duplicate_pk).await?;
        let (status, location) = get(&app, &authorize_uri, Some(&format!("sessionid={session}")), None).await?;
        ensure!(status == StatusCode::FOUND && location.context("consent redirect")?.contains("error=consent_required"));
        let prepare_uri = authorize_uri.replacen("/oauth/authorize?", "/oauth/authorize/prepare?", 1).replace("&prompt=none", "");
        let session_cookie = format!("sessionid={session}");
        let (status, headers, prepared) = call_json(&app, "GET", &prepare_uri, &session_cookie, None, None).await?;
        ensure!(status == StatusCode::OK && prepared["action"] == "consent", "prepare: {prepared}");
        let request_id = prepared["request_id"].as_str().context("missing request ID")?;
        let csrf_cookie = headers.get(header::SET_COOKIE).context("missing CSRF cookie")?.to_str()?.split(';').next().context("empty CSRF cookie")?;
        let csrf = csrf_cookie.split_once('=').context("malformed CSRF cookie")?.1;
        let browser_cookie = format!("{session_cookie}; {csrf_cookie}");
        let body = json!({"request_id":request_id,"scopes":["openid","email"],"remember":true});
        let (status, _, _) = call_json(&app, "POST", "/oauth/authorize/approve", &browser_cookie, None, Some(body.clone())).await?;
        ensure!(status == StatusCode::FORBIDDEN, "approval without CSRF passed");
        client.query_client().exec("UPSERT INTO idp_oidcclient (id, client_id, name, logo_url, description, client_secret_hash, redirect_uris, allowed_scopes, grant_types, response_types, is_public, is_first_party, created_at, updated_at) VALUES ($id, $client_id, 'Ambiguous OIDC client', '', '', '', Unwrap(CAST($redirects AS Json)), Unwrap(CAST('[\"openid\",\"email\"]' AS Json)), Unwrap(CAST('[\"authorization_code\"]' AS Json)), Unwrap(CAST('[\"code\"]' AS Json)), true, false, CurrentUtcDatetime(), CurrentUtcDatetime())")
            .param("$id", duplicate_pk).param("$client_id", client_id.clone())
            .param("$redirects", r#"["https://rp.example.invalid/callback"]"#).await?;
        let (status, _, _) = call_json(&app, "POST", "/oauth/authorize/approve", &browser_cookie, Some(csrf), Some(body.clone())).await?;
        ensure!(status == StatusCode::BAD_REQUEST, "pending consent issued a code for an ambiguous client");
        client.query_client().exec("DELETE FROM idp_oidcclient WHERE id = $id")
            .param("$id", duplicate_pk).await?;
        let (status, _, approved) = call_json(&app, "POST", "/oauth/authorize/approve", &browser_cookie, Some(csrf), Some(body.clone())).await?;
        ensure!(status == StatusCode::OK && approved["redirect_uri"].as_str().is_some_and(|uri| uri.contains("code=")), "approval failed: {approved}");
        let (status, _, _) = call_json(&app, "POST", "/oauth/authorize/approve", &browser_cookie, Some(csrf), Some(body)).await?;
        ensure!(status == StatusCode::NOT_FOUND, "approval request was reused");
        let mut consent_rows = client.query_client();
        let mut stream = consent_rows.query("SELECT id, CAST(scopes AS Utf8) AS scopes FROM idp_oidcconsent VIEW oidc_consent_user_idx WHERE user_id = $user_id")
            .param("$user_id", user_id).await?;
        let mut found = 0;
        while let Some(rows) = stream.next_result_set().await? {
            for mut row in rows {
                let scopes: String = row.remove_field_by_name("scopes")?.try_into()?;
                ensure!(serde_json::from_str::<Vec<String>>(&scopes)?.contains(&"email".to_owned()));
                found += 1;
            }
        }
        stream.close().await?;
        ensure!(found == 1, "remembered consent missing or duplicated");
        let form = authorize_uri.split_once('?').context("missing authorize form")?.1;
        let (status, location) = post_form(&app, form, Some(&browser_cookie), "application/x-www-form-urlencoded").await?;
        ensure!(status == StatusCode::FOUND && location.context("form authorization redirect")?.contains("code="), "form authorization failed");
        let (status, location) = post_form(&app, &format!("{form}&client_id=duplicate"), Some(&browser_cookie), "application/x-www-form-urlencoded").await?;
        ensure!(status == StatusCode::BAD_REQUEST && location.is_none(), "duplicate form parameter accepted");
        let (status, location) = post_form(&app, form, Some(&browser_cookie), "application/json").await?;
        ensure!(status == StatusCode::BAD_REQUEST && location.is_none(), "JSON authorization form accepted");
        let (status, location) = post_form(&app, &form.replace("rp.example.invalid", "evil.example.invalid"), Some(&browser_cookie), "application/x-www-form-urlencoded").await?;
        ensure!(status == StatusCode::BAD_REQUEST && location.is_none(), "unregistered form redirect accepted");
        let (status, location) = post_form(&app, &format!("{form}&padding={}", "a".repeat(16_385)), Some(&browser_cookie), "application/x-www-form-urlencoded").await?;
        ensure!(status == StatusCode::BAD_REQUEST && location.is_none(), "oversized authorization form accepted");
        let forced = format!("{prepare_uri}&prompt=consent");
        let (status, _, pending) = call_json(&app, "GET", &forced, &browser_cookie, None, None).await?;
        ensure!(status == StatusCode::OK && pending["action"] == "consent");
        let pending_id = pending["request_id"].as_str().context("missing deny request")?;
        let (status, _, _) = call_json(&app, "POST", "/oauth/authorize/approve", &browser_cookie, Some(csrf),
            Some(json!({"request_id":pending_id,"scopes":["openid","address"],"remember":true}))).await?;
        ensure!(status == StatusCode::BAD_REQUEST, "scope escalation was accepted");
        let (status, _, _) = call_json(&app, "POST", "/oauth/authorize/deny", &browser_cookie, None,
            Some(json!({"request_id":pending_id}))).await?;
        ensure!(status == StatusCode::FORBIDDEN, "denial without CSRF passed");
        let (status, _, denied) = call_json(&app, "POST", "/oauth/authorize/deny", &browser_cookie, Some(csrf),
            Some(json!({"request_id":pending_id}))).await?;
        ensure!(status == StatusCode::OK && denied["redirect_uri"].as_str().is_some_and(|uri| uri.contains("error=access_denied") && !uri.contains("code=")),
            "denial failed: {denied}");
        let (status, _, _) = call_json(&app, "POST", "/oauth/authorize/deny", &browser_cookie, Some(csrf),
            Some(json!({"request_id":pending_id}))).await?;
        ensure!(status == StatusCode::NOT_FOUND, "denial request was reused");

        let (status, _, pending) = call_json(&app, "GET", &forced, &browser_cookie, None, None).await?;
        ensure!(status == StatusCode::OK && pending["action"] == "consent");
        let pending_id = pending["request_id"].as_str().context("missing race request")?.to_owned();
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..100 {
            let app = app.clone();
            let browser_cookie = browser_cookie.clone();
            let csrf = csrf.to_owned();
            let request_id = pending_id.clone();
            tasks.spawn(async move {
                call_json(&app, "POST", "/oauth/authorize/approve", &browser_cookie, Some(&csrf),
                    Some(json!({"request_id":request_id,"scopes":["openid"],"remember":false}))).await
            });
        }
        let mut issued = 0;
        while let Some(result) = tasks.join_next().await {
            let (status, _, body) = result??;
            if status == StatusCode::OK {
                ensure!(body["redirect_uri"].as_str().is_some_and(|uri| uri.contains("code=")));
                issued += 1;
            } else {
                ensure!(matches!(status, StatusCode::NOT_FOUND | StatusCode::SERVICE_UNAVAILABLE), "unexpected concurrent approval: {status} {body}");
            }
        }
        ensure!(issued == 1, "{issued} approvals succeeded for one request");
        let (status, _, pending) = call_json(&app, "GET", &forced, &browser_cookie, None, None).await?;
        ensure!(status == StatusCode::OK && pending["action"] == "consent");
        let expired_id = pending["request_id"].as_str().context("missing expiring request")?;
        client.query_client().exec("UPDATE idp_oidcauthorizationrequest SET expires_at = CAST($expiry AS Datetime) WHERE request_id = $id")
            .param("$id", expired_id.to_owned()).param("$expiry", SystemTime::now() - Duration::from_secs(1)).await?;
        let (status, _, _) = call_json(&app, "POST", "/oauth/authorize/approve", &browser_cookie, Some(csrf),
            Some(json!({"request_id":expired_id,"scopes":["openid"],"remember":true}))).await?;
        ensure!(status == StatusCode::BAD_REQUEST, "expired request was approved");

        let (status, _, pending) = call_json(&app, "GET", &forced, &browser_cookie, None, None).await?;
        ensure!(status == StatusCode::OK && pending["action"] == "consent");
        let disabled_id = pending["request_id"].as_str().context("missing disabled request")?;
        client.query_client().exec("UPDATE auth_user SET is_active = false WHERE id = $id").param("$id", user_id).await?;
        let (status, _, _) = call_json(&app, "POST", "/oauth/authorize/approve", &browser_cookie, Some(csrf),
            Some(json!({"request_id":disabled_id,"scopes":["openid"],"remember":true}))).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "disabled account approved consent");
        client.query_client().exec("UPDATE auth_user SET is_active = true WHERE id = $id").param("$id", user_id).await?;
        let (status, location) = get(&app, &authorize_uri, Some(&format!("sessionid={session}")), Some("invalid")).await?;
        ensure!(status == StatusCode::FOUND && location.context("invalid session redirect")?.contains("error=login_required"));
        let (status, location) = get(&app, &authorize_uri.replace("rp.example.invalid", "evil.example.invalid"), Some(&format!("sessionid={session}")), None).await?;
        ensure!(status == StatusCode::BAD_REQUEST && location.is_none());
        let (status, location) = get(&app, &authorize_uri, Some(&format!("sessionid={session}")), None).await?;
        ensure!(status == StatusCode::FOUND, "authorization failed: {status}");
        let location = Url::parse(&location.context("code redirect")?)?;
        ensure!(location.host_str() == Some("rp.example.invalid"));
        let code = location.query_pairs().find(|(key, _)| key == "code").map(|(_, value)| value.to_string()).context("missing code")?;
        let mut row = client.query_client().query_row("SELECT user_id, client_id, redirect_uri, scope, code_challenge FROM idp_oidcauthorizationcode WHERE code = $code")
            .param("$code", code.clone()).await?;
        let stored_user: i32 = row.remove_field_by_name("user_id")?.try_into()?;
        let stored_client: i64 = row.remove_field_by_name("client_id")?.try_into()?;
        let stored_redirect: String = row.remove_field_by_name("redirect_uri")?.try_into()?;
        let stored_scope: String = row.remove_field_by_name("scope")?.try_into()?;
        let stored_challenge: String = row.remove_field_by_name("code_challenge")?.try_into()?;
        ensure!(stored_user == user_id && stored_client == client_pk && stored_redirect == "https://rp.example.invalid/callback"
            && stored_scope == "openid email" && stored_challenge == challenge);
        let keys = Arc::new(keyset()?);
        let exchange = CodeExchange { client_id: client_id.clone(), client_secret: None, code: code.clone(),
            redirect_uri: stored_redirect, code_verifier: verifier.into() };
        let tokens = exchange_code(&client, keys.clone(), "https://id.example.invalid", "local-refresh-salt",
            exchange.clone(), SystemTime::now()).await?
            .map_err(|error| anyhow::anyhow!("Rust-issued code was not accepted: {error:?}"))?;
        ensure!(tokens.scope == "openid email" && !tokens.access_token.is_empty());
        ensure!(exchange_code(&client, keys, "https://id.example.invalid", "local-refresh-salt",
            exchange, SystemTime::now()).await?.is_err(), "authorization code replay was accepted");
        client.query_client().exec("DELETE FROM idp_oidcauthorizationcode WHERE code = $code").param("$code", code).await?;
        client.query_client().exec("UPSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $user_id, 'totp', Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime())")
            .param("$id", client_pk).param("$user_id", user_id).await?;
        let (status, location) = get(&app, &authorize_uri, Some(&format!("sessionid={session}")), None).await?;
        ensure!(status == StatusCode::FOUND && location.context("MFA redirect")?.contains("error=login_required"));
        Ok(())
    }.await;
    let mut query_client = client.query_client();
    let mut token_rows = query_client.query("SELECT id FROM idp_oidctoken VIEW oidc_token_user_client_idx WHERE user_id = $user_id AND client_id = $client_id")
        .param("$user_id", user_id).param("$client_id", client_pk).await?;
    let mut token_ids: Vec<i64> = Vec::new();
    while let Some(rows) = token_rows.next_result_set().await? {
        for mut row in rows {
            token_ids.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    token_rows.close().await?;
    for id in token_ids {
        client
            .query_client()
            .exec("DELETE FROM idp_oidctoken WHERE id = $id")
            .param("$id", id)
            .await?;
    }
    let mut query_client = client.query_client();
    let mut code_rows = query_client.query("SELECT code FROM idp_oidcauthorizationcode VIEW oidc_code_user_idx WHERE user_id = $user_id AND client_id = $client_id")
        .param("$user_id", user_id).param("$client_id", client_pk).await?;
    let mut code_ids: Vec<String> = Vec::new();
    while let Some(rows) = code_rows.next_result_set().await? {
        for mut row in rows {
            code_ids.push(row.remove_field_by_name("code")?.try_into()?);
        }
    }
    code_rows.close().await?;
    for code in code_ids {
        client
            .query_client()
            .exec("DELETE FROM idp_oidcauthorizationcode WHERE code = $code")
            .param("$code", code)
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM mfa_authenticator WHERE id = $id")
        .param("$id", client_pk)
        .await?;
    let mut query_client = client.query_client();
    let mut consents = query_client
        .query("SELECT id FROM idp_oidcconsent VIEW oidc_consent_user_idx WHERE user_id = $user_id")
        .param("$user_id", user_id)
        .await?;
    let mut consent_ids: Vec<i64> = Vec::new();
    while let Some(rows) = consents.next_result_set().await? {
        for mut row in rows {
            consent_ids.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    consents.close().await?;
    for id in consent_ids {
        client
            .query_client()
            .exec("DELETE FROM idp_oidcconsent WHERE id = $id")
            .param("$id", id)
            .await?;
    }
    let mut query_client = client.query_client();
    let mut pending = query_client.query("SELECT request_id FROM idp_oidcauthorizationrequest VIEW oidc_req_user_idx WHERE user_id = $user_id AND client_id = $client_id")
        .param("$user_id", user_id).param("$client_id", client_pk).await?;
    let mut pending_ids: Vec<String> = Vec::new();
    while let Some(rows) = pending.next_result_set().await? {
        for mut row in rows {
            pending_ids.push(row.remove_field_by_name("request_id")?.try_into()?);
        }
    }
    pending.close().await?;
    for id in pending_ids {
        client
            .query_client()
            .exec("DELETE FROM idp_oidcauthorizationrequest WHERE request_id = $id")
            .param("$id", id)
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM idp_oidcclient WHERE id = $id")
        .param("$id", client_pk - 100)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM idp_oidcclient WHERE id = $id")
        .param("$id", client_pk)
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
        .param("$key", session)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM auth_user WHERE id = $id")
        .param("$id", user_id)
        .await?;
    result
}
