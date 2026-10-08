#![recursion_limit = "256"]
//! Local Axum password login using legacy account/schema and portable cache.

use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
    routing::post,
};
use cookie::SameSite;
use hmac::{Hmac, KeyInit, Mac};
use id_compat::{
    account_jwt::AccountJwtCodec,
    cache::CacheValue,
    mfa_seal::{MfaSealKey, SecretKind},
    session::SessionCodec,
};
use id_runtime::{
    cache_store::CacheStore,
    form_token_http::{self, FormTokenConfig},
    login_http::{self, LoginHttpConfig, LoginHttpOptions},
    login_preflight::{LoginDecision, LoginPreflight},
    media_url::MediaUrl,
    session_issuer::{IssueTiming, MfaProof, SessionClient, issue_password_login_with_mfa},
    ymq::YmqPublisher,
};
use serde_json::{Value, json};
use sha1::Sha1;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;
use uuid::Uuid;

const PASSWORD: &str = "Synthetic пароль 🔐 with unicode and more than 72 bytes Synthetic пароль 🔐 with unicode and more than 72 bytes ";
const PASSWORD_HASH: &str = "argon2$argon2id$v=19$m=102400,t=2,p=8$U3ludGhldGljR29sZGVuU2FsdDEyMw$Q/uhIlhHnraeVEMP4b/SvQx5Gjb04zC0bEmIq6OPnUo";
const SECRET: &[u8] = b"synthetic-local-secret-min-32-characters";

async fn call(
    app: &Router,
    method: &str,
    body: Value,
    form_cookie: Option<&str>,
    csrf: Option<&str>,
    origin: Option<&str>,
) -> Result<(StatusCode, HeaderMap, Value)> {
    let uri = if method == "GET" {
        "/api/v1/auth/form_token?purpose=login"
    } else {
        "/api/v1/auth/login"
    };
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-forwarded-for", "192.0.2.5")
        .header(header::USER_AGENT, "Rust login HTTP test");
    if method == "POST" {
        request = request.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(cookie) = form_cookie {
        request = request.header(header::COOKIE, cookie);
    }
    if let Some(csrf) = csrf {
        request = request.header("x-csrftoken", csrf);
    }
    if let Some(origin) = origin {
        request = request.header(header::ORIGIN, origin);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string()))?)
        .await?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await?)?;
    Ok((status, headers, body))
}

async fn token(app: &Router) -> Result<(String, String)> {
    let (status, headers, body) = call(app, "GET", json!(null), None, None, None).await?;
    ensure!(status == StatusCode::OK);
    let token = body["form_token"]
        .as_str()
        .context("missing form token")?
        .to_owned();
    let cookie = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("csrftoken="))
        .context("missing csrf cookie")?
        .split(';')
        .next()
        .context("invalid csrf cookie")?
        .to_owned();
    Ok((token, cookie))
}

fn totp_code(unix_seconds: u64) -> Result<String> {
    let mut mac = Hmac::<Sha1>::new_from_slice(b"12345678901234567890")?;
    mac.update(&(unix_seconds / 30).to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 0x0f);
    let value = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]) % 1_000_000;
    Ok(format!("{value:06}"))
}

#[tokio::test]
#[ignore = "requires migrated local YDB; creates synthetic negative-ID account/session and scratch cache"]
async fn password_login_http_preserves_browser_and_python_contract() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "login HTTP test requires local /local YDB"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let account_id = -i32::try_from(stamp % 1_000_000_000 + 1)?;
    let identity_id = Uuid::from_u128((stamp << 32) | u128::from(std::process::id()));
    let email = format!("rust-login-http-{stamp}@example.invalid");
    let table = format!("id_login_http_{}_{}", std::process::id(), stamp);
    client.query_client().exec(format!(
        "CREATE TABLE `{table}` (cache_key Utf8 NOT NULL, value String, expires_at Uint64, PRIMARY KEY(cache_key))"
    )).await?;
    client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $password, true, $name, '', '', $email, false, false, CurrentUtcDatetime())")
        .param("$id", account_id).param("$password", PASSWORD_HASH)
        .param("$name", format!("rust-login-http-{stamp}"))
        .param("$email", email.clone()).await?;
    client
        .query_client()
        .exec(
            "UPSERT INTO accounts_accountemaillookup (user_id, email_key) VALUES ($id, $email_key)",
        )
        .param("$id", account_id)
        .param("$email_key", email.clone())
        .await?;
    let mut issued = Vec::new();
    let result: Result<()> = async {
        client.query_client().exec("UPSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($id, $user_id, $email, true, true)")
            .param("$id", account_id).param("$user_id", account_id).param("$email", email.clone()).await?;
        client.query_client().exec("UPSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, $name, $name, $email, true, 'active', false, CurrentUtcDatetime())")
            .param("$id", identity_id).param("$name", format!("rust-login-http-{stamp}"))
            .param("$email", email.clone()).await?;
        client.query_client().exec("UPSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($user_id, $identity_id, $subject, CurrentUtcDatetime())")
            .param("$user_id", account_id).param("$identity_id", identity_id)
            .param("$subject", format!("stable-login-http-{stamp}")).await?;
        let cache = CacheStore::new(client.clone(), &table, "", 1)?;
        let form = form_token_http::router(Arc::new(FormTokenConfig::new(cache.clone(),
            "csrftoken".into(), false, SameSite::Lax, None)?));
        let queue_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let queue_port = queue_listener.local_addr()?.port();
        let (queue_sender, mut queue_receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let queue_app = Router::new().route("/", post(move |body: axum::body::Bytes| {
            let sender = queue_sender.clone();
            async move {
                let _ = sender.send(body.to_vec()).await;
                "<SendMessageResponse><SendMessageResult><MessageId>local-test</MessageId></SendMessageResult></SendMessageResponse>"
            }
        }));
        let queue_server = tokio::spawn(async move { axum::serve(queue_listener, queue_app).await });
        let endpoint = format!("http://127.0.0.1:{queue_port}/");
        let queue_url = format!("http://127.0.0.1:{queue_port}/test-queue");
        let publisher = YmqPublisher::new(&endpoint, &queue_url, "test-access".into(), "test-secret".into())?;
        let login = login_http::router(Arc::new(LoginHttpConfig::new(
            client.clone(), cache.clone(), Arc::new(SessionCodec::new(SECRET, &[])?),
            AccountJwtCodec::new(SECRET)?, MediaUrl::new("http://id.localhost/media/")?,
            LoginHttpOptions {
                session_cookie_name: "sessionid".into(), csrf_cookie_name: "csrftoken".into(),
                session_cookie_secure: false, csrf_cookie_secure: false,
                session_same_site: SameSite::Lax, csrf_same_site: SameSite::Lax,
                session_cookie_domain: None, csrf_cookie_domain: None,
                session_cookie_age: 3600, login_ip_limit: 50,
                trusted_origins: vec!["http://id.localhost:5175".into()],
                device_fingerprint_salt: "device-salt".into(),
            },
        )?.with_ymq_publisher(publisher)));
        let app = form.merge(login);
        let (status, _, body) = call(&app, "POST", json!({"email":email,"password":PASSWORD}),
            None, None, None).await?;
        ensure!(status == StatusCode::BAD_REQUEST && body["code"] == "INVALID_FORM_TOKEN");

        let (form_token, csrf_cookie) = token(&app).await?;
        let base = json!({"email":email,"password":PASSWORD,"form_token":form_token});
        let (status, _, body) = call(&app, "POST", base.clone(), Some(&csrf_cookie), None,
            Some("http://id.localhost:5175")).await?;
        ensure!(status == StatusCode::FORBIDDEN && body["code"] == "CSRF_FAILED");
        let csrf_value = csrf_cookie.strip_prefix("csrftoken=").context("invalid csrf cookie")?;
        let (status, _, body) = call(&app, "POST", base.clone(), Some(&csrf_cookie), Some(csrf_value),
            Some("https://attacker.invalid")).await?;
        ensure!(status == StatusCode::FORBIDDEN && body["code"] == "CSRF_FAILED");

        let wrong = json!({"email":email,"password":"wrong","form_token":form_token});
        let (status, _, body) = call(&app, "POST", wrong, Some(&csrf_cookie), Some(csrf_value),
            Some("http://id.localhost:5175")).await?;
        ensure!(status == StatusCode::UNAUTHORIZED && body["code"] == "INVALID_CREDENTIALS");
        ensure!(queue_receiver.try_recv().is_err(), "failed login published a mail intent");
        let (status, _, body) = call(&app, "POST", base.clone(), Some(&csrf_cookie), Some(csrf_value),
            Some("http://id.localhost:5175")).await?;
        ensure!(status == StatusCode::BAD_REQUEST && body["code"] == "INVALID_FORM_TOKEN");

        client.query_client().exec("UPSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($row_id, $user_id, 'totp', Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime())")
            .param("$row_id", i64::from(account_id)).param("$user_id", account_id).await?;
        let (mfa_token, _) = token(&app).await?;
        let mfa_request = json!({"email":email,"password":PASSWORD,"form_token":mfa_token});
        let (status, _, body) = call(&app, "POST", mfa_request, Some(&csrf_cookie), Some(csrf_value),
            Some("http://id.localhost:5175")).await?;
        ensure!(status == StatusCode::UNAUTHORIZED && body["code"] == "MFA_REQUIRED");
        let (mfa_code_token, _) = token(&app).await?;
        let mfa_code_request = json!({"email":email,"password":PASSWORD,
            "form_token":mfa_code_token,"mfa_code":"123456"});
        let (status, headers, body) = call(&app, "POST", mfa_code_request,
            Some(&csrf_cookie), Some(csrf_value), Some("http://id.localhost:5175")).await?;
        ensure!(status == StatusCode::SERVICE_UNAVAILABLE && body["code"] == "MFA_UNAVAILABLE"
            && !headers.contains_key("x-session-token"), "malformed MFA response: {status} {body}");
        client.query_client().exec("DELETE FROM mfa_authenticator WHERE id = $id")
            .param("$id", i64::from(account_id)).await?;

        let (good_token, _) = token(&app).await?;
        let good = json!({"email":email,"password":PASSWORD,"form_token":good_token});
        let (status, headers, body) = call(&app, "POST", good, Some(&csrf_cookie), Some(csrf_value),
            Some("http://id.localhost:5175")).await?;
        ensure!(status == StatusCode::OK, "login status/body: {status} {body}");
        ensure!(headers[header::CACHE_CONTROL] == "no-store");
        ensure!(headers[header::ACCESS_CONTROL_ALLOW_ORIGIN] == "http://id.localhost:5175");
        let session = body["meta"]["session_token"].as_str().context("missing session")?;
        ensure!(headers["x-session-token"] == session && body["verification_required"] == false
            && body["recovery_codes"].is_null());
        ensure!(body["user"]["email"] == email);
        ensure!(cache.get(&format!("rl:login:email:{email}"), SystemTime::now()).await?.is_none(),
            "successful login did not clear its email penalty");
        let Some(CacheValue::Map(ip_budget)) = cache.get("rl:login:ip:192.0.2.5", SystemTime::now()).await? else {
            anyhow::bail!("successful login cleared the shared IP budget")
        };
        ensure!(ip_budget.get("count") == Some(&CacheValue::Int(4)),
            "IP budget did not include failed and successful attempts");
        ensure!(headers.get_all(header::SET_COOKIE).iter().filter_map(|value| value.to_str().ok())
            .any(|value| value.starts_with("sessionid=") && value.contains("HttpOnly")));
        ensure!(body["access_token"].as_str().is_some_and(|value| !value.is_empty()),
            "missing access JWT");
        let refresh = body["refresh_token"].as_str().context("missing refresh JWT")?;
        issued.push((session.to_owned(), refresh.to_owned()));
        let mut row = client.query_client().query_row(
            "SELECT COUNT(*) AS count FROM accounts_newdevicemailoutbox AS o INNER JOIN accounts_loginevent AS e ON o.event_id = e.id WHERE e.user_id = $id AND o.status = 'pending'"
        ).param("$id", account_id).await?;
        let mail_count: u64 = row.remove_field_by_name("count")?.try_into()?;
        ensure!(mail_count == 1, "first login must enqueue one durable device alert");
        let queue_body = tokio::time::timeout(std::time::Duration::from_secs(5), queue_receiver.recv())
            .await?.context("new-device login did not publish YMQ wakeup")?;
        let parameters: std::collections::HashMap<_, _> =
            url::form_urlencoded::parse(&queue_body).into_owned().collect();
        let queue_intent: Value = serde_json::from_str(parameters.get("MessageBody")
            .context("YMQ wakeup has no MessageBody")?)?;
        let event_id = queue_intent["event_id"].as_i64().context("YMQ wakeup has no event ID")?;
        ensure!(queue_intent["version"] == 1 && queue_intent["kind"] == "new_device_mail");
        let mut row = client.query_client().query_row(
            "SELECT status FROM accounts_newdevicemailoutbox WHERE event_id = $id"
        ).param("$id", event_id).await?;
        let status: String = row.remove_field_by_name("status")?.try_into()?;
        ensure!(status == "pending", "YMQ wakeup did not refer to a committed outbox intent");
        queue_server.abort();
        let seal_key = std::env::var("ID_MFA_SEAL_KEY_B64")
            .ok()
            .map(|encoded| MfaSealKey::from_base64(&encoded))
            .transpose()?;
        let totp_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let stored_totp = seal_key.as_ref().map_or_else(
            || Ok(totp_secret.to_owned()),
            |key| key.seal(i64::from(account_id), SecretKind::Totp, totp_secret),
        )?;
        client.query_client().exec("UPSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($row_id, $user_id, 'totp', Unwrap(CAST($data AS Json)), CurrentUtcDatetime())")
            .param("$row_id", i64::from(account_id)).param("$user_id", account_id)
            .param("$data", json!({"secret":stored_totp}).to_string()).await?;
        let current = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        if current % 30 > 25 {
            tokio::time::sleep(std::time::Duration::from_secs(31 - current % 30)).await;
        }
        let code = totp_code(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
        let (mfa_form, _) = token(&app).await?;
        let mfa_login = json!({"email":email,"password":PASSWORD,"form_token":mfa_form,"mfa_code":code});
        let (status, _, body) = call(&app, "POST", mfa_login, Some(&csrf_cookie), Some(csrf_value),
            Some("http://id.localhost:5175")).await?;
        ensure!(status == StatusCode::OK, "valid TOTP login failed: {status} {body}");
        let mfa_session = body["meta"]["session_token"].as_str().context("missing MFA session")?;
        let mfa_refresh = body["refresh_token"].as_str().context("missing MFA refresh")?;
        issued.push((mfa_session.to_owned(), mfa_refresh.to_owned()));
        let (replay_form, _) = token(&app).await?;
        let replay = json!({"email":email,"password":PASSWORD,"form_token":replay_form,"mfa_code":code});
        let (status, headers, body) = call(&app, "POST", replay, Some(&csrf_cookie), Some(csrf_value),
            Some("http://id.localhost:5175")).await?;
        ensure!(status == StatusCode::UNAUTHORIZED && body["code"] == "INVALID_CREDENTIALS"
            && !headers.contains_key("x-session-token"), "replayed TOTP issued credentials");

        let seed = "0123456789abcdef".repeat(5);
        let recovery = id_compat::recovery::codes(&seed)?;
        let stored_seed = seal_key.as_ref().map_or_else(
            || Ok(seed.clone()),
            |key| key.seal(i64::from(account_id), SecretKind::RecoverySeed, &seed),
        )?;
        client.query_client().exec("UPSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($row_id, $user_id, 'recovery_codes', Unwrap(CAST($data AS Json)), CurrentUtcDatetime())")
            .param("$row_id", i64::from(account_id) - 1).param("$user_id", account_id)
            .param("$data", json!({"seed":stored_seed,"used_mask":0}).to_string()).await?;
        let (recovery_form, _) = token(&app).await?;
        let recovery_login = json!({"email":email,"password":PASSWORD,"form_token":recovery_form,"recovery_code":recovery[0]});
        let (status, _, body) = call(&app, "POST", recovery_login, Some(&csrf_cookie), Some(csrf_value),
            Some("http://id.localhost:5175")).await?;
        ensure!(status == StatusCode::OK, "valid recovery login failed: {status} {body}");
        let recovery_session = body["meta"]["session_token"].as_str().context("missing recovery session")?;
        let recovery_refresh = body["refresh_token"].as_str().context("missing recovery refresh")?;
        issued.push((recovery_session.to_owned(), recovery_refresh.to_owned()));
        let (recovery_replay_form, _) = token(&app).await?;
        let recovery_replay = json!({"email":email,"password":PASSWORD,"form_token":recovery_replay_form,"recovery_code":recovery[0]});
        let (status, headers, body) = call(&app, "POST", recovery_replay, Some(&csrf_cookie), Some(csrf_value),
            Some("http://id.localhost:5175")).await?;
        ensure!(status == StatusCode::UNAUTHORIZED && body["code"] == "INVALID_CREDENTIALS"
            && !headers.contains_key("x-session-token"), "replayed recovery code issued credentials");

        let verifier = LoginPreflight::new(client.clone(), 1)?;
        let LoginDecision::MfaRequired(verified) = verifier.verify(&email, PASSWORD).await? else {
            anyhow::bail!("recovery account did not require MFA")
        };
        let verified = Arc::new(verified);
        let jwt = Arc::new(AccountJwtCodec::new(SECRET)?);
        let codec = Arc::new(SessionCodec::new(SECRET, &[])?);
        let mut attempts = tokio::task::JoinSet::new();
        for _ in 0..100 {
            let client = client.clone();
            let verified = verified.clone();
            let jwt = jwt.clone();
            let codec = codec.clone();
            let cache = cache.clone();
            let code = recovery[1].clone();
            attempts.spawn(async move {
                issue_password_login_with_mfa(&client, codec, &jwt, &verified,
                    &SessionClient { ip: "192.0.2.5".parse()?, user_agent: "synthetic concurrent MFA".into(), device_fingerprint_salt: "device-salt".into() },
                    IssueTiming { now: SystemTime::now(), lifetime: std::time::Duration::from_secs(3600) },
                    MfaProof { cache: &cache, code: &code }).await
            });
        }
        let mut winners = 0;
        while let Some(attempt) = attempts.join_next().await {
            if let Ok(Ok(Some(login))) = attempt {
                winners += 1;
                issued.push((login.session.token, login.refresh));
            }
        }
        ensure!(winners == 1, "100 concurrent recovery consumptions yielded {winners} credentials");
        let mut count_row = client.query_client().query_row(
            "SELECT COUNT(*) AS total FROM usersessions_usersession WHERE user_id = $id")
            .param("$id", account_id).await?;
        let count: u64 = count_row.remove_field_by_name("total")?.try_into()?;
        ensure!(count == 4, "MFA contention persisted {count} sessions instead of four");

        client.query_client().exec("UPDATE mfa_authenticator SET data = Unwrap(CAST($data AS Json)) WHERE id = $id")
            .param("$data", json!({"migrated_codes":["12345678","87654321"]}).to_string())
            .param("$id", i64::from(account_id) - 1).await?;
        let (migrated_form, _) = token(&app).await?;
        let migrated_login = json!({"email":email,"password":PASSWORD,"form_token":migrated_form,"recovery_code":"87654321"});
        let (status, _, body) = call(&app, "POST", migrated_login, Some(&csrf_cookie), Some(csrf_value),
            Some("http://id.localhost:5175")).await?;
        ensure!(status == StatusCode::OK, "migrated recovery login failed: {status} {body}");
        let migrated_session = body["meta"]["session_token"].as_str().context("missing migrated session")?;
        let migrated_refresh = body["refresh_token"].as_str().context("missing migrated refresh")?;
        issued.push((migrated_session.to_owned(), migrated_refresh.to_owned()));
        Ok(())
    }.await;
    for (session, refresh) in issued {
        if let Some(mut row) = client.query_client().query_row(
            "SELECT id FROM token_blacklist_outstandingtoken WHERE user_id = $id AND token = $refresh LIMIT 1")
            .param("$id", account_id).param("$refresh", refresh).optional().await? {
            let outstanding_id: i64 = row.remove_field_by_name("id")?.try_into()?;
            client.query_client().exec("DELETE FROM token_blacklist_blacklistedtoken WHERE token_id = $id")
                .param("$id", outstanding_id).await?;
        }
        for table in [
            "django_session",
            "usersessions_usersession",
            "core_usersessionmeta",
        ] {
            client
                .query_client()
                .exec(format!("DELETE FROM {table} WHERE session_key = $key"))
                .param("$key", session.clone())
                .await?;
        }
    }
    for table in ["core_usersessiontoken", "token_blacklist_outstandingtoken"] {
        client
            .query_client()
            .exec(format!("DELETE FROM {table} WHERE user_id = $id"))
            .param("$id", account_id)
            .await?;
    }
    let mut query_client = client.query_client();
    let mut events = query_client
        .query("SELECT id FROM accounts_loginevent VIEW acct_login_user_idx WHERE user_id = $id")
        .param("$id", account_id)
        .await?;
    let mut event_ids: Vec<i64> = Vec::new();
    while let Some(rows) = events.next_result_set().await? {
        for mut row in rows {
            event_ids.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    events.close().await?;
    for id in event_ids {
        client
            .query_client()
            .exec("DELETE FROM accounts_newdevicemailoutbox WHERE event_id = $id")
            .param("$id", id)
            .await?;
    }
    for table in ["accounts_loginevent", "accounts_userdevice"] {
        client
            .query_client()
            .exec(format!("DELETE FROM {table} WHERE user_id = $id"))
            .param("$id", account_id)
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM mfa_authenticator WHERE user_id = $id")
        .param("$id", account_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM account_emailaddress WHERE id = $id")
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
        .exec("DELETE FROM accounts_accountemaillookup WHERE user_id = $id")
        .param("$id", account_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM auth_user WHERE id = $id")
        .param("$id", account_id)
        .await?;
    client
        .query_client()
        .exec(format!("DROP TABLE `{table}`"))
        .await?;
    result
}
