#![recursion_limit = "256"]
//! Synthetic password login committed as Django/allauth rows in local YDB.

use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use id_compat::{account_jwt::AccountJwtCodec, session::SessionCodec};
use id_runtime::{
    login_preflight::{LoginDecision, LoginPreflight},
    session_issuer::{SessionClient, issue_password_login, issue_password_session},
    session_store::LEGACY_BACKENDS,
};
use std::{
    io::Write,
    net::IpAddr,
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;
use uuid::Uuid;

const PASSWORD: &str = "Synthetic пароль 🔐 with unicode and more than 72 bytes Synthetic пароль 🔐 with unicode and more than 72 bytes ";
const PASSWORD_HASH: &str = "argon2$argon2id$v=19$m=102400,t=2,p=8$U3ludGhldGljR29sZGVuU2FsdDEyMw$Q/uhIlhHnraeVEMP4b/SvQx5Gjb04zC0bEmIq6OPnUo";

#[tokio::test]
#[ignore = "requires local YDB after migrate_ydb; creates synthetic account/session"]
async fn issue_session_rechecks_policy_and_restores_in_rust() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "session issuer test requires local YDB on port 2136"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let account_id = i32::try_from(stamp % 1_000_000_000 + 1)?;
    let identity_id = Uuid::from_u128((stamp << 32) | u128::from(std::process::id()));
    let email = format!("rust-issue-{stamp}@example.invalid");
    let codec = Arc::new(SessionCodec::new(
        b"synthetic-local-secret-min-32-characters",
        &[],
    )?);
    let jwt_codec = AccountJwtCodec::new(b"synthetic-local-secret-min-32-characters")?;
    client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $password, true, $name, '', '', $email, false, false, CurrentUtcDatetime())")
        .param("$id", account_id).param("$password", PASSWORD_HASH)
        .param("$name", format!("rust-issue-{stamp}"))
        .param("$email", email.clone()).await?;
    client
        .query_client()
        .exec(
            "UPSERT INTO accounts_accountemaillookup (user_id, email_key) VALUES ($id, $email_key)",
        )
        .param("$id", account_id)
        .param("$email_key", email.clone())
        .await?;
    let mut tokens_to_clean = Vec::new();
    let result: Result<()> = async {
        client.query_client().exec("UPSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($id, $user_id, $email, true, true)")
            .param("$id", account_id).param("$user_id", account_id)
            .param("$email", email.clone()).await?;
        client.query_client().exec("UPSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, $name, $name, $email, true, 'active', false, CurrentUtcDatetime())")
            .param("$id", identity_id).param("$name", format!("rust-issue-{stamp}"))
            .param("$email", email.clone()).await?;
        client.query_client().exec("UPSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($user_id, $identity_id, $subject, CurrentUtcDatetime())")
            .param("$user_id", account_id).param("$identity_id", identity_id)
            .param("$subject", format!("stable-issue-subject-{stamp}")).await?;
        let verifier = LoginPreflight::new(client.clone(), 1)?;
        let LoginDecision::Ready(verified) = verifier.verify(&email, PASSWORD).await? else {
            anyhow::bail!("synthetic account did not pass preflight")
        };
        let request = SessionClient {
            ip: "192.0.2.5".parse::<IpAddr>()?,
            user_agent: "synthetic Rust login".into(),
            device_fingerprint_salt: "device-salt".into(),
        };
        let lifetime = Duration::from_secs(3600);
        let now = SystemTime::now();

        client.query_client().exec("UPDATE auth_user SET password = 'changed-hash' WHERE id = $id")
            .param("$id", account_id).await?;
        ensure!(issue_password_session(&client, codec.clone(), &verified, &request, now, lifetime).await?.is_none(), "stale password hash issued a session");
        client.query_client().exec("UPDATE auth_user SET password = $hash WHERE id = $id")
            .param("$hash", PASSWORD_HASH).param("$id", account_id).await?;
        client.query_client().exec("UPSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($row_id, $user_id, 'totp', Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime())")
            .param("$row_id", i64::from(account_id)).param("$user_id", account_id).await?;
        ensure!(issue_password_session(&client, codec.clone(), &verified, &request, now, lifetime).await?.is_none(), "new MFA requirement was bypassed");
        client.query_client().exec("DELETE FROM mfa_authenticator WHERE id = $id")
            .param("$id", i64::from(account_id)).await?;

        client.query_client().exec("UPDATE usid_user SET status = 'suspended' WHERE user_id = $id")
            .param("$id", identity_id).await?;
        ensure!(issue_password_session(&client, codec.clone(), &verified, &request, now, lifetime).await?.is_none(), "suspended identity issued a session");
        client.query_client().exec("UPDATE usid_user SET status = 'active' WHERE user_id = $id")
            .param("$id", identity_id).await?;
        client.query_client().exec("UPSERT INTO accounts_accountdeletionrequest (id, user_id, status, requested_at, reason) VALUES ($row_id, $user_id, 'pending', CurrentUtcDatetime(), '')")
            .param("$row_id", i64::from(account_id)).param("$user_id", account_id).await?;
        ensure!(issue_password_session(&client, codec.clone(), &verified, &request, now, lifetime).await?.is_none(), "pending deletion issued a session");
        client.query_client().exec("DELETE FROM accounts_accountdeletionrequest WHERE id = $id")
            .param("$id", i64::from(account_id)).await?;
        client.query_client().exec("UPDATE auth_user SET email = 'changed@example.invalid' WHERE id = $id")
            .param("$id", account_id).await?;
        ensure!(issue_password_session(&client, codec.clone(), &verified, &request, now, lifetime).await?.is_none(), "changed login email issued a session");
        client.query_client().exec("UPDATE auth_user SET email = $email WHERE id = $id")
            .param("$email", email.clone()).param("$id", account_id).await?;
        client.query_client().exec("UPDATE accounts_accountemaillookup SET email_key = 'moved@example.invalid' WHERE user_id = $id")
            .param("$id", account_id).await?;
        ensure!(issue_password_session(&client, codec.clone(), &verified, &request, now, lifetime).await?.is_none(), "stale indexed email issued a session");
        client.query_client().exec("UPDATE accounts_accountemaillookup SET email_key = $email_key WHERE user_id = $id")
            .param("$email_key", email.clone()).param("$id", account_id).await?;

        let login = issue_password_login(&client, codec.clone(), &jwt_codec, &verified, &request, now, lifetime)
            .await?.context("eligible account did not get a session")?;
        let issued = login.session;
        tokens_to_clean.push((issued.token.clone(), login.refresh.clone()));
        let jwt_app = id_runtime::account_jwt_http::router(Arc::new(
            id_runtime::account_jwt_http::AccountJwtHttpConfig::new(
                client.clone(), codec.clone(),
                Arc::new(AccountJwtCodec::new(b"synthetic-local-secret-min-32-characters")?),
                "sessionid".into(), "csrftoken".into(),
                vec!["http://id.localhost:5175".into()],
            )?,
        ));
        let (status, issued_pair, headers) = jwt_session_http_call(
            &jwt_app, Some(&issued.token), Some("invalid-cookie"), false,
        ).await?;
        ensure!(status == StatusCode::OK
            && issued_pair["access"].as_str().is_some()
            && issued_pair["refresh"].as_str().is_some()
            && headers[header::CACHE_CONTROL] == "private, no-store"
            && headers[header::PRAGMA] == "no-cache",
            "valid session could not mint an account JWT pair");
        let extra_refresh = issued_pair["refresh"].as_str().context("missing refresh")?.to_owned();
        tokens_to_clean.push((issued.token.clone(), extra_refresh.clone()));
        if std::env::var("ID_PYTHON_SESSION_CHECK").as_deref() == Ok("true") {
            python_check(serde_json::json!({"token":issued.token,"account_id":account_id,
                "access":issued_pair["access"],"refresh":extra_refresh}))?;
        }
        let (status, _, _) = jwt_session_http_call(&jwt_app, Some("invalid"), Some(&issued.token), false).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "invalid header fell back to a valid cookie");
        let (status, _, _) = jwt_session_http_call(&jwt_app, None, Some(&issued.token), false).await?;
        ensure!(status == StatusCode::FORBIDDEN, "cookie JWT issuance bypassed CSRF");
        let (status, _, _) = jwt_session_http_call(&jwt_app, None, Some(&issued.token), true).await?;
        ensure!(status == StatusCode::OK, "cookie JWT issuance rejected matching CSRF");
        client.query_client().exec("UPSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($row_id, $user_id, 'totp', Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime())")
            .param("$row_id", i64::from(account_id)).param("$user_id", account_id).await?;
        let (status, _, _) = jwt_session_http_call(&jwt_app, Some(&issued.token), None, false).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "session without MFA proof minted account JWT");
        client.query_client().exec("DELETE FROM mfa_authenticator WHERE id = $id")
            .param("$id", i64::from(account_id)).await?;
        ensure!(issued.token.len() == 32
            && issued.token.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()));
        ensure!(issued.expires_at == now + lifetime);
        let restored = id_runtime::session_store::restore_django_principal(
            &client, codec.clone(), &issued.token, LEGACY_BACKENDS, SystemTime::now()).await?
            .context("Rust could not restore its newly issued Django session")?;
        ensure!(restored.account_id.get() == i64::from(account_id)
            && restored.identity_id.get() == identity_id);
        let mut user_session = client.query_client().query_row(
            "SELECT user_id, ip, user_agent FROM usersessions_usersession WHERE session_key = $key")
            .param("$key", issued.token.clone()).await?;
        let tracked_user: i32 = user_session.remove_field_by_name("user_id")?.try_into()?;
        let tracked_ip: String = user_session.remove_field_by_name("ip")?.try_into()?;
        let tracked_agent: String = user_session.remove_field_by_name("user_agent")?.try_into()?;
        ensure!(tracked_user == account_id && tracked_ip == "192.0.2.5"
            && tracked_agent == "synthetic Rust login");
        if std::env::var("ID_PYTHON_SESSION_CHECK").as_deref() == Ok("true") {
            python_check(serde_json::json!({"token":issued.token,"account_id":account_id,
                "access":login.access,"refresh":login.refresh}))?;
        }
        let other = issue_password_login(&client, codec.clone(), &jwt_codec, &verified,
            &request, SystemTime::now(), lifetime).await?
            .context("second session was not issued")?;
        tokens_to_clean.push((other.session.token.clone(), other.refresh.clone()));
        let before = id_runtime::sessions_store::list_sessions(&client, codec.clone(),
            &issued.token, true, Some("192.0.2.5"), "synthetic Rust login", SystemTime::now())
            .await?.context("valid session could not list sessions")?;
        ensure!(before.len() == 2
            && before.iter().any(|row| row.id == issued.token && row.current && !row.revoked)
            && before.iter().any(|row| row.id == other.session.token && !row.current && !row.revoked),
            "Rust session list did not merge two active devices");
        if std::env::var("ID_PYTHON_SESSION_CHECK").as_deref() == Ok("true") {
            let output = python_check(serde_json::json!({"token":issued.token,
                "account_id":account_id,"session_list":true}))?;
            let python_rows: serde_json::Value = serde_json::from_str(&output)?;
            let rust_rows = serde_json::json!({"sessions":before});
            if python_rows != rust_rows {
                let mut redacted_python = python_rows.clone();
                let mut redacted_rust = rust_rows.clone();
                for snapshot in [&mut redacted_python, &mut redacted_rust] {
                    if let Some(rows) = snapshot["sessions"].as_array_mut() {
                        for row in rows { row["id"] = serde_json::json!("<redacted>"); }
                    }
                }
                anyhow::bail!("Python and Rust session-list JSON differ: Python {redacted_python}; Rust {redacted_rust}");
            }
        }
        let sessions_app = if std::env::var("ID_AUTH_SESSIONS_PILOT_ENABLED").as_deref() == Ok("true") {
            let config = id_runtime::sessions_http::SessionsHttpConfig::from_env(client.clone())?
                .context("sessions HTTP pilot not configured")?;
            Some(id_runtime::sessions_http::router(config))
        } else { None };
        if let Some(app) = sessions_app.as_ref() {
            let (status, guest) = sessions_http_call(app, None, None, "GET").await?;
            ensure!(status == StatusCode::UNAUTHORIZED && guest["code"] == "UNAUTHORIZED");
            let (status, invalid) = sessions_http_call(app, Some(&issued.token), Some("bad"), "GET").await?;
            ensure!(status == StatusCode::UNAUTHORIZED && invalid["code"] == "INVALID_OR_EXPIRED_TOKEN",
                "invalid header fell back to a valid session cookie");
            let (status, valid) = sessions_http_call(app, Some("bad"), Some(&issued.token), "GET").await?;
            ensure!(status == StatusCode::OK && valid["sessions"].as_array().is_some_and(|rows| rows.len() == 2),
                "valid header was ignored when cookie was invalid");
            let (status, _) = sessions_http_call(app, None, None, "OPTIONS").await?;
            ensure!(status == StatusCode::NO_CONTENT, "sessions preflight failed");
            let preflight = Request::builder().uri("/api/v1/auth/sessions").method("OPTIONS")
                .header(header::ORIGIN, "http://id.localhost:5175").body(Body::empty())?;
            let preflight = app.clone().oneshot(preflight).await?;
            ensure!(preflight.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN] == "http://id.localhost:5175");
            for (body, expected_status, expected_body) in [
                ("", StatusCode::UNPROCESSABLE_ENTITY,
                    serde_json::json!({"detail":[{"loc":["body","payload"],"type":"missing","msg":"Field required"}]})),
                ("{", StatusCode::BAD_REQUEST,
                    serde_json::json!({"code":"HTTP_ERROR","message":"Cannot parse request body",
                        "details":null,"errors":null,"fields":null,"detail":"Cannot parse request body","status":400})),
                (r#"{"ids":"one"}"#, StatusCode::UNPROCESSABLE_ENTITY,
                    serde_json::json!({"detail":[{"loc":["body","payload","ids"],"type":"list_type",
                        "msg":"Input should be a valid list"}]})),
            ] {
                let request = Request::builder().uri("/api/v1/auth/sessions/bulk").method("POST")
                    .header("x-session-token", issued.token.as_str())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))?;
                let result = app.clone().oneshot(request).await?;
                let status = result.status();
                let bytes = to_bytes(result.into_body(), 1_000_000).await?;
                let actual: serde_json::Value = serde_json::from_slice(&bytes)?;
                ensure!(status == expected_status && actual == expected_body,
                    "Rust bulk validation differs from Django: {status} {actual}");
            }
            let request = Request::builder().uri("/api/v1/auth/sessions/bulk").method("POST")
                .header("x-session-token", issued.token.as_str())
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from(r#"{"ids":["missing-session"]}"#))?;
            let result = app.clone().oneshot(request).await?;
            let status = result.status();
            let bytes = to_bytes(result.into_body(), 1_000_000).await?;
            let actual: serde_json::Value = serde_json::from_slice(&bytes)?;
            ensure!(status == StatusCode::OK
                && actual["skipped_ids"] == serde_json::json!(["missing-session"])
                && actual["revoked_ids"] == serde_json::json!([]),
                "Rust bulk rejected valid text/plain JSON accepted by Django: {status} {actual}");
        }
        // Older Django sessions may have no allauth row or metadata. Two
        // instances touching the same session must converge on one row each.
        client.query_client().exec("DELETE FROM core_usersessionmeta WHERE session_key = $key")
            .param("$key", issued.token.clone()).await?;
        client.query_client().exec("DELETE FROM usersessions_usersession WHERE session_key = $key")
            .param("$key", issued.token.clone()).await?;
        let touch_one = id_runtime::sessions_store::list_sessions(&client, codec.clone(),
            &issued.token, true, Some("192.0.2.5"), "synthetic Rust login", SystemTime::now());
        let touch_two = id_runtime::sessions_store::list_sessions(&client, codec.clone(),
            &issued.token, true, Some("192.0.2.5"), "synthetic Rust login", SystemTime::now());
        let (touch_one, touch_two) = tokio::join!(touch_one, touch_two);
        ensure!(touch_one?.is_some() && touch_two?.is_some(), "concurrent legacy touch failed");
        for table in ["core_usersessionmeta", "usersessions_usersession"] {
            let mut count = client.query_client().query_row(format!(
                "SELECT COUNT(*) AS count FROM {table} WHERE session_key = $key"))
                .param("$key", issued.token.clone()).await?;
            let count: u64 = count.remove_field_by_name("count")?.try_into()?;
            ensure!(count == 1, "concurrent touch created {count} {table} rows");
        }
        ensure!(id_runtime::logout_store::revoke_current_session(
            &client, codec.clone(), &other.session.token, SystemTime::now()).await?.is_some(),
            "second session did not revoke");
        if std::env::var("ID_PYTHON_SESSION_CHECK").as_deref() == Ok("true") {
            python_check(serde_json::json!({"token":other.session.token,"account_id":account_id,
                "refresh":other.refresh,"expect_revoked":true}))?;
        }
        ensure!(id_runtime::session_store::restore_django_principal(
            &client, codec.clone(), &other.session.token, LEGACY_BACKENDS, SystemTime::now()).await?.is_none(),
            "revoked session still restored");
        ensure!(id_runtime::session_store::restore_django_principal(
            &client, codec.clone(), &issued.token, LEGACY_BACKENDS, SystemTime::now()).await?.is_some(),
            "logout revoked another device");
        let mut revoked_mapping = client.query_client().query_row(
            "SELECT revoked_at, refresh_jti FROM core_usersessiontoken WHERE session_key = $key LIMIT 1")
            .param("$key", other.session.token.clone()).await?;
        let revoked_at: Option<SystemTime> = revoked_mapping.remove_field_by_name("revoked_at")?.try_into()?;
        let revoked_jti: String = revoked_mapping.remove_field_by_name("refresh_jti")?.try_into()?;
        ensure!(revoked_at.is_some(), "refresh mapping remains active");
        let mut outstanding = client.query_client().query_row(
            "SELECT id FROM token_blacklist_outstandingtoken WHERE user_id = $id AND jti = $jti LIMIT 1")
            .param("$id", account_id).param("$jti", revoked_jti).await?;
        let outstanding_id: i64 = outstanding.remove_field_by_name("id")?.try_into()?;
        ensure!(client.query_client().query_row(
            "SELECT id FROM token_blacklist_blacklistedtoken WHERE token_id = $id LIMIT 1")
            .param("$id", outstanding_id).optional().await?.is_some(),
            "refresh was not blacklisted for Python");
        ensure!(client.query_client().query_row(
            "SELECT id FROM core_usersessiontoken WHERE session_key = $key AND revoked_at IS NULL LIMIT 1")
            .param("$key", issued.token.clone()).optional().await?.is_some(),
            "other refresh mapping was revoked");
        let after = id_runtime::sessions_store::list_sessions(&client, codec.clone(),
            &issued.token, true, Some("192.0.2.5"), "synthetic Rust login", SystemTime::now())
            .await?.context("remaining session could not list sessions")?;
        ensure!(after.len() == 2 && after.iter().any(|row|
            row.id == other.session.token && row.revoked && row.expires.is_none()
            && row.revoked_reason.as_deref() == Some("logout")),
            "Rust session list lost revoked history or expiry state");
        if std::env::var("ID_PYTHON_SESSION_CHECK").as_deref() == Ok("true") {
            let output = python_check(serde_json::json!({"token":issued.token,
                "account_id":account_id,"session_list":true}))?;
            let python_rows: serde_json::Value = serde_json::from_str(&output)?;
            ensure!(python_rows == serde_json::json!({"sessions":after}),
                "Python and Rust disagree on revoked session history");
        }
        use id_runtime::session_revoke::{Outcome, Selection, TouchContext, revoke_sessions};
        client.query_client().exec("DELETE FROM core_usersessionmeta WHERE session_key = $key")
            .param("$key", issued.token.clone()).await?;
        client.query_client().exec("DELETE FROM usersessions_usersession WHERE session_key = $key")
            .param("$key", issued.token.clone()).await?;
        let actor_touch = TouchContext {
            x_session_header: true,
            ip: "198.51.100.8".into(),
            user_agent: "Rust session mutation".into(),
        };
        ensure!(revoke_sessions(&client, codec.clone(), &issued.token,
            Selection::One("missing-session".into()), "manual", actor_touch.clone(), SystemTime::now()).await?
            == Outcome::Missing, "unknown session did not return 404 state");
        let mut touched_meta = client.query_client().query_row(
            "SELECT session_token, ip, user_agent FROM core_usersessionmeta WHERE session_key = $key")
            .param("$key", issued.token.clone()).await?;
        let touched_token: Option<String> = touched_meta.remove_field_by_name("session_token")?.try_into()?;
        let touched_ip: Option<String> = touched_meta.remove_field_by_name("ip")?.try_into()?;
        let touched_agent: String = touched_meta.remove_field_by_name("user_agent")?.try_into()?;
        ensure!(touched_token.as_deref() == Some(issued.token.as_str())
            && touched_ip.as_deref() == Some("198.51.100.8")
            && touched_agent == "Rust session mutation",
            "mutation did not recreate legacy session metadata");
        let mut touched_tracked = client.query_client().query_row(
            "SELECT ip, user_agent FROM usersessions_usersession WHERE session_key = $key")
            .param("$key", issued.token.clone()).await?;
        let tracked_ip: String = touched_tracked.remove_field_by_name("ip")?.try_into()?;
        let tracked_agent: String = touched_tracked.remove_field_by_name("user_agent")?.try_into()?;
        ensure!(tracked_ip == "198.51.100.8" && tracked_agent == "Rust session mutation",
            "mutation did not recreate tracked legacy session");
        client.query_client().exec("UPDATE core_usersessionmeta SET session_token = NULL, ip = '', user_agent = '' WHERE session_key = $key")
            .param("$key", issued.token.clone()).await?;
        ensure!(revoke_sessions(&client, codec.clone(), &issued.token,
            Selection::One("missing-session".into()), "manual", actor_touch.clone(), SystemTime::now()).await?
            == Outcome::Missing);
        let mut fresh_meta = client.query_client().query_row(
            "SELECT session_token, ip, user_agent FROM core_usersessionmeta WHERE session_key = $key")
            .param("$key", issued.token.clone()).await?;
        let fresh_token: Option<String> = fresh_meta.remove_field_by_name("session_token")?.try_into()?;
        let fresh_ip: Option<String> = fresh_meta.remove_field_by_name("ip")?.try_into()?;
        let fresh_agent: String = fresh_meta.remove_field_by_name("user_agent")?.try_into()?;
        ensure!(fresh_token.as_deref() == Some(issued.token.as_str())
            && fresh_ip.as_deref() == Some("") && fresh_agent.is_empty(),
            "throttled touch changed IP or agent when only header token was due");
        let stale = SystemTime::now() - Duration::from_secs(60);
        client.query_client().exec("UPDATE core_usersessionmeta SET last_seen = CAST($old AS Datetime) WHERE session_key = $key")
            .param("$old", stale).param("$key", issued.token.clone()).await?;
        client.query_client().exec("UPDATE usersessions_usersession SET last_seen_at = CAST($old AS Datetime) WHERE session_key = $key")
            .param("$old", stale).param("$key", issued.token.clone()).await?;
        let foreign_key = format!("foreign-session-{stamp}");
        client.query_client().exec("INSERT INTO core_usersessionmeta (id, user_id, session_key, user_agent, first_seen, revoked_reason) VALUES ($id, $user_id, $key, '', CurrentUtcDatetime(), '')")
            .param("$id", i64::from(account_id) - 1)
            .param("$user_id", account_id - 1).param("$key", foreign_key.clone()).await?;
        let foreign = revoke_sessions(&client, codec.clone(), &issued.token,
            Selection::One(foreign_key.clone()), "manual", TouchContext::default(), SystemTime::now()).await?;
        client.query_client().exec("DELETE FROM core_usersessionmeta WHERE id = $id")
            .param("$id", i64::from(account_id) - 1).await?;
        ensure!(foreign == Outcome::Missing, "foreign session was visible to another owner");
        for (table, column) in [("core_usersessionmeta", "last_seen"),
            ("usersessions_usersession", "last_seen_at")] {
            let mut row = client.query_client().query_row(format!(
                "SELECT {column} FROM {table} WHERE session_key = $key"))
                .param("$key", issued.token.clone()).await?;
            let last_seen: Option<SystemTime> = row.remove_field_by_name(column)?.try_into()?;
            let last_seen = last_seen.context("mutation left activity timestamp empty")?;
            ensure!(last_seen.duration_since(stale).unwrap_or_default() >= Duration::from_secs(45),
                "mutation did not refresh {table} activity");
        }
        let third = issue_password_login(&client, codec.clone(), &jwt_codec, &verified,
            &request, SystemTime::now(), lifetime).await?.context("third session was not issued")?;
        tokens_to_clean.push((third.session.token.clone(), third.refresh.clone()));
        if let Some(app) = sessions_app.as_ref() {
            let path = format!("/api/v1/auth/sessions/{}", third.session.token);
            let (status, body) = sessions_http_mutate(app, "DELETE", &path,
                Some(&issued.token), None, None, None).await?;
            ensure!(status == StatusCode::FORBIDDEN && body["code"] == "CSRF_FAILED",
                "browser DELETE without CSRF was accepted");
            let (status, body) = sessions_http_mutate(app, "DELETE", "/api/v1/auth/sessions/missing-session",
                None, Some(&issued.token), None, None).await?;
            ensure!(status == StatusCode::NOT_FOUND && body["code"] == "HTTP_ERROR"
                && body["detail"] == "session not found",
                "unknown session did not return HTTP 404");
        }
        let single = revoke_sessions(&client, codec.clone(), &issued.token,
            Selection::One(third.session.token.clone()), "Manual", TouchContext::default(), SystemTime::now()).await?;
        ensure!(matches!(single, Outcome::One { ref id, ref reason, .. }
            if id == &third.session.token && reason == "manual"),
            "single session revoke did not return its receipt");
        if std::env::var("ID_PYTHON_SESSION_CHECK").as_deref() == Ok("true") {
            python_check(serde_json::json!({"token":third.session.token,"account_id":account_id,
                "refresh":third.refresh,"expect_revoked":true,"keep_history":true}))?;
        }
        let fourth = issue_password_login(&client, codec.clone(), &jwt_codec, &verified,
            &request, SystemTime::now(), lifetime).await?.context("fourth session was not issued")?;
        tokens_to_clean.push((fourth.session.token.clone(), fourth.refresh.clone()));
        if let Some(app) = sessions_app.as_ref() {
            let (status, body) = sessions_http_mutate(app, "POST", "/api/v1/auth/sessions/_bulk",
                None, Some(&issued.token), None, Some(serde_json::json!({"all_except_current":true}))).await?;
            ensure!(status == StatusCode::OK && body["current"] == issued.token
                && body["revoked_ids"] == serde_json::json!([fourth.session.token])
                && body["skipped_ids"].as_array().is_some_and(|rows| rows.len() == 2),
                "bulk alias did not isolate the current session and prior revocations: {status} {body}");
        } else {
            let bulk = revoke_sessions(&client, codec.clone(), &issued.token,
                Selection::Bulk { ids: None, all_except_current: true },
                "bulk_except_current", TouchContext::default(), SystemTime::now()).await?;
            ensure!(matches!(bulk, Outcome::Bulk { ref current, ref revoked_ids, ref skipped_ids, .. }
                if current == &issued.token && revoked_ids == &vec![fourth.session.token.clone()]
                    && skipped_ids.contains(&other.session.token) && skipped_ids.contains(&third.session.token)),
                "bulk revoke did not isolate the current session and prior revocations");
        }
        ensure!(id_runtime::session_store::restore_django_principal(
            &client, codec.clone(), &issued.token, LEGACY_BACKENDS, SystemTime::now()).await?.is_some(),
            "bulk revoke killed the current session");
        if std::env::var("ID_PYTHON_SESSION_CHECK").as_deref() == Ok("true") {
            python_check(serde_json::json!({"token":fourth.session.token,"account_id":account_id,
                "refresh":fourth.refresh,"expect_revoked":true,"keep_history":true}))?;
        }
        let fifth = issue_password_login(&client, codec.clone(), &jwt_codec, &verified,
            &request, SystemTime::now(), lifetime).await?.context("fifth session was not issued")?;
        tokens_to_clean.push((fifth.session.token.clone(), fifth.refresh.clone()));
        if let Some(app) = sessions_app.as_ref() {
            let path = format!("/api/v1/auth/sessions/{}", fifth.session.token);
            let (status, body) = sessions_http_mutate(app, "DELETE", &path,
                Some(&issued.token), Some("invalid"), Some("abcdefghijklmnopqrstuvwxyzABCDEF"), None).await?;
            ensure!(status == StatusCode::UNAUTHORIZED && body["code"] == "INVALID_OR_EXPIRED_TOKEN",
                "invalid header fell back to cookie on DELETE");
            let (status, body) = sessions_http_mutate(app, "DELETE", &path,
                Some(&issued.token), None, Some("abcdefghijklmnopqrstuvwxyzABCDEF"), None).await?;
            ensure!(status == StatusCode::OK && body["id"] == fifth.session.token,
                "CSRF-protected browser revoke failed: {status} {body}");
        } else {
            ensure!(matches!(revoke_sessions(&client, codec.clone(), &issued.token,
                Selection::One(fifth.session.token.clone()), "manual", TouchContext::default(), SystemTime::now()).await?,
                Outcome::One { .. }));
        }
        if std::env::var("ID_PYTHON_SESSION_CHECK").as_deref() == Ok("true") {
            python_check(serde_json::json!({"token":fifth.session.token,"account_id":account_id,
                "refresh":fifth.refresh,"expect_revoked":true,"keep_history":true}))?;
        }
        let sixth = issue_password_login(&client, codec.clone(), &jwt_codec, &verified,
            &request, SystemTime::now(), lifetime).await?.context("sixth session was not issued")?;
        tokens_to_clean.push((sixth.session.token.clone(), sixth.refresh.clone()));
        if let Some(app) = sessions_app.as_ref() {
            let (status, body) = sessions_http_mutate(app, "POST", "/api/v1/auth/sessions/bulk",
                None, Some(&issued.token), None,
                Some(serde_json::json!({"ids":[sixth.session.token,"missing-session"],
                    "all_except_current":true}))).await?;
            ensure!(status == StatusCode::OK && body["revoked_ids"] == serde_json::json!([sixth.session.token])
                && body["skipped_ids"] == serde_json::json!(["missing-session"]),
                "bulk explicit IDs did not separate owned and missing targets: {status} {body}");
        } else {
            let outcome = revoke_sessions(&client, codec.clone(), &issued.token,
                Selection::Bulk { ids: Some(vec![sixth.session.token.clone(), "missing-session".into()]),
                    all_except_current: true }, "bulk_except_current", TouchContext::default(), SystemTime::now()).await?;
            ensure!(matches!(outcome, Outcome::Bulk { ref revoked_ids, ref skipped_ids, .. }
                if revoked_ids == &vec![sixth.session.token.clone()] && skipped_ids == &vec!["missing-session".to_owned()]));
        }
        if std::env::var("ID_PYTHON_SESSION_CHECK").as_deref() == Ok("true") {
            python_check(serde_json::json!({"token":sixth.session.token,"account_id":account_id,
                "refresh":sixth.refresh,"expect_revoked":true,"keep_history":true}))?;
        }
        let mut active_mapping = client.query_client().query_row(
            "SELECT refresh_jti FROM core_usersessiontoken WHERE session_key = $key AND revoked_at IS NULL LIMIT 1")
            .param("$key", issued.token.clone()).await?;
        let active_jti: String = active_mapping.remove_field_by_name("refresh_jti")?.try_into()?;
        let mut active_outstanding = client.query_client().query_row(
            "SELECT token FROM token_blacklist_outstandingtoken WHERE user_id = $id AND jti = $jti LIMIT 1")
            .param("$id", account_id).param("$jti", active_jti).await?;
        let active_refresh: String = active_outstanding.remove_field_by_name("token")?.try_into()?;
        if let Some(app) = sessions_app.as_ref() {
            let csrf = "abcdefghijklmnopqrstuvwxyzABCDEF";
            let request = Request::builder()
                .uri(format!("/api/v1/auth/sessions/{}", issued.token)).method("DELETE")
                .header(header::ORIGIN, "http://id.localhost:5175")
                .header(header::COOKIE, format!("sessionid={}; csrftoken={csrf}", issued.token))
                .header("x-csrftoken", csrf).body(Body::empty())?;
            let response = app.clone().oneshot(request).await?;
            ensure!(response.status() == StatusCode::OK
                && response.headers().get_all(header::SET_COOKIE).iter()
                    .filter_map(|value| value.to_str().ok())
                    .any(|value| value.starts_with("sessionid=") && value.contains("Max-Age=0")),
                "self-revoke did not clear the browser session cookie");
        } else {
            ensure!(matches!(revoke_sessions(&client, codec.clone(), &issued.token,
                Selection::One(issued.token.clone()), "manual", TouchContext::default(), SystemTime::now()).await?,
                Outcome::One { .. }));
        }
        if std::env::var("ID_PYTHON_SESSION_CHECK").as_deref() == Ok("true") {
            python_check(serde_json::json!({"token":issued.token,"account_id":account_id,
                "refresh":active_refresh,"expect_revoked":true,"keep_history":true}))?;
            python_check(serde_json::json!({"token":issued.token,"account_id":account_id,
                "refresh":extra_refresh,"expect_revoked":true,"keep_history":true}))?;
        }
        let (status, _, _) = jwt_session_http_call(&jwt_app, Some(&issued.token), None, false).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "revoked session still minted account JWT");
        let mut active = client.query_client().query_row(
            "SELECT COUNT(*) AS count FROM core_usersessiontoken WHERE session_key = $key AND revoked_at IS NULL")
            .param("$key", issued.token.clone()).await?;
        let active: u64 = active.remove_field_by_name("count")?.try_into()?;
        ensure!(active == 0, "logout left a session-bound refresh active");
        let refresh_session = issue_password_login(&client, codec.clone(), &jwt_codec, &verified,
            &request, SystemTime::now(), lifetime).await?
            .context("refresh test session was not issued")?;
        tokens_to_clean.push((refresh_session.session.token.clone(), refresh_session.refresh.clone()));
        client.query_client().exec("UPDATE usid_user SET status = 'suspended' WHERE user_id = $id")
            .param("$id", identity_id).await?;
        let (status, _, _) = jwt_refresh_http_call(&jwt_app, &refresh_session.refresh).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "suspended identity rotated an account refresh");
        client.query_client().exec("UPDATE usid_user SET status = 'active' WHERE user_id = $id")
            .param("$id", identity_id).await?;
        client.query_client().exec("UPSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($row_id, $user_id, 'totp', Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime())")
            .param("$row_id", i64::from(account_id)).param("$user_id", account_id).await?;
        let (status, _, _) = jwt_refresh_http_call(&jwt_app, &refresh_session.refresh).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "session without MFA proof rotated an account refresh");
        client.query_client().exec("DELETE FROM mfa_authenticator WHERE id = $id")
            .param("$id", i64::from(account_id)).await?;
        let (status, rotated, headers) = jwt_refresh_http_call(&jwt_app, &refresh_session.refresh).await?;
        ensure!(status == StatusCode::OK
            && headers[header::CACHE_CONTROL] == "private, no-store"
            && rotated["access"].as_str().is_some()
            && rotated["refresh"].as_str().is_some(),
            "Rust account refresh rotation failed: {status}");
        let descendant = rotated["refresh"].as_str().context("rotated refresh missing")?.to_owned();
        tokens_to_clean.push((refresh_session.session.token.clone(), descendant.clone()));
        let (status, _, _) = jwt_refresh_http_call(&jwt_app, &refresh_session.refresh).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "replayed account refresh was accepted");
        let (status, _, _) = jwt_refresh_http_call(&jwt_app, &descendant).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "replay left a descendant refresh usable");
        ensure!(id_runtime::session_store::restore_django_principal(
            &client, codec.clone(), &refresh_session.session.token, LEGACY_BACKENDS,
            SystemTime::now()).await?.is_none(), "replay left its backing session alive");
        let mut active = client.query_client().query_row(
            "SELECT COUNT(*) AS count FROM core_usersessiontoken WHERE session_key = $key AND revoked_at IS NULL")
            .param("$key", refresh_session.session.token.clone()).await?;
        let active: u64 = active.remove_field_by_name("count")?.try_into()?;
        ensure!(active == 0, "replay left descendant mappings active");
        if std::env::var("ID_PYTHON_SESSION_CHECK").as_deref() == Ok("true") {
            python_check(serde_json::json!({"token":refresh_session.session.token,"account_id":account_id,
                "refresh":descendant,"expect_revoked":true,"keep_history":true}))?;
        }
        let race_session = issue_password_login(&client, codec.clone(), &jwt_codec, &verified,
            &request, SystemTime::now(), lifetime).await?
            .context("refresh race session was not issued")?;
        tokens_to_clean.push((race_session.session.token.clone(), race_session.refresh.clone()));
        let second_client = Arc::new(id_runtime::connect_ydb().await?);
        let race_codec = Arc::new(AccountJwtCodec::new(b"synthetic-local-secret-min-32-characters")?);
        let barrier = Arc::new(tokio::sync::Barrier::new(100));
        let mut contenders = tokio::task::JoinSet::new();
        for index in 0..100 {
            let client = if index % 2 == 0 { client.clone() } else { second_client.clone() };
            let codec = codec.clone();
            let jwt = race_codec.clone();
            let refresh = race_session.refresh.clone();
            let barrier = barrier.clone();
            contenders.spawn(async move {
                barrier.wait().await;
                id_runtime::account_jwt_refresh::rotate(&client, codec, jwt, &refresh,
                    SystemTime::now()).await
            });
        }
        let mut winners = 0;
        while let Some(result) = contenders.join_next().await {
            match result?? {
                id_runtime::account_jwt_refresh::RefreshOutcome::Rotated(_) => winners += 1,
                id_runtime::account_jwt_refresh::RefreshOutcome::Invalid
                | id_runtime::account_jwt_refresh::RefreshOutcome::ReplayRevoked => {},
            }
        }
        ensure!(winners == 1, "{winners} refresh rotations succeeded in 100-way race");
        let mut active = client.query_client().query_row(
            "SELECT COUNT(*) AS count FROM core_usersessiontoken WHERE session_key = $key AND revoked_at IS NULL")
            .param("$key", race_session.session.token.clone()).await?;
        let active: u64 = active.remove_field_by_name("count")?.try_into()?;
        ensure!(active == 0, "refresh race replay left descendants active");
        client.query_client().exec("UPSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $user_id, 'recovery_codes', Unwrap(CAST($data AS Json)), CurrentUtcDatetime())")
            .param("$id", i64::from(account_id)).param("$user_id", account_id)
            .param("$data", serde_json::json!({"migrated_codes":["87654321","12345678"]}).to_string()).await?;
        let verifier = LoginPreflight::new(client.clone(), 1)?;
        let LoginDecision::MfaRequired(delete_verified) = verifier.verify(&email, PASSWORD).await? else {
            anyhow::bail!("deletion test account did not require MFA")
        };
        let deletion_cache = id_runtime::cache_store::CacheStore::new(client.clone(), "id_shared_cache", "", 1)?;
        let delete_session = id_runtime::session_issuer::issue_password_login_with_mfa(
            &client, codec.clone(), &jwt_codec, &delete_verified, &request,
            id_runtime::session_issuer::IssueTiming { now: SystemTime::now(), lifetime },
            id_runtime::session_issuer::MfaProof { cache: &deletion_cache, code: "87654321" },
        ).await?
            .context("account deletion test session was not issued")?;
        tokens_to_clean.push((delete_session.session.token.clone(), delete_session.refresh.clone()));
        let deletion = id_runtime::account_deletion::AccountDeletion::new(
            client.clone(), codec.clone(), deletion_cache,
            None, b"synthetic-deletion-operation-key-min-32-characters", 2,
        )?;
        let deletion_app = id_runtime::account_deletion_http::router(Arc::new(
            id_runtime::account_deletion_http::AccountDeletionHttpConfig::new(
                deletion, "sessionid".into(), "csrftoken".into(),
                vec!["http://id.localhost:5175".into()],
            )?,
        ));
        let (status, _) = deletion_http_call(&deletion_app, Some(&delete_session.session.token),
            None, Some("deletion-once"), false, "wrong password").await?;
        ensure!(status == StatusCode::BAD_REQUEST, "wrong password accepted for deletion");
        let (status, _) = deletion_http_call(&deletion_app, Some("invalid"),
            Some(&delete_session.session.token), Some("deletion-once"), false, PASSWORD).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "invalid header fell back to deletion cookie");
        let (status, _) = deletion_http_call(&deletion_app, None,
            Some(&delete_session.session.token), Some("deletion-once"), false, PASSWORD).await?;
        ensure!(status == StatusCode::FORBIDDEN, "deletion cookie bypassed CSRF");
        let (status, _) = deletion_http_call(&deletion_app,
            Some(&delete_session.session.token), None, None, false, PASSWORD).await?;
        ensure!(status == StatusCode::BAD_REQUEST, "deletion accepted without an idempotency key");
        let (status, _) = deletion_http_call(&deletion_app,
            Some(&delete_session.session.token), None, Some("deletion-once"), false, PASSWORD).await?;
        ensure!(status == StatusCode::BAD_REQUEST, "deletion accepted without MFA reauthentication");
        let (status, _) = deletion_http_call_with_mfa(&deletion_app,
            Some(&delete_session.session.token), None, Some("deletion-once"), false,
            PASSWORD, Some("wrong-code")).await?;
        ensure!(status == StatusCode::BAD_REQUEST, "deletion accepted invalid MFA proof");
        let (status, accepted) = deletion_http_call_with_mfa(&deletion_app,
            None, Some(&delete_session.session.token), Some("deletion-once"), true,
            PASSWORD, Some("12345678")).await?;
        ensure!(status == StatusCode::ACCEPTED && accepted["status"] == "pending"
            && accepted["id"].as_str().is_some(), "deletion acceptance was not durable: {status} {accepted}");
        let (status, repeated) = deletion_http_call(&deletion_app,
            Some(&delete_session.session.token), None, Some("deletion-once"), false, PASSWORD).await?;
        ensure!(status == StatusCode::ACCEPTED && repeated["id"] == accepted["id"],
            "idempotent deletion retry changed operation");
        let (status, _) = deletion_http_call(&deletion_app,
            Some(&delete_session.session.token), None, Some("another-key"), false, PASSWORD).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "revoked session started another deletion");
        ensure!(id_runtime::session_store::restore_django_principal(&client, codec.clone(),
            &delete_session.session.token, LEGACY_BACKENDS, SystemTime::now()).await?.is_none(),
            "accepted deletion left session active");
        let mut account = client.query_client().query_row("SELECT is_active FROM auth_user WHERE id = $id")
            .param("$id", account_id).await?;
        let active: bool = account.remove_field_by_name("is_active")?.try_into()?;
        ensure!(!active, "accepted deletion left account active");
        let mut request = client.query_client().query_row("SELECT status FROM accounts_accountdeletionrequest WHERE id = $id")
            .param("$id", accepted["id"].as_str().context("missing deletion id")?.parse::<i64>()?).await?;
        let state: String = request.remove_field_by_name("status")?.try_into()?;
        ensure!(state == "pending", "deletion claimed cleanup completed before jobs ran");
        let operation_id: i64 = accepted["id"].as_str().context("missing deletion ID")?.parse()?;
        let operator_status = id_runtime::account_deletion::read_status(&client, operation_id)
            .await?.context("operator could not read deletion status")?;
        ensure!(operator_status.status == "pending" && !operator_status.cleanup_completed,
            "operator status incorrectly claimed cleanup was complete");
        let mut recovery = client.query_client().query_row("SELECT CAST(data AS Utf8) AS data FROM mfa_authenticator WHERE id = $id")
            .param("$id", i64::from(account_id)).await?;
        let recovery: String = recovery.remove_field_by_name("data")?.try_into()?;
        let recovery: serde_json::Value = serde_json::from_str(&recovery)?;
        ensure!(recovery["migrated_codes"] == serde_json::json!([]),
            "account deletion reauthentication did not consume its recovery code");
        if std::env::var("ID_PYTHON_SESSION_CHECK").as_deref() == Ok("true") {
            python_check(serde_json::json!({"token":delete_session.session.token,
                "account_id":account_id,"refresh":delete_session.refresh,"expect_revoked":true}))?;
        }
        id_runtime::passkey_index::ensure_schema(&client).await?;
        let index_digest = format!("synthetic-deletion-{account_id}");
        client.query_client().exec("INSERT INTO id_passkey_credential (digest, authenticator_id, account_id) VALUES ($digest, $authenticator, $account)")
            .param("$digest", index_digest.clone()).param("$authenticator", i64::from(account_id))
            .param("$account", account_id).await?;
        client.query_client().exec("UPSERT INTO token_blacklist_outstandingtoken (id, user_id, jti, token, expires_at) VALUES ($id, $user_id, $jti, 'synthetic-revoked-token', CAST($expires AS Datetime))")
            .param("$id", i64::from(account_id)).param("$user_id", account_id)
            .param("$jti", format!("deletion-{stamp}"))
            .param("$expires", SystemTime::now() + Duration::from_secs(3600)).await?;
        client.query_client().exec("UPSERT INTO token_blacklist_blacklistedtoken (id, token_id, blacklisted_at) VALUES ($id, $id, CurrentUtcDatetime())")
            .param("$id", i64::from(account_id)).await?;
        client.query_client().exec("UPSERT INTO socialaccount_socialaccount (id, user_id, provider, uid, last_login, date_joined, extra_data) VALUES ($id, $user_id, 'synthetic', $uid, CurrentUtcDatetime(), CurrentUtcDatetime(), Unwrap(CAST('{}' AS Json)))")
            .param("$id", account_id).param("$user_id", account_id)
            .param("$uid", format!("deletion-{stamp}")).await?;
        client.query_client().exec("UPSERT INTO socialaccount_socialtoken (id, account_id, token, token_secret) VALUES ($id, $account_id, 'synthetic-provider-token', 'synthetic-provider-secret')")
            .param("$id", account_id).param("$account_id", account_id).await?;
        client.query_client().exec("UPSERT INTO account_emailconfirmation (id, email_address_id, created, key) VALUES ($id, $id, CurrentUtcDatetime(), 'synthetic-email-key')")
            .param("$id", account_id).await?;
        let avatar_key = format!("avatars/user_{account_id}/synthetic.jpg");
        client.query_client().exec("UPSERT INTO accounts_userprofile (id, user_id, avatar, avatar_source, gravatar_enabled, phone_number, phone_verified, created_at, updated_at) VALUES ($id, $user_id, $avatar, 'upload', false, '', false, CurrentUtcDatetime(), CurrentUtcDatetime())")
            .param("$id", i64::from(account_id)).param("$user_id", account_id)
            .param("$avatar", ydb::Value::Bytes(avatar_key.clone().into_bytes().into())).await?;
        let drain = id_runtime::account_deletion_cleanup::drain_pending(&client, 10).await?;
        ensure!(drain.attempted == 1 && drain.completed == 1 && drain.deferred == 0,
            "timer recovery did not drain the pending deletion: {drain:?}");
        let erased = id_runtime::account_deletion_cleanup::erase_credentials(&client, operation_id)
            .await?.context("credential cleanup did not find deletion operation")?;
        ensure!(erased.status == "running" && erased.credential_stage_completed && !erased.cleanup_completed,
            "credential stage claimed full account cleanup");
        let repeated = id_runtime::account_deletion_cleanup::erase_credentials(&client, operation_id)
            .await?.context("repeat credential cleanup lost operation")?;
        ensure!(repeated == erased, "credential cleanup is not repeatable");
        ensure!(client.query_client().query_row("SELECT id FROM mfa_authenticator WHERE user_id = $id LIMIT 1")
            .param("$id", account_id).optional().await?.is_none(),
            "MFA credential survived deletion worker");
        ensure!(client.query_client().query_row("SELECT digest FROM id_passkey_credential WHERE digest = $digest")
            .param("$digest", index_digest).optional().await?.is_none(),
            "passkey credential index survived deletion worker");
        ensure!(client.query_client().query_row("SELECT id FROM token_blacklist_blacklistedtoken WHERE token_id = $id LIMIT 1")
            .param("$id", i64::from(account_id)).optional().await?.is_none(),
            "blacklisted token survived deletion worker");
        for (table, column) in [
            ("socialaccount_socialtoken", "account_id"),
            ("account_emailconfirmation", "email_address_id"),
        ] {
            ensure!(client.query_client().query_row(format!("SELECT id FROM {table} WHERE {column} = $id LIMIT 1"))
                .param("$id", account_id).optional().await?.is_none(),
                "dependent credential survived deletion worker: {table}");
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let media_port = listener.local_addr()?.port();
        let media_server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut bytes = [0u8; 4096];
            let size = stream.read(&mut bytes).await?;
            let request = String::from_utf8_lossy(&bytes[..size]).to_ascii_lowercase();
            ensure!(request.starts_with(&format!("delete /id-media/avatars/user_{account_id}/synthetic.jpg http/1.1")),
                "media worker sent an unexpected object request");
            stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").await?;
            Result::<()>::Ok(())
        });
        let media = id_runtime::media_delete::S3MediaDelete::new(
            &format!("http://127.0.0.1:{media_port}/"), "id-media", "ru-central1",
            "synthetic-access".into(), "synthetic-secret".into())?;
        let avatars = id_runtime::account_deletion_cleanup::drain_pending_avatars(&client, Some(&media), 10).await?;
        ensure!(avatars.attempted == 1 && avatars.completed == 1 && avatars.deferred == 0,
            "timer did not finish avatar deletion: {avatars:?}");
        media_server.await??;
        let no_more = id_runtime::account_deletion_cleanup::drain_pending_avatars(&client, Some(&media), 10).await?;
        ensure!(no_more.attempted == 0, "completed avatar was retried");
        let mut progress = client.query_client().query_row("SELECT avatar_done FROM id_deletion_progress WHERE operation_id = $id")
            .param("$id", operation_id).await?;
        let avatar_done: bool = progress.remove_field_by_name("avatar_done")?.try_into()?;
        ensure!(avatar_done, "avatar completion marker was not durable");
        let mut profile = client.query_client().query_row("SELECT CAST(avatar AS Utf8) AS avatar_key FROM accounts_userprofile WHERE id = $id")
            .param("$id", i64::from(account_id)).await?;
        let avatar_after: Option<String> = profile.remove_field_by_name("avatar_key")?.try_into()?;
        ensure!(avatar_after.is_none(), "avatar key survived successful object deletion");
        id_runtime::data_export_operation::ensure_schema(&client).await?;
        let export_id = format!("{account_id:032x}");
        let export_key = format!("exports/user_{account_id}/{export_id}/synthetic.ndjson");
        client.query_client().exec("INSERT INTO id_data_export_operation (id, user_id, status, attempts, next_attempt_at, claim_token, object_key, manifest, created_at) VALUES ($id, $owner, 'succeeded', 1, CurrentUtcDatetime(), '', $key, '{}', CurrentUtcDatetime())")
            .param("$id", export_id.clone()).param("$owner", account_id)
            .param("$key", export_key.clone()).await?;
        let running_export_id = format!("{:032x}", account_id + 1);
        let lease = SystemTime::now() + Duration::from_secs(15 * 60);
        client.query_client().exec("INSERT INTO id_data_export_operation (id, user_id, status, attempts, next_attempt_at, lease_until, claim_token, object_key, manifest, created_at) VALUES ($id, $owner, 'running', 1, CAST($lease AS Datetime), CAST($lease AS Datetime), $token, '', '', CurrentUtcDatetime())")
            .param("$id", running_export_id.clone()).param("$owner", account_id)
            .param("$lease", lease).param("$token", Uuid::new_v4().to_string()).await?;
        let blocked = id_runtime::account_deletion_cleanup::drain_pending_profiles(&client, 10).await?;
        ensure!(blocked.attempted == 1 && blocked.deferred == 1 && blocked.completed == 0,
            "profile deletion ignored an owned export: {blocked:?}");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let export_port = listener.local_addr()?.port();
        let orphan_key = format!("exports/user_{account_id}/orphan/attempt.ndjson");
        let export_server = tokio::spawn(async move {
            for index in 0..4 {
                let (mut stream, _) = listener.accept().await?;
                let mut bytes = [0u8; 4096];
                let size = stream.read(&mut bytes).await?;
                let request = String::from_utf8_lossy(&bytes[..size]).to_ascii_lowercase();
                match index {
                    0 | 2 => {
                        let key = if index == 0 { &export_key } else { &orphan_key };
                        ensure!(request.starts_with(&format!("delete /private-exports/{key} http/1.1")),
                            "deletion worker sent an unexpected export DELETE");
                        stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
                    }
                    _ => {
                        ensure!(request.starts_with("get /private-exports?list-type=2&max-keys=25&prefix=")
                            && request.contains(&format!("user_{account_id}%2f")),
                            "deletion worker did not list the owner's S3 prefix");
                        let contents = if index == 1 {
                            format!("<Contents><Key>{orphan_key}</Key></Contents>")
                        } else { String::new() };
                        let body = format!("<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>private-exports</Name><Prefix>exports/user_{account_id}/</Prefix><IsTruncated>false</IsTruncated>{contents}</ListBucketResult>");
                        stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await?;
                    }
                }
            }
            Result::<()>::Ok(())
        });
        let export_storage = id_runtime::data_export_s3::S3Export::new(
            &format!("http://127.0.0.1:{export_port}/"), "private-exports", "ru-central1",
            "synthetic-access".into(), "synthetic-secret".into())?;
        let leased = id_runtime::account_deletion_cleanup::drain_pending_profiles_with_exports(
            &client, Some(&export_storage), 10,
        ).await?;
        ensure!(leased.attempted == 1 && leased.deferred == 1 && leased.completed == 0,
            "profile deletion ignored an active export lease: {leased:?}");
        client.query_client().exec("UPDATE id_data_export_operation SET lease_until = CAST($past AS Datetime) WHERE id = $id")
            .param("$past", SystemTime::now() - Duration::from_secs(1))
            .param("$id", running_export_id).await?;
        let orphaned = id_runtime::account_deletion_cleanup::drain_pending_profiles_with_exports(
            &client, Some(&export_storage), 10,
        ).await?;
        ensure!(orphaned.attempted == 1 && orphaned.deferred == 1 && orphaned.completed == 0,
            "profile deletion did not await S3 prefix reconciliation: {orphaned:?}");
        let profiles = id_runtime::account_deletion_cleanup::drain_pending_profiles_with_exports(
            &client, Some(&export_storage), 10,
        ).await?;
        export_server.await??;
        ensure!(profiles.attempted == 1 && profiles.completed == 1 && profiles.deferred == 0,
            "timer did not remove profile/history: {profiles:?}");
        ensure!(id_runtime::data_export_operation::for_owner(&client, account_id, 1).await?.is_empty(),
            "deleted account retained an export owner binding");
        let no_profiles = id_runtime::account_deletion_cleanup::drain_pending_profiles(&client, 10).await?;
        ensure!(no_profiles.attempted == 0, "completed profile stage was retried");
        for table in ["accounts_userprofile", "accounts_loginevent", "accounts_userdevice", "account_emailaddress"] {
            ensure!(client.query_client().query_row(format!("SELECT user_id FROM {table} WHERE user_id = $id LIMIT 1"))
                .param("$id", account_id).optional().await?.is_none(),
                "owner-scoped personal data survived profile stage: {table}");
        }
        ensure!(client.query_client().query_row("SELECT user_id FROM accounts_accountidentity WHERE user_id = $id")
            .param("$id", account_id).optional().await?.is_some(),
            "profile stage removed the identity binding before final audit");
        ensure!(client.query_client().query_row("SELECT session_key FROM django_session WHERE session_key = $key")
            .param("$key", delete_session.session.token.clone()).optional().await?.is_none(),
            "known browser session survived profile stage");
        ensure!(client.query_client().query_row("SELECT user_id FROM core_usersessionmeta VIEW core_usersessionmeta_session_key_2f41cf47 WHERE session_key = $key LIMIT 1")
            .param("$key", delete_session.session.token.clone()).optional().await?.is_some(),
            "profile stage removed retry ownership before final audit");
        let operator_status = id_runtime::account_deletion::read_status(&client, operation_id)
            .await?.context("operator lost deletion status")?;
        ensure!(operator_status.status == "running" && !operator_status.cleanup_completed,
            "partial cleanup was reported as complete");
        client.query_client().exec("UPSERT INTO usid_audit_log (id, actor_user_id, action, target_type, target_id, meta_json, created_at) VALUES ($id, $owner, 'synthetic.deletion', 'user', $target, Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime())")
            .param("$id", i64::from(account_id)).param("$owner", identity_id)
            .param("$target", identity_id.to_string()).await?;
        client.query_client().exec("UPSERT INTO usid_outbox (id, tenant_id, event_type, payload_json, created_at, attempts, last_error) VALUES ($id, $tenant, 'synthetic.deletion', Unwrap(CAST($payload AS Json)), CurrentUtcDatetime(), 0, '')")
            .param("$id", i64::from(account_id)).param("$tenant", identity_id)
            .param("$payload", serde_json::json!({"user_id": identity_id.to_string(), "application_id": account_id}).to_string()).await?;
        client.query_client().exec("UPSERT INTO usid_application (id, tenant_slug, payload_json, status, created_at) VALUES ($id, 'synthetic', Unwrap(CAST($payload AS Json)), 'pending', CurrentUtcDatetime())")
            .param("$id", i64::from(account_id))
            .param("$payload", serde_json::json!({"email": email}).to_string()).await?;
        client.query_client().exec("UPSERT INTO usid_application (id, tenant_slug, payload_json, status, created_at) VALUES ($id, 'synthetic', Unwrap(CAST($payload AS Json)), 'pending', CurrentUtcDatetime())")
            .param("$id", i64::from(account_id) - 1)
            .param("$payload", serde_json::json!({"email": email}).to_string()).await?;
        let audit = id_runtime::account_deletion_audit::audit(&client, operation_id)
            .await?.context("final deletion audit lost operation")?;
        ensure!(audit.profile_stage_completed && audit.account_rows == 1
            && audit.identity_binding_rows == 1 && audit.identity_rows == 1
            && audit.session_metadata_rows > 0 && audit.audit_log.matched > 0
            && audit.outbox.matched > 0 && audit.applications.matched > 0
            && !audit.full_cleanup_proven,
            "final deletion audit misstated remaining identity data: {audit:?}");
        let first_global = id_runtime::account_deletion_cleanup::drain_pending_globals(&client, 10).await?;
        ensure!(first_global.attempted == 1 && first_global.completed == 1
            && first_global.deferred == 0, "timer did not erase global UUID references: {first_global:?}");
        ensure!(client.query_client().query_row("SELECT id FROM usid_application WHERE id = $id")
            .param("$id", i64::from(account_id)).optional().await?.is_none(),
            "linked application survived its UUID evidence");
        ensure!(client.query_client().query_row("SELECT id FROM usid_application WHERE id = $id")
            .param("$id", i64::from(account_id) - 1).optional().await?.is_some(),
            "email-only application was deleted without ownership proof");
        let repeated = id_runtime::account_deletion_audit::erase_global_uuid_references(&client, operation_id)
            .await?.context("global cleanup was not repeatable")?;
        ensure!(repeated.audit_candidates == 0 && repeated.outbox_candidates == 0
            && repeated.audit_removed == 0 && repeated.outbox_removed == 0,
            "global cleanup repeated deletion: {repeated:?}");
        let final_global = id_runtime::account_deletion_cleanup::drain_pending_globals(&client, 10).await?;
        ensure!(final_global.attempted == 1 && final_global.completed == 1
            && final_global.deferred == 0, "timer did not finish global UUID pass: {final_global:?}");
        let no_globals = id_runtime::account_deletion_cleanup::drain_pending_globals(&client, 10).await?;
        ensure!(no_globals.attempted == 0, "completed global pass was retried");
        let after = id_runtime::account_deletion_audit::audit(&client, operation_id)
            .await?.context("global cleanup lost final audit")?;
        ensure!(after.audit_log.matched == 0 && after.outbox.matched == 0
            && after.applications.matched > 0 && !after.full_cleanup_proven,
            "global cleanup erased unrelated application or claimed completion: {after:?}");
        Ok(())
    }.await;
    for (token, _) in tokens_to_clean {
        client
            .query_client()
            .exec("DELETE FROM django_session WHERE session_key = $key")
            .param("$key", token.clone())
            .await?;
        client
            .query_client()
            .exec("DELETE FROM usersessions_usersession WHERE session_key = $key")
            .param("$key", token.clone())
            .await?;
        client
            .query_client()
            .exec("DELETE FROM core_usersessionmeta WHERE session_key = $key")
            .param("$key", token)
            .await?;
    }
    let mut outstanding_client = client.query_client();
    let mut outstanding = outstanding_client
        .query("SELECT id FROM token_blacklist_outstandingtoken VIEW token_blacklist_outstandingtoken_user_id_83bc629a WHERE user_id = $id")
        .param("$id", account_id).await?;
    let mut outstanding_ids = Vec::new();
    while let Some(rows) = outstanding.next_result_set().await? {
        for mut row in rows {
            let id: i64 = row.remove_field_by_name("id")?.try_into()?;
            outstanding_ids.push(id);
        }
    }
    outstanding.close().await?;
    for id in outstanding_ids {
        client
            .query_client()
            .exec("DELETE FROM token_blacklist_blacklistedtoken WHERE token_id = $id")
            .param("$id", id)
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM core_usersessiontoken WHERE user_id = $id")
        .param("$id", account_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM token_blacklist_outstandingtoken WHERE user_id = $id")
        .param("$id", account_id)
        .await?;
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
        .exec("DELETE FROM mfa_authenticator WHERE id = $id")
        .param("$id", i64::from(account_id))
        .await?;
    client
        .query_client()
        .exec("DELETE FROM account_emailconfirmation WHERE email_address_id = $id")
        .param("$id", account_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM socialaccount_socialtoken WHERE account_id = $id")
        .param("$id", account_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM socialaccount_socialaccount WHERE user_id = $id")
        .param("$id", account_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_userprofile WHERE user_id = $id")
        .param("$id", account_id)
        .await?;
    id_runtime::account_deletion_cleanup::ensure_progress_schema(&client).await?;
    let mut cleanup_client = client.query_client();
    let mut deletions = cleanup_client.query("SELECT id FROM accounts_accountdeletionrequest VIEW accounts_accountdeletionrequest_user_id_6a166c52 WHERE user_id = $id")
        .param("$id", account_id).await?;
    let mut deletion_ids: Vec<i64> = Vec::new();
    while let Some(rows) = deletions.next_result_set().await? {
        for mut row in rows {
            deletion_ids.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    deletions.close().await?;
    for deletion_id in deletion_ids {
        client
            .query_client()
            .exec("DELETE FROM id_deletion_global_progress WHERE operation_id = $id")
            .param("$id", deletion_id)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM id_deletion_profile_progress WHERE operation_id = $id")
            .param("$id", deletion_id)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM id_deletion_progress WHERE operation_id = $id")
            .param("$id", deletion_id)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM accounts_accountdeletionrequest WHERE id = $id")
            .param("$id", deletion_id)
            .await?;
    }
    for table in ["usid_audit_log", "usid_outbox", "usid_application"] {
        client
            .query_client()
            .exec(format!("DELETE FROM {table} WHERE id = $id"))
            .param("$id", i64::from(account_id))
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM usid_application WHERE id = $id")
        .param("$id", i64::from(account_id) - 1)
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
    result
}

fn python_check(payload: serde_json::Value) -> Result<String> {
    let python_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../id")
        .canonicalize()?;
    let mut child = Command::new(python_dir.join(".venv/bin/python"))
        .arg("scripts/check_rust_session.py")
        .current_dir(&python_dir)
        .env("PYTHONPATH", "src")
        .env("DJANGO_SETTINGS_MODULE", "app.settings")
        .env("DJANGO_DEBUG", "true")
        .env(
            "DJANGO_SECRET_KEY",
            "synthetic-local-secret-min-32-characters",
        )
        .env("DB_DRIVER", "ydb")
        .env("YDB_NAME", "default")
        .env("YDB_CREDENTIALS_MODE", "token")
        .env("YDB_TOKEN", "local-ydb-token")
        .env("REDIS_URL", "")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .context("Python check stdin unavailable")?;
    let structured = payload["session_list"] == true;
    stdin.write_all(payload.to_string().as_bytes())?;
    drop(stdin);
    let output = child.wait_with_output()?;
    ensure!(
        output.status.success(),
        "Python compatibility check failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)?;
    if !structured {
        println!("{}", stdout.trim());
    }
    Ok(stdout.trim().to_owned())
}

async fn sessions_http_call(
    app: &Router,
    cookie: Option<&str>,
    header_token: Option<&str>,
    method: &str,
) -> Result<(StatusCode, serde_json::Value)> {
    let mut request = Request::builder()
        .uri("/api/v1/auth/sessions")
        .method(method)
        .header(header::ORIGIN, "http://id.localhost:5175");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, format!("sessionid={cookie}"));
    }
    if let Some(token) = header_token {
        request = request.header("x-session-token", token);
    }
    let response = app.clone().oneshot(request.body(Body::empty())?).await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1_000_000).await?;
    let body = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes)?
    };
    Ok((status, body))
}

async fn jwt_session_http_call(
    app: &Router,
    header_token: Option<&str>,
    cookie_token: Option<&str>,
    csrf: bool,
) -> Result<(StatusCode, serde_json::Value, axum::http::HeaderMap)> {
    let mut request = Request::builder()
        .uri("/api/v1/auth/jwt/from_session")
        .method("POST")
        .header(header::ORIGIN, "http://id.localhost:5175");
    if let Some(token) = header_token {
        request = request.header("x-session-token", token);
    }
    if let Some(token) = cookie_token {
        let cookie = if csrf {
            format!("sessionid={token}; csrftoken=abcdefghijklmnopqrstuvwxyzABCDEF")
        } else {
            format!("sessionid={token}")
        };
        request = request.header(header::COOKIE, cookie);
    }
    if csrf {
        request = request.header("x-csrftoken", "abcdefghijklmnopqrstuvwxyzABCDEF");
    }
    let result = app.clone().oneshot(request.body(Body::empty())?).await?;
    let status = result.status();
    let headers = result.headers().clone();
    let bytes = to_bytes(result.into_body(), 1_000_000).await?;
    Ok((status, serde_json::from_slice(&bytes)?, headers))
}

async fn jwt_refresh_http_call(
    app: &Router,
    refresh: &str,
) -> Result<(StatusCode, serde_json::Value, axum::http::HeaderMap)> {
    let request = Request::builder()
        .uri("/api/v1/auth/refresh")
        .method("POST")
        .header(header::ORIGIN, "http://id.localhost:5175")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({"refresh":refresh}).to_string(),
        ))?;
    let result = app.clone().oneshot(request).await?;
    let status = result.status();
    let headers = result.headers().clone();
    let bytes = to_bytes(result.into_body(), 1_000_000).await?;
    Ok((status, serde_json::from_slice(&bytes)?, headers))
}

async fn deletion_http_call(
    app: &Router,
    header_token: Option<&str>,
    cookie_token: Option<&str>,
    idempotency_key: Option<&str>,
    csrf: bool,
    password: &str,
) -> Result<(StatusCode, serde_json::Value)> {
    deletion_http_call_with_mfa(
        app,
        header_token,
        cookie_token,
        idempotency_key,
        csrf,
        password,
        None,
    )
    .await
}

async fn deletion_http_call_with_mfa(
    app: &Router,
    header_token: Option<&str>,
    cookie_token: Option<&str>,
    idempotency_key: Option<&str>,
    csrf: bool,
    password: &str,
    mfa_code: Option<&str>,
) -> Result<(StatusCode, serde_json::Value)> {
    let mut request = Request::builder()
        .uri("/api/v1/auth/account/deletions")
        .method("POST")
        .header(header::ORIGIN, "http://id.localhost:5175")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = header_token {
        request = request.header("x-session-token", token);
    }
    if let Some(token) = cookie_token {
        let cookie = if csrf {
            format!("sessionid={token}; csrftoken=abcdefghijklmnopqrstuvwxyzABCDEF")
        } else {
            format!("sessionid={token}")
        };
        request = request.header(header::COOKIE, cookie);
    }
    if let Some(key) = idempotency_key {
        request = request.header("idempotency-key", key);
    }
    if csrf {
        request = request.header("x-csrftoken", "abcdefghijklmnopqrstuvwxyzABCDEF");
    }
    let request = request.body(Body::from(
        serde_json::json!({"password":password,"mfa_code":mfa_code}).to_string(),
    ))?;
    let result = app.clone().oneshot(request).await?;
    let status = result.status();
    let body = to_bytes(result.into_body(), 1_000_000).await?;
    Ok((status, serde_json::from_slice(&body)?))
}

async fn sessions_http_mutate(
    app: &Router,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    header_token: Option<&str>,
    csrf: Option<&str>,
    body: Option<serde_json::Value>,
) -> Result<(StatusCode, serde_json::Value)> {
    let mut request = Request::builder()
        .uri(path)
        .method(method)
        .header(header::ORIGIN, "http://id.localhost:5175");
    if let Some(cookie) = cookie {
        let cookies = if let Some(csrf) = csrf {
            format!("sessionid={cookie}; csrftoken={csrf}")
        } else {
            format!("sessionid={cookie}")
        };
        request = request.header(header::COOKIE, cookies);
    }
    if let Some(token) = header_token {
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
    let result = app.clone().oneshot(request.body(body)?).await?;
    let status = result.status();
    let bytes = to_bytes(result.into_body(), 1_000_000).await?;
    let body = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes)?
    };
    Ok((status, body))
}
