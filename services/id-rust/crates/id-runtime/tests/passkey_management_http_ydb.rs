#![recursion_limit = "256"]
//! Passkey metadata and last-factor deletion against migrated local YDB.

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
    path: &str,
    cookie: &str,
    csrf: bool,
    body: Value,
) -> Result<(StatusCode, Value)> {
    let mut request = Request::builder()
        .uri(path)
        .method("POST")
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/json");
    if csrf {
        request = request
            .header("origin", "http://localhost:5175")
            .header("x-csrftoken", "a".repeat(32));
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string()))?)
        .await?;
    let status = response.status();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await?)?;
    Ok((status, body))
}

async fn data(client: &ydb::Client, id: i64) -> Result<Option<Value>> {
    let mut query = client.query_client();
    let mut stream = query
        .query("SELECT CAST(data AS Utf8) AS data FROM mfa_authenticator WHERE id = $id")
        .param("$id", id)
        .await?;
    let mut result = None;
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            let text: String = row.remove_field_by_name("data")?.try_into()?;
            result = Some(serde_json::from_str(&text)?);
        }
    }
    stream.close().await?;
    Ok(result)
}

#[tokio::test]
#[ignore = "requires migrated local YDB and opt-in Rust passkey management"]
async fn passkey_changes_require_owner_mfa_and_recent_auth() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local"
            && std::env::var("DJANGO_DEBUG")? == "true"
            && std::env::var("ID_AUTH_PASSKEY_MANAGEMENT_ENABLED")? == "true",
        "test requires local opt-in YDB"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    id_runtime::passkey_index::ensure_schema(&client).await?;
    id_runtime::security_mail::ensure_schema(&client).await?;
    let app = id_runtime::totp_setup_http::router(
        id_runtime::totp_setup_http::TotpSetupHttpConfig::from_env(client.clone())?
            .context("passkey pilot disabled")?,
    );
    let second_client = Arc::new(id_runtime::connect_ydb().await?);
    let second_app = id_runtime::totp_setup_http::router(
        id_runtime::totp_setup_http::TotpSetupHttpConfig::from_env(second_client)?
            .context("second passkey pilot disabled")?,
    );
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let user_id = -i32::try_from(stamp % 1_000_000_000 + 1)?;
    let identity_id = Uuid::from_u128((stamp << 32) | u128::from(std::process::id()));
    let first = i64::try_from(stamp)? + 1;
    let second = first + 1;
    let foreign = first + 2;
    let recovery = first + 3;
    let token = format!("rustpasskey{stamp:032x}session");
    let now = SystemTime::now();
    let codec = SessionCodec::new(std::env::var("DJANGO_SECRET_KEY")?.as_bytes(), &[])?;
    let password = "pbkdf2_sha256$1000000$synthetic$synthetic";
    let mut session = json!({"_auth_user_id":user_id.to_string(),
        "_auth_user_backend":"django.contrib.auth.backends.ModelBackend",
        "_auth_user_hash":codec.auth_hash(password)?,
        "account_authentication_methods":[{"method":"password","at":now.duration_since(UNIX_EPOCH)?.as_secs_f64()}]});
    let signed = codec.encode(
        session.as_object().context("session object")?,
        i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?,
        true,
    )?;
    client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $password, true, $name, '', '', $email, false, false, CurrentUtcDatetime())")
        .param("$id", user_id).param("$password", password)
        .param("$name", format!("rust-passkey-{stamp}"))
        .param("$email", format!("rust-passkey-{stamp}@example.invalid")).await?;
    let outcome: Result<()> = async {
        client.query_client().exec("UPSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, $data, CAST($expires AS Datetime))")
            .param("$key", token.clone()).param("$data", signed).param("$expires", now + Duration::from_secs(3600)).await?;
        client.query_client().exec("UPSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, $name, $name, $email, true, 'active', false, CurrentUtcDatetime())")
            .param("$id", identity_id).param("$name", format!("rust-passkey-{stamp}"))
            .param("$email", format!("rust-passkey-{stamp}@example.invalid")).await?;
        client.query_client().exec("UPSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($id, $identity, $subject, CurrentUtcDatetime())")
            .param("$id", user_id).param("$identity", identity_id)
            .param("$subject", format!("rust-passkey-sub-{stamp}")).await?;
        let mut credential = json!({"name":"Original","credential":{"publicKey":"preserve-me","clientExtensionResults":{"credProps":{"rk":true}}}});
        for (id, owner) in [(first, user_id), (second, user_id), (foreign, user_id - 1)] {
            let raw_id = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, id.to_be_bytes());
            credential["credential"]["rawId"] = json!(raw_id);
            client.query_client().exec("UPSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $user_id, 'webauthn', Unwrap(CAST($data AS Json)), CurrentUtcDatetime())")
                .param("$id", id).param("$user_id", owner).param("$data", credential.to_string()).await?;
            let digest = id_runtime::passkey_index::digest_of_record(&credential)?;
            client.query_client().exec("UPSERT INTO `id_passkey_credential` (digest, authenticator_id, account_id) VALUES ($digest, $id, $owner)")
                .param("$digest", digest).param("$id", id).param("$owner", owner).await?;
        }
        client.query_client().exec("UPSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $user_id, 'recovery_codes', Unwrap(CAST($data AS Json)), CurrentUtcDatetime())")
            .param("$id", recovery).param("$user_id", user_id)
            .param("$data", json!({"seed":"synthetic","used_mask":0}).to_string()).await?;
        let cookie = format!("sessionid={token}; csrftoken={}", "a".repeat(32));
        let rename = json!({"authenticator_id":first.to_string(),"new_name":"Renamed"});
        let (status, _) = call(&app, "/api/v1/auth/passkeys/rename", &cookie, false, rename.clone()).await?;
        ensure!(status == StatusCode::FORBIDDEN, "rename ignored CSRF");
        let (status, _) = call(&app, "/api/v1/auth/passkeys/rename", &cookie, true, rename.clone()).await?;
        ensure!(status == StatusCode::UNAUTHORIZED, "unproven MFA session renamed passkey");
        session["id_mfa_verified_user_id"] = json!(user_id.to_string());
        session["account_authentication_methods"] = json!([{"method":"password","at":0.0}]);
        let old = codec.encode(session.as_object().context("session object")?,
            i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?, true)?;
        client.query_client().exec("UPDATE django_session SET session_data = $data WHERE session_key = $key")
            .param("$data", old).param("$key", token.clone()).await?;
        let (status, body) = call(&app, "/api/v1/auth/passkeys/rename", &cookie, true, rename.clone()).await?;
        ensure!(status == StatusCode::UNAUTHORIZED && body["code"] == "REAUTH_REQUIRED", "stale auth renamed passkey: {body}");
        session["account_authentication_methods"] = json!([{"method":"password","at":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64()}]);
        let fresh = codec.encode(session.as_object().context("session object")?,
            i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?, true)?;
        client.query_client().exec("UPDATE django_session SET session_data = $data WHERE session_key = $key")
            .param("$data", fresh).param("$key", token.clone()).await?;
        let (status, body) = call(&app, "/api/v1/auth/passkeys/rename", &cookie, true,
            json!({"authenticator_id":foreign.to_string(),"new_name":"Steal"})).await?;
        ensure!(status == StatusCode::NOT_FOUND && body["code"] == "NOT_FOUND", "foreign passkey exposed: {body}");
        let (status, body) = call(&app, "/api/v1/auth/passkeys/rename", &cookie, true, rename).await?;
        ensure!(status == StatusCode::OK && body["ok"] == true, "rename failed: {body}");
        let renamed = data(&client, first).await?.context("renamed key disappeared")?;
        ensure!(renamed["name"] == "Renamed" && renamed["credential"]["publicKey"] == credential["credential"]["publicKey"],
            "rename corrupted WebAuthn credential");
        let (status, body) = call(&app, "/api/v1/auth/passkeys/delete", &cookie, true,
            json!({"ids":[first.to_string(),foreign.to_string()]})).await?;
        ensure!(status == StatusCode::NOT_FOUND && body["code"] == "NOT_FOUND" && data(&client, first).await?.is_some(),
            "foreign mixed batch partially deleted: {body}");
        let (status, body) = call(&app, "/api/v1/auth/passkeys/delete", &cookie, true,
            json!({"ids":[first.to_string()]})).await?;
        ensure!(status == StatusCode::OK && body["ok"] == true && data(&client, first).await?.is_none()
            && data(&client, recovery).await?.is_some(), "first deletion removed recovery prematurely: {body}");
        let first_digest = id_runtime::passkey_index::digest_of_bytes(&first.to_be_bytes())?;
        ensure!(client.query_client().query_row("SELECT digest FROM `id_passkey_credential` WHERE digest = $digest")
            .param("$digest", first_digest).optional().await?.is_none(), "deleted passkey retained login index");
        let mut tasks = tokio::task::JoinSet::new();
        for attempt in 0..100 {
            let app = if attempt % 2 == 0 { app.clone() } else { second_app.clone() };
            let cookie = cookie.clone();
            tasks.spawn(async move {
                call(&app, "/api/v1/auth/passkeys/delete", &cookie, true,
                    json!({"ids":[second.to_string()]})).await
            });
        }
        let mut successes = 0;
        while let Some(joined) = tasks.join_next().await {
            let (status, body) = joined??;
            if status == StatusCode::OK {
                ensure!(body["ok"] == true, "invalid successful deletion: {body}");
                successes += 1;
            } else {
                ensure!(status == StatusCode::NOT_FOUND, "unexpected concurrent deletion: {status} {body}");
            }
        }
        ensure!(successes == 1 && data(&client, second).await?.is_none()
            && data(&client, recovery).await?.is_none(), "last deletion had {successes} winners or retained recovery");
        let mut query_client = client.query_client();
        let mut mail_query = query_client.query(
            "SELECT id, status, kind FROM id_security_mail WHERE user_id = $user_id"
        ).param("$user_id", user_id).await?;
        let mut intents = 0;
        while let Some(rows) = mail_query.next_result_set().await? {
            for mut row in rows {
                let status: String = row.remove_field_by_name("status")?.try_into()?;
                let kind: String = row.remove_field_by_name("kind")?.try_into()?;
                ensure!(status == "pending" && kind == "passkey_removed", "invalid security mail intent");
                intents += 1;
            }
        }
        mail_query.close().await?;
        ensure!(intents == 2, "passkey deletions created {intents} mail intents");
        let second_digest = id_runtime::passkey_index::digest_of_bytes(&second.to_be_bytes())?;
        ensure!(client.query_client().query_row("SELECT digest FROM `id_passkey_credential` WHERE digest = $digest")
            .param("$digest", second_digest).optional().await?.is_none(), "last deleted passkey retained login index");
        let mut row = client.query_client().query_row("SELECT session_data FROM django_session WHERE session_key = $key")
            .param("$key", token.clone()).await?;
        let signed: String = row.remove_field_by_name("session_data")?.try_into()?;
        ensure!(codec.decode(&signed)?.data.get("id_mfa_verified_user_id").is_none(),
            "last-factor session retained MFA marker");
        ensure!(data(&client, foreign).await?.is_some(), "foreign passkey was changed");
        Ok(())
    }.await;
    for id in [first, second, foreign, recovery] {
        client
            .query_client()
            .exec("DELETE FROM mfa_authenticator WHERE id = $id")
            .param("$id", id)
            .await?;
    }
    for id in [first, second, foreign] {
        let digest = id_runtime::passkey_index::digest_of_bytes(&id.to_be_bytes())?;
        client
            .query_client()
            .exec("DELETE FROM `id_passkey_credential` WHERE digest = $digest")
            .param("$digest", digest)
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
        .exec("DELETE FROM django_session WHERE session_key = $key")
        .param("$key", token)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM auth_user WHERE id = $id")
        .param("$id", user_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM id_security_mail WHERE user_id = $id")
        .param("$id", user_id)
        .await?;
    outcome
}
