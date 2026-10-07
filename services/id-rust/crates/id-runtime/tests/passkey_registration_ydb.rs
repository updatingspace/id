#![recursion_limit = "256"]
//! Real YDB and two Axum instances; registration response uses a synthetic
//! attestation-none fixture with the challenge issued by the Rust endpoint.

use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use id_compat::session::SessionCodec;
use serde_json::{Value, json};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;
use uuid::Uuid;

async fn post(
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

#[tokio::test]
#[ignore = "requires migrated local YDB and opt-in Rust passkey registration"]
async fn one_registration_after_concurrent_completion_and_replay() -> Result<()> {
    ensure!(
        std::env::var("YDB_DATABASE")? == "/local"
            && std::env::var("DJANGO_DEBUG")? == "true"
            && std::env::var("ID_AUTH_TOTP_PILOT_ENABLED")? == "true"
            && std::env::var("ID_AUTH_PASSKEY_REGISTRATION_PILOT_ENABLED")? == "true",
        "test requires opt-in local YDB"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    let second = Arc::new(id_runtime::connect_ydb().await?);
    let initial = id_runtime::passkey_index::backfill(&client).await?;
    ensure!(
        initial.scanned == 0,
        "test requires an isolated passkey table"
    );
    let app = id_runtime::totp_setup_http::router(
        id_runtime::totp_setup_http::TotpSetupHttpConfig::from_env(client.clone())?
            .context("pilot disabled")?,
    );
    let second_app = id_runtime::totp_setup_http::router(
        id_runtime::totp_setup_http::TotpSetupHttpConfig::from_env(second)?
            .context("second pilot disabled")?,
    );
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let user_id = -i32::try_from(stamp % 1_000_000_000 + 1)?;
    let email_pk = user_id - 1;
    let identity_id = Uuid::from_u128((stamp << 32) | u128::from(std::process::id()));
    let session_token = format!("rustpasskey{stamp:032x}session");
    let now = SystemTime::now();
    let codec = SessionCodec::new(std::env::var("DJANGO_SECRET_KEY")?.as_bytes(), &[])?;
    let password = "pbkdf2_sha256$1000000$synthetic$synthetic";
    let email = format!("rust-passkey-{stamp}@example.invalid");
    let data = json!({"_auth_user_id":user_id.to_string(),
        "_auth_user_backend":"django.contrib.auth.backends.ModelBackend",
        "_auth_user_hash":codec.auth_hash(password)?,
        "account_authentication_methods":[{"method":"password","at":now.duration_since(UNIX_EPOCH)?.as_secs_f64()}]});
    let signed = codec.encode(
        data.as_object().context("session data")?,
        i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?,
        true,
    )?;
    client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $password, true, $name, '', '', $email, false, false, CurrentUtcDatetime())")
        .param("$id", user_id).param("$password", password).param("$name", format!("rust-passkey-{stamp}")).param("$email", email.clone()).await?;
    let outcome: Result<()> = async {
        client.query_client().exec("UPSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, $data, CAST($expires AS Datetime))")
            .param("$key", session_token.clone()).param("$data", signed).param("$expires", now + Duration::from_secs(3600)).await?;
        client.query_client().exec("UPSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, $name, $name, $email, true, 'active', false, CurrentUtcDatetime())")
            .param("$id", identity_id).param("$name", format!("rust-passkey-{stamp}")).param("$email", email.clone()).await?;
        client.query_client().exec("UPSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($id, $identity, $subject, CurrentUtcDatetime())")
            .param("$id", user_id).param("$identity", identity_id).param("$subject", format!("rust-passkey-sub-{stamp}")).await?;
        client.query_client().exec("UPSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($id, $user_id, $email, true, true)")
            .param("$id", email_pk).param("$user_id", user_id).param("$email", email.clone()).await?;
        let cookie = format!("sessionid={session_token}; csrftoken={}", "a".repeat(32));
        let (status, _) = post(&app, "/api/v1/auth/passkeys/begin", &cookie, false, json!({"passwordless":true})).await?;
        ensure!(status == StatusCode::FORBIDDEN, "begin ignored CSRF");
        let (status, begin) = post(&app, "/api/v1/auth/passkeys/begin", &cookie, true, json!({"passwordless":true})).await?;
        ensure!(status == StatusCode::OK, "begin failed: {begin}");
        let options = &begin["creation_options"]["publicKey"];
        ensure!(options["authenticatorSelection"]["residentKey"] == "required", "resident key not requested");
        let challenge = options["challenge"].as_str().context("challenge missing")?;
        let mut fixture: Value = serde_json::from_str(include_str!("fixtures/legacy_passkey.json"))?;
        let (status, rejected) = post(&app, "/api/v1/auth/passkeys/complete", &cookie, true,
            json!({"name":"Wrong challenge","credential":fixture["registration"]})).await?;
        ensure!(status == StatusCode::BAD_REQUEST && rejected["code"] == "INVALID_PASSKEY",
            "wrong challenge accepted");
        let client_data = json!({"type":"webauthn.create","challenge":challenge,"origin":"https://id.example.invalid","crossOrigin":false});
        fixture["registration"]["response"]["clientDataJSON"] = json!(URL_SAFE_NO_PAD.encode(client_data.to_string()));
        fixture["registration"]["clientExtensionResults"] = json!({"credProps":{"rk":false}});
        let (status, rejected) = post(&app, "/api/v1/auth/passkeys/complete", &cookie, true,
            json!({"name":"Non-discoverable","credential":fixture["registration"]})).await?;
        ensure!(status == StatusCode::BAD_REQUEST && rejected["code"] == "INVALID_PASSKEY",
            "explicitly non-discoverable credential accepted");
        // A browser may omit this optional extension result despite the
        // required residentKey option. Its absence is not a negative result.
        fixture["registration"]["clientExtensionResults"] = json!({});
        let credential = fixture["registration"].clone();
        let body = json!({"name":"Rust passkey","credential":credential,"passwordless":true});
        let mut tasks = tokio::task::JoinSet::new();
        for attempt in 0..20 {
            let app = if attempt % 2 == 0 { app.clone() } else { second_app.clone() };
            let cookie = cookie.clone(); let body = body.clone();
            tasks.spawn(async move { post(&app, "/api/v1/auth/passkeys/complete", &cookie, true, body).await });
        }
        let mut success = 0;
        while let Some(result) = tasks.join_next().await {
            let (status, response) = result??;
            if status == StatusCode::OK {
                success += 1;
                ensure!(response["recovery_codes"].as_array().is_some_and(|codes| codes.len() == 10), "first passkey lacked recovery codes");
            } else {
                ensure!((status == StatusCode::BAD_REQUEST && response["code"] == "INVALID_PASSKEY")
                    || (status == StatusCode::UNAUTHORIZED && response["code"] == "UNAUTHORIZED"),
                    "unexpected loser: {status} {response}");
            }
        }
        ensure!(success == 1, "registration had {success} winners");
        let (status, response) = post(&app, "/api/v1/auth/passkeys/complete", &cookie, true, body).await?;
        ensure!(matches!(status, StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED)
            && matches!(response["code"].as_str(), Some("INVALID_PASSKEY" | "UNAUTHORIZED")), "replay accepted");
        let mut query = client.query_client();
        let mut stream = query.query("SELECT type FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $id")
            .param("$id", user_id).await?;
        let mut kinds = Vec::new();
        while let Some(rows) = stream.next_result_set().await? {
            for mut row in rows { let kind: String = row.remove_field_by_name("type")?.try_into()?; kinds.push(kind); }
        }
        stream.close().await?;
        kinds.sort();
        ensure!(kinds == ["recovery_codes", "webauthn"], "registration rows: {kinds:?}");
        let audit = id_runtime::passkey_audit::audit(&client, "id.example.invalid", "https://id.example.invalid").await?;
        ensure!(audit.scanned == 1 && audit.convertible == 1 && audit.ready(),
            "new credential cannot be audited or re-imported: {audit:?}");
        let indexed = id_runtime::passkey_index::backfill(&client).await?;
        ensure!(indexed.scanned == 1 && indexed.existing == 1 && indexed.inserted == 0,
            "new credential is not indexed or backfill is not repeatable: {indexed:?}");
        let mut row = client.query_client().query_row("SELECT session_data FROM django_session WHERE session_key = $key")
            .param("$key", session_token.clone()).await?;
        let signed: String = row.remove_field_by_name("session_data")?.try_into()?;
        let session = codec.decode(&signed)?;
        ensure!(session.data.get("id_rust_passkey_pending").is_none()
            && session.data.get("id_mfa_verified_user_id") == Some(&json!(user_id.to_string())),
            "registration left challenge or no MFA proof");
        Ok(())
    }.await;
    let mut query = client.query_client();
    let mut stream = query.query("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $id")
        .param("$id", user_id).await?;
    let mut ids = Vec::new();
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            let id: i64 = row.remove_field_by_name("id")?.try_into()?;
            ids.push(id);
        }
    }
    stream.close().await?;
    for id in ids {
        client
            .query_client()
            .exec("DELETE FROM mfa_authenticator WHERE id = $id")
            .param("$id", id)
            .await?;
    }
    let mut query = client.query_client();
    let mut stream = query
        .query("SELECT id FROM accounts_accountevent VIEW acct_event_user_idx WHERE user_id = $id")
        .param("$id", user_id)
        .await?;
    let mut events = Vec::new();
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            let id: i64 = row.remove_field_by_name("id")?.try_into()?;
            events.push(id);
        }
    }
    stream.close().await?;
    for id in events {
        client
            .query_client()
            .exec("DELETE FROM accounts_accountevent WHERE id = $id")
            .param("$id", id)
            .await?;
    }
    let fixture: Value = serde_json::from_str(include_str!("fixtures/legacy_passkey.json"))?;
    let raw = URL_SAFE_NO_PAD.decode(
        fixture["registration"]["rawId"]
            .as_str()
            .context("fixture raw ID")?,
    )?;
    let digest = id_runtime::passkey_index::digest_of_bytes(&raw)?;
    client
        .query_client()
        .exec("DELETE FROM id_passkey_credential WHERE digest = $digest")
        .param("$digest", digest)
        .await?;
    for (table, field, value) in [
        ("account_emailaddress", "id", i64::from(email_pk)),
        ("accounts_accountidentity", "user_id", i64::from(user_id)),
        ("auth_user", "id", i64::from(user_id)),
    ] {
        client
            .query_client()
            .exec(format!("DELETE FROM `{table}` WHERE `{field}` = $id"))
            .param("$id", value)
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM usid_user WHERE user_id = $id")
        .param("$id", identity_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM django_session WHERE session_key = $key")
        .param("$key", session_token)
        .await?;
    outcome
}
