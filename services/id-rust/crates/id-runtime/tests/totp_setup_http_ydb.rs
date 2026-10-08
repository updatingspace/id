#![recursion_limit = "256"]
//! Real-YDB TOTP enrollment through Axum, including concurrent confirmations.

use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use hmac::{Hmac, Mac};
use id_compat::{
    mfa_seal::{MfaSealKey, SecretKind},
    session::SessionCodec,
};
use serde_json::{Value, json};
use sha1::Sha1;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;
use uuid::Uuid;

async fn call(
    app: &Router,
    path: &str,
    cookie: Option<&str>,
    csrf: bool,
    body: Option<Value>,
) -> Result<(StatusCode, Value)> {
    let mut builder = Request::builder().uri(path).method("POST");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    if csrf {
        builder = builder
            .header("origin", "http://localhost:5175")
            .header("x-csrftoken", "a".repeat(32));
    }
    let body = if let Some(body) = body {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
        Body::from(body.to_string())
    } else {
        Body::empty()
    };
    let response = app.clone().oneshot(builder.body(body)?).await?;
    let status = response.status();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await?)?;
    Ok((status, body))
}

async fn call_recovery(
    app: &Router,
    cookie: &str,
    csrf: bool,
    idempotency_key: Option<&str>,
) -> Result<(StatusCode, Value)> {
    let mut builder = Request::builder()
        .uri("/api/v1/auth/mfa/recovery/regenerate")
        .method("POST")
        .header(header::COOKIE, cookie);
    if csrf {
        builder = builder
            .header("origin", "http://localhost:5175")
            .header("x-csrftoken", "a".repeat(32));
    }
    if let Some(key) = idempotency_key {
        builder = builder.header("idempotency-key", key);
    }
    let response = app.clone().oneshot(builder.body(Body::empty())?).await?;
    let status = response.status();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await?)?;
    Ok((status, body))
}

fn current_totp(secret: &str, seconds: u64) -> Result<String> {
    let mut decoded = Vec::with_capacity(20);
    let mut bits = 0u32;
    let mut count = 0;
    for byte in secret.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => anyhow::bail!("invalid fixture base32"),
        };
        bits = (bits << 5) | u32::from(value);
        count += 5;
        if count >= 8 {
            count -= 8;
            decoded.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    let mut mac = Hmac::<Sha1>::new_from_slice(&decoded)?;
    mac.update(&(seconds / 30).to_be_bytes());
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
#[ignore = "requires migrated local YDB and opt-in Rust TOTP enrollment"]
async fn one_totp_and_one_recovery_set_after_parallel_confirmation() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local"
            && std::env::var("DJANGO_DEBUG")? == "true"
            && std::env::var("ID_AUTH_TOTP_PILOT_ENABLED")? == "true",
        "test requires opt-in local YDB"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    let app = id_runtime::totp_setup_http::router(
        id_runtime::totp_setup_http::TotpSetupHttpConfig::from_env(client.clone())?
            .context("TOTP pilot disabled")?,
    );
    let second_client = Arc::new(id_runtime::connect_ydb().await?);
    let second_app = id_runtime::totp_setup_http::router(
        id_runtime::totp_setup_http::TotpSetupHttpConfig::from_env(second_client)?
            .context("TOTP pilot disabled on second instance")?,
    );
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let user_id = -i32::try_from(stamp % 1_000_000_000 + 1)?;
    let email_pk = user_id - 1;
    let identity_id = Uuid::from_u128((stamp << 32) | u128::from(std::process::id()));
    let session_token = format!("rusttotp{stamp:032x}session");
    let now = SystemTime::now();
    let codec = Arc::new(SessionCodec::new(
        std::env::var("DJANGO_SECRET_KEY")?.as_bytes(),
        &[],
    )?);
    let password = "pbkdf2_sha256$1000000$synthetic$synthetic";
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
        .param("$id", user_id).param("$password", password)
        .param("$name", format!("rust-totp-{stamp}"))
        .param("$email", format!("rust-totp-{stamp}@example.invalid")).await?;
    let outcome: Result<()> = async {
        client.query_client().exec("UPSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, $data, CAST($expires AS Datetime))")
            .param("$key", session_token.clone()).param("$data", signed).param("$expires", now + Duration::from_secs(3600)).await?;
        client.query_client().exec("UPSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, $name, $name, $email, true, 'active', false, CurrentUtcDatetime())")
            .param("$id", identity_id).param("$name", format!("rust-totp-{stamp}"))
            .param("$email", format!("rust-totp-{stamp}@example.invalid")).await?;
        client.query_client().exec("UPSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($id, $identity, $subject, CurrentUtcDatetime())")
            .param("$id", user_id).param("$identity", identity_id)
            .param("$subject", format!("rust-totp-sub-{stamp}")).await?;
        client.query_client().exec("UPSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($id, $user_id, $email, true, true)")
            .param("$id", email_pk).param("$user_id", user_id)
            .param("$email", format!("rust-totp-{stamp}@example.invalid")).await?;
        let cookie = format!("sessionid={session_token}; csrftoken={}", "a".repeat(32));
        let (status, _) = call(&app, "/api/v1/auth/mfa/totp/begin", Some(&cookie), false, None).await?;
        ensure!(status == StatusCode::FORBIDDEN, "TOTP begin ignored CSRF");
        let (status, started) = call(&app, "/api/v1/auth/mfa/totp/begin", Some(&cookie), true, None).await?;
        ensure!(status == StatusCode::OK && started["secret"].as_str().is_some_and(|value| value.len() == 32)
            && started["svg"].as_str().is_some_and(|value| value.contains("<svg")), "begin: {started}");
        let secret = started["secret"].as_str().context("missing secret")?;
        let valid_now = current_totp(secret, SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
        let wrong_code = if valid_now == "000000" { "000001" } else { "000000" };
        let (status, _) = call(&app, "/api/v1/auth/mfa/totp/confirm", Some(&cookie), true,
            Some(json!({"code":wrong_code}))).await?;
        ensure!(status == StatusCode::BAD_REQUEST, "wrong code activated MFA");
        let mut query = client.query_client();
        let mut stream = query.query("SELECT type FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $id")
            .param("$id", user_id).await?;
        let mut before = 0;
        while let Some(rows) = stream.next_result_set().await? {
            for _ in rows { before += 1; }
        }
        stream.close().await?;
        ensure!(before == 0, "wrong code wrote credentials");
        if SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() % 30 >= 28 {
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        let code = current_totp(secret, SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
        let mut tasks = tokio::task::JoinSet::new();
        for attempt in 0..100 {
            let app = if attempt % 2 == 0 { app.clone() } else { second_app.clone() };
            let cookie = cookie.clone(); let code = code.clone();
            tasks.spawn(async move { call(&app, "/api/v1/auth/mfa/totp/confirm", Some(&cookie), true,
                Some(json!({"code":code}))).await });
        }
        let mut successes = 0;
        let mut returned_codes = None;
        while let Some(joined) = tasks.join_next().await {
            let (status, body) = joined??;
            if status == StatusCode::OK {
                successes += 1;
                returned_codes = Some(body["recovery_codes"].clone());
            } else {
                ensure!(matches!(status, StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED),
                    "unexpected concurrent confirmation: {status} {body}");
            }
        }
        ensure!(successes == 1 && returned_codes.as_ref().and_then(Value::as_array).is_some_and(|codes| codes.len() == 10),
            "TOTP confirmation created {successes} sets");
        let (status, body) = call(&app, "/api/v1/auth/mfa/totp/confirm", Some(&cookie), true,
            Some(json!({"code":code}))).await?;
        ensure!(status == StatusCode::BAD_REQUEST && body["code"] == "TOTP_ALREADY_ENABLED", "replay: {body}");
        let mut query = client.query_client();
        let mut stream = query.query("SELECT type, CAST(data AS Utf8) AS data FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $id")
            .param("$id", user_id).await?;
        let mut rows_seen = Vec::new();
        while let Some(rows) = stream.next_result_set().await? {
            for mut row in rows {
                let kind: String = row.remove_field_by_name("type")?.try_into()?;
                let stored: String = row.remove_field_by_name("data")?.try_into()?;
                rows_seen.push((kind, stored));
            }
        }
        stream.close().await?;
        ensure!(rows_seen.len() == 2 && rows_seen.iter().all(|(_, stored)| stored.contains("id-mfa-v1:")),
            "credentials missing or not encrypted");
        ensure!(rows_seen.iter().all(|(_, stored)| !stored.contains(secret)), "TOTP secret stored in plaintext");
        let mut row = client.query_client().query_row("SELECT session_data FROM django_session WHERE session_key = $key")
            .param("$key", session_token.clone()).await?;
        let signed: String = row.remove_field_by_name("session_data")?.try_into()?;
        let confirmed = codec.decode(&signed)?;
        ensure!(confirmed.data.get("id_mfa_verified_user_id") == Some(&json!(user_id.to_string()))
            && confirmed.data.get("id_rust_totp_pending").is_none(), "MFA session was not finalized");
        let old_codes: Vec<String> = serde_json::from_value(returned_codes.context("missing original codes")?)?;
        let rotation_key = "r".repeat(32);
        let (status, _) = call_recovery(&app, &cookie, false, Some(&rotation_key)).await?;
        ensure!(status == StatusCode::FORBIDDEN, "recovery rotation ignored CSRF");
        let (status, _) = call_recovery(&app, &cookie, true, None).await?;
        ensure!(status == StatusCode::UNPROCESSABLE_ENTITY, "recovery rotation accepted no idempotency key");
        // A request can capture its authorization time before a later request
        // commits first. Put the winner in the next second deterministically.
        let delayed_request_now = SystemTime::now();
        let fraction = delayed_request_now.duration_since(UNIX_EPOCH)?.subsec_nanos();
        tokio::time::sleep(Duration::from_secs(1) - Duration::from_nanos(u64::from(fraction))).await;
        let mut rotations = tokio::task::JoinSet::new();
        for attempt in 0..100 {
            let app = if attempt % 2 == 0 { app.clone() } else { second_app.clone() };
            let cookie = cookie.clone(); let key = rotation_key.clone();
            rotations.spawn(async move { call_recovery(&app, &cookie, true, Some(&key)).await });
        }
        let mut rotated_codes = None;
        while let Some(joined) = rotations.join_next().await {
            let (status, body) = joined??;
            ensure!(status == StatusCode::OK, "concurrent rotation failed: {status} {body}");
            let codes: Vec<String> = serde_json::from_value(body["recovery_codes"].clone())?;
            ensure!(codes.len() == 10 && codes != old_codes, "rotation did not replace old code set");
            if let Some(previous) = &rotated_codes {
                ensure!(previous == &codes, "same idempotency key returned different code sets");
            } else {
                rotated_codes = Some(codes);
            }
        }
        let rotated_codes = rotated_codes.context("no recovery rotation result")?;
        let delayed = id_runtime::recovery_rotation::regenerate(
            &client, codec.clone(), &session_token, &rotation_key, delayed_request_now,
        ).await.context("delayed same-key request after later commit")?;
        match delayed {
            id_runtime::recovery_rotation::RotationOutcome::Replayed(codes) => {
                ensure!(codes == rotated_codes, "delayed request returned different recovery codes");
            }
            _ => anyhow::bail!("delayed same-key request did not replay the committed rotation"),
        }
        let (status, body) = call_recovery(&app, &cookie, true, Some(&"s".repeat(32))).await?;
        ensure!(status == StatusCode::CONFLICT && body["code"] == "ROTATION_IN_PROGRESS",
            "different key replaced fresh codes: {body}");
        let (status, body) = call_recovery(&app, &cookie, true, Some(&rotation_key)).await?;
        ensure!(status == StatusCode::OK && body["recovery_codes"] == json!(rotated_codes),
            "idempotent replay returned different codes");
        let mut query = client.query_client();
        let mut stream = query.query("SELECT id, CAST(data AS Utf8) AS data FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $id AND type = 'recovery_codes'")
            .param("$id", user_id).await?;
        let mut saved = Vec::new();
        while let Some(rows) = stream.next_result_set().await? {
            for mut row in rows {
                let id: i64 = row.remove_field_by_name("id")?.try_into()?;
                let data: String = row.remove_field_by_name("data")?.try_into()?;
                saved.push((id, serde_json::from_str::<Value>(&data)?));
            }
        }
        stream.close().await?;
        ensure!(saved.len() == 1, "rotation duplicated recovery authenticator");
        let (recovery_id, mut recovery_data) = saved.pop().context("recovery row missing")?;
        let seal_key = MfaSealKey::from_base64(&std::env::var("ID_MFA_SEAL_KEY_B64")?)?;
        let seed = seal_key.unseal(i64::from(user_id), SecretKind::RecoverySeed,
            recovery_data["seed"].as_str().context("sealed seed missing")?)?;
        ensure!(id_compat::recovery::codes(&seed)? == rotated_codes, "persisted seed does not match response");
        let mut future_data = recovery_data.clone();
        future_data["rotated_at"] = json!(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 3600);
        client.query_client().exec("UPDATE mfa_authenticator SET data = Unwrap(CAST($data AS Json)) WHERE id = $id")
            .param("$data", future_data.to_string()).param("$id", recovery_id).await?;
        let future = id_runtime::recovery_rotation::regenerate(
            &client, codec.clone(), &session_token, &rotation_key, SystemTime::now(),
        ).await;
        client.query_client().exec("UPDATE mfa_authenticator SET data = Unwrap(CAST($data AS Json)) WHERE id = $id")
            .param("$data", recovery_data.to_string()).param("$id", recovery_id).await?;
        ensure!(future.is_err_and(|error| error.to_string().contains("future recovery rotation marker")),
            "future rotation marker was accepted");
        let mut query = client.query_client();
        let mut events = query.query("SELECT action FROM accounts_accountevent VIEW acct_event_user_idx WHERE user_id = $id")
            .param("$id", user_id).await?;
        let mut rotations_recorded = 0;
        while let Some(rows) = events.next_result_set().await? {
            for mut row in rows {
                let action: String = row.remove_field_by_name("action")?.try_into()?;
                if action == "mfa_recovery_regenerated" { rotations_recorded += 1; }
            }
        }
        events.close().await?;
        ensure!(rotations_recorded == 1, "100 retries wrote {rotations_recorded} rotation audits");
        recovery_data["used_mask"] = json!(1);
        client.query_client().exec("UPDATE mfa_authenticator SET data = Unwrap(CAST($data AS Json)) WHERE id = $id")
            .param("$data", recovery_data.to_string()).param("$id", recovery_id).await?;
        let (status, body) = call_recovery(&app, &cookie, true, Some(&rotation_key)).await?;
        ensure!(status == StatusCode::CONFLICT && body["code"] == "ROTATION_REPLAY_UNAVAILABLE",
            "used code was re-exposed: {body}");
        let (status, _) = call(&app, "/api/v1/auth/mfa/totp/disable", Some(&cookie), false, None).await?;
        ensure!(status == StatusCode::FORBIDDEN, "TOTP disable ignored CSRF");
        let mut disable_attempts = tokio::task::JoinSet::new();
        for attempt in 0..100 {
            let app = if attempt % 2 == 0 { app.clone() } else { second_app.clone() };
            let cookie = cookie.clone();
            disable_attempts.spawn(async move {
                call(&app, "/api/v1/auth/mfa/totp/disable", Some(&cookie), true, None).await
            });
        }
        let mut disabled = 0;
        while let Some(joined) = disable_attempts.join_next().await {
            let (status, body) = joined??;
            if status == StatusCode::OK {
                disabled += 1;
            } else {
                ensure!(status == StatusCode::NOT_FOUND && body["code"] == "TOTP_NOT_ENABLED",
                    "unexpected concurrent disable: {status} {body}");
            }
        }
        ensure!(disabled == 1, "concurrent TOTP disable had {disabled} winners");
        let mut query = client.query_client();
        let mut stream = query.query("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $id")
            .param("$id", user_id).await?;
        let mut remaining = 0;
        while let Some(rows) = stream.next_result_set().await? {
            for _ in rows { remaining += 1; }
        }
        stream.close().await?;
        ensure!(remaining == 0, "disable left dangling recovery codes or TOTP");
        let mut row = client.query_client().query_row("SELECT session_data FROM django_session WHERE session_key = $key")
            .param("$key", session_token.clone()).await?;
        let signed: String = row.remove_field_by_name("session_data")?.try_into()?;
        let disabled_session = codec.decode(&signed)?;
        ensure!(disabled_session.data.get("id_mfa_verified_user_id").is_none()
            && disabled_session.data["account_authentication_methods"].as_array().is_some_and(|methods|
                methods.iter().all(|method| method["method"] != "mfa")),
            "disable left stale MFA proof in session");
        let (status, body) = call_recovery(&app, &cookie, true, Some(&"t".repeat(32))).await?;
        ensure!(status == StatusCode::BAD_REQUEST && body["code"] == "MFA_REQUIRED",
            "recovery rotation ran without an active MFA factor: {body}");
        let mut with_passkey = disabled_session.data;
        with_passkey.insert("id_mfa_verified_user_id".into(), json!(user_id.to_string()));
        with_passkey["account_authentication_methods"].as_array_mut()
            .context("authentication methods missing")?
            .insert(0, json!({"method":"mfa","type":"webauthn",
                "at":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64()}));
        let signed = codec.encode(&with_passkey,
            i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?, true)?;
        client.query_client().exec("UPDATE django_session SET session_data = $data WHERE session_key = $key")
            .param("$data", signed).param("$key", session_token.clone()).await?;
        for (offset, kind, data) in [
            (10i64, "totp", json!({"secret":"LEGACY"})),
            (11, "recovery_codes", json!({"seed":"LEGACY","used_mask":0})),
            (12, "webauthn", json!({"name":"synthetic passkey"})),
        ] {
            client.query_client().exec("UPSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $user_id, $kind, Unwrap(CAST($data AS Json)), CurrentUtcDatetime())")
                .param("$id", i64::from(user_id) - offset).param("$user_id", user_id)
                .param("$kind", kind).param("$data", data.to_string()).await?;
        }
        let (status, body) = call(&app, "/api/v1/auth/mfa/totp/disable", Some(&cookie), true, None).await?;
        ensure!(status == StatusCode::OK, "disable with passkey failed: {body}");
        let mut query = client.query_client();
        let mut stream = query.query("SELECT type FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $id")
            .param("$id", user_id).await?;
        let mut kinds = Vec::new();
        while let Some(rows) = stream.next_result_set().await? {
            for mut row in rows {
                let kind: String = row.remove_field_by_name("type")?.try_into()?;
                kinds.push(kind);
            }
        }
        stream.close().await?;
        kinds.sort();
        ensure!(kinds == ["recovery_codes", "webauthn"], "disable removed passkey or its recovery codes");
        let mut row = client.query_client().query_row("SELECT session_data FROM django_session WHERE session_key = $key")
            .param("$key", session_token.clone()).await?;
        let signed: String = row.remove_field_by_name("session_data")?.try_into()?;
        ensure!(codec.decode(&signed)?.data.get("id_mfa_verified_user_id") == Some(&json!(user_id.to_string())),
            "disable removed MFA proof with passkey still active");
        let (status, body) = call_recovery(&app, &cookie, true, Some(&"u".repeat(32))).await?;
        ensure!(status == StatusCode::OK && body["recovery_codes"].as_array().is_some_and(|codes| codes.len() == 10),
            "passkey-only recovery rotation failed: {body}");
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
    let mut events = query
        .query("SELECT id FROM accounts_accountevent VIEW acct_event_user_idx WHERE user_id = $id")
        .param("$id", user_id)
        .await?;
    let mut ids = Vec::new();
    while let Some(rows) = events.next_result_set().await? {
        for mut row in rows {
            let id: i64 = row.remove_field_by_name("id")?.try_into()?;
            ids.push(id);
        }
    }
    events.close().await?;
    for id in ids {
        client
            .query_client()
            .exec("DELETE FROM accounts_accountevent WHERE id = $id")
            .param("$id", id)
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM account_emailaddress WHERE id = $id")
        .param("$id", email_pk)
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
        .param("$key", session_token)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM auth_user WHERE id = $id")
        .param("$id", user_id)
        .await?;
    outcome
}
