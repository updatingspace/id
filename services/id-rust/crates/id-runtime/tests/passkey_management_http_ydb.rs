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

#[cfg(feature = "passkeys")]
fn synthetic_passkey(id: Uuid) -> Result<Value> {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/legacy_passkey.json"))?;
    let key = id_runtime::legacy_passkey::import_registration(
        &fixture["registration"],
        "id.example.invalid",
        "https://id.example.invalid",
    )?;
    let mut key = serde_json::to_value(key)?;
    let raw = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        id.as_bytes(),
    );
    *key.pointer_mut("/cred/cred_id")
        .context("serialized credential ID")? = json!(raw);
    let key: webauthn_rs::prelude::Passkey = serde_json::from_value(key)?;
    ensure!(
        key.cred_id().as_ref() == id.as_bytes(),
        "synthetic credential ID changed"
    );
    Ok(
        json!({"name":"Synthetic key","passwordless":true,"credential":{"rawId":raw},"rust_passkey":key}),
    )
}

#[cfg(feature = "passkeys")]
#[tokio::test]
#[ignore = "requires migrated local YDB and opt-in Rust passkey management"]
async fn passwordless_owner_cannot_remove_the_last_login_method() -> Result<()> {
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
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let user_id = -i32::try_from(stamp % 1_000_000_000 + 1)?;
    let identity = Uuid::new_v4();
    let key_id = i64::try_from(stamp)?;
    let recovery_id = key_id + 1;
    let second_key_id = key_id + 2;
    let totp_id = key_id + 3;
    let mut second_credential = synthetic_passkey(Uuid::new_v4())?;
    second_credential
        .as_object_mut()
        .context("credential object")?
        .remove("passwordless");
    second_credential["credential"]["clientExtensionResults"] = json!({"credProps":{"rk":true}});
    let second_digest = id_runtime::passkey_index::digest_of_record(&second_credential)?;
    let token = format!("lastlogin{}", Uuid::new_v4().simple());
    let email = format!("last-login-{identity}@example.invalid");
    let now = SystemTime::now();
    let codec = SessionCodec::new(std::env::var("DJANGO_SECRET_KEY")?.as_bytes(), &[])?;
    let session = json!({"_auth_user_id":user_id.to_string(),
        "_auth_user_backend":"django.contrib.auth.backends.ModelBackend",
        "_auth_user_hash":codec.auth_hash("!unusable")?,
        "id_mfa_verified_user_id":user_id.to_string(),
        "account_authentication_methods":[{"method":"mfa","type":"webauthn","passwordless":true,"at":now.duration_since(UNIX_EPOCH)?.as_secs_f64()}]});
    let signed = codec.encode(
        session.as_object().context("session object")?,
        i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?,
        true,
    )?;
    let credential = synthetic_passkey(identity)?;
    let digest = id_runtime::passkey_index::digest_of_record(&credential)?;
    // INSERT precedes the cleanup scope: a fixture-ID collision cannot delete
    // an account owned by another concurrently running integration test.
    client.query_client().exec("INSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, '!unusable', true, $name, '', '', $email, false, false, CurrentUtcDatetime())")
        .param("$id", user_id).param("$name", format!("last-login-{identity}")).param("$email", email.clone()).await?;
    let outcome: Result<()> = async {
        client.query_client().exec("INSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, $name, $name, $email, true, 'active', false, CurrentUtcDatetime())")
            .param("$id", identity).param("$name", format!("last-login-{identity}")).param("$email", email.clone()).await?;
        client.query_client().exec("INSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($id, $identity, $subject, CurrentUtcDatetime())")
            .param("$id", user_id).param("$identity", identity).param("$subject", identity.to_string()).await?;
        client.query_client().exec("INSERT INTO accounts_accountemaillookup (user_id, email_key) VALUES ($id, $email)")
            .param("$id", user_id).param("$email", email.clone()).await?;
        client.query_client().exec("INSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($id, $id, $email, true, true)")
            .param("$id", user_id).param("$email", email.clone()).await?;
        client.query_client().exec("INSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, $data, CAST($expires AS Datetime))")
            .param("$key", token.clone()).param("$data", signed.clone()).param("$expires", now + Duration::from_secs(3600)).await?;
        client.query_client().exec("INSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($key, $owner, 'webauthn', Unwrap(CAST($data AS Json)), CurrentUtcDatetime()), ($recovery, $owner, 'recovery_codes', Unwrap(CAST($codes AS Json)), CurrentUtcDatetime())")
            .param("$key", key_id).param("$owner", user_id).param("$data", credential.to_string())
            .param("$recovery", recovery_id).param("$codes", json!({"seed":"synthetic","used_mask":0}).to_string()).await?;
        client.query_client().exec("INSERT INTO id_passkey_credential (digest, authenticator_id, account_id) VALUES ($digest, $key, $owner)")
            .param("$digest", digest.clone()).param("$key", key_id).param("$owner", user_id).await?;
        let cookie = format!("sessionid={token}; csrftoken={}", "a".repeat(32));
        let (status, body) = call(&app, "/api/v1/auth/passkeys/delete", &cookie, true,
            json!({"ids":[key_id.to_string()]})).await?;
        ensure!(status == StatusCode::CONFLICT && body["code"] == "LAST_LOGIN_METHOD",
            "passwordless owner lost their last primary login: {status} {body}");
        ensure!(data(&client, key_id).await? == Some(credential.clone())
            && data(&client, recovery_id).await? == Some(json!({"seed":"synthetic","used_mask":0})),
            "denied deletion changed authenticators");
        let mut row = client.query_client().query_row("SELECT session_data FROM django_session WHERE session_key = $key")
            .param("$key", token.clone()).await?;
        let retained: String = row.remove_field_by_name("session_data")?.try_into()?;
        ensure!(retained == signed, "denied deletion changed the session");
        ensure!(client.query_client().query_row("SELECT digest FROM id_passkey_credential WHERE digest = $digest")
            .param("$digest", digest.clone()).optional().await?.is_some(), "denied deletion changed the login index");
        for table in ["accounts_accountevent", "id_security_mail"] {
            let mut row = client.query_client().query_row(format!("SELECT COUNT(*) AS n FROM {table} WHERE user_id = $owner"))
                .param("$owner", user_id).await?;
            let count: u64 = row.remove_field_by_name("n")?.try_into()?;
            ensure!(count == 0, "denied deletion recorded a success effect in {table}");
        }

        // Neither a TOTP factor nor recovery codes are a primary login.
        client.query_client().exec("INSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $owner, 'totp', Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime())")
            .param("$id", totp_id).param("$owner", user_id).await?;
        let (status, body) = call(&app, "/api/v1/auth/passkeys/delete", &cookie, true,
            json!({"ids":[key_id.to_string()]})).await?;
        ensure!(status == StatusCode::CONFLICT && body["code"] == "LAST_LOGIN_METHOD", "TOTP counted as primary login");
        client.query_client().exec("DELETE FROM mfa_authenticator WHERE id = $id AND user_id = $owner")
            .param("$id", totp_id).param("$owner", user_id).await?;

        let subject = stamp.to_string();
        client.query_client().exec("INSERT INTO socialaccount_socialaccount (id, user_id, provider, uid, extra_data, date_joined, last_login) VALUES ($id, $owner, 'github', $subject, Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime(), CurrentUtcDatetime())")
            .param("$id", user_id).param("$owner", user_id).param("$subject", subject.clone()).await?;
        use id_runtime::{login_http::{LoginHttpConfig, LoginHttpOptions}, provider_login::ProviderLoginConfig};
        let secret = std::env::var("DJANGO_SECRET_KEY")?;
        let login = Arc::new(LoginHttpConfig::new(client.clone(),
            id_runtime::cache_store::CacheStore::new(client.clone(), "id_shared_cache", "", 1)?,
            Arc::new(SessionCodec::new(secret.as_bytes(), &[])?),
            id_compat::account_jwt::AccountJwtCodec::new(secret.as_bytes())?,
            id_runtime::media_url::MediaUrl::new("https://id.example.invalid/media/")?,
            LoginHttpOptions {
                session_cookie_name:"sessionid".into(),csrf_cookie_name:"csrftoken".into(),
                session_cookie_secure:true,csrf_cookie_secure:true,
                session_same_site:cookie::SameSite::Lax,csrf_same_site:cookie::SameSite::Lax,
                session_cookie_domain:None,csrf_cookie_domain:None,session_cookie_age:3600,
                login_ip_limit:100,trusted_origins:vec!["https://id.example.invalid".into()],
                device_fingerprint_salt:"synthetic".into(),
            })?);
        let providers = vec![Arc::new(ProviderLoginConfig::github(login, "synthetic".into(), "synthetic".into(),
            "https://id.example.invalid/api/v1/auth/oauth/callback/github".into(), vec!["/account".into()])?)];
        let owner_codec = Arc::new(SessionCodec::new(secret.as_bytes(), &[])?);
        use id_runtime::passkey_management::{delete, Outcome};
        ensure!(delete(&client, owner_codec.clone(), &token, &[key_id], SystemTime::now(), &[]).await?
            == Outcome::LastLoginMethod, "disabled provider counted as primary login");
        // A raw conflicting UUID binding reserves the same subject even when
        // its owner is absent/inactive. Login and deletion must agree.
        client.query_client().exec("INSERT INTO usid_external_identity (id, user_id, provider, subject, created_at) VALUES ($id, $owner, 'github', $subject, CurrentUtcDatetime())")
            .param("$id", key_id).param("$owner", Uuid::new_v4()).param("$subject", subject.clone()).await?;
        ensure!(delete(&client, owner_codec.clone(), &token, &[key_id], SystemTime::now(), &providers).await?
            == Outcome::LastLoginMethod, "conflicting provider counted as primary login");
        client.query_client().exec("DELETE FROM usid_external_identity WHERE id = $id AND subject = $subject")
            .param("$id", key_id).param("$subject", subject.clone()).await?;
        client.query_client().exec("INSERT INTO socialaccount_socialaccount (id, user_id, provider, uid, extra_data, date_joined, last_login) VALUES ($id, $owner, 'github', $subject, Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime(), CurrentUtcDatetime())")
            .param("$id", user_id - 1).param("$owner", user_id - 1).param("$subject", subject.clone()).await?;
        ensure!(delete(&client, owner_codec.clone(), &token, &[key_id], SystemTime::now(), &providers).await?
            == Outcome::LastLoginMethod, "duplicate provider subject counted as primary login");
        client.query_client().exec("DELETE FROM socialaccount_socialaccount WHERE id = $id AND uid = $subject")
            .param("$id", user_id - 1).param("$subject", subject.clone()).await?;
        ensure!(data(&client, key_id).await? == Some(credential.clone())
            && data(&client, recovery_id).await?.is_some(), "denied fallback checks changed credentials");
        for table in ["accounts_accountevent", "id_security_mail"] {
            let mut row = client.query_client().query_row(format!("SELECT COUNT(*) AS n FROM {table} WHERE user_id = $owner"))
                .param("$owner", user_id).await?;
            let count: u64 = row.remove_field_by_name("n")?.try_into()?;
            ensure!(count == 0, "denied fallback checks recorded success in {table}");
        }

        client.query_client().exec("INSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $owner, 'webauthn', Unwrap(CAST($data AS Json)), CurrentUtcDatetime())")
            .param("$id", second_key_id).param("$owner", user_id).param("$data", second_credential.to_string()).await?;
        client.query_client().exec("INSERT INTO id_passkey_credential (digest, authenticator_id, account_id) VALUES ($digest, $id, $owner)")
            .param("$digest", second_digest.clone()).param("$id", second_key_id).param("$owner", user_id).await?;
        // An indexed second-factor-only key does not preserve discoverable
        // login. Unknown resident-key metadata is insufficient too.
        for discoverability in [Some(false), None, Some(true)] {
            let mut unusable = second_credential.clone();
            if let Some(value) = discoverability {
                unusable["passwordless"] = json!(value);
                if value { unusable["credential"]["clientExtensionResults"]["credProps"]["rk"] = json!(false); }
            }
            else {
                unusable.as_object_mut().context("credential object")?.remove("passwordless");
                unusable["credential"].as_object_mut().context("credential response")?.remove("clientExtensionResults");
            }
            client.query_client().exec("UPDATE mfa_authenticator SET data = Unwrap(CAST($data AS Json)) WHERE id = $id AND user_id = $owner")
                .param("$data", unusable.to_string()).param("$id", second_key_id).param("$owner", user_id).await?;
            let (status, body) = call(&app, "/api/v1/auth/passkeys/delete", &cookie, true,
                json!({"ids":[key_id.to_string()]})).await?;
            ensure!(status == StatusCode::CONFLICT && body["code"] == "LAST_LOGIN_METHOD",
                "non-discoverable key counted as a primary login");
        }
        client.query_client().exec("UPDATE mfa_authenticator SET data = Unwrap(CAST($data AS Json)) WHERE id = $id AND user_id = $owner")
            .param("$data", second_credential.to_string()).param("$id", second_key_id).param("$owner", user_id).await?;
        let second_client = Arc::new(id_runtime::connect_ydb().await?);
        let second_app = id_runtime::totp_setup_http::router(
            id_runtime::totp_setup_http::TotpSetupHttpConfig::from_env(second_client)?
                .context("second passkey pilot disabled")?);
        let (first, second) = tokio::join!(
            call(&app, "/api/v1/auth/passkeys/delete", &cookie, true, json!({"ids":[key_id.to_string()]})),
            call(&second_app, "/api/v1/auth/passkeys/delete", &cookie, true, json!({"ids":[second_key_id.to_string()]})),
        );
        let outcomes = [first?, second?];
        ensure!(outcomes.iter().filter(|(status, _)| *status == StatusCode::OK).count() == 1
            && outcomes.iter().filter(|(status, body)| *status == StatusCode::CONFLICT && body["code"] == "LAST_LOGIN_METHOD").count() == 1,
            "concurrent removal of different keys must preserve a login: {outcomes:?}");
        let retained = if data(&client, key_id).await?.is_some() { key_id } else { second_key_id };
        ensure!(data(&client, retained).await?.is_some() && data(&client, recovery_id).await?.is_some(),
            "concurrent removal lost the final key or recovery");
        ensure!(delete(&client, owner_codec, &token, &[retained], SystemTime::now(), &providers).await?
            == Outcome::Deleted(1), "valid configured provider did not preserve login");
        ensure!(data(&client, retained).await?.is_none() && data(&client, recovery_id).await?.is_none(),
            "successful provider fallback did not remove requested credentials");
        for table in ["accounts_accountevent", "id_security_mail"] {
            let mut row = client.query_client().query_row(format!("SELECT COUNT(*) AS n FROM {table} WHERE user_id = $owner"))
                .param("$owner", user_id).await?;
            let count: u64 = row.remove_field_by_name("n")?.try_into()?;
            ensure!(count == 2, "only the two successful deletions may record effects in {table}");
        }
        Ok(())
    }.await;
    for table in [
        "mfa_authenticator",
        "accounts_accountevent",
        "id_security_mail",
        "accounts_accountidentity",
        "accounts_accountemaillookup",
        "account_emailaddress",
    ] {
        client
            .query_client()
            .exec(format!("DELETE FROM {table} WHERE user_id = $owner"))
            .param("$owner", user_id)
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM id_passkey_credential WHERE digest = $digest AND account_id = $owner")
        .param("$digest", digest)
        .param("$owner", user_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM id_passkey_credential WHERE digest = $digest AND account_id = $owner")
        .param("$digest", second_digest)
        .param("$owner", user_id)
        .await?;
    for id in [user_id, user_id - 1] {
        client
            .query_client()
            .exec("DELETE FROM socialaccount_socialaccount WHERE id = $id AND uid = $subject")
            .param("$id", id)
            .param("$subject", stamp.to_string())
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM usid_external_identity WHERE id = $id AND subject = $subject")
        .param("$id", key_id)
        .param("$subject", stamp.to_string())
        .await?;
    client
        .query_client()
        .exec("DELETE FROM django_session WHERE session_key = $key")
        .param("$key", token)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM usid_user WHERE user_id = $id")
        .param("$id", identity)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM auth_user WHERE id = $id")
        .param("$id", user_id)
        .await?;
    outcome
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
    let golden: Value =
        serde_json::from_str(include_str!("../../id-compat/tests/fixtures/django.json"))?;
    let password = golden["password_hashes"][0]
        .as_str()
        .context("golden password hash")?;
    ensure!(
        id_compat::password::verify(
            golden["password"].as_str().context("golden password")?,
            password
        )?,
        "positive control must retain a working password"
    );
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
        client.query_client().exec("INSERT INTO accounts_accountemaillookup (user_id, email_key) VALUES ($id, $email)")
            .param("$id", user_id).param("$email", format!("rust-passkey-{stamp}@example.invalid")).await?;
        client.query_client().exec("INSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($id, $id, $email, true, true)")
            .param("$id", user_id).param("$email", format!("rust-passkey-{stamp}@example.invalid")).await?;
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
    for table in ["accounts_accountemaillookup", "account_emailaddress"] {
        client
            .query_client()
            .exec(format!("DELETE FROM {table} WHERE user_id = $id"))
            .param("$id", user_id)
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
