#![recursion_limit = "256"]
#![cfg(feature = "passkeys")]
//! Signed WebAuthn assertion through two HTTP instances and real YDB.

use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cookie::SameSite;
use id_compat::{account_jwt::AccountJwtCodec, session::SessionCodec};
use id_runtime::{
    cache_store::CacheStore,
    login_http::{self, LoginHttpConfig, LoginHttpOptions},
    media_url::MediaUrl,
    passkey_index,
};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    hash::{MessageDigest, hash},
    nid::Nid,
    sign::Signer,
};
use serde_cbor_2::Value as Cbor;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;
use uuid::Uuid;
use webauthn_rs::prelude::{Url, WebauthnBuilder};

const RP: &str = "id.example.invalid";
const ORIGIN: &str = "https://id.example.invalid";
const SECRET: &[u8] = b"synthetic-local-secret-min-32-characters";

async fn post(
    app: &Router,
    path: &str,
    cookie: Option<&str>,
    body: Value,
) -> Result<(StatusCode, Vec<String>, Value)> {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-forwarded-for", "192.0.2.93");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string()))?)
        .await?;
    let status = response.status();
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|header| header.to_str().ok())
        .map(str::to_owned)
        .collect();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await?)?;
    Ok((status, cookies, body))
}

fn cbor_map(entries: Vec<(Cbor, Cbor)>) -> Cbor {
    Cbor::Map(entries.into_iter().collect::<BTreeMap<_, _>>())
}

fn synthetic_registration(
    challenge: &str,
    key: &EcKey<openssl::pkey::Private>,
    cred_id: &[u8],
) -> Result<Value> {
    let mut context = BigNumContext::new()?;
    let mut x = BigNum::new()?;
    let mut y = BigNum::new()?;
    key.public_key()
        .affine_coordinates_gfp(key.group(), &mut x, &mut y, &mut context)?;
    let x = x.to_vec_padded(32)?;
    let y = y.to_vec_padded(32)?;
    let cose = cbor_map(vec![
        (Cbor::Integer(1), Cbor::Integer(2)),
        (Cbor::Integer(3), Cbor::Integer(-7)),
        (Cbor::Integer(-1), Cbor::Integer(1)),
        (Cbor::Integer(-2), Cbor::Bytes(x)),
        (Cbor::Integer(-3), Cbor::Bytes(y)),
    ]);
    let mut auth = hash(MessageDigest::sha256(), RP.as_bytes())?.to_vec();
    auth.push(0x45); // user present, verified, attested credential data
    auth.extend_from_slice(&0u32.to_be_bytes());
    auth.extend_from_slice(&[0u8; 16]);
    auth.extend_from_slice(&u16::try_from(cred_id.len())?.to_be_bytes());
    auth.extend_from_slice(cred_id);
    auth.extend_from_slice(&serde_cbor_2::to_vec(&cose)?);
    let attestation = cbor_map(vec![
        (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
        (Cbor::Text("attStmt".into()), cbor_map(vec![])),
        (Cbor::Text("authData".into()), Cbor::Bytes(auth)),
    ]);
    let client_data =
        json!({"type":"webauthn.create","challenge":challenge,"origin":ORIGIN,"crossOrigin":false});
    let id = URL_SAFE_NO_PAD.encode(cred_id);
    Ok(json!({"id":id,"rawId":id,"type":"public-key","response":{
        "clientDataJSON":URL_SAFE_NO_PAD.encode(client_data.to_string()),
        "attestationObject":URL_SAFE_NO_PAD.encode(serde_cbor_2::to_vec(&attestation)?),
        "transports":["internal"]},"clientExtensionResults":{"credProps":{"rk":true}}}))
}

fn assertion(
    challenge: &str,
    key: &EcKey<openssl::pkey::Private>,
    cred_id: &[u8],
    counter: u32,
    origin: &str,
) -> Result<Value> {
    let client_data =
        json!({"type":"webauthn.get","challenge":challenge,"origin":origin,"crossOrigin":false})
            .to_string();
    let mut auth = hash(MessageDigest::sha256(), RP.as_bytes())?.to_vec();
    auth.push(0x05); // user present and verified
    auth.extend_from_slice(&counter.to_be_bytes());
    let mut signed = auth.clone();
    signed.extend_from_slice(&hash(MessageDigest::sha256(), client_data.as_bytes())?);
    let pkey = openssl::pkey::PKey::from_ec_key(key.clone())?;
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
    signer.update(&signed)?;
    let signature = signer.sign_to_vec()?;
    let id = URL_SAFE_NO_PAD.encode(cred_id);
    Ok(json!({"id":id,"rawId":id,"type":"public-key","response":{
        "clientDataJSON":URL_SAFE_NO_PAD.encode(client_data),
        "authenticatorData":URL_SAFE_NO_PAD.encode(auth),
        "signature":URL_SAFE_NO_PAD.encode(signature),"userHandle":null},"clientExtensionResults":{}}))
}

#[tokio::test]
#[ignore = "requires migrated local YDB and synthetic account"]
async fn signed_passkey_login_issues_once_and_rejects_replay() -> Result<()> {
    ensure!(
        std::env::var("YDB_DATABASE")? == "/local",
        "local YDB required"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    let second = Arc::new(id_runtime::connect_ydb().await?);
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let account_id = -i32::try_from(stamp % 1_000_000_000 + 1)?;
    let identity = Uuid::from_u128((stamp << 32) | u128::from(std::process::id()));
    let email = format!("rust-passkey-login-{stamp}@example.invalid");
    let password = "pbkdf2_sha256$1000000$synthetic$synthetic";
    let cache_table = format!("id_passkey_login_{}_{}", std::process::id(), stamp);
    client.query_client().exec(format!("CREATE TABLE `{cache_table}` (cache_key Utf8 NOT NULL, value String, expires_at Uint64, PRIMARY KEY(cache_key))")).await?;
    client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $password, true, $name, '', '', $email, false, false, CurrentUtcDatetime())")
        .param("$id", account_id).param("$password", password).param("$name", format!("rust-passkey-login-{stamp}")).param("$email", email.clone()).await?;
    client
        .query_client()
        .exec("UPSERT INTO accounts_accountemaillookup (user_id, email_key) VALUES ($id, $email)")
        .param("$id", account_id)
        .param("$email", email.clone())
        .await?;
    client.query_client().exec("UPSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($id, $id, $email, true, true)")
        .param("$id", account_id).param("$email", email.clone()).await?;
    client.query_client().exec("UPSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, $name, $name, $email, true, 'active', false, CurrentUtcDatetime())")
        .param("$id", identity).param("$name", format!("rust-passkey-login-{stamp}")).param("$email", email.clone()).await?;
    client.query_client().exec("UPSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($id, $identity, $subject, CurrentUtcDatetime())")
        .param("$id", account_id).param("$identity", identity).param("$subject", format!("rust-passkey-login-sub-{stamp}")).await?;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let key = EcKey::generate(&group)?;
    let cred_id = rand::random::<[u8; 32]>();
    let webauthn = WebauthnBuilder::new(RP, &Url::parse(ORIGIN)?)?.build()?;
    let (creation, state) = webauthn.start_passkey_registration(identity, &email, &email, None)?;
    let challenge = serde_json::to_value(creation)?["publicKey"]["challenge"]
        .as_str()
        .context("registration challenge")?
        .to_owned();
    let registration = synthetic_registration(&challenge, &key, &cred_id)?;
    let response = serde_json::from_value(registration.clone())?;
    let passkey = webauthn.finish_passkey_registration(&response, &state)?;
    let authenticator_id = -i64::try_from(stamp)?;
    client.query_client().exec("UPSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $user_id, 'webauthn', Unwrap(CAST($data AS Json)), CurrentUtcDatetime())")
        .param("$id", authenticator_id).param("$user_id", account_id)
        .param("$data", json!({"name":"Synthetic passkey","credential":registration,"rust_passkey":passkey}).to_string()).await?;
    passkey_index::backfill(&client).await?;
    if let Ok(output) = std::env::var("ID_PASSKEY_BROWSER_FIXTURE_OUTPUT") {
        let private_key = openssl::pkey::PKey::from_ec_key(key.clone())?.private_key_to_pkcs8()?;
        std::fs::write(
            &output,
            json!({
                "credential_id": URL_SAFE_NO_PAD.encode(cred_id),
                "private_key_pkcs8": URL_SAFE_NO_PAD.encode(private_key),
                "cache_table": cache_table,
                "account_id": account_id,
                "email": email,
                "rp_id": RP,
                "origin": ORIGIN,
            })
            .to_string(),
        )?;
        let done = std::env::var("ID_PASSKEY_BROWSER_DONE")?;
        for _ in 0..240 {
            if std::path::Path::new(&done).exists() {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        anyhow::bail!("browser fixture did not signal completion");
    }
    let cache = CacheStore::new(client.clone(), &cache_table, "", 1)?;
    let options = LoginHttpOptions {
        session_cookie_name: "sessionid".into(),
        csrf_cookie_name: "csrftoken".into(),
        session_cookie_secure: false,
        csrf_cookie_secure: false,
        session_same_site: SameSite::Lax,
        csrf_same_site: SameSite::Lax,
        session_cookie_domain: None,
        csrf_cookie_domain: None,
        session_cookie_age: 3600,
        login_ip_limit: 100,
        trusted_origins: vec!["http://id.localhost:5175".into()],
        device_fingerprint_salt: "synthetic-device-salt".into(),
    };
    let first = login_http::router(Arc::new(
        LoginHttpConfig::new(
            client.clone(),
            cache.clone(),
            Arc::new(SessionCodec::new(SECRET, &[])?),
            AccountJwtCodec::new(SECRET)?,
            MediaUrl::new("http://id.localhost/media/")?,
            options,
        )?
        .with_passkey(RP, ORIGIN)?,
    ));
    let options = LoginHttpOptions {
        session_cookie_name: "sessionid".into(),
        csrf_cookie_name: "csrftoken".into(),
        session_cookie_secure: false,
        csrf_cookie_secure: false,
        session_same_site: SameSite::Lax,
        csrf_same_site: SameSite::Lax,
        session_cookie_domain: None,
        csrf_cookie_domain: None,
        session_cookie_age: 3600,
        login_ip_limit: 100,
        trusted_origins: vec!["http://id.localhost:5175".into()],
        device_fingerprint_salt: "synthetic-device-salt".into(),
    };
    let second_app = login_http::router(Arc::new(
        LoginHttpConfig::new(
            second,
            cache,
            Arc::new(SessionCodec::new(SECRET, &[])?),
            AccountJwtCodec::new(SECRET)?,
            MediaUrl::new("http://id.localhost/media/")?,
            options,
        )?
        .with_passkey(RP, ORIGIN)?,
    ));
    let (status, cookies, begin) =
        post(&first, "/api/v1/auth/passkeys/login/begin", None, json!({})).await?;
    ensure!(status == StatusCode::OK, "passkey begin failed: {begin}");
    let cookie = cookies
        .iter()
        .find(|value| value.starts_with("id_passkey_ceremony="))
        .context("ceremony cookie")?
        .split(';')
        .next()
        .context("ceremony cookie parse")?
        .to_owned();
    let challenge = begin["request_options"]["publicKey"]["challenge"]
        .as_str()
        .context("login challenge")?;
    let credential = assertion(challenge, &key, &cred_id, 1, ORIGIN)?;
    let body = json!({"credential":credential});
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..20 {
        let app = if index % 2 == 0 {
            first.clone()
        } else {
            second_app.clone()
        };
        let cookie = cookie.clone();
        let body = body.clone();
        tasks.spawn(async move {
            post(
                &app,
                "/api/v1/auth/passkeys/login/complete",
                Some(&cookie),
                body,
            )
            .await
        });
    }
    let mut successes = 0;
    while let Some(result) = tasks.join_next().await {
        let (status, _, body) = result??;
        if status == StatusCode::OK {
            successes += 1;
            ensure!(
                body["meta"]["session_token"].as_str().is_some()
                    && body["refresh_token"].as_str().is_some(),
                "login omitted credentials"
            );
        } else {
            ensure!(
                status == StatusCode::UNAUTHORIZED && body["code"] == "INVALID_PASSKEY",
                "unexpected replay: {status} {body}"
            );
        }
    }
    ensure!(
        successes == 1,
        "expected one successful passkey login, got {successes}"
    );
    let (status, _, _) = post(
        &first,
        "/api/v1/auth/passkeys/login/complete",
        Some(&cookie),
        body,
    )
    .await?;
    ensure!(
        status == StatusCode::UNAUTHORIZED,
        "passkey challenge replay accepted"
    );
    let (status, cookies, begin) = post(
        &second_app,
        "/api/v1/auth/passkeys/login/begin",
        None,
        json!({}),
    )
    .await?;
    ensure!(status == StatusCode::OK, "second passkey begin failed");
    let cookie = cookies
        .iter()
        .find(|value| value.starts_with("id_passkey_ceremony="))
        .context("second ceremony cookie")?
        .split(';')
        .next()
        .context("cookie parse")?;
    let challenge = begin["request_options"]["publicKey"]["challenge"]
        .as_str()
        .context("second challenge")?;
    let wrong_origin = assertion(challenge, &key, &cred_id, 2, "https://attacker.invalid")?;
    let (status, _, _) = post(
        &first,
        "/api/v1/auth/passkeys/login/complete",
        Some(cookie),
        json!({"credential":wrong_origin}),
    )
    .await?;
    ensure!(
        status == StatusCode::UNAUTHORIZED,
        "wrong WebAuthn origin accepted"
    );
    let (status, cookies, begin) =
        post(&first, "/api/v1/auth/passkeys/login/begin", None, json!({})).await?;
    ensure!(status == StatusCode::OK, "third passkey begin failed");
    let cookie = cookies
        .iter()
        .find(|value| value.starts_with("id_passkey_ceremony="))
        .context("third ceremony cookie")?
        .split(';')
        .next()
        .context("cookie parse")?;
    let challenge = begin["request_options"]["publicKey"]["challenge"]
        .as_str()
        .context("third challenge")?;
    client
        .query_client()
        .exec("UPDATE auth_user SET is_active = false WHERE id = $id")
        .param("$id", account_id)
        .await?;
    let valid = assertion(challenge, &key, &cred_id, 2, ORIGIN)?;
    let (status, _, _) = post(
        &second_app,
        "/api/v1/auth/passkeys/login/complete",
        Some(cookie),
        json!({"credential":valid}),
    )
    .await?;
    ensure!(
        status == StatusCode::UNAUTHORIZED,
        "disabled account received a passkey session"
    );
    Ok(())
}
