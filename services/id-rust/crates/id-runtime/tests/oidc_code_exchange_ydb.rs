#![recursion_limit = "256"]
//! Real-YDB single-winner OIDC authorization-code exchange.

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use id_runtime::{
    media_url::MediaUrl,
    oidc_code_exchange::{CodeExchange, ExchangeFailure, exchange_code},
    oidc_keys::OidcKeyRing,
    oidc_refresh::{RefreshRequest, rotate},
    oidc_revoke::{RevokeRequest, revoke},
    oidc_userinfo::userinfo,
};
use jsonwebtoken::{Algorithm, Validation, decode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

fn generated_pair() -> Result<(String, String)> {
    let private = Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
        ])
        .output()?;
    ensure!(private.status.success(), "ephemeral RSA generation failed");
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
    ensure!(
        public.status.success(),
        "ephemeral RSA public export failed"
    );
    Ok((
        String::from_utf8(private.stdout)?,
        String::from_utf8(public.stdout)?,
    ))
}

#[tokio::test]
#[ignore = "requires migrated local YDB"]
async fn code_is_single_use_and_signed_subject_remains_stable() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "test requires local YDB"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    let (private, public) = generated_pair()?;
    let keys = Arc::new(OidcKeyRing::from_json(
        &json!({
            "private_key_pem":private,"public_key_pem":public,"kid":"local-oidc-test"
        })
        .to_string(),
    )?);
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let user_id = -i32::try_from(stamp % 1_000_000_000 + 1)?;
    let client_pk = -i64::try_from(stamp % 1_000_000_000 + 10_000_000_000)?;
    let email_pk = user_id - 1;
    let profile_pk = client_pk - 3;
    let preferences_pk = client_pk - 4;
    let identity_id = Uuid::from_u128((stamp << 32) | u128::from(std::process::id()));
    let subject = format!("stable-subject-{stamp}");
    let client_id = format!("rust-oidc-client-{stamp}");
    let code = format!("rust-oidc-code-{stamp}");
    let offline_code = format!("rust-oidc-offline-{stamp}");
    let disabled_code = format!("rust-oidc-disabled-{stamp}");
    let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let now = SystemTime::now();
    let email = format!("oidc-{stamp}@example.invalid");
    let password = "pbkdf2_sha256$1000000$synthetic$synthetic";
    client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $password, true, $name, 'Ada', 'Lovelace', $email, false, false, CurrentUtcDatetime())")
        .param("$id", user_id).param("$password", password).param("$name", format!("oidc-{stamp}"))
        .param("$email", email.clone()).await?;
    let result: Result<()> = async {
        client.query_client().exec("UPSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, $name, 'Ada Lovelace', $email, true, 'active', false, CurrentUtcDatetime())")
            .param("$id", identity_id).param("$name", format!("oidc-{stamp}"))
            .param("$email", email.clone()).await?;
        client.query_client().exec("UPSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($user_id, $identity_id, $subject, CurrentUtcDatetime())")
            .param("$user_id", user_id).param("$identity_id", identity_id).param("$subject", subject.clone()).await?;
        client.query_client().exec("UPSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($id, $user_id, $email, true, true)")
            .param("$id", email_pk).param("$user_id", user_id).param("$email", email.clone()).await?;
        client.query_client().exec("UPSERT INTO accounts_userprofile (id, user_id, avatar, avatar_source, gravatar_enabled, phone_number, phone_verified, birth_date, created_at, updated_at) VALUES ($id, $user_id, CAST('avatars/saved.jpg' AS String), 'upload', false, '+123456789', true, CAST('2001-02-03' AS Date), CurrentUtcDatetime(), CurrentUtcDatetime())")
            .param("$id", profile_pk).param("$user_id", user_id).await?;
        client.query_client().exec("UPSERT INTO accounts_userpreferences (id, user_id, language, timezone, marketing_opt_in, privacy_scope_defaults, created_at, updated_at) VALUES ($id, $user_id, 'ru', 'Europe/Moscow', false, Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime(), CurrentUtcDatetime())")
            .param("$id", preferences_pk).param("$user_id", user_id).await?;
        client.query_client().exec("UPSERT INTO idp_oidcclient (id, client_id, name, logo_url, description, client_secret_hash, redirect_uris, allowed_scopes, grant_types, response_types, is_public, is_first_party, created_at, updated_at) VALUES ($id, $client_id, 'Rust OIDC test', '', '', '', Unwrap(CAST($redirects AS Json)), Unwrap(CAST('[\"openid\",\"email\",\"offline_access\",\"profile_extended\",\"phone\",\"address\"]' AS Json)), Unwrap(CAST('[\"authorization_code\",\"refresh_token\"]' AS Json)), Unwrap(CAST('[\"code\"]' AS Json)), true, false, CurrentUtcDatetime(), CurrentUtcDatetime())")
            .param("$id", client_pk).param("$client_id", client_id.clone())
            .param("$redirects", r#"["https://rp.example.invalid/callback"]"#).await?;
        client.query_client().exec("UPSERT INTO idp_oidcauthorizationcode (code, client_id, user_id, redirect_uri, scope, nonce, code_challenge, code_challenge_method, created_at, expires_at) VALUES ($code, $client_id, $user_id, $redirect, 'openid email', 'stable-nonce', $challenge, 'S256', CurrentUtcDatetime(), CAST($expires AS Datetime))")
            .param("$code", code.clone()).param("$client_id", client_pk).param("$user_id", user_id)
            .param("$redirect", "https://rp.example.invalid/callback").param("$challenge", challenge.clone())
            .param("$expires", now + Duration::from_secs(300)).await?;

        let request = CodeExchange { client_id: client_id.clone(), client_secret: None, code: code.clone(),
            redirect_uri: "https://rp.example.invalid/callback".into(), code_verifier: verifier.into() };
        let mut wrong = request.clone(); wrong.code_verifier = "x".repeat(43);
        ensure!(matches!(exchange_code(&client, keys.clone(), "https://id.example.invalid", "local-refresh-salt", wrong, now).await?, Err(ExchangeFailure::InvalidGrant)));
        let mut wrong = request.clone(); wrong.redirect_uri = "https://rp.example.invalid/other".into();
        ensure!(matches!(exchange_code(&client, keys.clone(), "https://id.example.invalid", "local-refresh-salt", wrong, now).await?, Err(ExchangeFailure::InvalidGrant)));
        client.query_client().exec("UPDATE idp_oidcclient SET redirect_uris = Unwrap(CAST('[\"https://rp.example.invalid/new\"]' AS Json)) WHERE id = $id")
            .param("$id", client_pk).await?;
        ensure!(matches!(exchange_code(&client, keys.clone(), "https://id.example.invalid", "local-refresh-salt", request.clone(), now).await?, Err(ExchangeFailure::InvalidGrant)),
            "authorization code survived removal of its redirect URI");
        client.query_client().exec("UPDATE idp_oidcclient SET redirect_uris = Unwrap(CAST('[\"https://rp.example.invalid/callback\"]' AS Json)) WHERE id = $id")
            .param("$id", client_pk).await?;
        let duplicate_pk = client_pk - 100;
        client.query_client().exec("UPSERT INTO idp_oidcclient (id, client_id, name, logo_url, description, client_secret_hash, redirect_uris, allowed_scopes, grant_types, response_types, is_public, is_first_party, created_at, updated_at) VALUES ($id, $client_id, 'Ambiguous OIDC client', '', '', '', Unwrap(CAST($redirects AS Json)), Unwrap(CAST('[\"openid\",\"email\"]' AS Json)), Unwrap(CAST('[\"authorization_code\"]' AS Json)), Unwrap(CAST('[\"code\"]' AS Json)), true, false, CurrentUtcDatetime(), CurrentUtcDatetime())")
            .param("$id", duplicate_pk).param("$client_id", client_id.clone())
            .param("$redirects", r#"["https://rp.example.invalid/callback"]"#).await?;
        ensure!(matches!(exchange_code(&client, keys.clone(), "https://id.example.invalid", "local-refresh-salt", request.clone(), now).await?, Err(ExchangeFailure::InvalidClient)),
            "ambiguous client exchanged an authorization code");
        client.query_client().exec("DELETE FROM idp_oidcclient WHERE id = $id")
            .param("$id", duplicate_pk).await?;

        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..25 {
            let client = client.clone(); let keys = keys.clone(); let request = request.clone();
            tasks.spawn(async move { exchange_code(&client, keys, "https://id.example.invalid", "local-refresh-salt", request, now).await });
        }
        let mut issued = Vec::new();
        while let Some(response) = tasks.join_next().await {
            match response?? {
                Ok(tokens) => issued.push(tokens),
                Err(ExchangeFailure::InvalidGrant) => {},
                Err(other) => anyhow::bail!("unexpected OAuth response: {other:?}"),
            }
        }
        ensure!(issued.len() == 1, "{} code exchanges succeeded", issued.len());
        let tokens = issued.pop().context("single token result")?;
        ensure!(tokens.refresh_token.is_none() && tokens.scope == "openid email");
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(std::slice::from_ref(&client_id));
        validation.set_issuer(&["https://id.example.invalid"]);
        let claims = decode::<Value>(&tokens.id_token,
            keys.verifier("local-oidc-test").context("test verifier")?, &validation)?.claims;
        ensure!(claims["sub"] == subject && claims["user_id"] == identity_id.to_string()
            && claims["nonce"] == "stable-nonce" && claims["email_verified"] == true);
        let info = userinfo(&client, &keys, "https://id.example.invalid", &tokens.access_token, None, now)
            .await?.context("issued access token must reach UserInfo")?;
        ensure!(info["sub"] == subject && info["user_id"] == identity_id.to_string()
            && info["email"] == email && info["email_verified"] == true
            && info.get("name").is_none(), "UserInfo claims differ from granted scopes");
        ensure!(userinfo(&client, &keys, "https://other.example.invalid", &tokens.access_token, None, now).await?.is_none(), "wrong issuer accepted");
        let tampered = format!("{}x", tokens.access_token);
        ensure!(userinfo(&client, &keys, "https://id.example.invalid", &tampered, None, now).await?.is_none(), "tampered access token accepted");
        let mut query_client = client.query_client();
        let mut rows = query_client.query("SELECT id FROM idp_oidctoken VIEW oidc_token_user_client_idx WHERE user_id = $user_id AND client_id = $client_id")
            .param("$user_id", user_id).param("$client_id", client_pk).await?;
        let mut count = 0;
        while let Some(set) = rows.next_result_set().await? { count += set.into_iter().count(); }
        rows.close().await?;
        ensure!(count == 1, "{count} token records created");
        let full_code = format!("oidc-full-{stamp}");
        client.query_client().exec("UPSERT INTO idp_oidcauthorizationcode (code, client_id, user_id, redirect_uri, scope, nonce, code_challenge, code_challenge_method, created_at, expires_at) VALUES ($code, $client_id, $user_id, $redirect, 'openid profile_extended phone address offline_access', '', $challenge, 'S256', CurrentUtcDatetime(), CAST($expires AS Datetime))")
            .param("$code", full_code.clone()).param("$client_id", client_pk).param("$user_id", user_id)
            .param("$redirect", "https://rp.example.invalid/callback").param("$challenge", challenge.clone())
            .param("$expires", now + Duration::from_secs(300)).await?;
        let mut full_request = request.clone();
        full_request.code = full_code;
        let full_tokens = exchange_code(&client, keys.clone(), "https://id.example.invalid", "local-refresh-salt", full_request, now).await?
            .map_err(|failure| anyhow::anyhow!("extended scopes rejected: {failure:?}"))?;
        let full_claims = decode::<Value>(&full_tokens.id_token,
            keys.verifier("local-oidc-test").context("test verifier")?, &validation)?.claims;
        ensure!(full_claims["name"] == "Ada Lovelace"
            && full_claims["given_name"] == "Ada"
            && full_claims["family_name"] == "Lovelace"
            && full_claims["locale"] == "ru"
            && full_claims["birthdate"] == "2001-02-03"
            && full_claims["phone_number"] == "+123456789"
            && full_claims["phone_number_verified"] == true
            && full_claims["address"] == json!({}),
            "extended ID token claims differ from granted scopes");
        let refreshed_full = rotate(&client, keys.clone(), "https://id.example.invalid", "local-refresh-salt", RefreshRequest {
            client_id: client_id.clone(), client_secret: None,
            refresh_token: full_tokens.refresh_token.context("extended scope refresh")?, scope: None,
        }, now).await?.map_err(|failure| anyhow::anyhow!("extended refresh rejected: {failure:?}"))?;
        let refreshed_claims = decode::<Value>(&refreshed_full.id_token,
            keys.verifier("local-oidc-test").context("test verifier")?, &validation)?.claims;
        ensure!(refreshed_claims["birthdate"] == "2001-02-03"
            && refreshed_claims["phone_number"] == "+123456789"
            && refreshed_claims["address"] == json!({}),
            "extended claims changed on refresh");
        client.query_client().exec("UPSERT INTO idp_oidcauthorizationcode (code, client_id, user_id, redirect_uri, scope, nonce, code_challenge, code_challenge_method, created_at, expires_at) VALUES ($code, $client_id, $user_id, $redirect, 'openid email offline_access', '', $challenge, 'S256', CurrentUtcDatetime(), CAST($expires AS Datetime))")
            .param("$code", offline_code.clone()).param("$client_id", client_pk).param("$user_id", user_id)
            .param("$redirect", "https://rp.example.invalid/callback").param("$challenge", URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())))
            .param("$expires", now + Duration::from_secs(300)).await?;
        let mut offline_request = request.clone();
        offline_request.code = offline_code.clone();
        let offline_tokens = exchange_code(&client, keys.clone(), "https://id.example.invalid", "local-refresh-salt", offline_request, now).await?
            .map_err(|failure| anyhow::anyhow!("offline code rejected: {failure:?}"))?;
        ensure!(offline_tokens.scope == "openid email offline_access" && offline_tokens.refresh_token.is_some(), "offline code did not issue refresh");
        let offline_refresh = offline_tokens.refresh_token.context("offline refresh")?;
        client.query_client().exec("UPSERT INTO idp_oidcclient (id, client_id, name, logo_url, description, client_secret_hash, redirect_uris, allowed_scopes, grant_types, response_types, is_public, is_first_party, created_at, updated_at) VALUES ($id, $client_id, 'Ambiguous OIDC client', '', '', '', Unwrap(CAST($redirects AS Json)), Unwrap(CAST('[\"openid\",\"email\"]' AS Json)), Unwrap(CAST('[\"authorization_code\"]' AS Json)), Unwrap(CAST('[\"code\"]' AS Json)), true, false, CurrentUtcDatetime(), CurrentUtcDatetime())")
            .param("$id", duplicate_pk).param("$client_id", client_id.clone())
            .param("$redirects", r#"["https://rp.example.invalid/callback"]"#).await?;
        ensure!(matches!(rotate(&client, keys.clone(), "https://id.example.invalid", "local-refresh-salt", RefreshRequest {
            client_id: client_id.clone(), client_secret: None,
            refresh_token: offline_refresh.clone(), scope: None,
        }, now).await?, Err(ExchangeFailure::InvalidClient)), "ambiguous client rotated a refresh token");
        client.query_client().exec("DELETE FROM idp_oidcclient WHERE id = $id")
            .param("$id", duplicate_pk).await?;
        let first_refresh = rotate(&client, keys.clone(), "https://id.example.invalid", "local-refresh-salt", RefreshRequest {
            client_id: client_id.clone(), client_secret: None,
            refresh_token: offline_refresh, scope: None,
        }, now).await?.map_err(|failure| anyhow::anyhow!("Rust-issued refresh rejected: {failure:?}"))?;
        ensure!(first_refresh.refresh_token.is_some(), "Rust-issued refresh did not rotate");
        let competing_refresh = first_refresh.refresh_token.context("second-generation refresh")?;
        let mut refresh_tasks = tokio::task::JoinSet::new();
        for _ in 0..100 {
            let client = client.clone();
            let keys = keys.clone();
            let refresh = competing_refresh.clone();
            let client_id = client_id.clone();
            refresh_tasks.spawn(async move {
                rotate(&client, keys, "https://id.example.invalid", "local-refresh-salt", RefreshRequest {
                    client_id, client_secret: None, refresh_token: refresh, scope: None,
                }, now).await
            });
        }
        let mut refresh_winners = Vec::new();
        while let Some(result) = refresh_tasks.join_next().await {
            match result?? {
                Ok(tokens) => refresh_winners.push(tokens),
                Err(ExchangeFailure::InvalidGrant) => {},
                Err(other) => anyhow::bail!("unexpected refresh race response: {other:?}"),
            }
        }
        ensure!(refresh_winners.len() == 1, "{} refresh rotations succeeded", refresh_winners.len());
        ensure!(userinfo(&client, &keys, "https://id.example.invalid", &refresh_winners[0].access_token, None, now).await?.is_none(),
            "replay in refresh race left descendant access valid");
        let access_revoke = RevokeRequest { client_id: client_id.clone(), client_secret: None, token: tokens.access_token.clone() };
        ensure!(revoke(&client, keys.clone(), "https://id.example.invalid", "local-refresh-salt", RevokeRequest {
            client_id: "other-client".into(), ..access_revoke.clone()
        }, now).await?.is_none(), "wrong client authenticated");
        ensure!(userinfo(&client, &keys, "https://id.example.invalid", &tokens.access_token, None, now).await?.is_some(), "wrong client revoked token");
        ensure!(revoke(&client, keys.clone(), "https://id.example.invalid", "local-refresh-salt", RevokeRequest {
            client_id: client_id.clone(), client_secret: None, token: format!("unknown-token-{stamp}")
        }, now).await?.is_some(), "unknown token leaked its existence");
        ensure!(userinfo(&client, &keys, "https://id.example.invalid", &tokens.access_token, None, now).await?.is_some(), "unknown-token revoke changed valid token");
        ensure!(revoke(&client, keys.clone(), "https://id.example.invalid", "local-refresh-salt", access_revoke.clone(), now).await?.is_some(), "access revoke failed");
        ensure!(revoke(&client, keys.clone(), "https://id.example.invalid", "local-refresh-salt", access_revoke, now).await?.is_some(), "repeat revoke was not idempotent");
        ensure!(userinfo(&client, &keys, "https://id.example.invalid", &tokens.access_token, None, now).await?.is_none(), "revoked access token accepted");
        let rotating_refresh = format!("rotating-refresh-{stamp}");
        let rotating_hash = hex::encode(Sha256::digest(format!("{rotating_refresh}local-refresh-salt").as_bytes()));
        client.query_client().exec("INSERT INTO idp_oidctoken (id, user_id, client_id, access_jti, id_jti, subject, refresh_token_hash, scope, created_at, access_expires_at, refresh_expires_at) VALUES ($id, $user_id, $client_id, $jti, '', $subject, $hash, 'openid email offline_access', CAST($now AS Datetime), CAST($access_expires AS Datetime), CAST($refresh_expires AS Datetime))")
            .param("$id", client_pk - 5).param("$user_id", user_id).param("$client_id", client_pk)
            .param("$jti", format!("rotating-access-{stamp}")).param("$subject", subject.clone())
            .param("$hash", rotating_hash).param("$now", now)
            .param("$access_expires", now + Duration::from_secs(1800))
            .param("$refresh_expires", now + Duration::from_secs(30 * 24 * 60 * 60)).await?;
        let refresh_request = RefreshRequest { client_id: client_id.clone(), client_secret: None,
            refresh_token: rotating_refresh.clone(), scope: None };
        ensure!(matches!(rotate(&client, keys.clone(), "https://id.example.invalid", "local-refresh-salt", RefreshRequest {
            client_id: "other-client".into(), ..refresh_request.clone()
        }, now).await?, Err(ExchangeFailure::InvalidClient)), "another client used refresh token");
        ensure!(matches!(rotate(&client, keys.clone(), "https://id.example.invalid", "local-refresh-salt", RefreshRequest {
            scope: Some("openid profile".into()), ..refresh_request.clone()
        }, now).await?, Err(ExchangeFailure::InvalidScope)), "refresh escalated scope");
        let rotated = rotate(&client, keys.clone(), "https://id.example.invalid", "local-refresh-salt", refresh_request.clone(), now).await?
            .map_err(|failure| anyhow::anyhow!("valid legacy refresh rejected: {failure:?}"))?;
        ensure!(rotated.scope == "openid email offline_access" && rotated.refresh_token.is_some(), "refresh rotation response lost scope or token");
        ensure!(userinfo(&client, &keys, "https://id.example.invalid", &rotated.access_token, None, now).await?.is_some(), "rotated access failed UserInfo");
        ensure!(revoke(&client, keys.clone(), "https://id.example.invalid", "local-refresh-salt", RevokeRequest {
            client_id: client_id.clone(), client_secret: None, token: refresh_request.refresh_token,
        }, now).await?.is_some(), "rotated legacy refresh revoke failed");
        ensure!(userinfo(&client, &keys, "https://id.example.invalid", &rotated.access_token, None, now).await?.is_none(), "revoking ancestor left descendant access valid");
        ensure!(matches!(rotate(&client, keys.clone(), "https://id.example.invalid", "local-refresh-salt", RefreshRequest {
            client_id: client_id.clone(), client_secret: None, refresh_token: rotated.refresh_token.context("rotated refresh")?, scope: None
        }, now).await?, Err(ExchangeFailure::InvalidGrant)), "revoking ancestor left descendant refresh valid");
        let legacy_jti = format!("legacy-access-{stamp}");
        let legacy_scope = "openid profile_extended phone address";
        let legacy_refresh = format!("legacy-refresh-{stamp}");
        let refresh_hash = hex::encode(Sha256::digest(format!("{legacy_refresh}local-refresh-salt").as_bytes()));
        let now_seconds = i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?;
        let legacy_access = keys.sign(&json!({"iss":"https://id.example.invalid","sub":subject,
            "aud":client_id,"exp":now_seconds+1800,"iat":now_seconds,"jti":legacy_jti,"scope":legacy_scope}))?;
        client.query_client().exec("INSERT INTO idp_oidctoken (id, user_id, client_id, access_jti, id_jti, subject, refresh_token_hash, scope, created_at, access_expires_at) VALUES ($id, $user_id, $client_id, $jti, '', '', $refresh_hash, $scope, CAST($now AS Datetime), CAST($expires AS Datetime))")
            .param("$id", client_pk - 2).param("$user_id", user_id).param("$client_id", client_pk)
            .param("$jti", legacy_jti).param("$refresh_hash", refresh_hash).param("$scope", legacy_scope)
            .param("$now", now).param("$expires", now + Duration::from_secs(1800)).await?;
        let media = MediaUrl::new("https://storage.yandexcloud.net/synthetic-id-media")?;
        ensure!(userinfo(&client, &keys, "https://id.example.invalid", &legacy_access, None, now).await.is_err(), "avatar was silently dropped without media configuration");
        let legacy_info = userinfo(&client, &keys, "https://id.example.invalid", &legacy_access, Some(media), now)
            .await?.context("legacy-scope access token must reach UserInfo")?;
        ensure!(legacy_info["sub"] == subject && legacy_info["name"] == "Ada Lovelace"
            && legacy_info["given_name"] == "Ada" && legacy_info["family_name"] == "Lovelace"
            && legacy_info["birthdate"] == "2001-02-03" && legacy_info["phone_number"] == "+123456789"
            && legacy_info["phone_number_verified"] == true && legacy_info["locale"] == "ru"
            && legacy_info["picture"] == "https://storage.yandexcloud.net/synthetic-id-media/avatars/saved.jpg"
            && legacy_info["address"] == json!({}),
            "legacy UserInfo scope claims changed");
        client.query_client().exec("UPSERT INTO idp_oidcauthorizationcode (code, client_id, user_id, redirect_uri, scope, nonce, code_challenge, code_challenge_method, created_at, expires_at) VALUES ($code, $client_id, $user_id, $redirect, 'openid email', 'stable-nonce', $challenge, 'S256', CurrentUtcDatetime(), CAST($expires AS Datetime))")
            .param("$code", disabled_code.clone()).param("$client_id", client_pk).param("$user_id", user_id)
            .param("$redirect", "https://rp.example.invalid/callback").param("$challenge", challenge)
            .param("$expires", now + Duration::from_secs(300)).await?;
        client.query_client().exec("UPDATE auth_user SET is_active = false WHERE id = $id")
            .param("$id", user_id).await?;
        ensure!(userinfo(&client, &keys, "https://id.example.invalid", &legacy_access, None, now).await?.is_none(), "disabled account retained UserInfo access");
        let mut disabled = request;
        disabled.code = disabled_code.clone();
        ensure!(matches!(exchange_code(&client, keys.clone(), "https://id.example.invalid", "local-refresh-salt", disabled, now).await?, Err(ExchangeFailure::InvalidGrant)), "disabled account exchanged code");
        client.query_client().exec("UPDATE auth_user SET is_active = true WHERE id = $id")
            .param("$id", user_id).await?;
        let media = MediaUrl::new("https://storage.yandexcloud.net/synthetic-id-media")?;
        ensure!(userinfo(&client, &keys, "https://id.example.invalid", &legacy_access, Some(media), now).await?.is_some(), "reenabled account did not regain valid access");
        let refresh_revoke = RevokeRequest { client_id: client_id.clone(), client_secret: None, token: legacy_refresh };
        ensure!(revoke(&client, keys.clone(), "https://id.example.invalid", "local-refresh-salt", refresh_revoke.clone(), now).await?.is_some(), "legacy refresh revoke failed");
        ensure!(revoke(&client, keys.clone(), "https://id.example.invalid", "local-refresh-salt", refresh_revoke, now).await?.is_some(), "repeat refresh revoke failed");
        ensure!(userinfo(&client, &keys, "https://id.example.invalid", &legacy_access, None, now).await?.is_none(), "refresh revoke left access valid");
        Ok(())
    }.await;
    let mut query_client = client.query_client();
    let mut stream = query_client.query("SELECT id FROM idp_oidctoken VIEW oidc_token_user_client_idx WHERE user_id = $user_id AND client_id = $client_id")
        .param("$user_id", user_id).param("$client_id", client_pk).await?;
    let mut token_ids: Vec<i64> = Vec::new();
    while let Some(set) = stream.next_result_set().await? {
        for mut row in set {
            token_ids.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    stream.close().await?;
    for id in token_ids {
        client
            .query_client()
            .exec("DELETE FROM idp_oidctoken WHERE id = $id")
            .param("$id", id)
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM idp_oidcauthorizationcode WHERE code = $code")
        .param("$code", code)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM idp_oidcauthorizationcode WHERE code = $code")
        .param("$code", offline_code)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM idp_oidcauthorizationcode WHERE code = $code")
        .param("$code", disabled_code)
        .await?;
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
        .exec("DELETE FROM account_emailaddress WHERE id = $id")
        .param("$id", email_pk)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_userprofile WHERE id = $id")
        .param("$id", profile_pk)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_userpreferences WHERE id = $id")
        .param("$id", preferences_pk)
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
        .exec("DELETE FROM auth_user WHERE id = $id")
        .param("$id", user_id)
        .await?;
    result
}
