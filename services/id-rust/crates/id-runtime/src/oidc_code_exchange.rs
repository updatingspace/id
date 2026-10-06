//! Atomic authorization-code exchange and refresh-family creation.

use crate::{
    oidc_client::{authenticate, read_client_tx},
    oidc_id_claims::add_profile_claims,
    oidc_keys::OidcKeyRing,
    oidc_protocol::{ProtocolError, narrow_scopes, verify_pkce_s256},
    session_store::active_principal_tx,
    tx_retry::retry_known_abort,
};
use anyhow::Result;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use ydb::{Client, Transaction, TxMode, closure};

const ACCESS_TTL: Duration = Duration::from_secs(30 * 60);
const ID_TTL: Duration = Duration::from_secs(10 * 60);
const REFRESH_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

#[derive(Clone)]
pub struct CodeExchange {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub code: String,
    pub redirect_uri: String,
    pub code_verifier: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeFailure {
    InvalidClient,
    InvalidGrant,
    InvalidScope,
    UnsupportedGrant,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub id_token: String,
    pub refresh_token: Option<String>,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub scope: String,
}

pub async fn exchange_code(
    client: &Client,
    keys: Arc<OidcKeyRing>,
    issuer: &str,
    refresh_salt: &str,
    request: CodeExchange,
    now: SystemTime,
) -> Result<std::result::Result<TokenResponse, ExchangeFailure>> {
    if request.client_id.is_empty()
        || request.client_id.len() > 64
        || request.code.is_empty()
        || request.code.len() > 128
        || request.redirect_uri.is_empty()
        || request.redirect_uri.len() > 4096
        || request.code_verifier.len() > 128
    {
        return Ok(Err(ExchangeFailure::InvalidGrant));
    }
    let Some(metadata) =
        authenticate(client, &request.client_id, request.client_secret.as_deref()).await?
    else {
        return Ok(Err(ExchangeFailure::InvalidClient));
    };
    if !metadata.grant_types.is_empty()
        && !metadata
            .grant_types
            .iter()
            .any(|grant| grant == "authorization_code")
    {
        return Ok(Err(ExchangeFailure::UnsupportedGrant));
    }
    let issuer = issuer.to_owned();
    let media = std::env::var("MEDIA_PUBLIC_BASE_URL")
        .ok()
        .filter(|base| !base.is_empty())
        .map(|base| crate::media_url::MediaUrl::from_env(&base))
        .transpose()?;
    let token_id = i64::try_from(rand::random::<u64>() & (i64::MAX as u64))?;
    let access_jti = format!("{:032x}", rand::random::<u128>());
    let id_jti = format!("{:032x}", rand::random::<u128>());
    let refresh_token = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let refresh_hash = hex::encode(Sha256::digest(
        format!("{refresh_token}{refresh_salt}").as_bytes(),
    ));
    let refresh_family = format!("{:032x}", rand::random::<u128>());
    retry_known_abort(|| {
        let keys = keys.clone();
        let request = request.clone();
        let metadata = metadata.clone();
        let issuer = issuer.clone();
        let access_jti = access_jti.clone();
        let id_jti = id_jti.clone();
        let refresh_token = refresh_token.clone();
        let refresh_hash = refresh_hash.clone();
        let refresh_family = refresh_family.clone();
        let media = media.clone();
        async {
            client.query_client().retry_tx(closure!([keys, request, metadata, issuer, access_jti, id_jti, refresh_token, refresh_hash, refresh_family, media], async |tx: &mut Transaction| {
                let Some(current_client) = read_client_tx(tx, metadata.id).await? else {
                    return Ok(Err(ExchangeFailure::InvalidClient));
                };
                if !metadata.same_configuration(&current_client) {
                    return Ok(Err(ExchangeFailure::InvalidClient));
                }
                let Some(mut code) = tx.query_row("SELECT client_id, user_id, redirect_uri, scope, nonce, code_challenge, code_challenge_method, expires_at, used_at FROM idp_oidcauthorizationcode WHERE code = $code")
                    .param("$code", request.code.clone()).optional().await? else {
                    return Ok(Err(ExchangeFailure::InvalidGrant));
                };
                let code_client: i64 = code.remove_field_by_name("client_id")?.try_into()?;
                let user_id: i32 = code.remove_field_by_name("user_id")?.try_into()?;
                let redirect: String = code.remove_field_by_name("redirect_uri")?.try_into()?;
                let scope: String = code.remove_field_by_name("scope")?.try_into()?;
                let nonce: String = code.remove_field_by_name("nonce")?.try_into()?;
                let challenge: String = code.remove_field_by_name("code_challenge")?.try_into()?;
                let method: String = code.remove_field_by_name("code_challenge_method")?.try_into()?;
                let expires_at: SystemTime = code.remove_field_by_name("expires_at")?.try_into()?;
                let used_at: Option<SystemTime> = code.remove_field_by_name("used_at")?.try_into()?;
                if code_client != metadata.id || redirect != request.redirect_uri || expires_at <= now || used_at.is_some() {
                    return Ok(Err(ExchangeFailure::InvalidGrant));
                }
                if challenge.is_empty() {
                    if metadata.is_public || !request.code_verifier.is_empty() {
                        return Ok(Err(ExchangeFailure::InvalidGrant));
                    }
                } else if verify_pkce_s256(&request.code_verifier, &challenge, &method).is_err() {
                    return Ok(Err(ExchangeFailure::InvalidGrant));
                }
                let scopes = match narrow_scopes(&scope, None) {
                    Ok(scopes) => scopes,
                    Err(ProtocolError::InvalidScope) => return Ok(Err(ExchangeFailure::InvalidScope)),
                    Err(_) => return Ok(Err(ExchangeFailure::InvalidGrant)),
                };
                let Some(principal) = active_principal_tx(tx, user_id).await? else {
                    return Ok(Err(ExchangeFailure::InvalidGrant));
                };
                let mut user = tx.query_row("SELECT first_name, last_name, email FROM auth_user WHERE id = $user_id")
                    .param("$user_id", user_id).await?;
                let first_name: String = user.remove_field_by_name("first_name")?.try_into()?;
                let last_name: String = user.remove_field_by_name("last_name")?.try_into()?;
                let email: String = user.remove_field_by_name("email")?.try_into()?;
                let mut identity = tx.query_row("SELECT status, system_admin, email_verified FROM usid_user WHERE user_id = $id")
                    .param("$id", principal.identity_id.get()).await?;
                let status: String = identity.remove_field_by_name("status")?.try_into()?;
                let system_admin: bool = identity.remove_field_by_name("system_admin")?.try_into()?;
                let master_email_verified: bool = identity.remove_field_by_name("email_verified")?.try_into()?;
                if status != "active" { return Ok(Err(ExchangeFailure::InvalidGrant)); }
                let email_verified = if scopes.iter().any(|scope| scope == "email") {
                    let mut rows = tx.query("SELECT email, verified FROM account_emailaddress VIEW account_emailaddress_user_id_2c513194 WHERE user_id = $id AND primary = true LIMIT 2")
                        .param("$id", user_id).await?;
                    let mut found = Vec::new();
                    while let Some(set) = rows.next_result_set().await? {
                        for mut row in set {
                            let address: String = row.remove_field_by_name("email")?.try_into()?;
                            let verified: bool = row.remove_field_by_name("verified")?.try_into()?;
                            found.push(address.eq_ignore_ascii_case(&email) && verified);
                        }
                    }
                    rows.close().await?;
                    found.len() == 1 && found[0]
                } else { false };
                let issued_at = DateTime::<Utc>::from(now).timestamp();
                let subject = principal.public_subject.as_str();
                let audience = metadata.client_id.as_str();
                let scope_string = scopes.join(" ");
                let access = json!({"iss":issuer,"sub":subject,"aud":audience,"exp":issued_at + ACCESS_TTL.as_secs() as i64,
                    "iat":issued_at,"jti":access_jti,"scope":scope_string});
                let mut id = json!({"iss":issuer,"sub":subject,"aud":audience,"exp":issued_at + ID_TTL.as_secs() as i64,
                    "iat":issued_at,"jti":id_jti,"user_id":principal.identity_id.get().to_string(),
                    "master_flags":{"suspended":false,"banned":false,"system_admin":system_admin,
                        "email_verified":master_email_verified,"status":"active"}});
                if !nonce.is_empty() { id["nonce"] = Value::String(nonce); }
                if scopes.iter().any(|scope| scope == "email") {
                    id["email"] = Value::String(email);
                    id["email_verified"] = Value::Bool(email_verified);
                }
                add_profile_claims(tx, &mut id, user_id, &scopes, &first_name, &last_name, media.as_ref()).await?;
                let access_token = keys.sign(&access).map_err(|_| ydb::YdbOrCustomerError::from_err(std::io::Error::other("OIDC access signing failed")))?;
                let id_token = keys.sign(&id).map_err(|_| ydb::YdbOrCustomerError::from_err(std::io::Error::other("OIDC ID signing failed")))?;
                tx.exec("UPDATE idp_oidcauthorizationcode SET used_at = CAST($now AS Datetime) WHERE code = $code AND used_at IS NULL")
                    .param("$now", now).param("$code", request.code.clone()).await?;
                let has_refresh = scopes.iter().any(|scope| scope == "offline_access");
                let query = if has_refresh {
                    "INSERT INTO idp_oidctoken (id, user_id, client_id, access_jti, id_jti, subject, refresh_token_hash, refresh_family_id, scope, created_at, access_expires_at, refresh_expires_at) VALUES ($id, $user_id, $client_id, $access_jti, $id_jti, $subject, $refresh_hash, $family, $scope, CAST($now AS Datetime), CAST($expires AS Datetime), CAST($refresh_expires AS Datetime))"
                } else {
                    "INSERT INTO idp_oidctoken (id, user_id, client_id, access_jti, id_jti, subject, refresh_token_hash, scope, created_at, access_expires_at) VALUES ($id, $user_id, $client_id, $access_jti, $id_jti, $subject, '', $scope, CAST($now AS Datetime), CAST($expires AS Datetime))"
                };
                let insert = tx.exec(query)
                    .param("$id", token_id).param("$user_id", user_id).param("$client_id", metadata.id)
                    .param("$access_jti", access_jti.clone()).param("$id_jti", id_jti.clone())
                    .param("$subject", subject.to_owned()).param("$scope", scope_string.clone())
                    .param("$now", now).param("$expires", now + ACCESS_TTL);
                if has_refresh {
                    insert.param("$refresh_hash", refresh_hash.clone()).param("$family", refresh_family.clone())
                        .param("$refresh_expires", now + REFRESH_TTL).await?;
                } else {
                    insert.await?;
                }
                Ok(Ok(TokenResponse { access_token, id_token, refresh_token: has_refresh.then_some(refresh_token.clone()),
                    token_type: "Bearer", expires_in: ACCESS_TTL.as_secs(), scope: scope_string }))
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
                .timeout(Duration::from_secs(10)).await
        }
    }).await
}
