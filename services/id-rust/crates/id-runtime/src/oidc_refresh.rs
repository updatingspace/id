//! Atomic OIDC refresh rotation with a durable family replay marker.

use crate::{
    oidc_client::{authenticate, read_client_tx},
    oidc_code_exchange::{ExchangeFailure, TokenResponse},
    oidc_id_claims::add_profile_claims,
    oidc_keys::OidcKeyRing,
    oidc_protocol::narrow_scopes,
    session_store::active_principal_tx,
    tx_retry::retry_known_abort,
};
use anyhow::Result;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
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
pub struct RefreshRequest {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub refresh_token: String,
    pub scope: Option<String>,
}

pub async fn rotate(
    client: &Client,
    keys: Arc<OidcKeyRing>,
    issuer: &str,
    refresh_salt: &str,
    request: RefreshRequest,
    now: SystemTime,
) -> Result<std::result::Result<TokenResponse, ExchangeFailure>> {
    if request.refresh_token.is_empty()
        || request.refresh_token.len() > 256
        || request
            .scope
            .as_ref()
            .is_some_and(|value| value.len() > 1024)
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
            .any(|grant| grant == "refresh_token")
    {
        return Ok(Err(ExchangeFailure::UnsupportedGrant));
    }
    let old_hash = hex::encode(Sha256::digest(
        format!("{}{}", request.refresh_token, refresh_salt).as_bytes(),
    ));
    let next_refresh = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let next_hash = hex::encode(Sha256::digest(
        format!("{next_refresh}{refresh_salt}").as_bytes(),
    ));
    let access_jti = format!("{:032x}", rand::random::<u128>());
    let id_jti = format!("{:032x}", rand::random::<u128>());
    let token_id = i64::try_from(rand::random::<u64>() & (i64::MAX as u64))?;
    let new_family = format!("{:032x}", rand::random::<u128>());
    let issuer = issuer.to_owned();
    let media = std::env::var("MEDIA_PUBLIC_BASE_URL")
        .ok()
        .filter(|base| !base.is_empty())
        .map(|base| crate::media_url::MediaUrl::from_env(&base))
        .transpose()?;
    retry_known_abort(|| {
        let keys = keys.clone();
        let metadata = metadata.clone();
        let request = request.clone();
        let old_hash = old_hash.clone();
        let next_refresh = next_refresh.clone();
        let next_hash = next_hash.clone();
        let access_jti = access_jti.clone();
        let id_jti = id_jti.clone();
        let new_family = new_family.clone();
        let issuer = issuer.clone();
        let media = media.clone();
        async {
            client.query_client().retry_tx(closure!([keys, metadata, request, old_hash, next_refresh, next_hash, access_jti, id_jti, new_family, issuer, media], async |tx: &mut Transaction| {
                let Some(current_client) = read_client_tx(tx, metadata.id).await? else { return Ok(Err(ExchangeFailure::InvalidClient)); };
                if !metadata.same_configuration(&current_client) { return Ok(Err(ExchangeFailure::InvalidClient)); }
                let mut rows = tx.query("SELECT id, user_id, subject, scope, refresh_expires_at, revoked_at, rotated_at, refresh_family_id FROM idp_oidctoken VIEW oidc_token_refresh_hash_idx WHERE refresh_token_hash = $hash AND client_id = $client_id LIMIT 2")
                    .param("$hash", old_hash.clone()).param("$client_id", metadata.id).await?;
                let mut tokens = Vec::new();
                while let Some(set) = rows.next_result_set().await? { tokens.extend(set); }
                rows.close().await?;
                let [token] = tokens.as_mut_slice() else { return Ok(Err(ExchangeFailure::InvalidGrant)); };
                let old_id: i64 = token.remove_field_by_name("id")?.try_into()?;
                let user_id: i32 = token.remove_field_by_name("user_id")?.try_into()?;
                let subject: Option<String> = token.remove_field_by_name("subject")?.try_into()?;
                let original_scope: String = token.remove_field_by_name("scope")?.try_into()?;
                let expires: Option<SystemTime> = token.remove_field_by_name("refresh_expires_at")?.try_into()?;
                let revoked: Option<SystemTime> = token.remove_field_by_name("revoked_at")?.try_into()?;
                let rotated: Option<SystemTime> = token.remove_field_by_name("rotated_at")?.try_into()?;
                let family: Option<String> = token.remove_field_by_name("refresh_family_id")?.try_into()?;
                if rotated.is_some() && family.as_deref().is_some_and(|value| !value.is_empty()) {
                    let family = family.as_deref().unwrap_or_default();
                    let mut family_rows = tx.query("SELECT id FROM idp_oidctoken VIEW oidc_token_family_idx WHERE refresh_family_id = $family LIMIT 4097")
                        .param("$family", family.to_owned()).await?;
                    let mut ids = Vec::new();
                    while let Some(set) = family_rows.next_result_set().await? {
                        for mut row in set { let id: i64 = row.remove_field_by_name("id")?.try_into()?; ids.push(id); }
                    }
                    family_rows.close().await?;
                    if ids.len() > 4096 { return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("OIDC family exceeds replay revocation bound"))); }
                    for id in ids {
                        tx.exec("UPDATE idp_oidctoken SET revoked_at = CAST($now AS Datetime) WHERE id = $id AND revoked_at IS NULL")
                            .param("$now", now).param("$id", id).await?;
                    }
                    return Ok(Err(ExchangeFailure::InvalidGrant));
                }
                if revoked.is_some() || expires.is_none_or(|expiry| expiry <= now) { return Ok(Err(ExchangeFailure::InvalidGrant)); }
                let Some(subject) = subject.filter(|value| !value.is_empty()) else { return Ok(Err(ExchangeFailure::InvalidGrant)); };
                let scopes = match narrow_scopes(&original_scope, request.scope.as_deref()) {
                    Ok(scopes) => scopes,
                    Err(_) => return Ok(Err(ExchangeFailure::InvalidScope)),
                };
                let Some(principal) = active_principal_tx(tx, user_id).await? else { return Ok(Err(ExchangeFailure::InvalidGrant)); };
                if principal.public_subject.as_str() != subject { return Ok(Err(ExchangeFailure::InvalidGrant)); }
                let Some(mut user) = tx.query_row("SELECT first_name, last_name, email FROM auth_user WHERE id = $user_id")
                    .param("$user_id", user_id).optional().await? else { return Ok(Err(ExchangeFailure::InvalidGrant)); };
                let first_name: String = user.remove_field_by_name("first_name")?.try_into()?;
                let last_name: String = user.remove_field_by_name("last_name")?.try_into()?;
                let email: String = user.remove_field_by_name("email")?.try_into()?;
                let Some(mut identity) = tx.query_row("SELECT status, system_admin, email_verified FROM usid_user WHERE user_id = $id")
                    .param("$id", principal.identity_id.get()).optional().await? else { return Ok(Err(ExchangeFailure::InvalidGrant)); };
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
                let scope_string = scopes.join(" ");
                let access = json!({"iss":issuer,"sub":subject,"aud":metadata.client_id,"exp":issued_at + ACCESS_TTL.as_secs() as i64,
                    "iat":issued_at,"jti":access_jti,"scope":scope_string});
                let mut id = json!({"iss":issuer,"sub":subject,"aud":metadata.client_id,"exp":issued_at + ID_TTL.as_secs() as i64,
                    "iat":issued_at,"jti":id_jti,"user_id":principal.identity_id.get().to_string(),
                    "master_flags":{"suspended":false,"banned":false,"system_admin":system_admin,
                        "email_verified":master_email_verified,"status":"active"}});
                if scopes.iter().any(|scope| scope == "email") {
                    id["email"] = Value::String(email);
                    id["email_verified"] = Value::Bool(email_verified);
                }
                add_profile_claims(tx, &mut id, user_id, &scopes, &first_name, &last_name, media.as_ref()).await?;
                let access_token = keys.sign(&access).map_err(|_| ydb::YdbOrCustomerError::from_err(std::io::Error::other("OIDC access signing failed")))?;
                let id_token = keys.sign(&id).map_err(|_| ydb::YdbOrCustomerError::from_err(std::io::Error::other("OIDC ID signing failed")))?;
                let family = family.filter(|value| !value.is_empty()).unwrap_or(new_family.clone());
                tx.exec("UPDATE idp_oidctoken SET revoked_at = CAST($now AS Datetime), rotated_at = CAST($now AS Datetime), refresh_family_id = $family WHERE id = $id AND revoked_at IS NULL AND rotated_at IS NULL")
                    .param("$now", now).param("$family", family.clone()).param("$id", old_id).await?;
                let has_refresh = scopes.iter().any(|scope| scope == "offline_access");
                let refresh_hash = if has_refresh { next_hash.clone() } else { String::new() };
                let query = if has_refresh {
                    "INSERT INTO idp_oidctoken (id, user_id, client_id, access_jti, id_jti, subject, refresh_token_hash, refresh_family_id, scope, created_at, access_expires_at, refresh_expires_at) VALUES ($id, $user_id, $client_id, $access_jti, $id_jti, $subject, $refresh_hash, $family, $scope, CAST($now AS Datetime), CAST($access_expires AS Datetime), CAST($refresh_expires AS Datetime))"
                } else {
                    "INSERT INTO idp_oidctoken (id, user_id, client_id, access_jti, id_jti, subject, refresh_token_hash, refresh_family_id, scope, created_at, access_expires_at) VALUES ($id, $user_id, $client_id, $access_jti, $id_jti, $subject, $refresh_hash, $family, $scope, CAST($now AS Datetime), CAST($access_expires AS Datetime))"
                };
                let insert = tx.exec(query)
                    .param("$id", token_id).param("$user_id", user_id).param("$client_id", metadata.id)
                    .param("$access_jti", access_jti.clone()).param("$id_jti", id_jti.clone())
                    .param("$subject", subject).param("$refresh_hash", refresh_hash).param("$family", family)
                    .param("$scope", scope_string.clone()).param("$now", now).param("$access_expires", now + ACCESS_TTL);
                if has_refresh {
                    insert.param("$refresh_expires", now + REFRESH_TTL).await?;
                } else {
                    insert.await?;
                }
                Ok(Ok(TokenResponse { access_token, id_token,
                    refresh_token: has_refresh.then_some(next_refresh.clone()), token_type: "Bearer",
                    expires_in: ACCESS_TTL.as_secs(), scope: scope_string }))
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
                .timeout(Duration::from_secs(10)).await
        }
    }).await
}
