//! Idempotent OIDC access/refresh revocation scoped to the authenticated client.

use crate::{
    oidc_client::{authenticate, read_client_tx},
    oidc_keys::OidcKeyRing,
    tx_retry::retry_known_abort,
};
use anyhow::Result;
use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use ydb::{Client, Transaction, TxMode, closure};

#[derive(Clone)]
pub struct RevokeRequest {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub token: String,
}

/// `None` means invalid client credentials; `Some(())` is returned for known,
/// unknown and already-revoked tokens so the endpoint reveals no token state.
pub async fn revoke(
    client: &Client,
    keys: Arc<OidcKeyRing>,
    issuer: &str,
    refresh_salt: &str,
    request: RevokeRequest,
    now: SystemTime,
) -> Result<Option<()>> {
    let Some(metadata) =
        authenticate(client, &request.client_id, request.client_secret.as_deref()).await?
    else {
        return Ok(None);
    };
    let access_jti = verified_access_jti(&keys, issuer, &metadata.client_id, &request.token);
    let refresh_hash = hex::encode(Sha256::digest(
        format!("{}{}", request.token, refresh_salt).as_bytes(),
    ));
    retry_known_abort(|| {
        let metadata = metadata.clone();
        let access_jti = access_jti.clone();
        let refresh_hash = refresh_hash.clone();
        async {
            client.query_client().retry_tx(closure!([metadata, access_jti, refresh_hash], async |tx: &mut Transaction| {
                let Some(current) = read_client_tx(tx, metadata.id).await? else { return Ok(None); };
                if !metadata.same_authentication(&current) { return Ok(None); }
                let ids = if let Some(jti) = access_jti.as_ref() {
                    matching_ids(tx, "SELECT id FROM idp_oidctoken VIEW oidc_token_access_idx WHERE access_jti = $value AND client_id = $client_id LIMIT 2", jti, metadata.id).await?
                } else {
                    matching_ids(tx, "SELECT id FROM idp_oidctoken VIEW oidc_token_refresh_hash_idx WHERE refresh_token_hash = $value AND client_id = $client_id LIMIT 2", refresh_hash, metadata.id).await?
                };
                match ids.as_slice() {
                    [] => Ok(Some(())),
                    [id] => {
                        if access_jti.is_none() {
                            let Some(mut token) = tx.query_row("SELECT refresh_family_id FROM idp_oidctoken WHERE id = $id")
                                .param("$id", *id).optional().await? else { return Ok(Some(())); };
                            let family: Option<String> = token.remove_field_by_name("refresh_family_id")?.try_into()?;
                            if let Some(family) = family.filter(|value| !value.is_empty()) {
                                let ids = matching_ids(tx,
                                    "SELECT id FROM idp_oidctoken VIEW oidc_token_family_idx WHERE refresh_family_id = $value AND client_id = $client_id LIMIT 4097",
                                    &family, metadata.id).await?;
                                if ids.len() > 4096 { return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("OIDC family exceeds revocation bound"))); }
                                for id in ids {
                                    tx.exec("UPDATE idp_oidctoken SET revoked_at = CAST($now AS Datetime) WHERE id = $id AND revoked_at IS NULL")
                                        .param("$now", now).param("$id", id).await?;
                                }
                                return Ok(Some(()));
                            }
                        }
                        tx.exec("UPDATE idp_oidctoken SET revoked_at = CAST($now AS Datetime) WHERE id = $id AND revoked_at IS NULL")
                            .param("$now", now).param("$id", *id).await?;
                        Ok(Some(()))
                    },
                    _ => Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("ambiguous OIDC credential"))),
                }
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
                .timeout(Duration::from_secs(10)).await
        }
    }).await
}

fn verified_access_jti(
    keys: &OidcKeyRing,
    issuer: &str,
    client_id: &str,
    token: &str,
) -> Option<String> {
    if token.len() > 8192 {
        return None;
    }
    let header = decode_header(token).ok()?;
    if header.alg != Algorithm::RS256 {
        return None;
    }
    let key = keys.verifier(header.kid.as_deref().unwrap_or(keys.active_kid()))?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[issuer]);
    validation.validate_aud = false;
    validation.validate_exp = false;
    let claims = decode::<Value>(token, key, &validation).ok()?.claims;
    if claims["iss"] != issuer
        || claims["aud"] != client_id
        || claims["sub"].as_str().is_none_or(str::is_empty)
    {
        return None;
    }
    claims["jti"]
        .as_str()
        .filter(|jti| !jti.is_empty() && jti.len() <= 128)
        .map(str::to_owned)
}

async fn matching_ids(
    tx: &mut Transaction,
    query: &'static str,
    value: &str,
    client_id: i64,
) -> ydb::YdbResultWithCustomerErr<Vec<i64>> {
    let mut stream = tx
        .query(query)
        .param("$value", value.to_owned())
        .param("$client_id", client_id)
        .await?;
    let mut ids = Vec::new();
    while let Some(set) = stream.next_result_set().await? {
        for mut row in set {
            ids.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    stream.close().await?;
    Ok(ids)
}
