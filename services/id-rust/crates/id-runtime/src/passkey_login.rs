//! Passwordless WebAuthn ceremony. The challenge is consumed before signature
//! verification; session issuance separately rechecks the credential snapshot.

use crate::{
    cache_store::CacheStore,
    legacy_passkey,
    login_preflight::{VerifiedAccount, verified_passkey_owner},
    passkey_index,
    session_issuer::PasskeyProof,
};
use anyhow::{Context, Result, ensure};
use id_compat::cache::CacheValue;
use serde_json::Value;
use std::time::{Duration, SystemTime};
use webauthn_rs::prelude::{
    DiscoverableAuthentication, DiscoverableKey, Passkey, PublicKeyCredential, Webauthn,
};
use ydb::Client;

const CEREMONY_TTL: Duration = Duration::from_secs(300);

pub struct VerifiedPasskey {
    pub account: VerifiedAccount,
    pub proof: PasskeyProof,
}

pub struct PasskeyVerifier<'a> {
    pub client: &'a Client,
    pub webauthn: &'a Webauthn,
    pub cache: &'a CacheStore,
    pub rp_id: &'a str,
    pub origin: &'a str,
}

pub async fn begin(
    webauthn: &Webauthn,
    cache: &CacheStore,
    now: SystemTime,
) -> Result<(Value, String)> {
    let (options, state) = webauthn
        .start_discoverable_authentication()
        .context("start passkey login ceremony")?;
    let id = hex::encode(rand::random::<[u8; 32]>());
    let encoded = serde_json::to_string(&state)?;
    let expiry = now
        .checked_add(CEREMONY_TTL)
        .context("passkey ceremony expiry overflow")?;
    ensure!(
        cache
            .add(
                &format!("passkey-login:{id}"),
                &CacheValue::String(encoded),
                Some(expiry),
                now
            )
            .await?,
        "passkey ceremony collision"
    );
    Ok((serde_json::to_value(options)?, id))
}

pub async fn verify(
    verifier: PasskeyVerifier<'_>,
    ceremony_id: &str,
    credential: Value,
    now: SystemTime,
) -> Result<Option<VerifiedPasskey>> {
    let PasskeyVerifier {
        client,
        webauthn,
        cache,
        rp_id,
        origin,
    } = verifier;
    if ceremony_id.len() != 64 || !ceremony_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(None);
    }
    let Some(CacheValue::String(encoded)) = cache
        .take(&format!("passkey-login:{ceremony_id}"), now)
        .await?
    else {
        return Ok(None);
    };
    let state: DiscoverableAuthentication =
        serde_json::from_str(&encoded).context("stored passkey challenge corrupted")?;
    let Ok(response) = serde_json::from_value::<PublicKeyCredential>(credential) else {
        return Ok(None);
    };
    let Ok(digest) = passkey_index::digest_of_bytes(response.get_credential_id()) else {
        return Ok(None);
    };
    let Some((id, account_id)) = passkey_index::indexed_owner(client, &digest).await? else {
        return Ok(None);
    };
    let Some(mut row) = client.query_client().query_row("SELECT user_id, type, CAST(data AS Utf8) AS data FROM mfa_authenticator WHERE id = $id")
        .param("$id", id).optional().await? else { return Ok(None) };
    let owner: i32 = row.remove_field_by_name("user_id")?.try_into()?;
    let kind: String = row.remove_field_by_name("type")?.try_into()?;
    let original_data: String = row.remove_field_by_name("data")?.try_into()?;
    if owner != account_id || kind != "webauthn" {
        return Ok(None);
    }
    let mut record: Value =
        serde_json::from_str(&original_data).context("invalid passkey record")?;
    ensure!(
        passkey_index::digest_of_record(&record)? == digest,
        "passkey index mismatch"
    );
    let mut passkey: Passkey = if let Some(serialized) = record.get("rust_passkey") {
        serde_json::from_value(serialized.clone()).context("invalid Rust passkey record")?
    } else {
        legacy_passkey::import_registration(&record["credential"], rp_id, origin)
            .context("legacy passkey import failed")?
    };
    if passkey.cred_id().as_ref() != response.get_credential_id() {
        return Ok(None);
    }
    let key = DiscoverableKey::from(&passkey);
    let Ok(result) = webauthn.finish_discoverable_authentication(&response, state, &[key]) else {
        return Ok(None);
    };
    if !result.user_verified() || passkey.update_credential(&result).is_none() {
        return Ok(None);
    }
    record["rust_passkey"] = serde_json::to_value(passkey)?;
    let updated_data = serde_json::to_string(&record)?;
    let Some(account) = verified_passkey_owner(client, account_id).await? else {
        return Ok(None);
    };
    Ok(Some(VerifiedPasskey {
        account,
        proof: PasskeyProof {
            authenticator_id: id,
            digest,
            original_data,
            updated_data,
        },
    }))
}
