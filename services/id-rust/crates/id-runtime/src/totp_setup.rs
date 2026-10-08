//! One-winner TOTP enrollment in the transition YDB schema.

use crate::{
    mfa_secret,
    session_store::{LEGACY_BACKENDS, restore_django_session_tx},
    tx_retry::retry_known_abort,
};
use anyhow::{Context, Result};
use id_compat::{mfa_seal::SecretKind, session::SessionCodec};
use serde_json::{Map, Value, json};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use ydb::{Client, Transaction, TxMode, closure};

const SETUP_TTL: u64 = 600;
const REAUTH_TTL: u64 = 300;
const PENDING_KEY: &str = "id_rust_totp_pending";

#[derive(Debug, PartialEq, Eq)]
pub enum BeginOutcome {
    Started { secret: String, email: String },
    Unauthorized,
    ReauthRequired,
    EmailVerificationRequired,
    AlreadyEnabled,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConfirmOutcome {
    Activated { recovery_codes: Option<Vec<String>> },
    Unauthorized,
    ReauthRequired,
    SetupRequired,
    InvalidCode,
    AlreadyEnabled,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DisableOutcome {
    Disabled,
    Unauthorized,
    ReauthRequired,
    NotFound,
}

#[derive(Default)]
pub(crate) struct Factors {
    pub(crate) any: bool,
    pub(crate) totp: bool,
    pub(crate) recovery: bool,
    pub(crate) totp_id: Option<i64>,
    pub(crate) recovery_id: Option<i64>,
    pub(crate) passkeys: bool,
    pub(crate) passkey_ids: Vec<i64>,
}

pub(crate) async fn factors(
    tx: &mut Transaction,
    user_id: i32,
) -> ydb::YdbResultWithCustomerErr<Factors> {
    let mut stream = tx.query("SELECT id, type FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $user_id")
        .param("$user_id", user_id).await?;
    let mut result = Factors::default();
    let mut count = 0;
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            count += 1;
            if count > 1000 {
                return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
                    "too many MFA authenticators",
                )));
            }
            let id: i64 = row.remove_field_by_name("id")?.try_into()?;
            let kind: String = row.remove_field_by_name("type")?.try_into()?;
            result.any = true;
            match kind.as_str() {
                "totp" if !result.totp => {
                    result.totp = true;
                    result.totp_id = Some(id);
                }
                "recovery_codes" if !result.recovery => {
                    result.recovery = true;
                    result.recovery_id = Some(id);
                }
                "webauthn" => {
                    result.passkeys = true;
                    result.passkey_ids.push(id);
                }
                _ => {
                    return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
                        "invalid MFA authenticator set",
                    )));
                }
            }
        }
    }
    stream.close().await?;
    Ok(result)
}

pub(crate) async fn session_data(
    tx: &mut Transaction,
    codec: &SessionCodec,
    token: &str,
) -> ydb::YdbResultWithCustomerErr<Map<String, Value>> {
    let mut row = tx
        .query_row("SELECT session_data FROM django_session WHERE session_key = $key")
        .param("$key", token.to_owned())
        .await?;
    let signed: String = row.remove_field_by_name("session_data")?.try_into()?;
    Ok(codec
        .decode(&signed)
        .map_err(ydb::YdbOrCustomerError::from_err)?
        .data)
}

pub(crate) fn recent_auth(data: &Map<String, Value>, now: SystemTime) -> bool {
    let Ok(seconds) = now.duration_since(UNIX_EPOCH) else {
        return false;
    };
    let Some(method) = data
        .get("account_authentication_methods")
        .and_then(Value::as_array)
        .and_then(|items| items.last())
    else {
        return false;
    };
    if method
        .get("method")
        .and_then(Value::as_str)
        .is_none_or(|value| value == "session")
    {
        return false;
    }
    let Some(at) = method.get("at").and_then(Value::as_f64) else {
        return false;
    };
    let age = seconds.as_secs_f64() - at;
    age.is_finite() && (0.0..(REAUTH_TTL as f64)).contains(&age)
}

async fn verified_email(
    tx: &mut Transaction,
    user_id: i32,
) -> ydb::YdbResultWithCustomerErr<Option<String>> {
    let mut stream = tx.query("SELECT email, verified FROM account_emailaddress VIEW account_emailaddress_user_id_2c513194 WHERE user_id = $user_id AND primary = true LIMIT 2")
        .param("$user_id", user_id).await?;
    let mut result = Vec::new();
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            let email: String = row.remove_field_by_name("email")?.try_into()?;
            let verified: bool = row.remove_field_by_name("verified")?.try_into()?;
            result.push((email, verified));
        }
    }
    stream.close().await?;
    if result.len() > 1 {
        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
            "ambiguous primary email",
        )));
    }
    Ok(result
        .pop()
        .filter(|(email, verified)| *verified && !email.is_empty())
        .map(|(email, _)| email))
}

fn new_secret() -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let random: [u8; 20] = rand::random();
    let mut result = String::with_capacity(32);
    let mut bits = 0u32;
    let mut count = 0;
    for byte in random {
        bits = (bits << 8) | u32::from(byte);
        count += 8;
        while count >= 5 {
            count -= 5;
            result.push(char::from(ALPHABET[((bits >> count) & 31) as usize]));
        }
        bits &= (1 << count) - 1;
    }
    result
}

pub(crate) fn random_row_id() -> i64 {
    ((rand::random::<u64>() & ((1u64 << 62) - 1)) | (1u64 << 62)) as i64
}

pub async fn begin(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: &str,
    now: SystemTime,
) -> Result<BeginOutcome> {
    let seal_key =
        mfa_secret::key_from_env()?.context("MFA sealing key required for TOTP enrollment")?;
    let secret = new_secret();
    let token = token.to_owned();
    let backends: Vec<String> = LEGACY_BACKENDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    let now_secs = now.duration_since(UNIX_EPOCH)?.as_secs();
    retry_known_abort(|| {
        let (codec, token, backends, seal_key, secret) =
            (codec.clone(), token.clone(), backends.clone(), seal_key.clone(), secret.clone());
        async {
            client.query_client().retry_tx(closure!([codec, token, backends, seal_key, secret], async |tx: &mut Transaction| {
                let Some(session) = restore_django_session_tx(tx, codec.as_ref(), token, backends, now).await? else {
                    return Ok(BeginOutcome::Unauthorized);
                };
                let user_id = i32::try_from(session.principal.account_id.get()).map_err(ydb::YdbOrCustomerError::from_err)?;
                let factor_set = factors(tx, user_id).await?;
                if factor_set.any && !session.mfa_verified { return Ok(BeginOutcome::Unauthorized) }
                if factor_set.totp { return Ok(BeginOutcome::AlreadyEnabled) }
                let mut data = session_data(tx, codec.as_ref(), token).await?;
                if !recent_auth(&data, now) { return Ok(BeginOutcome::ReauthRequired) }
                let Some(email) = verified_email(tx, user_id).await? else { return Ok(BeginOutcome::EmailVerificationRequired) };
                let sealed = seal_key.seal(i64::from(user_id), SecretKind::PendingTotp, secret)
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                data.insert(PENDING_KEY.into(), json!({"secret":sealed,"created_at":now_secs}));
                let signed = codec.encode(&data, i64::try_from(now_secs).map_err(ydb::YdbOrCustomerError::from_err)?, true)
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                tx.exec("UPDATE django_session SET session_data = $data WHERE session_key = $key")
                    .param("$data", signed).param("$key", token.clone()).await?;
                Ok(BeginOutcome::Started { secret: secret.clone(), email })
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
                .timeout(Duration::from_secs(10)).await
        }
    }).await
}

pub async fn confirm(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: &str,
    code: &str,
    now: SystemTime,
) -> Result<ConfirmOutcome> {
    let seal_key =
        mfa_secret::key_from_env()?.context("MFA sealing key required for TOTP enrollment")?;
    let code = code.to_owned();
    let token = token.to_owned();
    let backends: Vec<String> = LEGACY_BACKENDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    let now_secs = now.duration_since(UNIX_EPOCH)?.as_secs();
    let recovery_seed = hex::encode(rand::random::<[u8; 40]>());
    let totp_id = random_row_id();
    let recovery_id = random_row_id();
    retry_known_abort(|| {
        let (codec, token, backends, seal_key, code, recovery_seed) =
            (codec.clone(), token.clone(), backends.clone(), seal_key.clone(), code.clone(), recovery_seed.clone());
        async {
            client.query_client().retry_tx(closure!([codec, token, backends, seal_key, code, recovery_seed], async |tx: &mut Transaction| {
                let Some(session) = restore_django_session_tx(tx, codec.as_ref(), token, backends, now).await? else {
                    return Ok(ConfirmOutcome::Unauthorized);
                };
                let user_id = i32::try_from(session.principal.account_id.get()).map_err(ydb::YdbOrCustomerError::from_err)?;
                let factor_set = factors(tx, user_id).await?;
                if factor_set.any && !session.mfa_verified { return Ok(ConfirmOutcome::Unauthorized) }
                if factor_set.totp { return Ok(ConfirmOutcome::AlreadyEnabled) }
                let mut data = session_data(tx, codec.as_ref(), token).await?;
                if !recent_auth(&data, now) { return Ok(ConfirmOutcome::ReauthRequired) }
                let Some(pending) = data.get(PENDING_KEY) else { return Ok(ConfirmOutcome::SetupRequired) };
                let Some(created_at) = pending.get("created_at").and_then(Value::as_u64) else { return Ok(ConfirmOutcome::SetupRequired) };
                if created_at > now_secs || now_secs - created_at >= SETUP_TTL { return Ok(ConfirmOutcome::SetupRequired) }
                let Some(sealed) = pending.get("secret").and_then(Value::as_str) else { return Ok(ConfirmOutcome::SetupRequired) };
                let secret = seal_key.unseal(i64::from(user_id), SecretKind::PendingTotp, sealed)
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                let valid = id_compat::totp::validate(&secret, code, now_secs, 30, 6, 0)
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                if !valid { return Ok(ConfirmOutcome::InvalidCode) }
                let sealed_totp = seal_key.seal(i64::from(user_id), SecretKind::Totp, &secret)
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                let recovery_codes = if factor_set.recovery { None } else {
                    Some(id_compat::recovery::codes(recovery_seed).map_err(ydb::YdbOrCustomerError::from_err)?)
                };
                tx.exec("INSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $user_id, 'totp', Unwrap(CAST($data AS Json)), CAST($now AS Datetime))")
                    .param("$id", totp_id).param("$user_id", user_id)
                    .param("$data", json!({"secret":sealed_totp}).to_string()).param("$now", now).await?;
                if recovery_codes.is_some() {
                    let sealed_seed = seal_key.seal(i64::from(user_id), SecretKind::RecoverySeed, recovery_seed)
                        .map_err(ydb::YdbOrCustomerError::from_err)?;
                    tx.exec("INSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $user_id, 'recovery_codes', Unwrap(CAST($data AS Json)), CAST($now AS Datetime))")
                        .param("$id", recovery_id).param("$user_id", user_id)
                        .param("$data", json!({"seed":sealed_seed,"used_mask":0}).to_string()).param("$now", now).await?;
                }
                data.remove(PENDING_KEY);
                data.insert("id_mfa_verified_user_id".into(), json!(user_id.to_string()));
                let methods = data.entry("account_authentication_methods").or_insert_with(|| json!([]));
                let Some(methods) = methods.as_array_mut() else {
                    return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("invalid authentication methods")))
                };
                methods.insert(0, json!({"method":"mfa","at":now_secs as f64,"type":"totp","passwordless":false}));
                let signed = codec.encode(&data, i64::try_from(now_secs).map_err(ydb::YdbOrCustomerError::from_err)?, true)
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                tx.exec("UPDATE django_session SET session_data = $data WHERE session_key = $key")
                    .param("$data", signed).param("$key", token.clone()).await?;
                tx.exec("INSERT INTO accounts_accountevent (user_id, action, meta, created_at) VALUES ($user_id, 'mfa_totp_enabled', Unwrap(CAST('{}' AS Json)), CAST($now AS Datetime))")
                    .param("$user_id", user_id).param("$now", now).await?;
                Ok(ConfirmOutcome::Activated { recovery_codes })
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
                .timeout(Duration::from_secs(10)).await
        }
    }).await
}

/// Remove TOTP and, when it was the last primary factor, its now-dangling
/// recovery codes in one transaction. A failed or ambiguous commit returns no
/// success response; callers can subsequently inspect MFA status.
pub async fn disable(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: &str,
    now: SystemTime,
) -> Result<DisableOutcome> {
    let token = token.to_owned();
    let backends: Vec<String> = LEGACY_BACKENDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    let now_secs = now.duration_since(UNIX_EPOCH)?.as_secs();
    retry_known_abort(|| {
        let (codec, token, backends) = (codec.clone(), token.clone(), backends.clone());
        async {
            client.query_client().retry_tx(closure!([codec, token, backends], async |tx: &mut Transaction| {
                let Some(session) = restore_django_session_tx(tx, codec.as_ref(), token, backends, now).await? else {
                    return Ok(DisableOutcome::Unauthorized);
                };
                let user_id = i32::try_from(session.principal.account_id.get()).map_err(ydb::YdbOrCustomerError::from_err)?;
                let factor_set = factors(tx, user_id).await?;
                if factor_set.any && !session.mfa_verified { return Ok(DisableOutcome::Unauthorized) }
                let mut data = session_data(tx, codec.as_ref(), token).await?;
                if !recent_auth(&data, now) { return Ok(DisableOutcome::ReauthRequired) }
                let Some(totp_id) = factor_set.totp_id else { return Ok(DisableOutcome::NotFound) };
                tx.exec("DELETE FROM mfa_authenticator WHERE id = $id").param("$id", totp_id).await?;
                if !factor_set.passkeys {
                    if let Some(recovery_id) = factor_set.recovery_id {
                        tx.exec("DELETE FROM mfa_authenticator WHERE id = $id")
                            .param("$id", recovery_id).await?;
                    }
                    data.remove("id_mfa_verified_user_id");
                    if let Some(methods) = data.get_mut("account_authentication_methods") {
                        let Some(methods) = methods.as_array_mut() else {
                            return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("invalid authentication methods")))
                        };
                        methods.retain(|method| method.get("method").and_then(Value::as_str) != Some("mfa"));
                    }
                }
                data.remove(PENDING_KEY);
                let signed = codec.encode(&data, i64::try_from(now_secs).map_err(ydb::YdbOrCustomerError::from_err)?, true)
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                tx.exec("UPDATE django_session SET session_data = $data WHERE session_key = $key")
                    .param("$data", signed).param("$key", token.clone()).await?;
                tx.exec("INSERT INTO accounts_accountevent (user_id, action, meta, created_at) VALUES ($user_id, 'mfa_totp_disabled', Unwrap(CAST('{}' AS Json)), CAST($now AS Datetime))")
                    .param("$user_id", user_id).param("$now", now).await?;
                Ok(DisableOutcome::Disabled)
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
                .timeout(Duration::from_secs(10)).await
        }
    }).await
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn secret_is_valid_base32_length_and_recent_auth_uses_method_time() -> Result<()> {
        let secret = new_secret();
        assert_eq!(secret.len(), 32);
        assert!(
            secret
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte))
        );
        let now = UNIX_EPOCH + Duration::from_secs(1000);
        let mut data = Map::new();
        data.insert(
            "account_authentication_methods".into(),
            json!([{"method":"password","at":900}]),
        );
        assert!(recent_auth(&data, now));
        assert!(!recent_auth(&data, now + Duration::from_secs(300)));
        Ok(())
    }
}
