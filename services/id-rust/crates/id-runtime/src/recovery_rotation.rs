//! Transactional recovery-code rotation with a bounded idempotent response window.

use crate::{
    mfa_secret,
    session_store::{LEGACY_BACKENDS, restore_django_session_tx},
    totp_setup::{factors, random_row_id, recent_auth, session_data},
    tx_retry::retry_known_abort,
};
use anyhow::{Context, Result};
use id_compat::{mfa_seal::SecretKind, session::SessionCodec};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use ydb::{Client, Transaction, TxMode, closure};

const REPLAY_TTL: u64 = 600;

#[derive(Debug, PartialEq, Eq)]
pub enum RotationOutcome {
    Rotated(Vec<String>),
    Replayed(Vec<String>),
    Unauthorized,
    ReauthRequired,
    MfaRequired,
    Conflict,
    ReplayUnavailable,
}

fn rotation_hash(account_id: i32, key: &str) -> String {
    hex::encode(Sha256::digest(
        format!("updspace-id:recovery-rotation:v1:{account_id}:{key}").as_bytes(),
    ))
}

pub fn valid_idempotency_key(key: &str) -> bool {
    (32..=128).contains(&key.len())
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub async fn regenerate(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: &str,
    idempotency_key: &str,
    now: SystemTime,
) -> Result<RotationOutcome> {
    if !valid_idempotency_key(idempotency_key) {
        anyhow::bail!("invalid recovery rotation idempotency key")
    }
    let seal_key = mfa_secret::key_from_env()?
        .context("MFA sealing key required for recovery-code rotation")?;
    let seed = hex::encode(rand::random::<[u8; 40]>());
    let new_codes = id_compat::recovery::codes(&seed)?;
    let row_id = random_row_id();
    let token = token.to_owned();
    let idempotency_key = idempotency_key.to_owned();
    let backends: Vec<String> = LEGACY_BACKENDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    let now_secs = now.duration_since(UNIX_EPOCH)?.as_secs();
    retry_known_abort(|| {
        let (codec, token, backends, seal_key, seed, new_codes, idempotency_key) = (
            codec.clone(), token.clone(), backends.clone(), seal_key.clone(),
            seed.clone(), new_codes.clone(), idempotency_key.clone(),
        );
        async {
            client.query_client().retry_tx(closure!([codec, token, backends, seal_key, seed, new_codes, idempotency_key], async |tx: &mut Transaction| {
                let Some(session) = restore_django_session_tx(tx, codec.as_ref(), token, backends, now).await? else {
                    return Ok(RotationOutcome::Unauthorized);
                };
                let user_id = i32::try_from(session.principal.account_id.get()).map_err(ydb::YdbOrCustomerError::from_err)?;
                let factor_set = factors(tx, user_id).await?;
                if factor_set.any && !session.mfa_verified { return Ok(RotationOutcome::Unauthorized) }
                let data = session_data(tx, codec.as_ref(), token).await?;
                if !recent_auth(&data, now) { return Ok(RotationOutcome::ReauthRequired) }
                if !factor_set.totp && !factor_set.passkeys { return Ok(RotationOutcome::MfaRequired) }
                let request_hash = rotation_hash(user_id, idempotency_key);
                if let Some(existing_id) = factor_set.recovery_id {
                    let mut row = tx.query_row("SELECT CAST(data AS Utf8) AS data FROM mfa_authenticator WHERE id = $id")
                        .param("$id", existing_id).await?;
                    let encoded: String = row.remove_field_by_name("data")?.try_into()?;
                    let existing: Value = serde_json::from_str(&encoded).map_err(ydb::YdbOrCustomerError::from_err)?;
                    if let Some(previous_hash) = existing.get("rotation_id").and_then(Value::as_str) {
                        let rotated_at = existing.get("rotated_at").and_then(Value::as_u64)
                            .ok_or_else(|| ydb::YdbOrCustomerError::from_err(std::io::Error::other("invalid recovery rotation marker")))?;
                        if rotated_at > now_secs {
                            return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("future recovery rotation marker")))
                        }
                        if now_secs - rotated_at < REPLAY_TTL {
                            if previous_hash != request_hash { return Ok(RotationOutcome::Conflict) }
                            if existing.get("used_mask").and_then(Value::as_u64) != Some(0) {
                                return Ok(RotationOutcome::ReplayUnavailable)
                            }
                            let saved_seed = existing.get("seed").and_then(Value::as_str)
                                .ok_or_else(|| ydb::YdbOrCustomerError::from_err(std::io::Error::other("missing recovery seed")))?;
                            let plaintext = seal_key.unseal(i64::from(user_id), SecretKind::RecoverySeed, saved_seed)
                                .map_err(ydb::YdbOrCustomerError::from_err)?;
                            let codes = id_compat::recovery::codes(&plaintext).map_err(ydb::YdbOrCustomerError::from_err)?;
                            return Ok(RotationOutcome::Replayed(codes));
                        }
                    }
                }
                let sealed = seal_key.seal(i64::from(user_id), SecretKind::RecoverySeed, seed)
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                let value = json!({"seed":sealed,"used_mask":0,"rotation_id":request_hash,"rotated_at":now_secs}).to_string();
                if let Some(existing_id) = factor_set.recovery_id {
                    tx.exec("UPDATE mfa_authenticator SET data = Unwrap(CAST($data AS Json)), created_at = CAST($now AS Datetime) WHERE id = $id")
                        .param("$data", value).param("$now", now).param("$id", existing_id).await?;
                } else {
                    tx.exec("INSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $user_id, 'recovery_codes', Unwrap(CAST($data AS Json)), CAST($now AS Datetime))")
                        .param("$id", row_id).param("$user_id", user_id)
                        .param("$data", value).param("$now", now).await?;
                }
                tx.exec("INSERT INTO accounts_accountevent (user_id, action, meta, created_at) VALUES ($user_id, 'mfa_recovery_regenerated', Unwrap(CAST('{}' AS Json)), CAST($now AS Datetime))")
                    .param("$user_id", user_id).param("$now", now).await?;
                Ok(RotationOutcome::Rotated(new_codes.clone()))
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
    fn rotation_hash_is_account_bound_and_does_not_embed_raw_key() {
        let key = "12345678-1234-4123-8123-123456789abc";
        let first = rotation_hash(42, key);
        assert_eq!(first.len(), 64);
        assert!(!first.contains(key));
        assert_ne!(first, rotation_hash(43, key));
    }
}
