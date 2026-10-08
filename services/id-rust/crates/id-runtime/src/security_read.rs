//! Read MFA status and passkey metadata with the same authorized YDB snapshot.

use crate::session_store::{LEGACY_BACKENDS, restore_django_session_tx};
use anyhow::{Context, Result, ensure};
use id_compat::session::SessionCodec;
use serde::Serialize;
use serde_json::Value;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use ydb::{Client, Transaction, TxMode, closure};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MfaStatus {
    pub has_totp: bool,
    pub has_webauthn: bool,
    pub has_recovery_codes: bool,
    pub recovery_codes_left: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Passkey {
    pub id: String,
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub created_at: u64,
    pub last_used_at: Option<u64>,
    pub is_passwordless: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecuritySnapshot {
    pub status: MfaStatus,
    pub passkeys: Vec<Passkey>,
}

pub async fn read_security(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: &str,
    now: SystemTime,
) -> Result<Option<SecuritySnapshot>> {
    let token = token.to_owned();
    let backends: Vec<String> = LEGACY_BACKENDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    let result = client
        .query_client()
        .retry_tx(closure!(
            [token, codec, backends],
            async |tx: &mut Transaction| {
                let Some(session) =
                    restore_django_session_tx(tx, codec.as_ref(), token, backends, now).await?
                else {
                    return Ok(None);
                };
                let user_id = i32::try_from(session.principal.account_id.get())
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                let rows = read_authenticators(tx, user_id).await?;
                if !rows.is_empty() && !session.mfa_verified {
                    return Ok(None);
                }
                Ok(Some(rows))
            }
        ))
        .isolation(TxMode::SerializableReadWrite)
        .timeout(Duration::from_secs(5))
        .await
        .context("read authorized MFA and passkey snapshot")?;
    result.map(assemble).transpose()
}

#[derive(Debug)]
struct AuthenticatorRow {
    id: i64,
    kind: String,
    data: String,
    created_at: SystemTime,
    last_used_at: Option<SystemTime>,
}

async fn read_authenticators(
    tx: &mut Transaction,
    user_id: i32,
) -> ydb::YdbResultWithCustomerErr<Vec<AuthenticatorRow>> {
    let mut stream = tx.query("SELECT id, type, CAST(data AS Utf8) AS data, created_at, last_used_at FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $user_id")
        .param("$user_id", user_id).await?;
    let mut result = Vec::new();
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            if result.len() >= 1000 {
                return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
                    "too many authenticators",
                )));
            }
            result.push(AuthenticatorRow {
                id: row.remove_field_by_name("id")?.try_into()?,
                kind: row.remove_field_by_name("type")?.try_into()?,
                data: row.remove_field_by_name("data")?.try_into()?,
                created_at: row.remove_field_by_name("created_at")?.try_into()?,
                last_used_at: row.remove_field_by_name("last_used_at")?.try_into()?,
            });
        }
    }
    stream.close().await?;
    Ok(result)
}

fn epoch_seconds(time: SystemTime) -> Result<u64> {
    Ok(time.duration_since(UNIX_EPOCH)?.as_secs())
}

fn recovery_left(data: &Value) -> Result<usize> {
    if let Some(migrated) = data.get("migrated_codes").filter(|value| !value.is_null()) {
        let values = migrated
            .as_array()
            .context("invalid migrated recovery codes")?;
        ensure!(
            values.len() <= 100 && values.iter().all(Value::is_string),
            "invalid migrated recovery codes"
        );
        return Ok(values.len());
    }
    let mask = data
        .get("used_mask")
        .and_then(Value::as_u64)
        .context("invalid recovery mask")?;
    let seed = data
        .get("seed")
        .and_then(Value::as_str)
        .context("invalid recovery seed")?;
    ensure!(
        !seed.is_empty() && mask >> 10 == 0,
        "invalid recovery code data"
    );
    Ok(10 - mask.count_ones() as usize)
}

fn assemble(rows: Vec<AuthenticatorRow>) -> Result<SecuritySnapshot> {
    let mut status = MfaStatus {
        has_totp: false,
        has_webauthn: false,
        has_recovery_codes: false,
        recovery_codes_left: 0,
    };
    let mut passkeys = Vec::new();
    for row in rows {
        let data: Value = serde_json::from_str(&row.data).context("invalid authenticator JSON")?;
        ensure!(data.is_object(), "invalid authenticator data");
        match row.kind.as_str() {
            "totp" => {
                ensure!(!status.has_totp, "duplicate TOTP authenticators");
                status.has_totp = true;
            }
            "recovery_codes" => {
                ensure!(
                    !status.has_recovery_codes,
                    "duplicate recovery authenticators"
                );
                status.has_recovery_codes = true;
                status.recovery_codes_left = recovery_left(&data)?;
            }
            "webauthn" => {
                status.has_webauthn = true;
                passkeys.push(Passkey {
                    id: row.id.to_string(),
                    name: data.get("name").and_then(Value::as_str).map(str::to_owned),
                    kind: "webauthn",
                    created_at: epoch_seconds(row.created_at)?,
                    last_used_at: row.last_used_at.map(epoch_seconds).transpose()?,
                    is_passwordless: data
                        .get("passwordless")
                        .and_then(Value::as_bool)
                        .unwrap_or_else(|| {
                            data.pointer("/credential/clientExtensionResults/credProps/rk")
                                .and_then(Value::as_bool)
                                .unwrap_or(false)
                        }),
                });
            }
            _ => anyhow::bail!("unknown MFA authenticator type"),
        }
    }
    passkeys.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| b.id.cmp(&a.id))
    });
    Ok(SecuritySnapshot { status, passkeys })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn recovery_mask_and_migrated_codes_count_without_exposing_values() -> Result<()> {
        assert_eq!(
            recovery_left(&json!({"seed":"encrypted","used_mask":0b101}))?,
            8
        );
        assert_eq!(
            recovery_left(&json!({"migrated_codes":["encrypted-a","encrypted-b"]}))?,
            2
        );
        assert!(recovery_left(&json!({"seed":"encrypted","used_mask":1024})).is_err());
        assert!(recovery_left(&json!({"migrated_codes":"bad"})).is_err());
        Ok(())
    }

    #[test]
    fn passkey_inventory_uses_stored_passwordless_choice_with_legacy_fallback() -> Result<()> {
        let now = UNIX_EPOCH + Duration::from_secs(100);
        let rows = [
            (
                1,
                json!({"name":"Mobile passkey","passwordless":true,"credential":{"clientExtensionResults":{}}}),
                true,
            ),
            (
                2,
                json!({"name":"Legacy passkey","credential":{"clientExtensionResults":{"credProps":{"rk":true}}}}),
                true,
            ),
            (
                3,
                json!({"name":"Second factor","passwordless":false,"credential":{"clientExtensionResults":{"credProps":{"rk":true}}}}),
                false,
            ),
        ];
        for (id, data, expected) in rows {
            let snapshot = assemble(vec![AuthenticatorRow {
                id,
                kind: "webauthn".into(),
                data: data.to_string(),
                created_at: now,
                last_used_at: None,
            }])?;
            assert_eq!(snapshot.passkeys[0].is_passwordless, expected);
        }
        Ok(())
    }
}
