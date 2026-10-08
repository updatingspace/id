//! Transactional management of existing WebAuthn credentials.

use crate::{
    login_preflight::verified_credential_owner_tx,
    passkey_index,
    provider_login::{ProviderLoginConfig, has_login_binding_tx},
    security_mail,
    session_store::{LEGACY_BACKENDS, restore_django_session_tx},
    totp_setup::{factors, recent_auth, session_data},
    tx_retry::retry_known_abort,
};
use anyhow::Result;
use id_compat::session::SessionCodec;
use serde_json::Value;
use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use ydb::{Client, Transaction, TxMode, closure};

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Renamed,
    Deleted(usize),
    Unauthorized,
    ReauthRequired,
    LastLoginMethod,
    NotFound,
}

async fn owned_passkey(
    tx: &mut Transaction,
    user_id: i32,
    id: i64,
) -> ydb::YdbResultWithCustomerErr<Option<Value>> {
    let mut stream = tx.query("SELECT user_id, type, CAST(data AS Utf8) AS data FROM mfa_authenticator WHERE id = $id")
        .param("$id", id).await?;
    let mut result = None;
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            let owner: i32 = row.remove_field_by_name("user_id")?.try_into()?;
            let kind: String = row.remove_field_by_name("type")?.try_into()?;
            let data: String = row.remove_field_by_name("data")?.try_into()?;
            if owner == user_id && kind == "webauthn" {
                let parsed = serde_json::from_str::<Value>(&data)
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                if !parsed.is_object() {
                    return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
                        "invalid passkey data",
                    )));
                }
                result = Some(parsed);
            }
        }
    }
    stream.close().await?;
    Ok(result)
}

#[cfg(feature = "passkeys")]
fn usable_passkey(record: &Value) -> bool {
    if record
        .pointer("/credential/clientExtensionResults/credProps/rk")
        .and_then(Value::as_bool)
        == Some(false)
        || !crate::security_read::passwordless_passkey(record)
    {
        return false;
    }
    let passkey = if let Some(serialized) = record.get("rust_passkey") {
        serde_json::from_value::<webauthn_rs::prelude::Passkey>(serialized.clone()).ok()
    } else if let (Ok(rp), Ok(origin)) = (
        std::env::var("ID_WEBAUTHN_RP_ID"),
        std::env::var("ID_WEBAUTHN_ORIGIN"),
    ) {
        crate::legacy_passkey::import_registration(&record["credential"], &rp, &origin).ok()
    } else {
        None
    };
    passkey.is_some_and(|key| matches!(
        (passkey_index::digest_of_bytes(key.cred_id().as_ref()), passkey_index::digest_of_record(record)),
        (Ok(actual), Ok(expected)) if actual == expected
    ))
}

#[cfg(not(feature = "passkeys"))]
fn usable_passkey(_: &Value) -> bool {
    false
}

pub async fn rename(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: &str,
    id: i64,
    name: &str,
    now: SystemTime,
) -> Result<Outcome> {
    let token = token.to_owned();
    let name = name.to_owned();
    let backends = LEGACY_BACKENDS
        .iter()
        .map(|s| (*s).to_owned())
        .collect::<Vec<String>>();
    retry_known_abort(|| {
        let (codec, token, name, backends) = (codec.clone(), token.clone(), name.clone(), backends.clone());
        async {
            client.query_client().retry_tx(closure!([codec, token, name, backends], async |tx: &mut Transaction| {
                let Some(session) = restore_django_session_tx(tx, codec.as_ref(), token, backends, now).await? else {
                    return Ok(Outcome::Unauthorized)
                };
                let user_id = i32::try_from(session.principal.account_id.get()).map_err(ydb::YdbOrCustomerError::from_err)?;
                let factor_set = factors(tx, user_id).await?;
                if factor_set.any && !session.mfa_verified { return Ok(Outcome::Unauthorized) }
                let data = session_data(tx, codec.as_ref(), token).await?;
                if !recent_auth(&data, now) { return Ok(Outcome::ReauthRequired) }
                let Some(mut credential) = owned_passkey(tx, user_id, id).await? else { return Ok(Outcome::NotFound) };
                let Some(object) = credential.as_object_mut() else {
                    return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("invalid passkey data")))
                };
                object.insert("name".into(), Value::String(name.to_owned()));
                let serialized = serde_json::to_string(&credential).map_err(ydb::YdbOrCustomerError::from_err)?;
                tx.exec("UPDATE mfa_authenticator SET data = Unwrap(CAST($data AS Json)) WHERE id = $id")
                    .param("$data", serialized).param("$id", id).await?;
                tx.exec("INSERT INTO accounts_accountevent (user_id, action, meta, created_at) VALUES ($user_id, 'mfa_passkey_renamed', Unwrap(CAST('{}' AS Json)), CAST($now AS Datetime))")
                    .param("$user_id", user_id).param("$now", now).await?;
                Ok(Outcome::Renamed)
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
                .timeout(Duration::from_secs(10)).await
        }
    }).await
}

pub async fn delete(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: &str,
    ids: &[i64],
    now: SystemTime,
    providers: &[Arc<ProviderLoginConfig>],
) -> Result<Outcome> {
    let token = token.to_owned();
    let ids = ids.to_vec();
    let providers = providers.to_vec();
    let backends = LEGACY_BACKENDS
        .iter()
        .map(|s| (*s).to_owned())
        .collect::<Vec<String>>();
    let now_secs = now.duration_since(UNIX_EPOCH)?.as_secs();
    let mail_id = Uuid::new_v4().to_string();
    retry_known_abort(|| {
        let (codec, token, ids, backends, mail_id, providers) = (codec.clone(), token.clone(), ids.clone(), backends.clone(), mail_id.clone(), providers.clone());
        async {
            client.query_client().retry_tx(closure!([codec, token, ids, backends, mail_id, providers], async |tx: &mut Transaction| {
                let Some(session) = restore_django_session_tx(tx, codec.as_ref(), token, backends, now).await? else {
                    return Ok(Outcome::Unauthorized)
                };
                let user_id = i32::try_from(session.principal.account_id.get()).map_err(ydb::YdbOrCustomerError::from_err)?;
                let factor_set = factors(tx, user_id).await?;
                if factor_set.any && !session.mfa_verified { return Ok(Outcome::Unauthorized) }
                let mut data = session_data(tx, codec.as_ref(), token).await?;
                if !recent_auth(&data, now) { return Ok(Outcome::ReauthRequired) }
                let mut indexed = Vec::with_capacity(ids.len());
                for id in ids.iter() {
                    let Some(credential) = owned_passkey(tx, user_id, *id).await? else { return Ok(Outcome::NotFound) };
                    let digest = passkey_index::digest_of_record(&credential)
                        .map_err(|_| ydb::YdbOrCustomerError::from_err(std::io::Error::other("invalid passkey credential ID")))?;
                    if let Some((indexed_id, indexed_owner)) = passkey_index::lookup_tx(tx, &digest).await?
                        && (indexed_id != *id || indexed_owner != user_id) {
                        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("passkey index mismatch")));
                    }
                    indexed.push(digest);
                }
                let removed = ids.iter().copied().collect::<HashSet<_>>();
                let Some(account) = verified_credential_owner_tx(tx, user_id).await? else {
                    return Ok(Outcome::LastLoginMethod);
                };
                let mut alternative = id_compat::password::is_usable(account.password_hash());
                // Match indexed_owner's backfill prerequisite without changing
                // the shared marker or treating an unready index as a backup.
                if !alternative && passkey_index::lookup_tx(tx, "ready").await? == Some((0, 0)) {
                    for id in factor_set.passkey_ids.iter().filter(|id| !removed.contains(id)) {
                        if let Some(record) = owned_passkey(tx, user_id, *id).await?
                            && usable_passkey(&record)
                            && let Ok(digest) = passkey_index::digest_of_record(&record)
                            && passkey_index::lookup_tx(tx, &digest).await? == Some((*id, user_id)) {
                            alternative = true;
                            break;
                        }
                    }
                }
                if !alternative && !has_login_binding_tx(tx, providers, user_id, account.identity_id.get()).await? {
                    return Ok(Outcome::LastLoginMethod);
                }
                for (id, digest) in ids.iter().zip(indexed.iter()) {
                    tx.exec("DELETE FROM `id_passkey_credential` WHERE digest = $digest AND authenticator_id = $id AND account_id = $owner")
                        .param("$digest", digest.clone()).param("$id", *id).param("$owner", user_id).await?;
                    tx.exec("DELETE FROM mfa_authenticator WHERE id = $id").param("$id", *id).await?;
                }
                let last_primary = !factor_set.totp && factor_set.passkey_ids.iter().all(|id| removed.contains(id));
                if last_primary {
                    if let Some(recovery_id) = factor_set.recovery_id {
                        tx.exec("DELETE FROM mfa_authenticator WHERE id = $id").param("$id", recovery_id).await?;
                    }
                    data.remove("id_mfa_verified_user_id");
                    if let Some(methods) = data.get_mut("account_authentication_methods") {
                        let Some(methods) = methods.as_array_mut() else {
                            return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("invalid authentication methods")))
                        };
                        methods.retain(|method| method.get("method").and_then(Value::as_str) != Some("mfa"));
                    }
                    let signed = codec.encode(&data, i64::try_from(now_secs).map_err(ydb::YdbOrCustomerError::from_err)?, true)
                        .map_err(ydb::YdbOrCustomerError::from_err)?;
                    tx.exec("UPDATE django_session SET session_data = $data WHERE session_key = $key")
                        .param("$data", signed).param("$key", token.clone()).await?;
                }
                tx.exec("INSERT INTO accounts_accountevent (user_id, action, meta, created_at) VALUES ($user_id, 'mfa_passkeys_deleted', Unwrap(CAST('{}' AS Json)), CAST($now AS Datetime))")
                    .param("$user_id", user_id).param("$now", now).await?;
                let Some(mut account) = tx.query_row("SELECT email FROM auth_user WHERE id = $user_id")
                    .param("$user_id", user_id).optional().await? else {
                    return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("passkey owner disappeared")));
                };
                let recipient: String = account.remove_field_by_name("email")?.try_into()?;
                if security_mail::valid_recipient(&recipient) {
                    security_mail::enqueue_tx(tx, mail_id, user_id, &recipient, "passkey_removed", now).await?;
                }
                Ok(Outcome::Deleted(ids.len()))
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
                .timeout(Duration::from_secs(10)).await
        }
    }).await
}
