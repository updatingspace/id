//! Usable sign-in methods checked inside credential-removal transactions.

use crate::{
    login_preflight::verified_credential_owner_tx,
    passkey_index,
    provider_login::{ProviderLoginConfig, has_login_binding_tx},
};
use serde_json::Value;
use std::sync::Arc;
use ydb::Transaction;

pub(crate) async fn owned_passkey(
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

pub(crate) async fn has_remaining_login_tx(
    tx: &mut Transaction,
    user_id: i32,
    remaining_passkey_ids: &[i64],
    providers: &[Arc<ProviderLoginConfig>],
) -> ydb::YdbResultWithCustomerErr<bool> {
    let Some(account) = verified_credential_owner_tx(tx, user_id).await? else {
        return Ok(false);
    };
    if id_compat::password::is_usable(account.password_hash()) {
        return Ok(true);
    }
    if passkey_index::lookup_tx(tx, "ready").await? == Some((0, 0)) {
        for id in remaining_passkey_ids {
            if let Some(record) = owned_passkey(tx, user_id, *id).await?
                && usable_passkey(&record)
                && let Ok(digest) = passkey_index::digest_of_record(&record)
                && passkey_index::lookup_tx(tx, &digest).await? == Some((*id, user_id))
            {
                return Ok(true);
            }
        }
    }
    has_login_binding_tx(tx, providers, user_id, account.identity_id.get()).await
}
