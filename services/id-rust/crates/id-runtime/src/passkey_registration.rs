//! Local pilot for WebAuthn registration against the transition YDB schema.
//! Ceremony state stays in the server-side session and is consumed with the insert.

use crate::{
    mfa_secret, passkey_index,
    session_store::{LEGACY_BACKENDS, restore_django_session_tx},
    totp_setup::{factors, random_row_id, recent_auth, session_data},
    tx_retry::retry_known_abort,
};
use anyhow::Result;
use id_compat::mfa_seal::SecretKind;
use id_compat::session::SessionCodec;
use serde_json::{Value, json};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use webauthn_rs::prelude::{PasskeyRegistration, RegisterPublicKeyCredential, Webauthn};
use ydb::{Client, Transaction, TxMode, closure};

const PENDING_KEY: &str = "id_rust_passkey_pending";
const CEREMONY_TTL: u64 = 300;

#[derive(Debug)]
pub enum BeginOutcome {
    Started(Value),
    Unauthorized,
    ReauthRequired,
    EmailVerificationRequired,
}

#[derive(Debug)]
pub enum CompleteOutcome {
    Registered {
        id: i64,
        passwordless: bool,
        recovery_codes: Option<Vec<String>>,
    },
    Unauthorized,
    ReauthRequired,
    InvalidPasskey,
    Duplicate,
}

pub struct RegistrationInput {
    pub name: String,
    pub credential: Value,
}

async fn verified_email(
    tx: &mut Transaction,
    user_id: i32,
) -> ydb::YdbResultWithCustomerErr<Option<String>> {
    let mut stream = tx.query("SELECT email, verified FROM account_emailaddress VIEW account_emailaddress_user_id_2c513194 WHERE user_id = $user_id AND primary = true LIMIT 2")
        .param("$user_id", user_id).await?;
    let mut found = Vec::new();
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            let email: String = row.remove_field_by_name("email")?.try_into()?;
            let verified: bool = row.remove_field_by_name("verified")?.try_into()?;
            found.push((email, verified));
        }
    }
    stream.close().await?;
    if found.len() > 1 {
        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
            "ambiguous primary email",
        )));
    }
    Ok(found
        .pop()
        .filter(|(email, verified)| *verified && !email.is_empty())
        .map(|(email, _)| email))
}

pub async fn begin(
    client: &Client,
    codec: Arc<SessionCodec>,
    webauthn: Arc<Webauthn>,
    token: &str,
    passwordless: bool,
    now: SystemTime,
) -> Result<BeginOutcome> {
    let token = token.to_owned();
    let backends = LEGACY_BACKENDS
        .iter()
        .map(|s| (*s).to_owned())
        .collect::<Vec<String>>();
    let now_secs = now.duration_since(UNIX_EPOCH)?.as_secs();
    retry_known_abort(|| {
        let (codec, webauthn, token, backends) = (codec.clone(), webauthn.clone(), token.clone(), backends.clone());
        async {
            client.query_client().retry_tx(closure!([codec, webauthn, token, backends], async |tx: &mut Transaction| {
                let Some(session) = restore_django_session_tx(tx, codec.as_ref(), token, backends, now).await? else { return Ok(BeginOutcome::Unauthorized) };
                let user_id = i32::try_from(session.principal.account_id.get()).map_err(ydb::YdbOrCustomerError::from_err)?;
                let factor_set = factors(tx, user_id).await?;
                if factor_set.any && !session.mfa_verified { return Ok(BeginOutcome::Unauthorized) }
                let mut data = session_data(tx, codec.as_ref(), token).await?;
                if !recent_auth(&data, now) { return Ok(BeginOutcome::ReauthRequired) }
                let Some(email) = verified_email(tx, user_id).await? else { return Ok(BeginOutcome::EmailVerificationRequired) };
                let (options, state) = webauthn.start_passkey_registration(session.principal.identity_id.get(), &email, &email, None)
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                let mut options = serde_json::to_value(options).map_err(ydb::YdbOrCustomerError::from_err)?;
                if passwordless {
                    options["publicKey"]["authenticatorSelection"]["residentKey"] = json!("required");
                    options["publicKey"]["authenticatorSelection"]["requireResidentKey"] = json!(true);
                }
                data.insert(PENDING_KEY.into(), json!({"state":state,"created_at":now_secs,"passwordless":passwordless}));
                let signed = codec.encode(&data, i64::try_from(now_secs).map_err(ydb::YdbOrCustomerError::from_err)?, true)
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                tx.exec("UPDATE django_session SET session_data = $data WHERE session_key = $key")
                    .param("$data", signed).param("$key", token.clone()).await?;
                Ok(BeginOutcome::Started(options))
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(10)).await
        }
    }).await
}

pub async fn complete(
    client: &Client,
    codec: Arc<SessionCodec>,
    webauthn: Arc<Webauthn>,
    token: &str,
    input: RegistrationInput,
    now: SystemTime,
) -> Result<CompleteOutcome> {
    let token = token.to_owned();
    let name = input.name;
    let credential = input.credential;
    let backends = LEGACY_BACKENDS
        .iter()
        .map(|s| (*s).to_owned())
        .collect::<Vec<String>>();
    let now_secs = now.duration_since(UNIX_EPOCH)?.as_secs();
    let row_id = random_row_id();
    let recovery_id = random_row_id();
    let recovery_seed = hex::encode(rand::random::<[u8; 40]>());
    let seal_key = mfa_secret::key_from_env()?
        .ok_or_else(|| anyhow::anyhow!("MFA seal key required for passkey registration"))?;
    retry_known_abort(|| {
        let (codec, webauthn, token, name, credential, backends, recovery_seed, seal_key) = (codec.clone(), webauthn.clone(), token.clone(), name.clone(), credential.clone(), backends.clone(), recovery_seed.clone(), seal_key.clone());
        async {
            client.query_client().retry_tx(closure!([codec, webauthn, token, name, credential, backends, recovery_seed, seal_key], async |tx: &mut Transaction| {
                let Some(session) = restore_django_session_tx(tx, codec.as_ref(), token, backends, now).await? else { return Ok(CompleteOutcome::Unauthorized) };
                let user_id = i32::try_from(session.principal.account_id.get()).map_err(ydb::YdbOrCustomerError::from_err)?;
                let factor_set = factors(tx, user_id).await?;
                if factor_set.any && !session.mfa_verified { return Ok(CompleteOutcome::Unauthorized) }
                let mut data = session_data(tx, codec.as_ref(), token).await?;
                if !recent_auth(&data, now) { return Ok(CompleteOutcome::ReauthRequired) }
                let Some(pending) = data.get(PENDING_KEY) else { return Ok(CompleteOutcome::InvalidPasskey) };
                let Some(created_at) = pending.get("created_at").and_then(Value::as_u64) else { return Ok(CompleteOutcome::InvalidPasskey) };
                if created_at > now_secs || now_secs - created_at >= CEREMONY_TTL { return Ok(CompleteOutcome::InvalidPasskey) }
                let passwordless = pending.get("passwordless").and_then(Value::as_bool).unwrap_or(false);
                let Some(state) = pending.get("state") else { return Ok(CompleteOutcome::InvalidPasskey) };
                let Ok(state) = serde_json::from_value::<PasskeyRegistration>(state.clone()) else { return Ok(CompleteOutcome::InvalidPasskey) };
                let Ok(response) = serde_json::from_value::<RegisterPublicKeyCredential>(credential.clone()) else { return Ok(CompleteOutcome::InvalidPasskey) };
                let Ok(passkey) = webauthn.finish_passkey_registration(&response, &state) else { return Ok(CompleteOutcome::InvalidPasskey) };
                // credProps is an optional client extension result. A required
                // residentKey request is enforced by the browser even when the
                // extension omits rk; an explicit false still contradicts it.
                let resident = credential.pointer("/clientExtensionResults/credProps/rk").and_then(Value::as_bool);
                if passwordless && resident == Some(false) { return Ok(CompleteOutcome::InvalidPasskey) }
                let digest = passkey_index::digest_of_bytes(passkey.cred_id().as_ref())
                    .map_err(|_| ydb::YdbOrCustomerError::from_err(std::io::Error::other("invalid credential ID")))?;
                if !passkey_index::claim_in_tx(tx, &digest, row_id, user_id).await? { return Ok(CompleteOutcome::Duplicate) }
                tx.exec("INSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $user_id, 'webauthn', Unwrap(CAST($data AS Json)), CAST($now AS Datetime))")
                    .param("$id", row_id).param("$user_id", user_id)
                    .param("$data", json!({"name":name,"credential":credential,"rust_passkey":passkey,"passwordless":passwordless}).to_string())
                    .param("$now", now).await?;
                let recovery_codes = if factor_set.recovery { None } else {
                    let codes = id_compat::recovery::codes(recovery_seed).map_err(ydb::YdbOrCustomerError::from_err)?;
                    let sealed = seal_key.seal(i64::from(user_id), SecretKind::RecoverySeed, recovery_seed)
                        .map_err(ydb::YdbOrCustomerError::from_err)?;
                    tx.exec("INSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $user_id, 'recovery_codes', Unwrap(CAST($data AS Json)), CAST($now AS Datetime))")
                        .param("$id", recovery_id).param("$user_id", user_id)
                        .param("$data", json!({"seed":sealed,"used_mask":0}).to_string()).param("$now", now).await?;
                    Some(codes)
                };
                data.remove(PENDING_KEY);
                data.insert("id_mfa_verified_user_id".into(), json!(user_id.to_string()));
                let methods = data.entry("account_authentication_methods").or_insert_with(|| json!([]));
                let Some(methods) = methods.as_array_mut() else {
                    return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("invalid authentication methods")))
                };
                methods.insert(0, json!({"method":"mfa","at":now_secs as f64,"type":"webauthn","passwordless":passwordless}));
                let signed = codec.encode(&data, i64::try_from(now_secs).map_err(ydb::YdbOrCustomerError::from_err)?, true)
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                tx.exec("UPDATE django_session SET session_data = $data WHERE session_key = $key")
                    .param("$data", signed).param("$key", token.clone()).await?;
                tx.exec("INSERT INTO accounts_accountevent (user_id, action, meta, created_at) VALUES ($user_id, 'mfa_passkey_added', Unwrap(CAST('{}' AS Json)), CAST($now AS Datetime))")
                    .param("$user_id", user_id).param("$now", now).await?;
                Ok(CompleteOutcome::Registered { id: row_id, passwordless, recovery_codes })
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(15)).await
        }
    }).await
}
