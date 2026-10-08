//! Atomic Django-compatible password session issuance after login preflight.
//! No token leaves this module until YDB confirms the entire write transaction.

use crate::{
    cache_store::CacheStore, github_login::GithubEvidence, login_activity,
    login_preflight::VerifiedAccount, mfa_secret,
};
use anyhow::{Context, Result, bail};
use id_compat::{
    account_jwt::{AccountJwtCodec, AccountJwtPair},
    mfa_seal::{self, MfaSealKey, SecretKind},
    session::SessionCodec,
};
use rand::Rng;
use serde_json::{Value, json};
use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use ydb::{Client, Transaction, TxMode, closure};

const DJANGO_SESSION_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
const EMAIL_BACKEND: &str = "accounts.backends.EmailBackend";

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum MfaVerdict {
    Reject,
    NoMfa,
    Totp,
    Recovery,
    Webauthn,
}

#[derive(Clone)]
pub struct SessionClient {
    pub ip: IpAddr,
    pub user_agent: String,
    pub device_fingerprint_salt: String,
}

#[derive(Clone, Copy)]
pub struct IssueTiming {
    pub now: SystemTime,
    pub lifetime: Duration,
}

#[derive(Clone, Copy)]
pub struct MfaProof<'a> {
    pub cache: &'a CacheStore,
    pub code: &'a str,
}

/// A WebAuthn assertion already verified against a credential snapshot. The
/// issuing transaction compares that snapshot again before writing a session.
#[derive(Clone)]
pub struct PasskeyProof {
    pub authenticator_id: i64,
    pub digest: String,
    pub original_data: String,
    pub updated_data: String,
}

enum LoginEvidence<'a> {
    Password,
    Mfa(MfaProof<'a>),
    Passkey(&'a PasskeyProof),
    Github(GithubEvidence<'a>),
}

pub struct IssuedSession {
    pub token: String,
    pub expires_at: SystemTime,
    pub new_device_mail_event_id: Option<i64>,
}

pub struct IssuedPasswordLogin {
    pub session: IssuedSession,
    pub access: String,
    pub refresh: String,
}

/// Commits the Django/allauth session and SimpleJWT revocation rows together.
/// No credential is released after an ambiguous or failed commit.
pub async fn issue_password_login(
    client: &Client,
    session_codec: Arc<SessionCodec>,
    jwt_codec: &AccountJwtCodec,
    verified: &VerifiedAccount,
    request: &SessionClient,
    now: SystemTime,
    lifetime: Duration,
) -> Result<Option<IssuedPasswordLogin>> {
    let (session, pair) = issue_password_session_inner(
        client,
        session_codec,
        Some(jwt_codec),
        verified,
        request,
        IssueTiming { now, lifetime },
        LoginEvidence::Password,
    )
    .await?;
    match (session, pair) {
        (Some(session), Some(pair)) => Ok(Some(IssuedPasswordLogin {
            session,
            access: pair.access,
            refresh: pair.refresh,
        })),
        (None, None) => Ok(None),
        _ => bail!("inconsistent login issuance result"),
    }
}

/// Password plus an allauth MFA code. The code is consumed in the same YDB
/// transaction as the session and account refresh token. This remains a
/// local-only pilot until runtime MFA settings and real RP flows are audited.
pub async fn issue_password_login_with_mfa(
    client: &Client,
    session_codec: Arc<SessionCodec>,
    jwt_codec: &AccountJwtCodec,
    verified: &VerifiedAccount,
    request: &SessionClient,
    timing: IssueTiming,
    proof: MfaProof<'_>,
) -> Result<Option<IssuedPasswordLogin>> {
    let (session, pair) = issue_password_session_inner(
        client,
        session_codec,
        Some(jwt_codec),
        verified,
        request,
        timing,
        LoginEvidence::Mfa(proof),
    )
    .await?;
    match (session, pair) {
        (Some(session), Some(pair)) => Ok(Some(IssuedPasswordLogin {
            session,
            access: pair.access,
            refresh: pair.refresh,
        })),
        (None, None) => Ok(None),
        _ => bail!("inconsistent MFA login issuance result"),
    }
}

/// Rechecks the exact password hash, email, MFA, identity and deletion state
/// inside the same serializable transaction that writes Django/allauth session
/// rows. `None` means the preflight snapshot became stale; errors include
/// ambiguous commit outcomes and never return a possibly issued credential.
pub async fn issue_password_session(
    client: &Client,
    codec: Arc<SessionCodec>,
    verified: &VerifiedAccount,
    request: &SessionClient,
    now: SystemTime,
    lifetime: Duration,
) -> Result<Option<IssuedSession>> {
    Ok(issue_password_session_inner(
        client,
        codec,
        None,
        verified,
        request,
        IssueTiming { now, lifetime },
        LoginEvidence::Password,
    )
    .await?
    .0)
}

pub async fn issue_passkey_login(
    client: &Client,
    session_codec: Arc<SessionCodec>,
    jwt_codec: &AccountJwtCodec,
    verified: &VerifiedAccount,
    request: &SessionClient,
    timing: IssueTiming,
    proof: &PasskeyProof,
) -> Result<Option<IssuedPasswordLogin>> {
    let (session, pair) = issue_password_session_inner(
        client,
        session_codec,
        Some(jwt_codec),
        verified,
        request,
        timing,
        LoginEvidence::Passkey(proof),
    )
    .await?;
    match (session, pair) {
        (Some(session), Some(pair)) => Ok(Some(IssuedPasswordLogin {
            session,
            access: pair.access,
            refresh: pair.refresh,
        })),
        (None, None) => Ok(None),
        _ => bail!("inconsistent passkey login issuance result"),
    }
}

/// The provider proof and any required MFA are checked in the same transaction
/// as credentials; caller-provided provider subjects are never accepted here.
pub(crate) async fn issue_github_login(
    client: &Client,
    session_codec: Arc<SessionCodec>,
    jwt_codec: &AccountJwtCodec,
    verified: &VerifiedAccount,
    request: &SessionClient,
    timing: IssueTiming,
    evidence: GithubEvidence<'_>,
) -> Result<Option<IssuedPasswordLogin>> {
    let (session, pair) = issue_password_session_inner(
        client,
        session_codec,
        Some(jwt_codec),
        verified,
        request,
        timing,
        LoginEvidence::Github(evidence),
    )
    .await?;
    match (session, pair) {
        (Some(session), Some(pair)) => Ok(Some(IssuedPasswordLogin {
            session,
            access: pair.access,
            refresh: pair.refresh,
        })),
        (None, None) => Ok(None),
        _ => bail!("inconsistent provider login issuance result"),
    }
}

async fn issue_password_session_inner(
    client: &Client,
    codec: Arc<SessionCodec>,
    jwt_codec: Option<&AccountJwtCodec>,
    verified: &VerifiedAccount,
    request: &SessionClient,
    timing: IssueTiming,
    evidence: LoginEvidence<'_>,
) -> Result<(Option<IssuedSession>, Option<AccountJwtPair>)> {
    let (mfa, passkey, github) = match evidence {
        LoginEvidence::Password => (None, None, None),
        LoginEvidence::Mfa(proof) => (Some(proof), None, None),
        LoginEvidence::Passkey(proof) => (None, Some(proof), None),
        LoginEvidence::Github(proof) => (
            proof.code.map(|code| MfaProof {
                cache: proof.cache,
                code,
            }),
            None,
            Some((proof.proof.clone(), proof.cache.clone())),
        ),
    };
    let IssueTiming { now, lifetime } = timing;
    if lifetime.is_zero() || lifetime > Duration::from_secs(60 * 60 * 24 * 30) {
        bail!("session lifetime must be between 1 second and 30 days");
    }
    let account_id =
        i32::try_from(verified.account_id.get()).context("account ID exceeds legacy YDB key")?;
    let identity_id = verified.identity_id.get();
    let subject = verified.public_subject.as_str().to_owned();
    let password_hash = verified.password_hash().to_owned();
    let email_key = verified.email_key().to_owned();
    let issued_at = i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?;
    let expires_at = now
        .checked_add(lifetime)
        .context("session expiry overflow")?;
    let token: String = (0..32)
        .map(|_| {
            DJANGO_SESSION_CHARS[rand::rng().random_range(0..DJANGO_SESSION_CHARS.len())] as char
        })
        .collect();
    let pair = jwt_codec
        .map(|signer| {
            signer.issue_pair(
                account_id,
                &token,
                issued_at,
                &format!("{:032x}", rand::random::<u128>()),
                &format!("{:032x}", rand::random::<u128>()),
            )
        })
        .transpose()?;
    let refresh = pair.as_ref().map(|pair| pair.refresh.clone());
    let refresh_jti = pair.as_ref().map(|pair| pair.refresh_jti.clone());
    let refresh_expiry = pair
        .as_ref()
        .map(|pair| -> Result<SystemTime> {
            let seconds = u64::try_from(pair.refresh_expires_at)?;
            UNIX_EPOCH
                .checked_add(Duration::from_secs(seconds))
                .context("refresh expiry overflow")
        })
        .transpose()?;
    let mut payload = serde_json::Map::new();
    payload.insert("_auth_user_id".into(), json!(account_id.to_string()));
    payload.insert("_auth_user_backend".into(), json!(EMAIL_BACKEND));
    payload.insert(
        "_auth_user_hash".into(),
        json!(codec.auth_hash(&password_hash)?),
    );
    payload.insert(
        "account_authentication_methods".into(),
        if let Some((proof, _)) = &github {
            json!([{"method":"socialaccount","provider":"github","at":proof.authenticated_at()}])
        } else {
            json!([{"method":"password","at":now.duration_since(UNIX_EPOCH)?.as_secs_f64(),"email":email_key}])
        },
    );
    let encoded = codec.encode(&payload, issued_at, true)?;
    let encoded_mfa = if mfa.is_some() {
        let mut variants = Vec::with_capacity(2);
        for method in [
            json!({"method":"mfa","at":now.duration_since(UNIX_EPOCH)?.as_secs_f64(),"type":"totp","passwordless":false}),
            json!({"method":"mfa","at":now.duration_since(UNIX_EPOCH)?.as_secs_f64(),"type":"recovery_codes"}),
        ] {
            let mut with_mfa = payload.clone();
            with_mfa.insert(
                "id_mfa_verified_user_id".into(),
                json!(account_id.to_string()),
            );
            let Some(Value::Array(methods)) = with_mfa.get_mut("account_authentication_methods")
            else {
                bail!("missing authentication methods in session payload");
            };
            methods.insert(0, method);
            variants.push(codec.encode(&with_mfa, issued_at, true)?);
        }
        Some(variants)
    } else {
        None
    };
    let encoded_passkey = if passkey.is_some() {
        let mut with_passkey = payload.clone();
        with_passkey.insert(
            "id_mfa_verified_user_id".into(),
            json!(account_id.to_string()),
        );
        with_passkey.insert("account_authentication_methods".into(), json!([
            {"method":"mfa","at":now.duration_since(UNIX_EPOCH)?.as_secs_f64(),"type":"webauthn","passwordless":true}
        ]));
        Some(codec.encode(&with_passkey, issued_at, true)?)
    } else {
        None
    };
    let passkey = passkey.cloned();
    let mfa_code = mfa.map(|proof| proof.code.to_owned());
    let mfa_cache = mfa.map(|proof| proof.cache.clone());
    let mfa_seal_key = mfa_secret::key_from_env()?;
    let token_for_tx = token.clone();
    let meta_id = random_bigint_id();
    let usersession_id = random_bigint_id();
    let outstanding_id = random_bigint_id();
    let session_token_id = random_bigint_id();
    let ip = request.ip.to_string();
    let activity_client = request.clone();
    let user_agent_200: String = request.user_agent.chars().take(200).collect();
    let user_agent_512: String = request.user_agent.chars().take(512).collect();
    let result = client
        .query_client()
        .retry_tx(closure!(
            [token_for_tx, encoded, encoded_mfa, encoded_passkey, mfa_code, mfa_cache, mfa_seal_key, passkey, github, password_hash, email_key, subject, ip, activity_client, user_agent_200, user_agent_512, refresh, refresh_jti, refresh_expiry],
            async |tx: &mut Transaction| {
                if !still_eligible(tx, account_id, identity_id, password_hash.as_str(),
                    email_key.as_str(), subject.as_str()).await? {
                    return Ok(None);
                }
                if let Some((proof, cache)) = github.as_ref()
                    && !proof.valid_in_tx(tx, cache, account_id, identity_id, now).await? {
                    return Ok(None);
                }
                let mfa_method = if let Some(proof) = passkey.as_ref() {
                    if !consume_passkey_proof(tx, account_id, proof, now).await? { return Ok(None) }
                    MfaVerdict::Webauthn
                } else {
                    check_and_consume_mfa(tx, account_id,
                        mfa_code.as_deref(), mfa_cache.as_ref(), mfa_seal_key.as_deref(), now).await?
                };
                let encoded_session = match mfa_method {
                    MfaVerdict::NoMfa if passkey.is_none() && encoded_mfa.is_none() => encoded.as_str(),
                    MfaVerdict::Totp => encoded_mfa.as_ref().map(|variants| variants[0].as_str()).unwrap_or(""),
                    MfaVerdict::Recovery => encoded_mfa.as_ref().map(|variants| variants[1].as_str()).unwrap_or(""),
                    MfaVerdict::Webauthn => encoded_passkey.as_deref().unwrap_or(""),
                    _ => return Ok(None),
                };
                if encoded_session.is_empty() { return Ok(None) }
                if let Some((proof, cache)) = github.as_ref() {
                    proof.consume_in_tx(tx, cache, now).await?;
                }
                tx.exec("INSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, $data, CAST($expiry AS Datetime))")
                    .param("$key", token_for_tx.clone())
                    .param("$data", encoded_session.to_owned())
                    .param("$expiry", expires_at).await?;
                tx.exec("INSERT INTO usersessions_usersession (id, user_id, session_key, ip, user_agent, created_at, last_seen_at, data) VALUES ($id, $user_id, $key, $ip, $ua, CAST($now AS Datetime), CAST($now AS Datetime), Unwrap(CAST('{}' AS Json)))")
                    .param("$id", usersession_id)
                    .param("$user_id", account_id)
                    .param("$key", token_for_tx.clone())
                    .param("$ip", ip.clone())
                    .param("$ua", user_agent_200.clone())
                    .param("$now", now).await?;
                tx.exec("INSERT INTO core_usersessionmeta (id, user_id, session_key, session_token, user_agent, ip, first_seen, last_seen, revoked_reason) VALUES ($id, $user_id, $key, $key, $ua, $ip, CAST($now AS Datetime), CAST($now AS Datetime), '')")
                    .param("$id", meta_id)
                    .param("$user_id", account_id)
                    .param("$key", token_for_tx.clone())
                    .param("$ua", user_agent_512.clone())
                    .param("$ip", ip.clone())
                    .param("$now", now).await?;
                tx.exec("UPDATE auth_user SET last_login = CAST($now AS Datetime) WHERE id = $user_id")
                    .param("$now", now)
                    .param("$user_id", account_id).await?;
                if let (Some(refresh), Some(jti), Some(expiry)) = (
                    refresh.as_ref(), refresh_jti.as_ref(), refresh_expiry,
                ) {
                    tx.exec("INSERT INTO token_blacklist_outstandingtoken (id, user_id, jti, token, created_at, expires_at) VALUES ($id, $user_id, $jti, $token, CAST($now AS Datetime), CAST($expiry AS Datetime))")
                        .param("$id", outstanding_id)
                        .param("$user_id", account_id)
                        .param("$jti", jti.clone())
                        .param("$token", refresh.clone())
                        .param("$now", now)
                        .param("$expiry", *expiry).await?;
                    tx.exec("INSERT INTO core_usersessiontoken (id, user_id, session_key, refresh_jti, created_at) VALUES ($id, $user_id, $key, $jti, CAST($now AS Datetime))")
                        .param("$id", session_token_id)
                        .param("$user_id", account_id)
                        .param("$key", token_for_tx.clone())
                        .param("$jti", jti.clone())
                        .param("$now", now).await?;
                }
                let mfa_label = match mfa_method {
                    MfaVerdict::NoMfa => "",
                    MfaVerdict::Totp => "totp",
                    MfaVerdict::Recovery => "recovery_code",
                    MfaVerdict::Webauthn => "webauthn",
                    MfaVerdict::Reject => return Ok(None),
                };
                let mail_event_id = login_activity::record_success_tx(tx, account_id, activity_client, now, mfa_label).await?;
                Ok(Some(mail_event_id))
            }
        ))
        .with_mode(TxMode::SerializableReadWrite)
        .idempotent(false)
        .timeout(Duration::from_secs(10))
        .await
        .context("issue legacy-compatible password session")?;
    let Some(mail_event_id) = result else {
        return Ok((None, None));
    };
    Ok((
        Some(IssuedSession {
            token,
            expires_at,
            new_device_mail_event_id: mail_event_id,
        }),
        pair,
    ))
}

fn random_bigint_id() -> i64 {
    let value = (rand::random::<u64>() & ((1u64 << 62) - 1)) | (1u64 << 62);
    value as i64
}

async fn consume_passkey_proof(
    tx: &mut Transaction,
    account_id: i32,
    proof: &PasskeyProof,
    now: SystemTime,
) -> ydb::YdbResultWithCustomerErr<bool> {
    let Some(mut marker) = tx
        .query_row(
            "SELECT authenticator_id, account_id FROM id_passkey_credential WHERE digest = 'ready'",
        )
        .optional()
        .await?
    else {
        return Ok(false);
    };
    let marker_id: i64 = marker
        .remove_field_by_name("authenticator_id")?
        .try_into()?;
    let marker_owner: i32 = marker.remove_field_by_name("account_id")?.try_into()?;
    if (marker_id, marker_owner) != (0, 0) {
        return Ok(false);
    }
    let Some(mut indexed) = tx
        .query_row(
            "SELECT authenticator_id, account_id FROM id_passkey_credential WHERE digest = $digest",
        )
        .param("$digest", proof.digest.clone())
        .optional()
        .await?
    else {
        return Ok(false);
    };
    let indexed_id: i64 = indexed
        .remove_field_by_name("authenticator_id")?
        .try_into()?;
    let indexed_owner: i32 = indexed.remove_field_by_name("account_id")?.try_into()?;
    if indexed_id != proof.authenticator_id || indexed_owner != account_id {
        return Ok(false);
    }
    let Some(mut row) = tx.query_row("SELECT user_id, type, CAST(data AS Utf8) AS data FROM mfa_authenticator WHERE id = $id")
        .param("$id", proof.authenticator_id).optional().await? else { return Ok(false) };
    let owner: i32 = row.remove_field_by_name("user_id")?.try_into()?;
    let kind: String = row.remove_field_by_name("type")?.try_into()?;
    let data: String = row.remove_field_by_name("data")?.try_into()?;
    if owner != account_id || kind != "webauthn" || data != proof.original_data {
        return Ok(false);
    }
    tx.exec("UPDATE mfa_authenticator SET data = Unwrap(CAST($data AS Json)), last_used_at = CAST($now AS Datetime) WHERE id = $id")
        .param("$data", proof.updated_data.clone())
        .param("$now", now)
        .param("$id", proof.authenticator_id).await?;
    Ok(true)
}

pub(crate) async fn check_and_consume_mfa(
    tx: &mut Transaction,
    account_id: i32,
    code: Option<&str>,
    cache: Option<&CacheStore>,
    seal_key: Option<&MfaSealKey>,
    now: SystemTime,
) -> ydb::YdbResultWithCustomerErr<MfaVerdict> {
    let mut stream = tx
        .query("SELECT id, type, data FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $user_id")
        .param("$user_id", account_id)
        .await?;
    let mut totp: Option<(i64, Value)> = None;
    let mut recovery: Option<(i64, Value)> = None;
    let mut count = 0;
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            count += 1;
            let id: i64 = row.remove_field_by_name("id")?.try_into()?;
            let kind: String = row.remove_field_by_name("type")?.try_into()?;
            let data: String = row.remove_field_by_name("data")?.try_into()?;
            let data: Value =
                serde_json::from_str(&data).map_err(ydb::YdbOrCustomerError::from_err)?;
            let target = match kind.as_str() {
                "totp" => Some(&mut totp),
                "recovery_codes" => Some(&mut recovery),
                "webauthn" => None,
                _ => {
                    return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
                        "unknown MFA authenticator type",
                    )));
                }
            };
            if let Some(target) = target
                && target.replace((id, data)).is_some()
            {
                return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
                    "duplicate MFA authenticator",
                )));
            }
        }
    }
    stream.close().await?;
    let Some(code) = code else {
        return Ok(if count == 0 {
            MfaVerdict::NoMfa
        } else {
            MfaVerdict::Reject
        });
    };
    let Some(cache) = cache else {
        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
            "MFA proof has no shared replay store",
        )));
    };
    if count == 0 || code.is_empty() || code.len() > 128 || !code.is_ascii() {
        return Ok(MfaVerdict::Reject);
    }
    // The local pilot is pinned to the installed allauth defaults. Production
    // must first prove its effective settings and MFA adapter match these.
    const PERIOD: u64 = 30;
    const DIGITS: u32 = 6;
    const TOLERANCE: u64 = 0;
    if let Some((_, data)) = totp {
        let secret = data.get("secret").and_then(Value::as_str).ok_or_else(|| {
            ydb::YdbOrCustomerError::from_err(std::io::Error::other("invalid TOTP data"))
        })?;
        let secret =
            mfa_seal::read_existing(seal_key, i64::from(account_id), SecretKind::Totp, secret)
                .map_err(ydb::YdbOrCustomerError::from_err)?;
        let seconds = now
            .duration_since(UNIX_EPOCH)
            .map_err(ydb::YdbOrCustomerError::from_err)?
            .as_secs();
        if id_compat::totp::validate(&secret, code, seconds, PERIOD, DIGITS, TOLERANCE)
            .map_err(ydb::YdbOrCustomerError::from_err)?
        {
            let key = format!("allauth.mfa.totp.used?user={account_id}&code={code}");
            let expiry = now + Duration::from_secs(PERIOD * (2 * TOLERANCE + 1));
            if cache.claim_in_tx(tx, &key, expiry, now).await? {
                return Ok(MfaVerdict::Totp);
            }
        }
    }
    if let Some((id, mut data)) = recovery {
        let object = data.as_object_mut().ok_or_else(|| {
            ydb::YdbOrCustomerError::from_err(std::io::Error::other("invalid recovery data"))
        })?;
        let matched = if let Some(migrated) = object
            .get("migrated_codes")
            .filter(|value| !value.is_null())
        {
            let codes: Vec<String> = serde_json::from_value(migrated.clone())
                .map_err(ydb::YdbOrCustomerError::from_err)?;
            let Some(index) = id_compat::recovery::migrated_index(&codes, code)
                .map_err(ydb::YdbOrCustomerError::from_err)?
            else {
                return Ok(MfaVerdict::Reject);
            };
            let mut remaining = codes;
            remaining.remove(index);
            object.insert("migrated_codes".into(), json!(remaining));
            true
        } else {
            let used_mask = object
                .get("used_mask")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    ydb::YdbOrCustomerError::from_err(std::io::Error::other(
                        "invalid recovery mask",
                    ))
                })?;
            let seed = object.get("seed").and_then(Value::as_str).ok_or_else(|| {
                ydb::YdbOrCustomerError::from_err(std::io::Error::other("invalid recovery seed"))
            })?;
            let seed = mfa_seal::read_existing(
                seal_key,
                i64::from(account_id),
                SecretKind::RecoverySeed,
                seed,
            )
            .map_err(ydb::YdbOrCustomerError::from_err)?;
            if let Some(index) = id_compat::recovery::unused_index(&seed, used_mask, code)
                .map_err(ydb::YdbOrCustomerError::from_err)?
            {
                object.insert("used_mask".into(), json!(used_mask | (1u64 << index)));
                true
            } else {
                false
            }
        };
        if matched {
            tx.exec(
                "UPDATE mfa_authenticator SET data = Unwrap(CAST($data AS Json)) WHERE id = $id",
            )
            .param("$data", data.to_string())
            .param("$id", id)
            .await?;
            return Ok(MfaVerdict::Recovery);
        }
    }
    Ok(MfaVerdict::Reject)
}

async fn still_eligible(
    tx: &mut Transaction,
    account_id: i32,
    identity_id: uuid::Uuid,
    password_hash: &str,
    email_key: &str,
    subject: &str,
) -> ydb::YdbResultWithCustomerErr<bool> {
    let Some(mut row) = tx
        .query_row("SELECT password, email, is_active FROM auth_user WHERE id = $user_id")
        .param("$user_id", account_id)
        .optional()
        .await?
    else {
        return Ok(false);
    };
    let current_hash: String = row.remove_field_by_name("password")?.try_into()?;
    let current_email: String = row.remove_field_by_name("email")?.try_into()?;
    let active: bool = row.remove_field_by_name("is_active")?.try_into()?;
    if !active || current_hash != password_hash || current_email.trim().to_lowercase() != email_key
    {
        return Ok(false);
    }
    let mut lookup = tx
        .query("SELECT user_id FROM accounts_accountemaillookup VIEW acct_email_key_idx WHERE email_key = $email LIMIT 2")
        .param("$email", email_key.to_owned())
        .await?;
    let mut matched: Vec<i32> = Vec::with_capacity(2);
    while let Some(rows) = lookup.next_result_set().await? {
        for mut row in rows {
            matched.push(row.remove_field_by_name("user_id")?.try_into()?);
        }
    }
    lookup.close().await?;
    if matched != [account_id] {
        return Ok(false);
    }
    if tx.query_row("SELECT id FROM account_emailaddress VIEW account_emailaddress_user_id_2c513194 WHERE user_id = $user_id AND Unicode::ToLower(email) = $email AND verified = true LIMIT 1")
        .param("$user_id", account_id)
        .param("$email", email_key.to_owned()).optional().await?.is_none() {
        return Ok(false);
    }
    let Some(mut binding) = tx.query_row("SELECT identity_id, public_subject FROM accounts_accountidentity WHERE user_id = $user_id")
        .param("$user_id", account_id).optional().await? else {
        return Ok(false);
    };
    let bound_id: Option<uuid::Uuid> = binding.remove_field_by_name("identity_id")?.try_into()?;
    let bound_subject: String = binding.remove_field_by_name("public_subject")?.try_into()?;
    if bound_id != Some(identity_id) || bound_subject != subject {
        return Ok(false);
    }
    let Some(mut identity) = tx
        .query_row("SELECT status FROM usid_user WHERE user_id = $identity_id")
        .param("$identity_id", identity_id)
        .optional()
        .await?
    else {
        return Ok(false);
    };
    let status: String = identity.remove_field_by_name("status")?.try_into()?;
    if status != "active" {
        return Ok(false);
    }
    if tx.query_row("SELECT id FROM accounts_accountdeletionrequest VIEW accounts_accountdeletionrequest_user_id_6a166c52 WHERE user_id = $user_id AND status != 'canceled' LIMIT 1")
        .param("$user_id", account_id).optional().await?.is_some() {
        return Ok(false);
    }
    Ok(true)
}
