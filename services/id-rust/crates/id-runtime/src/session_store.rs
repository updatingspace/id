//! Read-only legacy Django principal restore against the existing YDB schema.
//! This is not yet a complete authorization decision or a public API route.

use crate::ids::{AccountId, IdentityId, PublicSubject};
use anyhow::{Context, Result, bail};
use id_compat::{
    session::SessionCodec,
    session_auth::{SessionMeta, SessionSnapshot, eligible_account_id},
};
use std::{
    env,
    sync::Arc,
    time::{Duration, SystemTime},
};
use uuid::Uuid;
use ydb::{Client, Transaction, TxMode, closure};

pub const LEGACY_BACKENDS: &[&str] = &[
    "accounts.backends.EmailBackend",
    "django.contrib.auth.backends.ModelBackend",
];

pub fn session_codec_from_env() -> Result<Arc<SessionCodec>> {
    let secret = env::var("DJANGO_SECRET_KEY").context("DJANGO_SECRET_KEY is required")?;
    if secret.is_empty() {
        bail!("DJANGO_SECRET_KEY cannot be empty");
    }
    let fallback_keys: Vec<String> = env::var("DJANGO_SECRET_KEY_FALLBACKS")
        .ok()
        .map(|value| serde_json::from_str(&value))
        .transpose()?
        .unwrap_or_default();
    let fallbacks: Vec<&[u8]> = fallback_keys.iter().map(|key| key.as_bytes()).collect();
    Ok(Arc::new(SessionCodec::new(secret.as_bytes(), &fallbacks)?))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Principal {
    pub account_id: AccountId,
    pub identity_id: IdentityId,
    pub public_subject: PublicSubject,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RestoredSession {
    pub principal: Principal,
    pub cookie_expiry: SessionCookieExpiry,
    pub mfa_verified: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SessionCookieExpiry {
    Default,
    BrowserClose,
    Seconds(u64),
    At(SystemTime),
}

impl SessionCookieExpiry {
    /// `None` means a browser-session cookie, with no Max-Age attribute.
    pub fn max_age(
        &self,
        now: SystemTime,
        default_age: u64,
        default_browser_close: bool,
    ) -> Option<u64> {
        match self {
            Self::Default if default_browser_close => None,
            Self::Default => Some(default_age),
            Self::BrowserClose => None,
            Self::Seconds(seconds) => Some(*seconds),
            Self::At(expires_at) => {
                Some(expires_at.duration_since(now).unwrap_or_default().as_secs())
            }
        }
    }

    fn from_session_data(
        data: &serde_json::Map<String, serde_json::Value>,
        expires_at: SystemTime,
    ) -> Option<Self> {
        match data.get("_session_expiry") {
            None => Some(Self::Default),
            Some(serde_json::Value::Number(value)) => match value.as_u64()? {
                0 => Some(Self::BrowserClose),
                seconds => Some(Self::Seconds(seconds)),
            },
            Some(serde_json::Value::String(_)) => Some(Self::At(expires_at)),
            _ => None,
        }
    }
}

/// Reads session, account, revocation, immutable binding, global identity and
/// deletion state in one serializable transaction. Missing or inactive linkage
/// is not a principal. Dependency errors remain distinct from invalid sessions.
pub async fn restore_django_principal(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: &str,
    allowed_backends: &[&str],
    now: SystemTime,
) -> Result<Option<Principal>> {
    let token = token.to_owned();
    let allowed_backends: Vec<String> = allowed_backends
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    let restored = client
        .query_client()
        .retry_tx(closure!(
            [token, codec, allowed_backends],
            async |tx: &mut Transaction| {
                restore_django_session_tx(
                    tx,
                    codec.as_ref(),
                    token.as_str(),
                    allowed_backends.as_slice(),
                    now,
                )
                .await
            }
        ))
        .isolation(TxMode::SerializableReadWrite)
        .timeout(Duration::from_secs(5))
        .await?;
    Ok(restored.map(|session| session.principal))
}

pub(crate) async fn restore_django_session_tx(
    tx: &mut Transaction,
    codec: &SessionCodec,
    token: &str,
    allowed_backends: &[String],
    now: SystemTime,
) -> ydb::YdbResultWithCustomerErr<Option<RestoredSession>> {
    let Some(mut session_row) = tx
        .query_row("SELECT session_data, expire_date FROM django_session WHERE session_key = $key")
        .param("$key", token.to_owned())
        .optional()
        .await?
    else {
        return Ok(None);
    };
    let encoded: String = session_row
        .remove_field_by_name("session_data")?
        .try_into()?;
    let expires_at: SystemTime = session_row
        .remove_field_by_name("expire_date")?
        .try_into()?;
    if expires_at <= now {
        return Ok(None);
    }
    let Ok(decoded) = codec.decode(&encoded) else {
        return Ok(None);
    };
    let Some(cookie_expiry) = SessionCookieExpiry::from_session_data(&decoded.data, expires_at)
    else {
        return Ok(None);
    };
    let Some(account_id) = decoded
        .data
        .get("_auth_user_id")
        .and_then(|id| id.as_str())
        .and_then(|id| id.parse::<i32>().ok())
    else {
        return Ok(None);
    };

    let Some(mut account_row) = tx
        .query_row("SELECT password, is_active FROM auth_user WHERE id = $user_id")
        .param("$user_id", account_id)
        .optional()
        .await?
    else {
        return Ok(None);
    };
    let password_hash: String = account_row.remove_field_by_name("password")?.try_into()?;
    let is_active: bool = account_row.remove_field_by_name("is_active")?.try_into()?;

    // The existing Django migration created this global sync index.
    // Bound the result to detect ambiguous ownership without reading
    // an unbounded number of metadata rows.
    let mut stream = tx
        .query("SELECT user_id, revoked_at FROM core_usersessionmeta VIEW core_usersessionmeta_session_key_2f41cf47 WHERE session_key = $key LIMIT 2")
        .param("$key", token.to_owned())
        .await?;
    let mut metadata = Vec::with_capacity(2);
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            let user_id: i32 = row.remove_field_by_name("user_id")?.try_into()?;
            let revoked_at: Option<SystemTime> =
                row.remove_field_by_name("revoked_at")?.try_into()?;
            metadata.push(SessionMeta {
                user_id: i64::from(user_id),
                revoked: revoked_at.is_some(),
            });
        }
    }
    stream.close().await?;

    let snapshot = SessionSnapshot {
        encoded: &encoded,
        expires_at,
        user_id: i64::from(account_id),
        password_hash: &password_hash,
        is_active,
        metadata: &metadata,
    };
    let allowed: Vec<&str> = allowed_backends.iter().map(String::as_str).collect();
    let Some(account_id) = eligible_account_id(codec, &snapshot, &allowed, now) else {
        return Ok(None);
    };
    let Ok(account_key) = i32::try_from(account_id) else {
        return Ok(None);
    };

    let Some(principal) = active_principal_tx(tx, account_key).await? else {
        return Ok(None);
    };
    Ok(Some(RestoredSession {
        principal,
        cookie_expiry,
        mfa_verified: has_bound_mfa_proof(&decoded.data, account_id),
    }))
}

/// One principal decision shared by session restore and credential exchange.
/// A missing or disabled account, ambiguous binding, inactive master identity,
/// or pending deletion never becomes a token subject.
pub(crate) async fn active_principal_tx(
    tx: &mut Transaction,
    account_key: i32,
) -> ydb::YdbResultWithCustomerErr<Option<Principal>> {
    let Some(mut account) = tx
        .query_row("SELECT is_active FROM auth_user WHERE id = $user_id")
        .param("$user_id", account_key)
        .optional()
        .await?
    else {
        return Ok(None);
    };
    let is_active: bool = account.remove_field_by_name("is_active")?.try_into()?;
    if !is_active {
        return Ok(None);
    }
    let Some(mut binding) = tx
        .query_row("SELECT identity_id, public_subject FROM accounts_accountidentity WHERE user_id = $user_id")
        .param("$user_id", account_key)
        .optional()
        .await?
    else {
        return Ok(None);
    };
    let identity_id: Option<Uuid> = binding.remove_field_by_name("identity_id")?.try_into()?;
    let public_subject: String = binding.remove_field_by_name("public_subject")?.try_into()?;
    let Some(identity_id) = identity_id else {
        return Ok(None);
    };
    let Some(public_subject) = PublicSubject::parse(public_subject) else {
        return Ok(None);
    };
    let Some(mut identity) = tx
        .query_row("SELECT status FROM usid_user WHERE user_id = $identity_id")
        .param("$identity_id", identity_id)
        .optional()
        .await?
    else {
        return Ok(None);
    };
    let status: String = identity.remove_field_by_name("status")?.try_into()?;
    if status != "active" {
        return Ok(None);
    }
    let deletion = tx
        .query_row("SELECT id FROM accounts_accountdeletionrequest VIEW accounts_accountdeletionrequest_user_id_6a166c52 WHERE user_id = $user_id AND status != 'canceled' LIMIT 1")
        .param("$user_id", account_key)
        .optional()
        .await?;
    if deletion.is_some() {
        return Ok(None);
    }
    Ok(Some(Principal {
        account_id: AccountId::new(i64::from(account_key)),
        identity_id: IdentityId::new(identity_id),
        public_subject,
    }))
}

fn has_bound_mfa_proof(data: &serde_json::Map<String, serde_json::Value>, account_id: i64) -> bool {
    data.get("id_mfa_verified_user_id")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| value == account_id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn session_cookie_age_matches_django_expiry_modes() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let expires_at = now + Duration::from_secs(3600);
        let parse = |value: serde_json::Value| {
            SessionCookieExpiry::from_session_data(value.as_object()?, expires_at)
        };
        assert_eq!(parse(json!({})), Some(SessionCookieExpiry::Default));
        assert_eq!(
            parse(json!({"_session_expiry": 0})),
            Some(SessionCookieExpiry::BrowserClose)
        );
        assert_eq!(
            parse(json!({"_session_expiry": 900})),
            Some(SessionCookieExpiry::Seconds(900))
        );
        assert_eq!(
            parse(json!({"_session_expiry": "2030-01-01T00:00:00+00:00"})),
            Some(SessionCookieExpiry::At(expires_at))
        );
        assert_eq!(parse(json!({"_session_expiry": []})), None);
        assert_eq!(
            SessionCookieExpiry::Default.max_age(now, 1209600, false),
            Some(1209600)
        );
        assert_eq!(
            SessionCookieExpiry::Default.max_age(now, 1209600, true),
            None
        );
        assert_eq!(
            SessionCookieExpiry::BrowserClose.max_age(now, 1209600, false),
            None
        );
        assert_eq!(
            SessionCookieExpiry::Seconds(900).max_age(now, 1209600, false),
            Some(900)
        );
        assert_eq!(
            SessionCookieExpiry::At(expires_at).max_age(now, 1209600, false),
            Some(3600)
        );
    }

    #[test]
    fn mfa_proof_must_be_bound_to_the_authenticated_account() {
        let mut data = serde_json::Map::new();
        assert!(!has_bound_mfa_proof(&data, 42));
        data.insert("id_mfa_verified_user_id".into(), serde_json::json!(41));
        assert!(!has_bound_mfa_proof(&data, 42));
        data.insert("id_mfa_verified_user_id".into(), serde_json::json!("41"));
        assert!(!has_bound_mfa_proof(&data, 42));
        data.insert("id_mfa_verified_user_id".into(), serde_json::json!("42"));
        assert!(has_bound_mfa_proof(&data, 42));
    }
}
