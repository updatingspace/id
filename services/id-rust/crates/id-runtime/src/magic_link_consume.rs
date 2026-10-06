//! Atomic Portal magic-link consumption and optional BFF exchange issuance.

use crate::{cache_store::CacheStore, tx_retry::retry_known_abort};
use anyhow::Result;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use id_compat::cache::CacheValue;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime},
};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use ydb::{Client, Transaction, TxMode, closure};

const SESSION_TTL: Duration = Duration::from_secs(14 * 24 * 3600);
const EXCHANGE_TTL: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct ConsumeRequest {
    pub token: String,
    pub tenant_id: Uuid,
    pub tenant_slug: String,
    pub ip: String,
    pub user_agent: String,
    pub issue_exchange: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Consumed {
    pub user_id: Uuid,
    pub session_token: String,
    pub exchange_code: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConsumeFailure {
    InvalidToken,
    NotFound,
    Used,
    Expired,
    ContextMismatch,
    InactiveIdentity,
    UnverifiedEmail,
    InvalidTenant,
    InactiveMembership,
}

pub async fn consume(
    client: &Client,
    cache: &CacheStore,
    token_secret: &[u8],
    request: ConsumeRequest,
    now: SystemTime,
) -> Result<std::result::Result<Consumed, ConsumeFailure>> {
    if token_secret.is_empty()
        || request.token.len() < 16
        || request.token.len() > 128
        || !request
            .token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || request.tenant_slug.is_empty()
        || request.tenant_slug.len() > 64
        || request.ip.len() > 256
        || request.user_agent.len() > 1024
    {
        return Ok(Err(ConsumeFailure::InvalidToken));
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(token_secret)?;
    mac.update(request.token.as_bytes());
    let token_hash = hex::encode(mac.finalize().into_bytes());
    let ip_hash = hex::encode(Sha256::digest(request.ip.as_bytes()));
    let ua_hash = hex::encode(Sha256::digest(request.user_agent.as_bytes()));
    let session_token = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let exchange_code = request
        .issue_exchange
        .then(|| URL_SAFE_NO_PAD.encode(rand::random::<[u8; 24]>()));
    retry_known_abort(|| {
        let cache = cache.clone();
        let request = request.clone();
        let token_hash = token_hash.clone();
        let ip_hash = ip_hash.clone();
        let ua_hash = ua_hash.clone();
        let session_token = session_token.clone();
        let exchange_code = exchange_code.clone();
        async move {
            client
                .query_client()
                .retry_tx(closure!([cache, request, token_hash, ip_hash, ua_hash, session_token, exchange_code], async |tx: &mut Transaction| {
                    let Some(mut token) = tx.query_row("SELECT user_id, expires_at, used_at, ip_hash, ua_hash, skip_context_validation FROM usid_magic_link_token WHERE token = $token")
                        .param("$token", token_hash.clone()).optional().await? else {
                        return Ok(Err(ConsumeFailure::NotFound));
                    };
                    let user_id: Uuid = token.remove_field_by_name("user_id")?.try_into()?;
                    let expires_at: SystemTime = token.remove_field_by_name("expires_at")?.try_into()?;
                    let used_at: Option<SystemTime> = token.remove_field_by_name("used_at")?.try_into()?;
                    let stored_ip: String = token.remove_field_by_name("ip_hash")?.try_into()?;
                    let stored_ua: String = token.remove_field_by_name("ua_hash")?.try_into()?;
                    let skip_context: bool = token.remove_field_by_name("skip_context_validation")?.try_into()?;
                    if used_at.is_some() { return Ok(Err(ConsumeFailure::Used)); }
                    if expires_at <= now { return Ok(Err(ConsumeFailure::Expired)); }
                    if !skip_context && (!hash_matches(&stored_ip, ip_hash) || !hash_matches(&stored_ua, ua_hash)) {
                        return Ok(Err(ConsumeFailure::ContextMismatch));
                    }
                    let Some(mut user) = tx.query_row("SELECT status, email_verified, system_admin FROM usid_user WHERE user_id = $user_id")
                        .param("$user_id", user_id).optional().await? else {
                        return Ok(Err(ConsumeFailure::InactiveIdentity));
                    };
                    let status: String = user.remove_field_by_name("status")?.try_into()?;
                    let verified: bool = user.remove_field_by_name("email_verified")?.try_into()?;
                    let system_admin: bool = user.remove_field_by_name("system_admin")?.try_into()?;
                    if status != "active" { return Ok(Err(ConsumeFailure::InactiveIdentity)); }
                    if !verified { return Ok(Err(ConsumeFailure::UnverifiedEmail)); }
                    let Some(mut tenant) = tx.query_row("SELECT slug FROM usid_tenant WHERE id = $id")
                        .param("$id", request.tenant_id).optional().await? else {
                        return Ok(Err(ConsumeFailure::InvalidTenant));
                    };
                    let slug: String = tenant.remove_field_by_name("slug")?.try_into()?;
                    if slug != request.tenant_slug { return Ok(Err(ConsumeFailure::InvalidTenant)); }
                    let mut count = tx.query_row("SELECT COUNT(*) AS n FROM usid_tenant_membership WHERE user_id = $user_id AND tenant_id = $tenant_id")
                        .param("$user_id", user_id).param("$tenant_id", request.tenant_id).await?;
                    let membership_count: u64 = count.remove_field_by_name("n")?.try_into()?;
                    if membership_count != 1 { return Ok(Err(ConsumeFailure::InactiveMembership)); }
                    let Some(mut membership) = tx.query_row("SELECT status FROM usid_tenant_membership WHERE user_id = $user_id AND tenant_id = $tenant_id LIMIT 1")
                        .param("$user_id", user_id).param("$tenant_id", request.tenant_id).optional().await? else {
                        return Ok(Err(ConsumeFailure::InactiveMembership));
                    };
                    let membership_status: String = membership.remove_field_by_name("status")?.try_into()?;
                    if membership_status != "active" { return Ok(Err(ConsumeFailure::InactiveMembership)); }
                    tx.exec("UPDATE usid_magic_link_token SET used_at = CAST($now AS Datetime) WHERE token = $token AND used_at IS NULL")
                        .param("$now", now).param("$token", token_hash.clone()).await?;
                    tx.exec("INSERT INTO usid_session (token, user_id, created_at, expires_at, ip_hash, ua_hash) VALUES ($token, $user_id, CAST($now AS Datetime), CAST($expires AS Datetime), $ip, $ua)")
                        .param("$token", session_token.clone()).param("$user_id", user_id)
                        .param("$now", now).param("$expires", now + SESSION_TTL)
                        .param("$ip", ip_hash.clone()).param("$ua", ua_hash.clone()).await?;
                    if let Some(code) = exchange_code.as_ref() {
                        let value = CacheValue::Map(BTreeMap::from([
                            ("user_id".into(), CacheValue::String(user_id.to_string())),
                            ("master_flags".into(), CacheValue::Map(BTreeMap::from([
                                ("email_verified".into(), CacheValue::Bool(verified)),
                                ("system_admin".into(), CacheValue::Bool(system_admin)),
                            ]))),
                            ("ttl_seconds".into(), CacheValue::Int(SESSION_TTL.as_secs() as i64)),
                        ]));
                        cache.insert_new_in_tx(tx, &format!("usid:exchange:{code}"), &value, now + EXCHANGE_TTL).await?;
                    }
                    let audit = json!({"session_expires_at":chrono::DateTime::<chrono::Utc>::from(now + SESSION_TTL).to_rfc3339()}).to_string();
                    tx.exec("INSERT INTO usid_audit_log (actor_user_id, action, target_type, target_id, tenant_id, meta_json, created_at) VALUES ($user_id, 'magic_link.consumed', 'user', $target, $tenant_id, UNWRAP(CAST($meta AS Json)), CAST($now AS Datetime))")
                        .param("$user_id", user_id).param("$target", user_id.to_string())
                        .param("$tenant_id", request.tenant_id).param("$meta", audit)
                        .param("$now", now).await?;
                    let event = json!({"user_id":user_id,"tenant_id":request.tenant_id,"tenant_slug":request.tenant_slug,"method":"magic_link"}).to_string();
                    tx.exec("INSERT INTO usid_outbox (tenant_id, event_type, payload_json, created_at, attempts, last_error) VALUES ($tenant_id, 'session.created', UNWRAP(CAST($payload AS Json)), CAST($now AS Datetime), 0, '')")
                        .param("$tenant_id", request.tenant_id).param("$payload", event)
                        .param("$now", now).await?;
                    Ok(Ok(Consumed { user_id, session_token: session_token.clone(), exchange_code: exchange_code.clone() }))
                }))
                .with_mode(TxMode::SerializableReadWrite)
                .idempotent(false)
                .timeout(Duration::from_secs(10))
                .await
        }
    }).await
}

fn hash_matches(stored: &str, current: &str) -> bool {
    stored.is_empty()
        || (stored.len() == current.len()
            && bool::from(stored.as_bytes().ct_eq(current.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_hashes_fail_closed_except_legacy_empty_hashes() {
        let hash = hex::encode(Sha256::digest(b"192.0.2.5"));
        assert!(hash_matches(&hash, &hash));
        assert!(!hash_matches(
            &hash,
            &hex::encode(Sha256::digest(b"192.0.2.6"))
        ));
        assert!(hash_matches("", &hash));
    }
}
