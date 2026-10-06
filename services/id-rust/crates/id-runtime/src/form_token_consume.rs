//! Single-use transition form-token validation against the shared YDB cache.

use crate::cache_store::CacheStore;
use anyhow::Result;
use id_compat::cache::CacheValue;
use std::time::{SystemTime, UNIX_EPOCH};

/// Consumes before validation, matching transition Python. A wrong purpose or
/// expired token is burned too. Ambiguous YDB outcomes are errors, never a
/// successful form validation or permission to issue credentials.
pub async fn consume_login_form_token(
    cache: &CacheStore,
    token: Option<&str>,
    now: SystemTime,
) -> Result<bool> {
    consume_form_token(cache, token, "login", now).await
}

pub async fn consume_form_token(
    cache: &CacheStore,
    token: Option<&str>,
    purpose: &str,
    now: SystemTime,
) -> Result<bool> {
    if !matches!(
        purpose,
        "login" | "register" | "password_reset" | "email_verification"
    ) {
        return Ok(false);
    }
    let Some(token) = token.filter(|token| valid_token(token)) else {
        return Ok(false);
    };
    let Some(CacheValue::Map(fields)) = cache.take(&format!("formtoken:{token}"), now).await?
    else {
        return Ok(false);
    };
    let now_seconds = i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?;
    Ok(
        fields.get("purpose") == Some(&CacheValue::String(purpose.into()))
            && matches!(fields.get("expires_at"), Some(CacheValue::Int(exp)) if *exp >= now_seconds)
            && fields.get("used") != Some(&CacheValue::Bool(true)),
    )
}

fn valid_token(token: &str) -> bool {
    token.len() == 43
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_urlsafe_32_byte_tokens_reach_storage() {
        assert!(valid_token("Abcdefghijklmnopqrstuvwxyz0123456789_-ABCDE"));
        assert!(!valid_token("short"));
        assert!(!valid_token(&"a".repeat(43).replace('a', "/")));
    }
}
