//! The transition Python and Rust login paths spend the same YDB budgets.

use crate::cache_store::{CacheStore, WindowCounter};
use anyhow::Result;
use std::time::SystemTime;

const LOGIN_ACCOUNT_LIMIT: i64 = 5;
const LOGIN_WINDOW_SECONDS: u64 = 300;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoginRateDecision {
    pub blocked: bool,
    pub retry_after_seconds: u64,
}

pub async fn login_attempt(
    cache: &CacheStore,
    ip: Option<&str>,
    email: Option<&str>,
    ip_limit: i64,
    now: SystemTime,
) -> Result<LoginRateDecision> {
    if ip_limit < 1 {
        anyhow::bail!("login IP limit must be positive");
    }
    let mut budgets = Vec::with_capacity(2);
    if let Some(ip) = ip.filter(|value| !value.is_empty()) {
        budgets.push((format!("ip:{ip}"), ip_limit));
    }
    if let Some(email) = email.filter(|value| !value.is_empty()) {
        budgets.push((
            format!("email:{}", email.trim().to_lowercase()),
            LOGIN_ACCOUNT_LIMIT,
        ));
    }
    if budgets.is_empty() {
        budgets.push(("unknown".into(), LOGIN_ACCOUNT_LIMIT));
    }
    let now_seconds = i64::try_from(now.duration_since(SystemTime::UNIX_EPOCH)?.as_secs())?;
    let mut retry_after_seconds = 0;
    let mut blocked = false;
    for (identifier, limit) in budgets {
        let key = format!("rl:login:{}", identifier.replace(' ', "_"));
        let WindowCounter { count, reset_at } = cache
            .advance_window(&key, LOGIN_WINDOW_SECONDS, now)
            .await?;
        if count > limit {
            blocked = true;
            retry_after_seconds =
                retry_after_seconds.max(u64::try_from((reset_at - now_seconds).max(0))?);
        }
    }
    Ok(LoginRateDecision {
        blocked,
        retry_after_seconds,
    })
}

/// A verified login clears only its own email budget. The shared IP budget
/// continues to count successful requests, as in transition Python.
pub async fn reset_verified_email(cache: &CacheStore, email: &str) -> Result<()> {
    if !email.is_empty() {
        let identifier = format!("email:{}", email.trim().to_lowercase());
        let key = format!("rl:login:{}", identifier.replace(' ', "_"));
        cache.delete(&key).await?;
    }
    Ok(())
}
