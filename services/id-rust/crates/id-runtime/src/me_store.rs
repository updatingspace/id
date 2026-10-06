//! Consistent session authorization and profile read for the future `/auth/me`.

use crate::{
    profile_store::{ProfileDetails, finish_profile_rows, read_profile_details_tx},
    session_store::{Principal, SessionCookieExpiry, restore_django_session_tx},
};
use anyhow::{Context, Result, ensure};
use id_compat::session::SessionCodec;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use ydb::{Client, Transaction, TxMode, closure};

#[derive(Debug, PartialEq, Eq)]
pub struct AuthenticatedProfile {
    pub principal: Principal,
    pub cookie_expiry: SessionCookieExpiry,
    pub details: ProfileDetails,
}

/// A missing, expired or revoked credential returns `None`; database failures
/// and ambiguous profile ownership return an error. All reads share one
/// serializable transaction so access checks and returned data agree.
pub async fn restore_django_profile(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: &str,
    allowed_backends: &[&str],
    now: SystemTime,
) -> Result<Option<AuthenticatedProfile>> {
    let token = token.to_owned();
    let allowed_backends: Vec<String> = allowed_backends
        .iter()
        .map(|backend| (*backend).to_owned())
        .collect();
    let result = client
        .query_client()
        .retry_tx(closure!(
            [token, codec, allowed_backends],
            async |tx: &mut Transaction| {
                let Some(session) = restore_django_session_tx(
                    tx,
                    codec.as_ref(),
                    token.as_str(),
                    allowed_backends.as_slice(),
                    now,
                )
                .await?
                else {
                    return Ok(None);
                };
                // The session codec accepts only an Int32 Django user ID.
                let user_id = i32::try_from(session.principal.account_id.get())
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                let rows = read_profile_details_tx(tx, user_id).await?;
                Ok(Some((session, rows)))
            }
        ))
        .isolation(TxMode::SerializableReadWrite)
        .timeout(Duration::from_secs(5))
        .await
        .context("restore legacy authenticated profile")?;
    let Some((session, rows)) = result else {
        return Ok(None);
    };
    let details = finish_profile_rows(rows)?;
    ensure!(
        details
            .account
            .as_ref()
            .is_some_and(|account| account.is_active),
        "authorized account missing or inactive in profile snapshot"
    );
    if details.has_mfa && !session.mfa_verified {
        return Ok(None);
    }
    Ok(Some(AuthenticatedProfile {
        principal: session.principal,
        cookie_expiry: session.cookie_expiry,
        details,
    }))
}
