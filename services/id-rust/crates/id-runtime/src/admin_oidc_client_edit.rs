//! Password-confirmed operator edits to OIDC redirect allowlists.
//! The final transaction rechecks the actor and reviewed configuration.

use crate::{
    admin_oidc_client::redirect_revision,
    session_store::{LEGACY_BACKENDS, restore_django_session_tx},
    tx_retry::retry_known_abort,
};
use anyhow::{Context, Result};
use id_compat::session::SessionCodec;
use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, SystemTime},
};
use url::Url;
use ydb::{Client, Transaction, TxMode, closure};

#[derive(Clone)]
pub struct RedirectUpdate {
    pub token: String,
    pub actor_id: i32,
    pub password_hash: String,
    pub client_id: String,
    pub expected_revision: String,
    pub redirect_uris: Vec<String>,
    pub now: SystemTime,
}

#[derive(Debug, PartialEq, Eq)]
pub enum UpdateOutcome {
    Updated { revision: String },
    Unauthorized,
    Forbidden,
    PasswordChanged,
    ClientNotFound,
    Ambiguous,
    StaleReview,
}

pub fn valid_redirects(uris: &[String]) -> bool {
    if uris.is_empty()
        || uris.len() > 100
        || uris.iter().map(String::len).sum::<usize>() > 16 * 1024
    {
        return false;
    }
    let mut unique = HashSet::with_capacity(uris.len());
    uris.iter().all(|uri| {
        if uri.is_empty()
            || uri.len() > 2048
            || uri.trim() != uri
            || uri.contains('*')
            || uri.contains('\\')
            || uri.chars().any(char::is_control)
            || !unique.insert(uri)
        {
            return false;
        }
        let Ok(url) = Url::parse(uri) else {
            return false;
        };
        if url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return false;
        }
        match url.scheme() {
            "https" => true,
            "http" => matches!(
                url.host_str(),
                Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
            ),
            _ => false,
        }
    })
}

pub async fn update(
    client: &Client,
    codec: Arc<SessionCodec>,
    input: RedirectUpdate,
) -> Result<UpdateOutcome> {
    let backends = LEGACY_BACKENDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    retry_known_abort(|| {
        let input = input.clone();
        let codec = codec.clone();
        let backends = backends.clone();
        async {
            client.query_client().retry_tx(closure!([input, codec, backends], async |tx: &mut Transaction| {
                let Some(session) = restore_django_session_tx(tx, codec.as_ref(), &input.token, backends, input.now).await? else {
                    return Ok(UpdateOutcome::Unauthorized);
                };
                if session.principal.account_id.get() != i64::from(input.actor_id) {
                    return Ok(UpdateOutcome::Unauthorized);
                }
                let Some(mut actor) = tx.query_row("SELECT password, is_staff, is_superuser FROM auth_user WHERE id = $id")
                    .param("$id", input.actor_id).optional().await? else { return Ok(UpdateOutcome::Unauthorized) };
                let current_hash: String = actor.remove_field_by_name("password")?.try_into()?;
                let staff: bool = actor.remove_field_by_name("is_staff")?.try_into()?;
                let superuser: bool = actor.remove_field_by_name("is_superuser")?.try_into()?;
                let has_mfa = tx.query_row("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $id LIMIT 1")
                    .param("$id", input.actor_id).optional().await?.is_some();
                if !staff || !superuser || !has_mfa || !session.mfa_verified {
                    return Ok(UpdateOutcome::Forbidden);
                }
                if current_hash != input.password_hash {
                    return Ok(UpdateOutcome::PasswordChanged);
                }
                let mut query = tx.query("SELECT id, CAST(redirect_uris AS Utf8) AS redirects FROM idp_oidcclient VIEW oidc_client_id_idx WHERE client_id = $id LIMIT 2")
                    .param("$id", input.client_id.clone()).await?;
                let mut found = Vec::with_capacity(2);
                while let Some(rows) = query.next_result_set().await? {
                    for mut row in rows {
                        let id: i64 = row.remove_field_by_name("id")?.try_into()?;
                        let redirects: String = row.remove_field_by_name("redirects")?.try_into()?;
                        found.push((id, redirects));
                    }
                }
                query.close().await?;
                let (client_pk, previous) = match found.len() {
                    0 => return Ok(UpdateOutcome::ClientNotFound),
                    1 => found.remove(0),
                    _ => return Ok(UpdateOutcome::Ambiguous),
                };
                let old_revision = redirect_revision(&previous);
                if old_revision != input.expected_revision {
                    return Ok(UpdateOutcome::StaleReview);
                }
                let updated = serde_json::to_string(&input.redirect_uris).map_err(ydb::YdbOrCustomerError::from_err)?;
                let new_revision = redirect_revision(&updated);
                if old_revision == new_revision {
                    return Ok(UpdateOutcome::Updated { revision: new_revision });
                }
                tx.exec("UPDATE idp_oidcclient SET redirect_uris = Unwrap(CAST($redirects AS Json)), updated_at = CAST($now AS Datetime) WHERE id = $id")
                    .param("$redirects", updated).param("$now", input.now).param("$id", client_pk).await?;
                let meta = serde_json::json!({"old_revision":old_revision,"new_revision":new_revision,"redirect_count":input.redirect_uris.len()}).to_string();
                tx.exec("INSERT INTO usid_audit_log (actor_user_id, action, target_type, target_id, tenant_id, meta_json, created_at) VALUES ($actor, 'oidc_client.redirects_updated', 'oidc_client', $target, NULL, Unwrap(CAST($meta AS Json)), CAST($now AS Datetime))")
                    .param("$actor", session.principal.identity_id.get())
                    .param("$target", input.client_id.clone()).param("$meta", meta)
                    .param("$now", input.now).await?;
                Ok(UpdateOutcome::Updated { revision: new_revision })
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
                .timeout(Duration::from_secs(30)).await
        }
    }).await.context("operator OIDC redirect update")
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn redirect_allowlist_is_exact_and_safe() {
        assert!(valid_redirects(&[
            "https://rp.example.invalid/callback?source=id".into()
        ]));
        assert!(valid_redirects(&["http://127.0.0.1:8000/callback".into()]));
        for uri in [
            "http://rp.example.invalid/callback",
            "https://rp.example.invalid/cb#frag",
            "https://user@rp.example.invalid/cb",
            "javascript:alert(1)",
            "https://rp.example.invalid/cb\n",
            "https://*.example.invalid/cb",
            "https://rp.example.invalid\\@evil.invalid/cb",
        ] {
            assert!(!valid_redirects(&[uri.into()]), "accepted {uri:?}");
        }
        assert!(!valid_redirects(&[
            "https://rp.example.invalid/cb".into(),
            "https://rp.example.invalid/cb".into()
        ]));
    }
}
