//! One-winner approval or denial of pending OIDC authorization requests.

use crate::{
    oidc_authorize::redirect_uri_with,
    oidc_client::unique_client_pk_tx,
    session_store::{LEGACY_BACKENDS, restore_django_session_tx},
    tx_retry::retry_known_abort,
};
use anyhow::Result;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use id_compat::session::SessionCodec;
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
    time::{Duration, SystemTime},
};
use ydb::{Client, Transaction, TxMode, closure};

#[derive(Clone)]
pub enum Decision {
    Approve { scopes: Option<Vec<String>> },
    Deny,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecisionOutcome {
    Redirect(String),
    Unauthorized,
    NotFound,
    Expired,
    InvalidScope,
    InvalidClient,
    ConsentChanged,
}

fn selected_scopes(
    requested: &[String],
    approved: Option<&[String]>,
    existing: Option<&[String]>,
    required: &[String],
) -> Option<Vec<String>> {
    let mut selected = match existing {
        Some(granted) => requested
            .iter()
            .filter(|scope| granted.contains(scope))
            .cloned()
            .collect(),
        None => approved.unwrap_or(requested).to_vec(),
    };
    if !selected.iter().any(|scope| scope == "openid") {
        selected.insert(0, "openid".into());
    }
    if selected.iter().any(|scope| !requested.contains(scope))
        || required.iter().any(|scope| !selected.contains(scope))
        || (existing.is_some()
            && approved.is_some_and(|scopes| {
                scopes.iter().collect::<HashSet<_>>() != selected.iter().collect::<HashSet<_>>()
            }))
    {
        return None;
    }
    let mut seen = HashSet::new();
    selected.retain(|scope| seen.insert(scope.clone()));
    Some(selected)
}

pub async fn decide(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: &str,
    request_id: &str,
    decision: Decision,
    required: &BTreeMap<String, Vec<String>>,
    now: SystemTime,
) -> Result<DecisionOutcome> {
    if request_id.is_empty() || request_id.len() > 64 || token.is_empty() || token.len() > 512 {
        return Ok(DecisionOutcome::NotFound);
    }
    let code = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let token = token.to_owned();
    let request_id = request_id.to_owned();
    let backends: Vec<String> = LEGACY_BACKENDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    retry_known_abort(|| {
        let (codec, token, request_id, decision, code, backends, required) =
            (codec.clone(), token.clone(), request_id.clone(), decision.clone(), code.clone(), backends.clone(), required.clone());
        async {
            client.query_client().retry_tx(closure!([codec, token, request_id, decision, code, backends, required], async |tx: &mut Transaction| {
                let Some(session) = restore_django_session_tx(tx, codec.as_ref(), token, backends, now).await? else {
                    return Ok(DecisionOutcome::Unauthorized);
                };
                let user_id = i32::try_from(session.principal.account_id.get()).map_err(ydb::YdbOrCustomerError::from_err)?;
                let has_mfa = tx.query_row("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $user_id LIMIT 1")
                    .param("$user_id", user_id).optional().await?.is_some();
                if has_mfa && !session.mfa_verified { return Ok(DecisionOutcome::Unauthorized) }
                let Some(mut request) = tx.query_row("SELECT user_id, client_id, redirect_uri, scope, state, nonce, code_challenge, code_challenge_method, prompt, expires_at FROM idp_oidcauthorizationrequest WHERE request_id = $id")
                    .param("$id", request_id.clone()).optional().await? else { return Ok(DecisionOutcome::NotFound) };
                let owner: i32 = request.remove_field_by_name("user_id")?.try_into()?;
                if owner != user_id { return Ok(DecisionOutcome::NotFound) }
                let client_pk: i64 = request.remove_field_by_name("client_id")?.try_into()?;
                let redirect_uri: String = request.remove_field_by_name("redirect_uri")?.try_into()?;
                let scope: String = request.remove_field_by_name("scope")?.try_into()?;
                let state: String = request.remove_field_by_name("state")?.try_into()?;
                let nonce: String = request.remove_field_by_name("nonce")?.try_into()?;
                let challenge: String = request.remove_field_by_name("code_challenge")?.try_into()?;
                let method: String = request.remove_field_by_name("code_challenge_method")?.try_into()?;
                let prompt: String = request.remove_field_by_name("prompt")?.try_into()?;
                let expiry: SystemTime = request.remove_field_by_name("expires_at")?.try_into()?;
                if expiry <= now { return Ok(DecisionOutcome::Expired) }
                let Some(mut client_row) = tx.query_row("SELECT client_id, CAST(redirect_uris AS Utf8) AS redirects, CAST(allowed_scopes AS Utf8) AS allowed FROM idp_oidcclient WHERE id = $id")
                    .param("$id", client_pk).optional().await? else { return Ok(DecisionOutcome::InvalidClient) };
                let client_id: String = client_row.remove_field_by_name("client_id")?.try_into()?;
                if !unique_client_pk_tx(tx, &client_id, client_pk).await? {
                    return Ok(DecisionOutcome::InvalidClient);
                }
                let redirects: String = client_row.remove_field_by_name("redirects")?.try_into()?;
                let redirects: Vec<String> = serde_json::from_str(&redirects).map_err(ydb::YdbOrCustomerError::from_err)?;
                if !redirects.contains(&redirect_uri) { return Ok(DecisionOutcome::InvalidClient) }
                let allowed: String = client_row.remove_field_by_name("allowed")?.try_into()?;
                let allowed: Vec<String> = serde_json::from_str(&allowed).map_err(ydb::YdbOrCustomerError::from_err)?;
                if matches!(decision, Decision::Deny) {
                    tx.exec("DELETE FROM idp_oidcauthorizationrequest WHERE request_id = $id")
                        .param("$id", request_id.clone()).await?;
                    let url = redirect_uri_with(&redirect_uri, &[("error", "access_denied"), ("state", &state)])
                        .map_err(ydb::YdbOrCustomerError::from_err)?;
                    return Ok(DecisionOutcome::Redirect(url));
                }
                let Decision::Approve { scopes: approved } = &decision else { unreachable!() };
                let existing = {
                    let mut rows = tx.query("SELECT id, client_id, CAST(scopes AS Utf8) AS scopes FROM idp_oidcconsent VIEW oidc_consent_user_idx WHERE user_id = $user_id")
                        .param("$user_id", user_id).await?;
                    let mut matched = Vec::new();
                    while let Some(set) = rows.next_result_set().await? {
                        for mut row in set {
                            let pk: i64 = row.remove_field_by_name("client_id")?.try_into()?;
                            if pk == client_pk {
                                let id: i64 = row.remove_field_by_name("id")?.try_into()?;
                                let raw: String = row.remove_field_by_name("scopes")?.try_into()?;
                                let scopes: Vec<String> = serde_json::from_str(&raw).map_err(ydb::YdbOrCustomerError::from_err)?;
                                matched.push((id, scopes));
                            }
                        }
                    }
                    rows.close().await?;
                    if matched.len() > 1 { return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("ambiguous OIDC consent"))) }
                    matched.pop()
                };
                if prompt == "confirm" && existing.is_none() {
                    return Ok(DecisionOutcome::ConsentChanged);
                }
                let requested: Vec<String> = scope.split_whitespace().map(str::to_owned).collect();
                let required = required.get(&client_id).map(Vec::as_slice).unwrap_or_default();
                let Some(final_scopes) = selected_scopes(&requested, approved.as_deref(),
                    existing.as_ref().map(|(_, scopes)| scopes.as_slice()), required) else {
                    return Ok(DecisionOutcome::InvalidScope);
                };
                if final_scopes.iter().any(|item| item != "openid" && !allowed.is_empty() && !allowed.contains(item)) {
                    return Ok(DecisionOutcome::InvalidScope);
                }
                if let Some(mut prefs) = tx.query_row("SELECT CAST(privacy_scope_defaults AS Utf8) AS defaults FROM accounts_userpreferences VIEW acct_prefs_user_idx WHERE user_id = $user_id LIMIT 1")
                    .param("$user_id", user_id).optional().await? {
                    let raw: String = prefs.remove_field_by_name("defaults")?.try_into()?;
                    let defaults: Value = serde_json::from_str(&raw).map_err(ydb::YdbOrCustomerError::from_err)?;
                    if final_scopes.iter().any(|item| item != "openid" && defaults[item] == "deny") {
                        return Ok(DecisionOutcome::InvalidScope);
                    }
                }
                // The request is the one-winner claim; its deletion and code creation commit together.
                tx.exec("DELETE FROM idp_oidcauthorizationrequest WHERE request_id = $id")
                    .param("$id", request_id.clone()).await?;
                tx.exec("INSERT INTO idp_oidcauthorizationcode (code, client_id, user_id, redirect_uri, scope, nonce, code_challenge, code_challenge_method, created_at, expires_at) VALUES ($code, $client_id, $user_id, $redirect_uri, $scope, $nonce, $challenge, $method, CAST($now AS Datetime), CAST($expires AS Datetime))")
                    .param("$code", code.clone()).param("$client_id", client_pk).param("$user_id", user_id)
                    .param("$redirect_uri", redirect_uri.clone()).param("$scope", final_scopes.join(" "))
                    .param("$nonce", nonce).param("$challenge", challenge).param("$method", method)
                    .param("$now", now).param("$expires", now + Duration::from_secs(300)).await?;
                if let Some((id, _)) = existing {
                    tx.exec("UPDATE idp_oidcconsent SET last_used_at = CAST($now AS Datetime) WHERE id = $id")
                        .param("$id", id).param("$now", now).await?;
                } else {
                    let raw = serde_json::to_string(&final_scopes).map_err(ydb::YdbOrCustomerError::from_err)?;
                    tx.exec("INSERT INTO idp_oidcconsent (user_id, client_id, scopes, created_at, updated_at, last_used_at) VALUES ($user_id, $client_id, Unwrap(CAST($scopes AS Json)), CAST($now AS Datetime), CAST($now AS Datetime), CAST($now AS Datetime))")
                        .param("$user_id", user_id).param("$client_id", client_pk).param("$scopes", raw).param("$now", now).await?;
                }
                let url = redirect_uri_with(&redirect_uri, &[("code", code), ("state", &state)])
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                Ok(DecisionOutcome::Redirect(url))
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
                .timeout(Duration::from_secs(10)).await
        }
    }).await
}

#[cfg(test)]
mod tests {
    use super::selected_scopes;

    fn scopes(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).into()).collect()
    }

    #[test]
    fn first_grant_requires_service_scopes_but_keeps_optional_choice() {
        let requested = scopes(&["openid", "email", "profile", "phone"]);
        let required = scopes(&["email", "profile"]);
        assert_eq!(
            selected_scopes(
                &requested,
                Some(&scopes(&["email", "profile"])),
                None,
                &required
            ),
            Some(scopes(&["openid", "email", "profile"]))
        );
        assert!(
            selected_scopes(
                &requested,
                Some(&scopes(&["openid", "email"])),
                None,
                &required
            )
            .is_none()
        );
        assert!(
            selected_scopes(&requested, Some(&scopes(&["openid", "address"])), None, &[]).is_none()
        );
    }

    #[test]
    fn existing_grant_cannot_be_expanded_or_reduced_by_approval() {
        let requested = scopes(&["openid", "email", "profile"]);
        let saved = scopes(&["openid", "email"]);
        assert_eq!(
            selected_scopes(&requested, None, Some(&saved), &[]),
            Some(saved.clone())
        );
        assert!(selected_scopes(&requested, Some(&requested), Some(&saved), &[]).is_none());
        assert!(
            selected_scopes(&requested, Some(&scopes(&["openid"])), Some(&saved), &[]).is_none()
        );
        assert!(selected_scopes(&requested, None, Some(&saved), &scopes(&["profile"])).is_none());
        assert_eq!(
            selected_scopes(&scopes(&["openid"]), None, Some(&saved), &[]),
            Some(scopes(&["openid"]))
        );
    }
}
