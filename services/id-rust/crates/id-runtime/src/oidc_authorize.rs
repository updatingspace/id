//! Local-only, remembered-consent OIDC authorization-code issuance.

use crate::{
    oidc_protocol::parse_token_body,
    session_store::{LEGACY_BACKENDS, restore_django_session_tx},
    tx_retry::retry_known_abort,
};
use anyhow::Result;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use id_compat::session::SessionCodec;
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime},
};
use url::Url;
use ydb::{Client, Transaction, TxMode, closure};

#[derive(Debug, PartialEq, Eq)]
pub enum Authorization {
    Redirect(String),
    Prepared(PreparedAuthorization),
    LoginRequired,
    ConsentRequired(String),
    InvalidClient,
    InvalidRedirect,
    InvalidRequest,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct PreparedAuthorization {
    pub request_id: String,
    pub client_id: String,
    pub client_name: String,
    pub client_logo_url: String,
    pub scopes: Vec<String>,
    pub state: String,
    pub redirect_uri: String,
}

#[derive(Clone, Copy)]
enum Mode {
    RedirectOnly,
    Prepare,
}

pub(crate) fn redirect_uri_with(
    uri: &str,
    params: &[(&str, &str)],
) -> std::result::Result<String, url::ParseError> {
    let mut url = Url::parse(uri)?;
    url.query_pairs_mut().extend_pairs(params.iter().copied());
    Ok(url.into())
}

fn requested_scopes(raw: &str) -> Option<Vec<String>> {
    let mut scopes = vec!["openid".to_owned()];
    for scope in raw.split_whitespace() {
        if !matches!(
            scope,
            "openid"
                | "email"
                | "profile"
                | "profile_basic"
                | "profile_extended"
                | "phone"
                | "address"
                | "offline_access"
        ) {
            return None;
        }
        if !scopes.iter().any(|entry| entry == scope) {
            scopes.push(scope.to_owned());
        }
    }
    Some(scopes)
}

pub async fn authorize_remembered(
    client: &Client,
    codec: Arc<SessionCodec>,
    session: Option<&str>,
    params: BTreeMap<String, String>,
    now: SystemTime,
) -> Result<Authorization> {
    authorize_request(client, codec, session, params, now, Mode::RedirectOnly).await
}

pub async fn prepare_authorization(
    client: &Client,
    codec: Arc<SessionCodec>,
    session: Option<&str>,
    params: BTreeMap<String, String>,
    now: SystemTime,
) -> Result<Authorization> {
    authorize_request(client, codec, session, params, now, Mode::Prepare).await
}

async fn authorize_request(
    client: &Client,
    codec: Arc<SessionCodec>,
    session: Option<&str>,
    params: BTreeMap<String, String>,
    now: SystemTime,
    mode: Mode,
) -> Result<Authorization> {
    let get = |name: &str| params.get(name).map(String::as_str).unwrap_or("");
    let client_id = get("client_id");
    let redirect_uri = get("redirect_uri");
    let state = get("state");
    let nonce = get("nonce");
    let challenge = get("code_challenge");
    let method = get("code_challenge_method");
    let prompt = get("prompt");
    let scope = get("scope");
    if client_id.is_empty()
        || client_id.len() > 64
        || redirect_uri.is_empty()
        || redirect_uri.len() > 4096
    {
        return Ok(Authorization::InvalidRequest);
    }
    // Reject malformed and duplicate parameters before any redirect is trusted.
    if params.len() > 32
        || params.keys().any(|key| {
            !matches!(
                key.as_str(),
                "client_id"
                    | "redirect_uri"
                    | "response_type"
                    | "scope"
                    | "state"
                    | "nonce"
                    | "code_challenge"
                    | "code_challenge_method"
                    | "prompt"
                    | "response_mode"
            )
        })
    {
        return Ok(Authorization::InvalidRequest);
    }
    if state.len() > 256
        || nonce.len() > 256
        || scope.len() > 2048
        || prompt.len() > 32
        || get("response_type") != "code"
        || !matches!(get("response_mode"), "" | "query")
        || !matches!(prompt, "" | "none" | "consent")
        || (!challenge.is_empty()
            && (method != "S256"
                || challenge.len() != 43
                || !challenge
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))))
        || (challenge.is_empty() && !method.is_empty())
    {
        return Ok(Authorization::InvalidRequest);
    }
    let Some(scopes) = requested_scopes(scope) else {
        return Ok(Authorization::InvalidRequest);
    };
    let code = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let request_id = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 24]>());
    let session = session.map(str::to_owned);
    let client_id = client_id.to_owned();
    let redirect_uri = redirect_uri.to_owned();
    let state = state.to_owned();
    let nonce = nonce.to_owned();
    let challenge = challenge.to_owned();
    let method = method.to_owned();
    let prompt = prompt.to_owned();
    let backends: Vec<String> = LEGACY_BACKENDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    retry_known_abort(|| {
        let (session, codec, scopes, code, request_id, client_id, redirect_uri, state, nonce, challenge, method, prompt, backends) =
            (session.clone(), codec.clone(), scopes.clone(), code.clone(), request_id.clone(), client_id.clone(), redirect_uri.clone(), state.clone(), nonce.clone(), challenge.clone(), method.clone(), prompt.clone(), backends.clone());
        async {
            client.query_client().retry_tx(closure!([session, codec, scopes, code, request_id, client_id, redirect_uri, state, nonce, challenge, method, prompt, backends, mode], async |tx: &mut Transaction| {
                let mut clients = tx.query("SELECT id, name, logo_url, CAST(redirect_uris AS Utf8) AS redirects, CAST(allowed_scopes AS Utf8) AS allowed, CAST(response_types AS Utf8) AS responses, CAST(grant_types AS Utf8) AS grants, is_public FROM idp_oidcclient VIEW oidc_client_id_idx WHERE client_id = $client_id LIMIT 2")
                    .param("$client_id", client_id.clone()).await?;
                let mut rows = Vec::with_capacity(2);
                while let Some(set) = clients.next_result_set().await? { rows.extend(set); }
                clients.close().await?;
                if rows.len() != 1 { return Ok(Authorization::InvalidClient) }
                let mut row = rows.remove(0);
                let client_pk: i64 = row.remove_field_by_name("id")?.try_into()?;
                let client_name: String = row.remove_field_by_name("name")?.try_into()?;
                let client_logo_url: String = row.remove_field_by_name("logo_url")?.try_into()?;
                let redirects: String = row.remove_field_by_name("redirects")?.try_into()?;
                let redirects: Vec<String> = serde_json::from_str(&redirects).map_err(ydb::YdbOrCustomerError::from_err)?;
                if !redirects.iter().any(|uri| uri == redirect_uri.as_str()) { return Ok(Authorization::InvalidRedirect) }
                let allowed: String = row.remove_field_by_name("allowed")?.try_into()?;
                let allowed: Vec<String> = serde_json::from_str(&allowed).map_err(ydb::YdbOrCustomerError::from_err)?;
                let responses: String = row.remove_field_by_name("responses")?.try_into()?;
                let responses: Vec<String> = serde_json::from_str(&responses).map_err(ydb::YdbOrCustomerError::from_err)?;
                let grants: String = row.remove_field_by_name("grants")?.try_into()?;
                let grants: Vec<String> = serde_json::from_str(&grants).map_err(ydb::YdbOrCustomerError::from_err)?;
                let is_public: bool = row.remove_field_by_name("is_public")?.try_into()?;
                if (!responses.is_empty() && !responses.iter().any(|value| value == "code")) ||
                    (!grants.is_empty() && !grants.iter().any(|value| value == "authorization_code")) ||
                    (is_public && challenge.is_empty()) ||
                    scopes.iter().any(|scope| scope != "openid" && !allowed.is_empty() && !allowed.contains(scope)) {
                    return Ok(Authorization::InvalidRequest);
                }
                let Some(token) = session.as_deref() else { return Ok(Authorization::LoginRequired) };
                let Some(restored) = restore_django_session_tx(tx, codec.as_ref(), token, backends, now).await? else {
                    return Ok(Authorization::LoginRequired);
                };
                let user_id = i32::try_from(restored.principal.account_id.get()).map_err(ydb::YdbOrCustomerError::from_err)?;
                let has_mfa = tx.query_row("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $user_id LIMIT 1")
                    .param("$user_id", user_id).optional().await?.is_some();
                if has_mfa && !restored.mfa_verified { return Ok(Authorization::LoginRequired) }
                let mut scopes = scopes.to_vec();
                if let Some(mut prefs) = tx.query_row("SELECT CAST(privacy_scope_defaults AS Utf8) AS defaults FROM accounts_userpreferences VIEW acct_prefs_user_idx WHERE user_id = $user_id LIMIT 1")
                    .param("$user_id", user_id).optional().await? {
                    let raw: String = prefs.remove_field_by_name("defaults")?.try_into()?;
                    let defaults: Value = serde_json::from_str(&raw).map_err(ydb::YdbOrCustomerError::from_err)?;
                    scopes.retain(|scope| scope == "openid" || defaults[scope] != "deny");
                }
                let mut consents = tx.query("SELECT client_id, CAST(scopes AS Utf8) AS scopes FROM idp_oidcconsent VIEW oidc_consent_user_idx WHERE user_id = $user_id")
                    .param("$user_id", user_id).await?;
                let mut matched = Vec::new();
                while let Some(rows) = consents.next_result_set().await? {
                    for mut consent in rows {
                        let pk: i64 = consent.remove_field_by_name("client_id")?.try_into()?;
                        if pk == client_pk {
                            let raw: String = consent.remove_field_by_name("scopes")?.try_into()?;
                            let granted: Vec<String> = serde_json::from_str(&raw).map_err(ydb::YdbOrCustomerError::from_err)?;
                            matched.push(granted);
                        }
                    }
                }
                consents.close().await?;
                if matched.len() > 1 { return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("ambiguous OIDC consent"))) }
                let grant_ok = prompt != "consent" && matched.first().is_some_and(|granted| scopes.iter().all(|scope| granted.contains(scope)));
                if !grant_ok {
                    if matches!(mode, Mode::Prepare) && prompt != "none" {
                        tx.exec("INSERT INTO idp_oidcauthorizationrequest (request_id, client_id, user_id, redirect_uri, scope, state, nonce, code_challenge, code_challenge_method, prompt, created_at, expires_at) VALUES ($request_id, $client_id, $user_id, $redirect_uri, $scope, $state, $nonce, $challenge, $method, $prompt, CAST($now AS Datetime), CAST($expires AS Datetime))")
                            .param("$request_id", request_id.clone()).param("$client_id", client_pk).param("$user_id", user_id)
                            .param("$redirect_uri", redirect_uri.clone()).param("$scope", scopes.join(" "))
                            .param("$state", state.clone()).param("$nonce", nonce.clone())
                            .param("$challenge", challenge.clone()).param("$method", method.clone())
                            .param("$prompt", prompt.clone()).param("$now", now)
                            .param("$expires", now + Duration::from_secs(600)).await?;
                        return Ok(Authorization::Prepared(PreparedAuthorization {
                            request_id: request_id.clone(), client_id: client_id.clone(), client_name,
                            client_logo_url, scopes, state: state.clone(), redirect_uri: redirect_uri.clone(),
                        }));
                    }
                    let uri = redirect_uri_with(redirect_uri, &[("error", "consent_required"), ("state", state)])
                        .map_err(ydb::YdbOrCustomerError::from_err)?;
                    return Ok(Authorization::ConsentRequired(uri));
                }
                tx.exec("INSERT INTO idp_oidcauthorizationcode (code, client_id, user_id, redirect_uri, scope, nonce, code_challenge, code_challenge_method, created_at, expires_at) VALUES ($code, $client_id, $user_id, $redirect_uri, $scope, $nonce, $challenge, $method, CAST($now AS Datetime), CAST($expires AS Datetime))")
                    .param("$code", code.clone()).param("$client_id", client_pk).param("$user_id", user_id)
                    .param("$redirect_uri", redirect_uri.clone()).param("$scope", scopes.join(" "))
                    .param("$nonce", nonce.clone()).param("$challenge", challenge.clone()).param("$method", method.clone())
                    .param("$now", now).param("$expires", now + Duration::from_secs(300)).await?;
                let uri = redirect_uri_with(redirect_uri, &[("code", code), ("state", state)])
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                Ok(Authorization::Redirect(uri))
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
                .timeout(Duration::from_secs(10)).await
        }
    }).await
}

pub fn parse_authorization_query(raw: &str) -> Option<BTreeMap<String, String>> {
    parse_token_body("application/x-www-form-urlencoded", raw.as_bytes()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_duplicate_query_and_scope_escalation() {
        assert!(parse_authorization_query("client_id=a&client_id=b").is_none());
        assert!(requested_scopes("openid unknown").is_none());
        assert_eq!(
            requested_scopes("email email"),
            Some(vec!["openid".into(), "email".into()])
        );
        assert_eq!(
            requested_scopes("profile_extended phone address"),
            Some(vec![
                "openid".into(),
                "profile_extended".into(),
                "phone".into(),
                "address".into(),
            ])
        );
    }
    #[test]
    fn redirect_retains_query_and_fragment() -> Result<()> {
        assert_eq!(
            redirect_uri_with("https://rp.example/cb?old=1#part", &[("state", "a+b")])?,
            "https://rp.example/cb?old=1&state=a%2Bb#part"
        );
        Ok(())
    }
}
