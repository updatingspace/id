//! Account-owned OAuth application inventory and revocation on the transition schema.

use crate::{
    session_store::{LEGACY_BACKENDS, restore_django_session_tx},
    tx_retry::retry_known_abort,
};
use anyhow::Result;
use chrono::{DateTime, SecondsFormat, Utc};
use id_compat::session::SessionCodec;
use serde::Serialize;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use ydb::{Client, Transaction, TxMode, closure};

#[derive(Debug, Clone, Serialize)]
pub struct AuthorizedApp {
    pub client_id: String,
    pub name: String,
    pub logo_url: Option<String>,
    pub scopes: Vec<String>,
    pub last_used_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone)]
struct Consent {
    id: i64,
    client_pk: i64,
    scopes: Vec<String>,
    created_at: SystemTime,
    last_used_at: Option<SystemTime>,
}

pub enum AppsOperation {
    List,
    Revoke(String),
}

pub enum AppsResult {
    Listed(Vec<AuthorizedApp>),
    Revoked(bool),
}

pub async fn account_apps(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: &str,
    operation: AppsOperation,
    now: SystemTime,
) -> Result<Option<AppsResult>> {
    let token = token.to_owned();
    let backends: Vec<String> = LEGACY_BACKENDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    retry_known_abort(|| {
        let token = token.clone();
        let codec = codec.clone();
        let backends = backends.clone();
        let operation = match &operation {
            AppsOperation::List => AppsOperation::List,
            AppsOperation::Revoke(id) => AppsOperation::Revoke(id.clone()),
        };
        async {
            client.query_client().retry_tx(closure!([token, codec, backends, operation], async |tx: &mut Transaction| {
                let Some(session) = restore_django_session_tx(tx, codec.as_ref(), token, backends, now).await? else {
                    return Ok(None);
                };
                let user_id = i32::try_from(session.principal.account_id.get())
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                let has_mfa = tx.query_row("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $user_id LIMIT 1")
                    .param("$user_id", user_id).optional().await?.is_some();
                if has_mfa && !session.mfa_verified { return Ok(None); }

                let consents = read_consents(tx, user_id).await?;
                let mut apps = Vec::with_capacity(consents.len());
                let mut selected = None;
                for consent in consents {
                    let Some(mut client_row) = tx.query_row("SELECT client_id, name, logo_url FROM idp_oidcclient WHERE id = $id")
                        .param("$id", consent.client_pk).optional().await? else {
                            return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("orphan OAuth consent")));
                        };
                    let client_id: String = client_row.remove_field_by_name("client_id")?.try_into()?;
                    if let AppsOperation::Revoke(requested) = &operation
                        && requested == &client_id
                    {
                        selected = Some(consent.clone());
                    }
                    let logo: String = client_row.remove_field_by_name("logo_url")?.try_into()?;
                    apps.push(AuthorizedApp {
                        client_id,
                        name: client_row.remove_field_by_name("name")?.try_into()?,
                        logo_url: if logo.is_empty() { None } else { Some(logo) },
                        scopes: consent.scopes,
                        last_used_at: consent.last_used_at.map(format_time),
                        created_at: format_time(consent.created_at),
                    });
                }
                match operation {
                    AppsOperation::List => {
                        apps.sort_by(|a, b| b.last_used_at.cmp(&a.last_used_at).then_with(|| a.client_id.cmp(&b.client_id)));
                        Ok(Some(AppsResult::Listed(apps)))
                    }
                    AppsOperation::Revoke(_) => {
                        let Some(consent) = selected else { return Ok(Some(AppsResult::Revoked(false))); };
                        revoke_pending_requests(tx, user_id, consent.client_pk).await?;
                        revoke_pending_codes(tx, user_id, consent.client_pk).await?;
                        revoke_tokens(tx, user_id, consent.client_pk, now).await?;
                        tx.exec("DELETE FROM idp_oidcconsent WHERE id = $id")
                            .param("$id", consent.id).await?;
                        let meta = serde_json::json!({"client_pk":consent.client_pk,"source":"account"}).to_string();
                        tx.exec("INSERT INTO accounts_accountevent (user_id, action, meta, created_at) VALUES ($user_id, 'oauth_app_revoked', Unwrap(CAST($meta AS Json)), CAST($now AS Datetime))")
                            .param("$user_id", user_id).param("$meta", meta).param("$now", now).await?;
                        Ok(Some(AppsResult::Revoked(true)))
                    }
                }
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
                .timeout(Duration::from_secs(10)).await
        }
    }).await
}

async fn read_consents(
    tx: &mut Transaction,
    user_id: i32,
) -> ydb::YdbResultWithCustomerErr<Vec<Consent>> {
    let mut stream = tx.query("SELECT id, client_id, CAST(scopes AS Utf8) AS scopes, created_at, last_used_at FROM idp_oidcconsent VIEW oidc_consent_user_idx WHERE user_id = $user_id")
        .param("$user_id", user_id).await?;
    let mut result = Vec::new();
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            let scopes_raw: String = row.remove_field_by_name("scopes")?.try_into()?;
            let scopes: Vec<String> =
                serde_json::from_str(&scopes_raw).map_err(ydb::YdbOrCustomerError::from_err)?;
            result.push(Consent {
                id: row.remove_field_by_name("id")?.try_into()?,
                client_pk: row.remove_field_by_name("client_id")?.try_into()?,
                scopes,
                created_at: row.remove_field_by_name("created_at")?.try_into()?,
                last_used_at: row.remove_field_by_name("last_used_at")?.try_into()?,
            });
        }
    }
    stream.close().await?;
    Ok(result)
}

async fn revoke_tokens(
    tx: &mut Transaction,
    user_id: i32,
    client_pk: i64,
    now: SystemTime,
) -> ydb::YdbResultWithCustomerErr<()> {
    let mut stream = tx.query("SELECT id FROM idp_oidctoken VIEW oidc_token_user_client_idx WHERE user_id = $user_id AND client_id = $client_id")
        .param("$user_id", user_id).param("$client_id", client_pk).await?;
    let mut ids: Vec<i64> = Vec::new();
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            ids.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    stream.close().await?;
    for id in ids {
        tx.exec("UPDATE idp_oidctoken SET revoked_at = CAST($now AS Datetime) WHERE id = $id AND revoked_at IS NULL")
            .param("$now", now).param("$id", id).await?;
    }
    Ok(())
}

async fn revoke_pending_codes(
    tx: &mut Transaction,
    user_id: i32,
    client_pk: i64,
) -> ydb::YdbResultWithCustomerErr<()> {
    let mut stream = tx.query("SELECT code FROM idp_oidcauthorizationcode VIEW oidc_code_user_idx WHERE user_id = $user_id AND client_id = $client_id")
        .param("$user_id", user_id).param("$client_id", client_pk).await?;
    let mut codes: Vec<String> = Vec::new();
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            codes.push(row.remove_field_by_name("code")?.try_into()?);
        }
    }
    stream.close().await?;
    for code in codes {
        tx.exec("DELETE FROM idp_oidcauthorizationcode WHERE code = $code")
            .param("$code", code)
            .await?;
    }
    Ok(())
}

async fn revoke_pending_requests(
    tx: &mut Transaction,
    user_id: i32,
    client_pk: i64,
) -> ydb::YdbResultWithCustomerErr<()> {
    let mut stream = tx.query("SELECT request_id FROM idp_oidcauthorizationrequest VIEW oidc_req_user_idx WHERE user_id = $user_id AND client_id = $client_id")
        .param("$user_id", user_id).param("$client_id", client_pk).await?;
    let mut ids: Vec<String> = Vec::new();
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            ids.push(row.remove_field_by_name("request_id")?.try_into()?);
        }
    }
    stream.close().await?;
    for id in ids {
        tx.exec("DELETE FROM idp_oidcauthorizationrequest WHERE request_id = $id")
            .param("$id", id)
            .await?;
    }
    Ok(())
}

fn format_time(value: SystemTime) -> String {
    DateTime::<Utc>::from(value).to_rfc3339_opts(SecondsFormat::Secs, true)
}
