#![recursion_limit = "256"]
//! Infrastructure pilot with an opt-in `/auth/me` compatibility route.
pub mod account_deletion;
#[cfg(feature = "passkeys")]
pub mod account_deletion_audit;
#[cfg(feature = "passkeys")]
pub mod account_deletion_cleanup;
#[cfg(feature = "passkeys")]
pub mod account_deletion_finalize;
pub mod account_deletion_http;
pub mod account_jwt_http;
pub mod account_jwt_refresh;
pub mod account_jwt_session;
pub mod admin_http;
pub mod admin_oidc_client;
pub mod admin_oidc_client_edit;
mod admin_suspend;
pub mod authorized_apps_http;
pub mod authorized_apps_store;
pub mod avatar_delete;
pub mod avatar_delete_http;
pub mod avatar_upload;
pub mod cache_store;
pub mod consent_store;
pub mod data_export;
pub mod data_export_escrow;
pub mod data_export_http;
pub mod data_export_job;
pub mod data_export_mail;
pub mod data_export_operation;
pub mod data_export_s3;
pub mod email_cancel;
pub mod email_cancel_http;
pub mod email_change;
pub mod email_lookup_reconcile;
pub mod email_status;
pub mod email_verify;
pub mod email_verify_http;
pub mod exchange_http;
pub mod form_token_consume;
pub mod form_token_http;
pub mod gravatar_job;
pub mod identity_reconcile;
pub mod ids;
pub mod internal_identity_http;
pub mod jobs_http;
pub mod legacy_cutover_reset;
#[cfg(feature = "passkeys")]
pub mod legacy_passkey;
pub mod legacy_schema;
pub(crate) mod login_activity;
pub mod login_credential_audit;
pub mod login_email_audit;
pub mod login_history;
pub mod login_http;
pub mod login_preflight;
pub mod login_rate_limit;
pub mod logout_http;
pub mod logout_store;
pub mod magic_link_consume;
pub mod magic_link_http;
pub mod magic_link_request;
pub mod me_http;
pub mod me_store;
pub mod media_delete;
pub mod media_url;
pub mod mfa_secret;
pub mod migration_ledger;
pub mod new_device_mail;
pub mod oauth_providers_http;
pub mod oidc_authorize;
pub mod oidc_authorize_http;
mod oidc_client;
pub mod oidc_client_operator;
pub mod oidc_code_exchange;
pub mod oidc_consent;
pub mod oidc_discovery;
pub mod oidc_id_claims;
pub mod oidc_jwks_http;
pub mod oidc_keys;
pub mod oidc_protocol;
pub mod oidc_refresh;
pub mod oidc_revoke;
pub mod oidc_token_http;
pub mod oidc_userinfo;
#[cfg(feature = "passkeys")]
pub mod passkey_audit;
#[cfg(feature = "passkeys")]
pub mod passkey_index;
#[cfg(feature = "passkeys")]
pub mod passkey_login;
pub mod passkey_management;
#[cfg(feature = "passkeys")]
pub mod passkey_registration;
pub mod password_change;
pub mod password_change_http;
pub mod password_mail;
pub mod password_policy;
pub mod password_reset;
pub mod password_reset_http;
pub mod preferences_domain;
pub mod preferences_http;
pub mod preferences_store;
pub mod profile_http;
pub mod profile_response;
pub mod profile_store;
pub mod profile_update;
pub mod provider_login;
pub mod recovery_rotation;
pub mod security_http;
pub mod security_mail;
pub mod security_read;
pub mod session_audit;
pub mod session_issuer;
pub mod session_revoke;
pub mod session_store;
pub mod sessions_http;
pub mod sessions_store;
pub mod signup;
pub mod signup_http;
mod steam_openid;
pub mod token_cleanup;
pub mod totp_setup;
pub mod totp_setup_http;
pub(crate) mod tx_retry;
pub mod ymq;
use anyhow::{Context, Result, bail};
use std::{env, time::Duration};
use ydb::{
    AccessTokenCredentials, AnonymousCredentials, Client, ClientBuilder, HasGrpcOptions,
    MetadataUrlCredentials, SessionPoolSettings,
};

/// Finish in-flight HTTP requests when the process is asked to stop.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

pub async fn connect_ydb() -> Result<Client> {
    let endpoint = env::var("YDB_ENDPOINT").context("YDB_ENDPOINT is required")?;
    let database = env::var("YDB_DATABASE").context("YDB_DATABASE is required")?;
    validate_endpoint(&endpoint, &database)?;
    let mut builder =
        ClientBuilder::new_from_connection_string(endpoint.clone())?.with_database(database);
    match env::var("YDB_CREDENTIALS_MODE").as_deref() {
        Ok("anonymous") => {
            if !is_loopback(&endpoint)? {
                bail!("anonymous credentials require a loopback endpoint");
            }
            builder = builder.with_credentials(AnonymousCredentials::new());
        }
        Ok("token") => {
            if !endpoint.starts_with("grpcs://") && !is_loopback(&endpoint)? {
                bail!("token credentials require TLS outside loopback");
            }
            let token = env::var("YDB_TOKEN").context("YDB_TOKEN is required")?;
            if token.is_empty() {
                bail!("YDB_TOKEN must not be empty");
            }
            builder = builder.with_credentials(AccessTokenCredentials::from(token));
        }
        Ok("metadata") => {
            if !endpoint.starts_with("grpcs://") {
                bail!("metadata credentials require TLS");
            }
            builder = builder.with_credentials(MetadataUrlCredentials::new());
        }
        _ => bail!("YDB_CREDENTIALS_MODE must be explicitly anonymous, token or metadata"),
    }
    if let Ok(path) = env::var("YDB_CA_FILE") {
        builder = builder.load_certificate(path)?;
    }
    // Bound discovery/connection too, not just subsequent query execution.
    tokio::time::timeout(Duration::from_secs(15), async {
        let client = builder.build().await?;
        // The SDK applies this separately to CreateSession and AttachSession.
        // Keep the default zero warm-up so idle containers create no sessions.
        client
            .with_session_pool(
                SessionPoolSettings::default().with_session_create_timeout(Duration::from_secs(2)),
            )
            .await
    })
    .await
    .context("YDB connection timed out")?
    .context("YDB connection failed")
}

pub fn validate_endpoint(endpoint: &str, database: &str) -> Result<()> {
    let url = url::Url::parse(endpoint).context("invalid YDB endpoint")?;
    if !matches!(url.scheme(), "grpc" | "grpcs")
        || url.host_str().is_none()
        || url.port().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
        || !database.starts_with('/')
        || database.len() < 2
    {
        bail!("YDB endpoint must be grpc(s)://host:port and database an absolute path");
    }
    Ok(())
}

fn is_loopback(endpoint: &str) -> Result<bool> {
    let url = url::Url::parse(endpoint)?;
    Ok(matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]")
    ))
}

pub async fn probe(client: &Client) -> Result<()> {
    let mut row = client
        .query_client()
        .query_row("SELECT 1 AS probe")
        .timeout(Duration::from_secs(5))
        .await?;
    let value: i64 = row.remove_field_by_name("probe")?.try_into()?;
    if value != 1 {
        bail!("unexpected YDB probe result");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_incomplete_or_embedded_credential_endpoints() {
        for endpoint in [
            "localhost",
            "http://localhost:2136",
            "grpc://localhost",
            "grpc://u:p@localhost:2136",
            "grpc://localhost:2136/local",
            "grpc://localhost:2136?database=other",
        ] {
            assert!(validate_endpoint(endpoint, "/local").is_err(), "{endpoint}");
        }
        assert!(validate_endpoint("grpc://localhost:2136", "/local").is_ok());
        assert!(validate_endpoint("grpcs://example.com:2135", "local").is_err());
    }
}

pub(crate) mod credential_methods;
