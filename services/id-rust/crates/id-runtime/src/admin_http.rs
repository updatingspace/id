//! Read-only operator lookup. The web UI does not query YDB or decide roles.

use crate::{
    account_deletion,
    logout_http::cookie_value,
    me_http::env_flag,
    me_store::restore_django_profile,
    session_store::{LEGACY_BACKENDS, session_codec_from_env},
};
use anyhow::{Context, Result, ensure};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use id_compat::{headers::session_token, session::SessionCodec};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    env,
    sync::Arc,
    time::{Duration, SystemTime},
};
use ydb::{Client, Transaction, TxMode, closure};

pub struct AdminReadConfig {
    client: Arc<Client>,
    codec: Arc<SessionCodec>,
    session_cookie_name: String,
}

#[derive(Serialize)]
struct AccountSnapshot {
    id: i32,
    email: String,
    is_active: bool,
    is_staff: bool,
    is_superuser: bool,
    has_mfa: bool,
    identity_id: Option<uuid::Uuid>,
    public_subject: Option<String>,
}

impl AdminReadConfig {
    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        if !env_flag("ID_AUTH_ADMIN_READ_ENABLED", false)? {
            return Ok(None);
        }
        let name = env::var("SESSION_COOKIE_NAME").unwrap_or_else(|_| "sessionid".into());
        ensure!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
            "invalid admin session cookie name"
        );
        Ok(Some(Arc::new(Self {
            client,
            codec: session_codec_from_env()?,
            session_cookie_name: name,
        })))
    }
}

pub fn router(config: Arc<AdminReadConfig>) -> Router {
    Router::new()
        .route("/api/v1/auth/admin/me", get(operator_session))
        .route("/api/v1/auth/admin/accounts/{id}", get(account_status))
        .route("/api/v1/auth/admin/deletions/{id}", get(deletion_status))
        .with_state(config)
}

async fn operator_session(
    State(config): State<Arc<AdminReadConfig>>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authorize(&config, &headers).await {
        return *response;
    }
    json_response(StatusCode::OK, json!({"operator": true}))
}

async fn deletion_status(
    State(config): State<Arc<AdminReadConfig>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authorize(&config, &headers).await {
        return *response;
    }
    let Ok(id) = id.parse::<i64>() else {
        return error(StatusCode::BAD_REQUEST, "INVALID_OPERATION_ID");
    };
    if id <= 0 {
        return error(StatusCode::BAD_REQUEST, "INVALID_OPERATION_ID");
    }
    match account_deletion::read_status(&config.client, id).await {
        Ok(Some(operation)) => json_response(StatusCode::OK, json!({"operation": operation})),
        Ok(None) => error(StatusCode::NOT_FOUND, "OPERATION_NOT_FOUND"),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "OPERATION_UNAVAILABLE"),
    }
}

async fn account_status(
    State(config): State<Arc<AdminReadConfig>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authorize(&config, &headers).await {
        return *response;
    }
    let Ok(id) = id.parse::<i32>() else {
        return error(StatusCode::BAD_REQUEST, "INVALID_ACCOUNT_ID");
    };
    if id <= 0 {
        return error(StatusCode::BAD_REQUEST, "INVALID_ACCOUNT_ID");
    }
    match read_account(&config.client, id).await {
        Ok(Some(account)) => json_response(StatusCode::OK, json!({"account": account})),
        Ok(None) => error(StatusCode::NOT_FOUND, "ACCOUNT_NOT_FOUND"),
        Err(err) => {
            tracing::error!(error = %err, "operator account lookup failed");
            error(StatusCode::SERVICE_UNAVAILABLE, "ACCOUNT_UNAVAILABLE")
        }
    }
}

async fn read_account(client: &Client, id: i32) -> Result<Option<AccountSnapshot>> {
    client.query_client()
        .retry_tx(closure!([id], async |tx: &mut Transaction| {
            let Some(mut account) = tx.query_row("SELECT email, is_active, is_staff, is_superuser FROM auth_user WHERE id = $id")
                .param("$id", *id).optional().await? else { return Ok(None) };
            let email: String = account.remove_field_by_name("email")?.try_into()?;
            let active: bool = account.remove_field_by_name("is_active")?.try_into()?;
            let staff: bool = account.remove_field_by_name("is_staff")?.try_into()?;
            let superuser: bool = account.remove_field_by_name("is_superuser")?.try_into()?;
            let binding = tx.query_row("SELECT identity_id, public_subject FROM accounts_accountidentity WHERE user_id = $id")
                .param("$id", *id).optional().await?;
            let (identity_id, public_subject) = if let Some(mut binding) = binding {
                let identity_id: Option<uuid::Uuid> = binding.remove_field_by_name("identity_id")?.try_into()?;
                let public_subject: String = binding.remove_field_by_name("public_subject")?.try_into()?;
                (identity_id, Some(public_subject))
            } else { (None, None) };
            let has_mfa = tx.query_row("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $id LIMIT 1")
                .param("$id", *id).optional().await?.is_some();
            Ok(Some(AccountSnapshot {
                id: *id,
                email,
                is_active: active,
                is_staff: staff,
                is_superuser: superuser,
                has_mfa,
                identity_id,
                public_subject,
            }))
        }))
        .isolation(TxMode::SnapshotReadOnly)
        .timeout(Duration::from_secs(5))
        .await
        .context("read operator account snapshot")
}

async fn authorize(
    config: &AdminReadConfig,
    headers: &HeaderMap,
) -> std::result::Result<(), Box<Response>> {
    let explicit = match session_token(headers) {
        Ok(value) => value,
        Err(_) => {
            return Err(Box::new(error(
                StatusCode::UNAUTHORIZED,
                "INVALID_OR_EXPIRED_TOKEN",
            )));
        }
    };
    let cookie = cookie_value(headers, &config.session_cookie_name);
    let Some(token) = explicit.or(cookie.as_deref()) else {
        return Err(Box::new(error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED")));
    };
    let profile = match restore_django_profile(
        &config.client,
        config.codec.clone(),
        token,
        LEGACY_BACKENDS,
        SystemTime::now(),
    )
    .await
    {
        Ok(Some(profile)) => profile,
        Ok(None) => {
            return Err(Box::new(error(
                StatusCode::UNAUTHORIZED,
                "INVALID_OR_EXPIRED_TOKEN",
            )));
        }
        Err(_) => {
            return Err(Box::new(error(
                StatusCode::SERVICE_UNAVAILABLE,
                "AUTH_UNAVAILABLE",
            )));
        }
    };
    let account = profile.details.account.as_ref();
    if !operator_allowed(
        account.is_some_and(|value| value.is_staff),
        account.is_some_and(|value| value.is_superuser),
        profile.details.has_mfa,
    ) {
        return Err(Box::new(error(
            StatusCode::FORBIDDEN,
            "OPERATOR_ACCESS_REQUIRED",
        )));
    }
    Ok(())
}

fn operator_allowed(is_staff: bool, is_superuser: bool, has_mfa: bool) -> bool {
    is_staff && is_superuser && has_mfa
}

fn error(status: StatusCode, code: &'static str) -> Response {
    json_response(status, json!({"code": code}))
}

fn json_response(status: StatusCode, body: Value) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        Json(body),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_requires_staff_superuser_and_mfa() {
        assert!(operator_allowed(true, true, true));
        for (staff, superuser, mfa) in [
            (false, true, true),
            (true, false, true),
            (true, true, false),
            (false, false, false),
        ] {
            assert!(!operator_allowed(staff, superuser, mfa));
        }
    }

    #[test]
    fn errors_do_not_expose_account_details_or_cache() {
        let response = error(StatusCode::FORBIDDEN, "OPERATOR_ACCESS_REQUIRED");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
}
