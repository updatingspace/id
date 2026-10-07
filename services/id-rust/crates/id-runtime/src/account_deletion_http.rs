//! Opt-in acceptance endpoint for asynchronous account deletion.

use crate::{
    account_deletion::{AccountDeletion, DeletionResult},
    cache_store::CacheStore,
    logout_http::{cookie_value, csrf_allowed},
    me_http::env_flag,
    mfa_secret,
    session_store::session_codec_from_env,
};
use anyhow::{Result, bail};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use id_compat::headers::session_token;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{env, sync::Arc, time::SystemTime};
use url::Url;
use ydb::Client;

const MAX_BODY: usize = 16 * 1024;

pub struct AccountDeletionHttpConfig {
    deletion: AccountDeletion,
    session_cookie_name: String,
    csrf_cookie_name: String,
    trusted_origins: Vec<String>,
}

impl AccountDeletionHttpConfig {
    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        let pilot = env_flag("ID_AUTH_DELETION_PILOT_ENABLED", false)?;
        let rollout = env_flag("ID_AUTH_DELETION_ROLLOUT_ENABLED", false)?;
        if !pilot && !rollout {
            return Ok(None);
        }
        if pilot {
            let endpoint = Url::parse(&env::var("YDB_ENDPOINT")?)?;
            if !env_flag("DJANGO_DEBUG", false)?
                || !matches!(
                    endpoint.host_str(),
                    Some("localhost" | "127.0.0.1" | "[::1]")
                )
                || env::var("YDB_DATABASE")? != "/local"
            {
                bail!("account deletion pilot is restricted to local debug YDB");
            }
        }
        if rollout && !env_flag("ID_EXPORT_DELAYED_ROLLOUT_ENABLED", false)? {
            bail!("account deletion rollout requires delayed export escrow");
        }
        let trusted_origins = env::var("CSRF_TRUSTED_ORIGINS")
            .unwrap_or_else(|_| {
                "http://id.localhost,http://id.localhost:5175,http://localhost:5175".into()
            })
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                let url = Url::parse(value)?;
                if !matches!(url.scheme(), "http" | "https")
                    || url.path() != "/"
                    || url.query().is_some()
                    || url.fragment().is_some()
                    || !url.username().is_empty()
                    || url.password().is_some()
                {
                    bail!("invalid account deletion trusted origin");
                }
                Ok(url.origin().ascii_serialization())
            })
            .collect::<Result<Vec<_>>>()?;
        let table = env::var("YDB_CACHE_TABLE").unwrap_or_else(|_| "id_shared_cache".into());
        let cache = CacheStore::new(client.clone(), &table, "", 1)?;
        let secret = env::var("ID_DELETION_OPERATION_KEY")?;
        let deletion = AccountDeletion::new(
            client,
            session_codec_from_env()?,
            cache,
            mfa_secret::key_from_env()?,
            secret.as_bytes(),
            2,
        )?;
        Ok(Some(Arc::new(Self::new(
            deletion,
            env::var("SESSION_COOKIE_NAME").unwrap_or_else(|_| "sessionid".into()),
            env::var("CSRF_COOKIE_NAME").unwrap_or_else(|_| "csrftoken".into()),
            trusted_origins,
        )?)))
    }

    pub fn new(
        deletion: AccountDeletion,
        session_cookie_name: String,
        csrf_cookie_name: String,
        trusted_origins: Vec<String>,
    ) -> Result<Self> {
        if [&session_cookie_name, &csrf_cookie_name]
            .iter()
            .any(|name| {
                name.is_empty()
                    || !name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            })
            || trusted_origins.is_empty()
        {
            bail!("invalid account deletion HTTP configuration");
        }
        Ok(Self {
            deletion,
            session_cookie_name,
            csrf_cookie_name,
            trusted_origins,
        })
    }
}

pub fn router(config: Arc<AccountDeletionHttpConfig>) -> Router {
    Router::new()
        .route(
            "/api/v1/auth/account/deletions",
            post(create).options(preflight),
        )
        .with_state(config)
}

#[derive(Deserialize)]
struct DeletionIn {
    password: String,
    mfa_code: Option<String>,
    recovery_code: Option<String>,
    reason: Option<String>,
}

async fn create(
    State(config): State<Arc<AccountDeletionHttpConfig>>,
    request: Request,
) -> Response {
    let headers = request.headers().clone();
    let mut result = create_inner(&config, request).await;
    add_cors(result.headers_mut(), &headers, &config.trusted_origins);
    result
}

async fn create_inner(config: &AccountDeletionHttpConfig, request: Request) -> Response {
    let headers = request.headers();
    let explicit = match session_token(headers) {
        Ok(value) => value,
        Err(_) => {
            return error(
                StatusCode::UNAUTHORIZED,
                "INVALID_OR_EXPIRED_TOKEN",
                "Недействительная сессия",
            );
        }
    };
    let cookie = cookie_value(headers, &config.session_cookie_name);
    let Some(token) = explicit.or(cookie.as_deref()) else {
        return error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Требуется авторизация",
        );
    };
    if explicit.is_none()
        && !csrf_allowed(headers, &config.csrf_cookie_name, &config.trusted_origins)
    {
        return error(
            StatusCode::FORBIDDEN,
            "CSRF_FAILED",
            "CSRF verification failed",
        );
    }
    let Some(key) = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
    else {
        return error(
            StatusCode::BAD_REQUEST,
            "IDEMPOTENCY_KEY_REQUIRED",
            "Нужен Idempotency-Key",
        );
    };
    let token = token.to_owned();
    let key = key.to_owned();
    if !headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
        })
    {
        return error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "UNSUPPORTED_MEDIA_TYPE",
            "Content-Type must be application/json",
        );
    }
    let bytes = match to_bytes(request.into_body(), MAX_BODY + 1).await {
        Ok(bytes) if bytes.len() <= MAX_BODY => bytes,
        _ => {
            return error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "VALIDATION_ERROR",
                "Invalid request body",
            );
        }
    };
    let Ok(input) = serde_json::from_slice::<DeletionIn>(&bytes) else {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "Invalid request body",
        );
    };
    match config
        .deletion
        .request(
            &token,
            &key,
            &input.password,
            input
                .mfa_code
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .or(input.recovery_code.as_deref()),
            input.reason.as_deref(),
            SystemTime::now(),
        )
        .await
    {
        Ok(DeletionResult::Accepted { id, status, .. }) => json_response(
            StatusCode::ACCEPTED,
            json!({"id":id.to_string(),"status":status,"message":"Удаление принято"}),
        ),
        Ok(DeletionResult::Unauthorized) => error(
            StatusCode::UNAUTHORIZED,
            "INVALID_OR_EXPIRED_TOKEN",
            "Недействительная сессия",
        ),
        Ok(DeletionResult::WrongPassword) => error(
            StatusCode::BAD_REQUEST,
            "INVALID_PASSWORD",
            "Неверный текущий пароль",
        ),
        Ok(DeletionResult::MfaRequired) => {
            error(StatusCode::BAD_REQUEST, "MFA_REQUIRED", "Требуется код MFA")
        }
        Ok(DeletionResult::WrongMfa) => error(
            StatusCode::BAD_REQUEST,
            "INVALID_MFA_CODE",
            "Неверный код MFA",
        ),
        Ok(DeletionResult::Stale) => error(
            StatusCode::CONFLICT,
            "PASSWORD_CHANGED",
            "Пароль изменён, повторите вход",
        ),
        Err(failure) => {
            tracing::error!(?failure, "account deletion acceptance failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            )
        }
    }
}

async fn preflight(
    State(config): State<Arc<AccountDeletionHttpConfig>>,
    headers: HeaderMap,
) -> Response {
    let mut result = StatusCode::NO_CONTENT.into_response();
    add_cors(result.headers_mut(), &headers, &config.trusted_origins);
    result
}

fn json_response(status: StatusCode, body: Value) -> Response {
    let mut result = (status, Json(body)).into_response();
    result.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    result
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    result
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Cookie, origin"));
    result
}

fn error(status: StatusCode, code: &str, message: &str) -> Response {
    json_response(
        status,
        json!({"code":code,"message":message,"status":status.as_u16(),
        "details":null,"errors":null,"fields":null,
        "detail":format!("{{'code': '{code}', 'message': '{message}'}}") }),
    )
}

fn add_cors(output: &mut HeaderMap, input: &HeaderMap, trusted_origins: &[String]) {
    let origin = input
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok());
    let canonical = origin
        .and_then(|value| Url::parse(value).ok())
        .filter(|url| {
            matches!(url.scheme(), "http" | "https")
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none()
                && url.username().is_empty()
                && url.password().is_none()
        })
        .map(|url| url.origin().ascii_serialization());
    if let Some(origin) = origin
        && canonical
            .as_ref()
            .is_some_and(|value| trusted_origins.contains(value))
        && let Ok(origin) = HeaderValue::from_str(origin)
    {
        output.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        output.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
        output.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("POST, OPTIONS"),
        );
        output.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static(
                "Content-Type, X-CSRFToken, X-Session-Token, Authorization, Idempotency-Key",
            ),
        );
    }
}
