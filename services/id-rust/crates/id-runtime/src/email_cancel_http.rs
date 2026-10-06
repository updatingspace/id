//! HTTP cancellation of a pending email change.

use crate::{
    cache_store::CacheStore,
    email_cancel::{CancelResult, cancel},
    email_change::{self, StageResult},
    logout_http::{cookie_value, csrf_allowed},
    me_http::env_flag,
    session_store::session_codec_from_env,
};
use anyhow::{Result, bail};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::delete,
};
use id_compat::{headers::session_token, session::SessionCodec};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{env, sync::Arc, time::SystemTime};
use url::Url;
use ydb::Client;

pub struct EmailCancelHttpConfig {
    client: Arc<Client>,
    cache: CacheStore,
    codec: Arc<SessionCodec>,
    cancel_enabled: bool,
    change_enabled: bool,
    session_cookie_name: String,
    csrf_cookie_name: String,
    trusted_origins: Vec<String>,
}

impl EmailCancelHttpConfig {
    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        let cancel_enabled = env_flag("ID_AUTH_EMAIL_CANCEL_PILOT_ENABLED", false)?;
        let change_enabled = env_flag("ID_AUTH_EMAIL_CHANGE_PILOT_ENABLED", false)?;
        if !cancel_enabled && !change_enabled {
            return Ok(None);
        }
        let endpoint = Url::parse(&env::var("YDB_ENDPOINT")?)?;
        let local = env_flag("DJANGO_DEBUG", false)?
            && matches!(
                endpoint.host_str(),
                Some("localhost" | "127.0.0.1" | "[::1]")
            )
            && env::var("YDB_DATABASE")?.as_str() == "/local";
        if !local && !env_flag("ID_RUST_EARLY_ROLLOUT_ENABLED", false)? {
            bail!("Rust email cancellation requires local YDB or explicit rollout flag");
        }
        let trusted_origins = env::var("CSRF_TRUSTED_ORIGINS")
            .unwrap_or_else(|_| "http://id.localhost,http://localhost:5175".into())
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
                    bail!("invalid trusted origin for email cancellation");
                }
                Ok(url.origin().ascii_serialization())
            })
            .collect::<Result<Vec<_>>>()?;
        if trusted_origins.is_empty() {
            bail!("missing trusted origin for email cancellation");
        }
        Ok(Some(Arc::new(Self {
            cache: CacheStore::new(
                client.clone(),
                &env::var("YDB_CACHE_TABLE").unwrap_or_else(|_| "id_shared_cache".into()),
                "",
                1,
            )?,
            client,
            codec: session_codec_from_env()?,
            cancel_enabled,
            change_enabled,
            session_cookie_name: env::var("SESSION_COOKIE_NAME")
                .unwrap_or_else(|_| "sessionid".into()),
            csrf_cookie_name: env::var("CSRF_COOKIE_NAME").unwrap_or_else(|_| "csrftoken".into()),
            trusted_origins,
        })))
    }
}

pub fn router(config: Arc<EmailCancelHttpConfig>) -> Router {
    Router::new()
        .route(
            "/api/v1/auth/email/change",
            delete(handle).post(change).options(preflight),
        )
        .with_state(config)
}

async fn handle(State(config): State<Arc<EmailCancelHttpConfig>>, request: Request) -> Response {
    let headers = request.headers();
    let mut result = handle_inner(&config, headers).await;
    add_cors(result.headers_mut(), headers, &config.trusted_origins);
    result
}

async fn handle_inner(config: &EmailCancelHttpConfig, headers: &HeaderMap) -> Response {
    if !config.cancel_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
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
    match cancel(
        &config.client,
        config.codec.clone(),
        token,
        SystemTime::now(),
    )
    .await
    {
        Ok(CancelResult::Cancelled { .. }) => json_response(
            StatusCode::OK,
            json!({"ok":true,"message":"Смена email отменена"}),
        ),
        Ok(CancelResult::Unauthorized) => error(
            StatusCode::UNAUTHORIZED,
            if explicit.is_some() {
                "INVALID_OR_EXPIRED_TOKEN"
            } else {
                "UNAUTHORIZED"
            },
            "Недействительная сессия",
        ),
        Err(failure) => {
            tracing::error!(?failure, "Rust email change cancellation failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            )
        }
    }
}

#[derive(Deserialize)]
struct ChangeEmailIn {
    new_email: String,
}

async fn change(State(config): State<Arc<EmailCancelHttpConfig>>, request: Request) -> Response {
    let headers = request.headers().clone();
    let mut result = change_inner(&config, request).await;
    add_cors(result.headers_mut(), &headers, &config.trusted_origins);
    result
}

async fn change_inner(config: &EmailCancelHttpConfig, request: Request) -> Response {
    if !config.change_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
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
    let token = token.to_owned();
    let explicit_present = explicit.is_some();
    let ip_digest = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .map(|value| hex::encode(Sha256::digest(value.as_bytes())));
    let body = match to_bytes(request.into_body(), 16 * 1024 + 1).await {
        Ok(bytes) if bytes.len() <= 16 * 1024 => bytes,
        _ => {
            return error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "VALIDATION_ERROR",
                "Invalid request body",
            );
        }
    };
    let Ok(payload) = serde_json::from_slice::<ChangeEmailIn>(&body) else {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "Invalid request body",
        );
    };
    let now = SystemTime::now();
    if let Some(ip_digest) = ip_digest {
        match config
            .cache
            .advance_window(&format!("rl:email_change:ip:{ip_digest}"), 600, now)
            .await
        {
            Ok(value) if value.count <= 5 => {}
            Ok(_) => {
                return error(
                    StatusCode::TOO_MANY_REQUESTS,
                    "EMAIL_RATE_LIMITED",
                    "Слишком много писем. Попробуйте через несколько минут.",
                );
            }
            Err(failure) => {
                tracing::error!(?failure, "Rust email change IP rate limit failed");
                return error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "SERVICE_UNAVAILABLE",
                    "Временно недоступно",
                );
            }
        }
    }
    let token_digest = hex::encode(Sha256::digest(token.as_bytes()));
    match config
        .cache
        .advance_window(&format!("rl:email_change:session:{token_digest}"), 600, now)
        .await
    {
        Ok(value) if value.count <= 5 => {}
        Ok(_) => {
            return error(
                StatusCode::TOO_MANY_REQUESTS,
                "EMAIL_RATE_LIMITED",
                "Слишком много писем. Попробуйте через несколько минут.",
            );
        }
        Err(failure) => {
            tracing::error!(?failure, "Rust email change rate limit failed");
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            );
        }
    }
    match email_change::stage(
        &config.client,
        config.codec.clone(),
        &token,
        &payload.new_email,
        now,
    )
    .await
    {
        Ok(StageResult::Staged | StageResult::NoChange) => json_response(
            StatusCode::OK,
            json!({"ok":true,"message":"Проверьте почту, чтобы подтвердить новый адрес"}),
        ),
        Ok(StageResult::InvalidEmail) => error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Введите корректный email.",
        ),
        Ok(StageResult::EmailExists) => error(
            StatusCode::BAD_REQUEST,
            "EMAIL_ALREADY_EXISTS",
            "Этот email уже используется другим аккаунтом",
        ),
        Ok(StageResult::ReauthRequired) => error(
            StatusCode::UNAUTHORIZED,
            "REAUTH_REQUIRED",
            "Подтвердите вход заново перед сменой email.",
        ),
        Ok(StageResult::Unauthorized) => error(
            StatusCode::UNAUTHORIZED,
            if explicit_present {
                "INVALID_OR_EXPIRED_TOKEN"
            } else {
                "UNAUTHORIZED"
            },
            "Недействительная сессия",
        ),
        Ok(StageResult::AddressIdCollision) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "SERVICE_UNAVAILABLE",
            "Временно недоступно",
        ),
        Err(failure) => {
            tracing::error!(?failure, "Rust email change request failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            )
        }
    }
}

async fn preflight(
    State(config): State<Arc<EmailCancelHttpConfig>>,
    headers: HeaderMap,
) -> Response {
    let mut result = StatusCode::NO_CONTENT.into_response();
    add_cors(result.headers_mut(), &headers, &config.trusted_origins);
    result
}

fn json_response(status: StatusCode, body: serde_json::Value) -> Response {
    let mut result = (status, Json(body)).into_response();
    result.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    result.headers_mut().insert(
        header::VARY,
        HeaderValue::from_static("Cookie, Origin, X-Session-Token"),
    );
    result
}

fn error(status: StatusCode, code: &str, message: &str) -> Response {
    json_response(
        status,
        json!({"code":code,"message":message,"details":null,"errors":null,
        "fields":null,"status":status.as_u16()}),
    )
}

fn add_cors(output: &mut HeaderMap, input: &HeaderMap, origins: &[String]) {
    let Some(origin) = input
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return;
    };
    let Ok(url) = Url::parse(origin) else { return };
    if url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || !origins.contains(&url.origin().ascii_serialization())
    {
        return;
    }
    if let Ok(value) = HeaderValue::from_str(origin) {
        output.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
        output.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
        output.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("DELETE, POST, OPTIONS"),
        );
        output.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Content-Type, X-CSRFToken, X-Session-Token, Authorization"),
        );
    }
}
