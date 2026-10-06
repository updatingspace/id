//! Local pilot routes for reading MFA state and passkey metadata.

use crate::{
    email_status, login_history, logout_http::cookie_value, me_http::env_flag,
    security_read::read_security, session_store::session_codec_from_env,
};
use anyhow::{Result, bail};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use id_compat::{headers::session_token, session::SessionCodec};
use serde_json::{Value, json};
use std::{env, sync::Arc, time::SystemTime};
use url::Url;
use ydb::Client;

pub struct SecurityReadHttpConfig {
    client: Arc<Client>,
    codec: Arc<SessionCodec>,
    session_cookie_name: String,
    trusted_origins: Vec<String>,
}

impl SecurityReadHttpConfig {
    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        if !env_flag("ID_AUTH_SECURITY_READ_PILOT_ENABLED", false)? {
            return Ok(None);
        }
        let endpoint = Url::parse(&env::var("YDB_ENDPOINT")?)?;
        let local_ydb = env_flag("DJANGO_DEBUG", false)?
            && matches!(
                endpoint.host_str(),
                Some("localhost" | "127.0.0.1" | "[::1]")
            )
            && env::var("YDB_DATABASE")?.as_str() == "/local";
        if !local_ydb && !env_flag("ID_RUST_EARLY_ROLLOUT_ENABLED", false)? {
            bail!("Rust security inventory rollout requires ID_RUST_EARLY_ROLLOUT_ENABLED");
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
                    bail!("invalid trusted origin for MFA pilot");
                }
                Ok(url.origin().ascii_serialization())
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(Arc::new(Self {
            client,
            codec: session_codec_from_env()?,
            session_cookie_name: env::var("SESSION_COOKIE_NAME")
                .unwrap_or_else(|_| "sessionid".into()),
            trusted_origins,
        })))
    }
}

pub fn router(config: Arc<SecurityReadHttpConfig>) -> Router {
    Router::new()
        .route("/api/v1/auth/mfa/status", get(status).options(preflight))
        .route("/api/v1/auth/passkeys", get(passkeys).options(preflight))
        .route("/api/v1/auth/security", get(combined).options(preflight))
        .route("/api/v1/auth/email", get(email).options(preflight))
        .route(
            "/api/v1/auth/login-history",
            get(history).options(preflight),
        )
        .with_state(config)
}

async fn history(
    State(config): State<Arc<SecurityReadHttpConfig>>,
    headers: HeaderMap,
) -> Response {
    let explicit = match session_token(&headers) {
        Ok(value) => value,
        Err(_) => {
            return error(
                StatusCode::UNAUTHORIZED,
                "INVALID_OR_EXPIRED_TOKEN",
                "Сессия недействительна",
            );
        }
    };
    let cookie = cookie_value(&headers, &config.session_cookie_name);
    let Some(token) = explicit.or(cookie.as_deref()) else {
        return error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Требуется авторизация",
        );
    };
    let mut response = match login_history::read(
        &config.client,
        config.codec.clone(),
        token,
        SystemTime::now(),
    )
    .await
    {
        Ok(Some(events)) => json_response(StatusCode::OK, json!({"events":events})),
        Ok(None) => error(
            StatusCode::UNAUTHORIZED,
            if explicit.is_some() {
                "INVALID_OR_EXPIRED_TOKEN"
            } else {
                "UNAUTHORIZED"
            },
            "Сессия недействительна, пожалуйста, войдите заново",
        ),
        Err(failure) => {
            tracing::error!(?failure, "Rust login history read failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            )
        }
    };
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

async fn email(State(config): State<Arc<SecurityReadHttpConfig>>, headers: HeaderMap) -> Response {
    let mut response = email_inner(&config, &headers).await;
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

async fn email_inner(config: &SecurityReadHttpConfig, headers: &HeaderMap) -> Response {
    let explicit = match session_token(headers) {
        Ok(value) => value,
        Err(_) => {
            return error(
                StatusCode::UNAUTHORIZED,
                "INVALID_OR_EXPIRED_TOKEN",
                "Сессия недействительна",
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
    match email_status::read(
        &config.client,
        config.codec.clone(),
        token,
        SystemTime::now(),
    )
    .await
    {
        Ok(Some(status)) => json_response(StatusCode::OK, json!(status)),
        Ok(None) => error(
            StatusCode::UNAUTHORIZED,
            if explicit.is_some() {
                "INVALID_OR_EXPIRED_TOKEN"
            } else {
                "UNAUTHORIZED"
            },
            "Сессия недействительна, пожалуйста, войдите заново",
        ),
        Err(failure) => {
            tracing::error!(?failure, "Rust email status read failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            )
        }
    }
}

#[derive(Clone, Copy)]
enum View {
    Status,
    Passkeys,
    Combined,
}

async fn status(State(config): State<Arc<SecurityReadHttpConfig>>, headers: HeaderMap) -> Response {
    handle(config, headers, View::Status).await
}

async fn passkeys(
    State(config): State<Arc<SecurityReadHttpConfig>>,
    headers: HeaderMap,
) -> Response {
    handle(config, headers, View::Passkeys).await
}

async fn combined(
    State(config): State<Arc<SecurityReadHttpConfig>>,
    headers: HeaderMap,
) -> Response {
    handle(config, headers, View::Combined).await
}

async fn handle(config: Arc<SecurityReadHttpConfig>, headers: HeaderMap, view: View) -> Response {
    let mut response = handle_inner(&config, &headers, view).await;
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

async fn handle_inner(
    config: &SecurityReadHttpConfig,
    headers: &HeaderMap,
    view: View,
) -> Response {
    let explicit = match session_token(headers) {
        Ok(token) => token,
        Err(_) => {
            return error(
                StatusCode::UNAUTHORIZED,
                "INVALID_OR_EXPIRED_TOKEN",
                "Сессия недействительна",
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
    match read_security(
        &config.client,
        config.codec.clone(),
        token,
        SystemTime::now(),
    )
    .await
    {
        Ok(Some(snapshot)) => match view {
            View::Status => json_response(StatusCode::OK, json!(snapshot.status)),
            View::Passkeys => {
                json_response(StatusCode::OK, json!({"authenticators":snapshot.passkeys}))
            }
            View::Combined => json_response(
                StatusCode::OK,
                json!({"mfa":snapshot.status,"authenticators":snapshot.passkeys}),
            ),
        },
        Ok(None) => error(
            StatusCode::UNAUTHORIZED,
            if explicit.is_some() {
                "INVALID_OR_EXPIRED_TOKEN"
            } else {
                "UNAUTHORIZED"
            },
            "Сессия недействительна, пожалуйста, войдите заново",
        ),
        Err(failure) => {
            tracing::error!(?failure, "Rust MFA state read failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            )
        }
    }
}

async fn preflight(
    State(config): State<Arc<SecurityReadHttpConfig>>,
    headers: HeaderMap,
) -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

fn json_response(status: StatusCode, body: Value) -> Response {
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response.headers_mut().insert(
        header::VARY,
        HeaderValue::from_static("Cookie, Origin, X-Session-Token"),
    );
    response
}

fn error(status: StatusCode, code: &str, message: &str) -> Response {
    json_response(
        status,
        json!({"code":code,"message":message,"details":null,"errors":null,
        "fields":null,"detail":format!("{{'code': '{code}', 'message': '{message}'}}"),"status":status.as_u16()}),
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
            HeaderValue::from_static("GET, OPTIONS"),
        );
        output.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("X-Session-Token, Authorization"),
        );
    }
}
