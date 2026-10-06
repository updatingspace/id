//! HTTP password change with current-password confirmation and durable mail.

use crate::{
    logout_http::{cookie_value, csrf_allowed},
    me_http::env_flag,
    password_change::{ChangeResult, PasswordChanger},
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
use serde_json::json;
use std::{env, sync::Arc, time::SystemTime};
use url::Url;
use ydb::Client;

const MAX_BODY: usize = 16 * 1024;

pub struct PasswordChangeHttpConfig {
    changer: PasswordChanger,
    session_cookie_name: String,
    csrf_cookie_name: String,
    trusted_origins: Vec<String>,
}

impl PasswordChangeHttpConfig {
    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        if !env_flag("ID_AUTH_PASSWORD_CHANGE_PILOT_ENABLED", false)? {
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
            bail!("Rust password change requires local YDB or explicit rollout approval");
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
                    bail!("invalid trusted origin for password change");
                }
                Ok(url.origin().ascii_serialization())
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(Arc::new(Self {
            changer: PasswordChanger::new(client, session_codec_from_env()?, 2)?,
            session_cookie_name: env::var("SESSION_COOKIE_NAME")
                .unwrap_or_else(|_| "sessionid".into()),
            csrf_cookie_name: env::var("CSRF_COOKIE_NAME").unwrap_or_else(|_| "csrftoken".into()),
            trusted_origins,
        })))
    }
}

pub fn router(config: Arc<PasswordChangeHttpConfig>) -> Router {
    Router::new()
        .route(
            "/api/v1/auth/change_password",
            post(change).options(preflight),
        )
        .with_state(config)
}

#[derive(Deserialize)]
struct ChangePasswordIn {
    current_password: String,
    new_password: String,
}

async fn change(State(config): State<Arc<PasswordChangeHttpConfig>>, request: Request) -> Response {
    let headers = request.headers().clone();
    let mut response = change_inner(&config, request).await;
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

async fn change_inner(config: &PasswordChangeHttpConfig, request: Request) -> Response {
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
    let explicit_present = explicit.is_some();
    let token = token.to_owned();
    let body = match to_bytes(request.into_body(), MAX_BODY + 1).await {
        Ok(value) if value.len() <= MAX_BODY => value,
        _ => {
            return error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "VALIDATION_ERROR",
                "Invalid request body",
            );
        }
    };
    let Ok(payload) = serde_json::from_slice::<ChangePasswordIn>(&body) else {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "Invalid request body",
        );
    };
    match config
        .changer
        .change(
            &token,
            &payload.current_password,
            &payload.new_password,
            SystemTime::now(),
        )
        .await
    {
        Ok(ChangeResult::Changed) => json_response(
            StatusCode::OK,
            json!({"ok":true,"message":"password changed"}),
        ),
        Ok(ChangeResult::WrongCurrent) => error(
            StatusCode::BAD_REQUEST,
            "WRONG_CURRENT_PASSWORD",
            "wrong current password",
        ),
        Ok(ChangeResult::WeakNew) => error(
            StatusCode::BAD_REQUEST,
            "WEAK_PASSWORD",
            "new password does not meet policy",
        ),
        Ok(ChangeResult::Stale) => error(
            StatusCode::CONFLICT,
            "PASSWORD_CHANGED",
            "password changed concurrently",
        ),
        Ok(ChangeResult::Unauthorized) => error(
            StatusCode::UNAUTHORIZED,
            if explicit_present {
                "INVALID_OR_EXPIRED_TOKEN"
            } else {
                "UNAUTHORIZED"
            },
            "Недействительная сессия",
        ),
        Err(failure) => {
            tracing::error!(?failure, "Rust password change failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            )
        }
    }
}

async fn preflight(
    State(config): State<Arc<PasswordChangeHttpConfig>>,
    headers: HeaderMap,
) -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

fn json_response(status: StatusCode, body: serde_json::Value) -> Response {
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Cookie, origin"));
    response
}

fn error(status: StatusCode, code: &str, message: &str) -> Response {
    json_response(
        status,
        json!({"code":code,"message":message,"details":null,"errors":null,"fields":null,"status":status.as_u16()}),
    )
}

fn add_cors(output: &mut HeaderMap, input: &HeaderMap, origins: &[String]) {
    let Some(origin) = input
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return;
    };
    let Ok(url) = Url::parse(origin) else {
        return;
    };
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
            HeaderValue::from_static("POST, OPTIONS"),
        );
        output.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("content-type,x-csrftoken,x-session-token,authorization"),
        );
        output.insert(header::VARY, HeaderValue::from_static("Cookie, origin"));
    }
}
