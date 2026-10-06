//! Opt-in HTTP routes for account-owned OAuth applications.

use crate::{
    authorized_apps_store::{AppsOperation, AppsResult, account_apps},
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
    routing::get,
};
use id_compat::{headers::session_token, session::SessionCodec};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{env, sync::Arc, time::SystemTime};
use url::Url;
use ydb::Client;

pub struct AuthorizedAppsHttpConfig {
    client: Arc<Client>,
    codec: Arc<SessionCodec>,
    session_cookie_name: String,
    csrf_cookie_name: String,
    trusted_origins: Vec<String>,
}

impl AuthorizedAppsHttpConfig {
    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        if !env_flag("ID_AUTH_APPS_PILOT_ENABLED", false)? {
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
            bail!("Rust OAuth application rollout requires ID_RUST_EARLY_ROLLOUT_ENABLED");
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
                    bail!("invalid trusted origin for OAuth apps pilot");
                }
                Ok(url.origin().ascii_serialization())
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(Arc::new(Self {
            client,
            codec: session_codec_from_env()?,
            session_cookie_name: env::var("SESSION_COOKIE_NAME")
                .unwrap_or_else(|_| "sessionid".into()),
            csrf_cookie_name: env::var("CSRF_COOKIE_NAME").unwrap_or_else(|_| "csrftoken".into()),
            trusted_origins,
        })))
    }
}

pub fn router(config: Arc<AuthorizedAppsHttpConfig>) -> Router {
    Router::new()
        .route("/api/v1/auth/oauth/apps", get(list).options(preflight))
        .route(
            "/api/v1/auth/oauth/apps/revoke",
            axum::routing::post(revoke).options(preflight),
        )
        .with_state(config)
}

#[derive(Deserialize)]
struct RevokeIn {
    client_id: String,
}

async fn list(State(config): State<Arc<AuthorizedAppsHttpConfig>>, request: Request) -> Response {
    handle(config, request, false).await
}

async fn revoke(State(config): State<Arc<AuthorizedAppsHttpConfig>>, request: Request) -> Response {
    handle(config, request, true).await
}

async fn handle(
    config: Arc<AuthorizedAppsHttpConfig>,
    request: Request,
    mutation: bool,
) -> Response {
    let headers = request.headers().clone();
    let mut response = handle_inner(&config, request, mutation).await;
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

async fn handle_inner(
    config: &AuthorizedAppsHttpConfig,
    request: Request,
    mutation: bool,
) -> Response {
    let headers = request.headers();
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
    if mutation
        && explicit.is_none()
        && !csrf_allowed(headers, &config.csrf_cookie_name, &config.trusted_origins)
    {
        return error(
            StatusCode::FORBIDDEN,
            "CSRF_FAILED",
            "CSRF verification failed",
        );
    }
    let explicit_present = explicit.is_some();
    let token = token.to_owned();
    let operation = if mutation {
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
        let bytes = match to_bytes(request.into_body(), 2049).await {
            Ok(value) if value.len() <= 2048 => value,
            _ => {
                return error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "VALIDATION_ERROR",
                    "Invalid request body",
                );
            }
        };
        let Ok(payload) = serde_json::from_slice::<RevokeIn>(&bytes) else {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_ERROR",
                "Invalid request body",
            );
        };
        if payload.client_id.is_empty() || payload.client_id.len() > 64 {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_ERROR",
                "Invalid client ID",
            );
        }
        AppsOperation::Revoke(payload.client_id)
    } else {
        AppsOperation::List
    };
    match account_apps(
        &config.client,
        config.codec.clone(),
        &token,
        operation,
        SystemTime::now(),
    )
    .await
    {
        Ok(Some(AppsResult::Listed(items))) => {
            json_response(StatusCode::OK, json!({"items":items}))
        }
        Ok(Some(AppsResult::Revoked(true))) => json_response(
            StatusCode::OK,
            json!({"ok":true,"message":"Доступ отозван"}),
        ),
        Ok(Some(AppsResult::Revoked(false))) => error(
            StatusCode::BAD_REQUEST,
            "APP_NOT_FOUND",
            "Приложение не найдено",
        ),
        Ok(None) => error(
            StatusCode::UNAUTHORIZED,
            if explicit_present {
                "INVALID_OR_EXPIRED_TOKEN"
            } else {
                "UNAUTHORIZED"
            },
            "Сессия недействительна, пожалуйста, войдите заново",
        ),
        Err(failure) => {
            tracing::error!(?failure, "Rust OAuth application operation failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            )
        }
    }
}

async fn preflight(
    State(config): State<Arc<AuthorizedAppsHttpConfig>>,
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
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Cookie, origin"));
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
            HeaderValue::from_static("GET, POST, OPTIONS"),
        );
        output.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Content-Type, X-CSRFToken, X-Session-Token, Authorization"),
        );
    }
}
