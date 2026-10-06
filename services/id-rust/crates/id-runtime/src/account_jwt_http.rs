//! Account JWT issuance from a verified session and refresh rotation.

use crate::{
    account_jwt_refresh::{RefreshOutcome, rotate},
    account_jwt_session::issue_from_session,
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
    routing::post,
};
use id_compat::{account_jwt::AccountJwtCodec, headers::session_token, session::SessionCodec};
use serde_json::{Value, json};
use std::{env, sync::Arc, time::SystemTime};
use url::Url;
use ydb::Client;

pub struct AccountJwtHttpConfig {
    client: Arc<Client>,
    session_codec: Arc<SessionCodec>,
    jwt_codec: Arc<AccountJwtCodec>,
    session_cookie_name: String,
    csrf_cookie_name: String,
    trusted_origins: Vec<String>,
}

impl AccountJwtHttpConfig {
    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        if !env_flag("ID_AUTH_JWT_SESSION_PILOT_ENABLED", false)? {
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
            bail!("account JWT session pilot requires local YDB or explicit rollout approval");
        }
        let secret = env::var("DJANGO_SECRET_KEY")?;
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
                    bail!("invalid trusted origin for account JWT");
                }
                Ok(url.origin().ascii_serialization())
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(Arc::new(Self::new(
            client,
            session_codec_from_env()?,
            Arc::new(AccountJwtCodec::new(secret.as_bytes())?),
            env::var("SESSION_COOKIE_NAME").unwrap_or_else(|_| "sessionid".into()),
            env::var("CSRF_COOKIE_NAME").unwrap_or_else(|_| "csrftoken".into()),
            trusted_origins,
        )?)))
    }

    pub fn new(
        client: Arc<Client>,
        session_codec: Arc<SessionCodec>,
        jwt_codec: Arc<AccountJwtCodec>,
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
            bail!("invalid account JWT HTTP configuration");
        }
        Ok(Self {
            client,
            session_codec,
            jwt_codec,
            session_cookie_name,
            csrf_cookie_name,
            trusted_origins,
        })
    }
}

pub fn router(config: Arc<AccountJwtHttpConfig>) -> Router {
    Router::new()
        .route(
            "/api/v1/auth/jwt/from_session",
            post(from_session).options(preflight),
        )
        .route("/api/v1/auth/refresh", post(refresh).options(preflight))
        .with_state(config)
}

async fn refresh(State(config): State<Arc<AccountJwtHttpConfig>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let mut result = refresh_result(&config, body).await;
    add_cors(
        result.headers_mut(),
        &parts.headers,
        &config.trusted_origins,
    );
    result
}

async fn refresh_result(config: &AccountJwtHttpConfig, body: axum::body::Body) -> Response {
    let Ok(bytes) = to_bytes(body, 8192).await else {
        return error(StatusCode::BAD_REQUEST, "INVALID_REQUEST");
    };
    let Ok(input) = serde_json::from_slice::<Value>(&bytes) else {
        return error(StatusCode::BAD_REQUEST, "INVALID_REQUEST");
    };
    let Some(refresh) = input.get("refresh").and_then(Value::as_str) else {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "INVALID_REQUEST");
    };
    match rotate(
        &config.client,
        config.session_codec.clone(),
        config.jwt_codec.clone(),
        refresh,
        SystemTime::now(),
    )
    .await
    {
        Ok(RefreshOutcome::Rotated(pair)) => response(
            StatusCode::OK,
            json!({"access":pair.access,"refresh":pair.refresh}),
        ),
        Ok(RefreshOutcome::Invalid | RefreshOutcome::ReplayRevoked) => {
            error(StatusCode::UNAUTHORIZED, "INVALID_OR_EXPIRED_TOKEN")
        }
        Err(failure) => {
            tracing::error!(?failure, "account JWT refresh transaction failed");
            error(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE")
        }
    }
}

async fn from_session(
    State(config): State<Arc<AccountJwtHttpConfig>>,
    headers: HeaderMap,
) -> Response {
    let mut result = from_session_result(&config, &headers).await;
    add_cors(result.headers_mut(), &headers, &config.trusted_origins);
    result
}

async fn from_session_result(config: &AccountJwtHttpConfig, headers: &HeaderMap) -> Response {
    let explicit = match session_token(headers) {
        Ok(value) => value,
        Err(_) => return error(StatusCode::UNAUTHORIZED, "INVALID_OR_EXPIRED_TOKEN"),
    };
    let cookie = cookie_value(headers, &config.session_cookie_name);
    let Some(token) = explicit.or(cookie.as_deref()) else {
        return error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED");
    };
    if explicit.is_none()
        && !csrf_allowed(headers, &config.csrf_cookie_name, &config.trusted_origins)
    {
        return error(StatusCode::FORBIDDEN, "CSRF_FAILED");
    }
    match issue_from_session(
        &config.client,
        config.session_codec.clone(),
        config.jwt_codec.clone(),
        token,
        SystemTime::now(),
    )
    .await
    {
        Ok(Some(pair)) => response(
            StatusCode::OK,
            json!({"access":pair.access,"refresh":pair.refresh}),
        ),
        Ok(None) => error(StatusCode::UNAUTHORIZED, "INVALID_OR_EXPIRED_TOKEN"),
        Err(failure) => {
            tracing::error!(?failure, "account JWT issue transaction failed");
            error(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE")
        }
    }
}

async fn preflight(
    State(config): State<Arc<AccountJwtHttpConfig>>,
    headers: HeaderMap,
) -> Response {
    let mut result = StatusCode::NO_CONTENT.into_response();
    add_cors(result.headers_mut(), &headers, &config.trusted_origins);
    result
}

fn response(status: StatusCode, body: Value) -> Response {
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

fn error(status: StatusCode, code: &str) -> Response {
    let message = match code {
        "UNAUTHORIZED" => "Требуется авторизация",
        "CSRF_FAILED" => "CSRF verification failed",
        "SERVICE_UNAVAILABLE" => "Временно недоступно",
        "INVALID_REQUEST" => "Некорректный запрос",
        _ => "Сессия недействительна, пожалуйста, войдите заново",
    };
    response(
        status,
        json!({
            "code":code, "message":message, "details":null, "errors":null, "fields":null,
            "detail":format!("{{'code': '{code}', 'message': '{message}'}}"), "status":status.as_u16(),
        }),
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
            HeaderValue::from_static("X-CSRFToken, X-Session-Token, Authorization"),
        );
    }
}
