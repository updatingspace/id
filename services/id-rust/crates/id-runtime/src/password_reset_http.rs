//! Opt-in public recovery endpoints. Unknown account outcomes deliberately
//! share one response; the reset bearer never appears in URL query or logs.

use crate::{
    cache_store::CacheStore,
    form_token_consume::consume_form_token,
    logout_http::csrf_allowed,
    me_http::env_flag,
    password_reset::{ConfirmResult, PasswordResetter, ResetKey},
};
use anyhow::{Result, bail};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{env, net::SocketAddr, sync::Arc, time::SystemTime};
use url::Url;
use ydb::Client;

const MAX_BODY: usize = 16 * 1024;
const WINDOW: u64 = 600;

pub struct PasswordResetHttpConfig {
    client: Arc<Client>,
    cache: CacheStore,
    resetter: PasswordResetter,
    csrf_cookie_name: String,
    trusted_origins: Vec<String>,
}

impl PasswordResetHttpConfig {
    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        if !env_flag("ID_AUTH_PASSWORD_RESET_PILOT_ENABLED", false)? {
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
            bail!("unqualified Rust password reset is restricted to local debug YDB");
        }
        if !env_flag("ID_AUTH_FORM_TOKEN_ENABLED", false)? {
            bail!("password reset requires Rust form-token issuance");
        }
        let origins = env::var("CSRF_TRUSTED_ORIGINS")
            .unwrap_or_else(|_| "http://id.localhost,http://localhost:5175".into());
        let trusted_origins = origins
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|raw| {
                let url = Url::parse(raw)?;
                if !matches!(url.scheme(), "http" | "https")
                    || url.path() != "/"
                    || url.query().is_some()
                    || url.fragment().is_some()
                    || !url.username().is_empty()
                    || url.password().is_some()
                {
                    bail!("invalid trusted origin for password reset");
                }
                Ok(url.origin().ascii_serialization())
            })
            .collect::<Result<Vec<_>>>()?;
        let table = env::var("YDB_CACHE_TABLE").unwrap_or_else(|_| "id_shared_cache".into());
        let cache = CacheStore::new(client.clone(), &table, "", 1)?;
        Ok(Some(Arc::new(Self {
            resetter: PasswordResetter::new(client.clone(), ResetKey::from_env()?, 2)?,
            client,
            cache,
            csrf_cookie_name: env::var("CSRF_COOKIE_NAME").unwrap_or_else(|_| "csrftoken".into()),
            trusted_origins,
        })))
    }
}

pub fn router(config: Arc<PasswordResetHttpConfig>) -> Router {
    Router::new()
        .route(
            "/api/v1/auth/password/reset/request",
            post(request_reset).options(preflight),
        )
        .route(
            "/api/v1/auth/password/reset/confirm",
            post(confirm_reset).options(preflight),
        )
        .with_state(config)
}

#[derive(Deserialize)]
struct RequestIn {
    email: String,
    form_token: String,
}

#[derive(Deserialize)]
struct ConfirmIn {
    key: String,
    password: String,
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
    if !origins.iter().any(|allowed| allowed == origin) {
        return;
    }
    if let Ok(value) = HeaderValue::from_str(origin) {
        output.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
        output.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
        output.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("content-type, x-csrftoken"),
        );
        output.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("POST, OPTIONS"),
        );
    }
}

async fn preflight(
    State(config): State<Arc<PasswordResetHttpConfig>>,
    headers: HeaderMap,
) -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
        })
}

async fn body(request: Request) -> Result<Vec<u8>, Box<Response>> {
    if !is_json(request.headers()) {
        return Err(Box::new(error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "UNSUPPORTED_MEDIA_TYPE",
            "Content-Type must be application/json",
        )));
    }
    match to_bytes(request.into_body(), MAX_BODY + 1).await {
        Ok(value) if value.len() <= MAX_BODY => Ok(value.to_vec()),
        _ => Err(Box::new(error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "VALIDATION_ERROR",
            "Invalid request body",
        ))),
    }
}

fn client_ip(headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .map(str::to_owned)
        .or_else(|| peer.map(|value| value.ip().to_string()))
        .unwrap_or_else(|| "unknown".into())
}

async fn limited(cache: &CacheStore, key: &str, maximum: i64, now: SystemTime) -> Result<bool> {
    let count = cache.advance_window(key, WINDOW, now).await?;
    Ok(count.count > maximum)
}

fn rate_response() -> Response {
    let mut response = error(
        StatusCode::TOO_MANY_REQUESTS,
        "RECOVERY_RATE_LIMITED",
        "Слишком много запросов. Попробуйте через несколько минут.",
    );
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("600"));
    response
}

async fn request_reset(
    State(config): State<Arc<PasswordResetHttpConfig>>,
    request: Request,
) -> Response {
    let headers = request.headers().clone();
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|value| value.0);
    let mut response = request_inner(&config, request, &headers, peer).await;
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

async fn request_inner(
    config: &PasswordResetHttpConfig,
    request: Request,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
) -> Response {
    if !csrf_allowed(headers, &config.csrf_cookie_name, &config.trusted_origins) {
        return error(
            StatusCode::FORBIDDEN,
            "CSRF_FAILED",
            "CSRF verification failed",
        );
    }
    let bytes = match body(request).await {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let Ok(payload) = serde_json::from_slice::<RequestIn>(&bytes) else {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "Invalid request body",
        );
    };
    if payload.email.len() > 254
        || payload.form_token.len() > 256
        || !crate::password_mail::valid_recipient(payload.email.trim())
    {
        return error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Введите корректный email.",
        );
    }
    let now = SystemTime::now();
    match consume_form_token(
        &config.cache,
        Some(&payload.form_token),
        "password_reset",
        now,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            return error(
                StatusCode::BAD_REQUEST,
                "INVALID_FORM_TOKEN",
                "Неверный или просроченный токен формы",
            );
        }
        Err(_) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            );
        }
    }
    let ip = client_ip(headers, peer);
    let email_digest = hex::encode(Sha256::digest(
        payload.email.trim().to_lowercase().as_bytes(),
    ));
    let blocked = match limited(&config.cache, &format!("rl:password_reset:ip:{ip}"), 5, now).await
    {
        Ok(value) => value,
        Err(_) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            );
        }
    };
    let blocked_email = match limited(
        &config.cache,
        &format!("rl:password_reset:email:{email_digest}"),
        5,
        now,
    )
    .await
    {
        Ok(value) => value,
        Err(_) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            );
        }
    };
    if blocked || blocked_email {
        return rate_response();
    }
    match crate::password_reset::request(&config.client, &payload.email, now).await {
        Ok(()) => json_response(
            StatusCode::OK,
            json!({"ok":true,"message":"Если аккаунт с таким email существует, вы получите письмо для восстановления доступа."}),
        ),
        Err(failure) => {
            tracing::error!(?failure, "Rust password reset request failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            )
        }
    }
}

async fn confirm_reset(
    State(config): State<Arc<PasswordResetHttpConfig>>,
    request: Request,
) -> Response {
    let headers = request.headers().clone();
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|value| value.0);
    let mut response = confirm_inner(&config, request, &headers, peer).await;
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

async fn confirm_inner(
    config: &PasswordResetHttpConfig,
    request: Request,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
) -> Response {
    if !csrf_allowed(headers, &config.csrf_cookie_name, &config.trusted_origins) {
        return error(
            StatusCode::FORBIDDEN,
            "CSRF_FAILED",
            "CSRF verification failed",
        );
    }
    let bytes = match body(request).await {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let Ok(payload) = serde_json::from_slice::<ConfirmIn>(&bytes) else {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "Invalid request body",
        );
    };
    if payload.key.is_empty()
        || payload.key.len() > 512
        || payload.password.is_empty()
        || payload.password.len() > 4096
    {
        return error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Неверные данные для восстановления пароля",
        );
    }
    let now = SystemTime::now();
    let ip = client_ip(headers, peer);
    match limited(
        &config.cache,
        &format!("rl:password_reset_confirm:ip:{ip}"),
        10,
        now,
    )
    .await
    {
        Ok(true) => return rate_response(),
        Ok(false) => {}
        Err(_) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            );
        }
    }
    match config
        .resetter
        .confirm(&payload.key, &payload.password, now)
        .await
    {
        Ok(ConfirmResult::Changed) => json_response(
            StatusCode::OK,
            json!({"ok":true,"message":"Пароль изменён. Войдите с новым паролем."}),
        ),
        Ok(ConfirmResult::WeakPassword) => error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Пароль не соответствует требованиям безопасности",
        ),
        Ok(ConfirmResult::Invalid) => error(
            StatusCode::BAD_REQUEST,
            "INVALID_RECOVERY_LINK",
            "Ссылка недействительна или уже использована. Запросите новое письмо.",
        ),
        Err(failure) => {
            tracing::error!(?failure, "Rust password reset confirmation failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            )
        }
    }
}
