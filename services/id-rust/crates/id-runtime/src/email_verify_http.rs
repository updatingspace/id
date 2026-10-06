//! Public email verification request/confirm endpoints, enabled only as a pilot.

use crate::{
    cache_store::CacheStore,
    email_status,
    email_verify::{self, ConfirmResult, VerifyKey},
    form_token_consume::consume_form_token,
    logout_http::{cookie_value, csrf_allowed},
    me_http::env_flag,
    session_store::session_codec_from_env,
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
use id_compat::{headers::session_token, session::SessionCodec};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{env, net::SocketAddr, sync::Arc, time::SystemTime};
use url::Url;
use ydb::Client;

const MAX_BODY: usize = 16 * 1024;
const WINDOW: u64 = 600;

pub struct EmailVerifyHttpConfig {
    client: Arc<Client>,
    cache: CacheStore,
    key: VerifyKey,
    codec: Option<Arc<SessionCodec>>,
    resend_enabled: bool,
    session_cookie_name: String,
    csrf_cookie_name: String,
    trusted_origins: Vec<String>,
}

impl EmailVerifyHttpConfig {
    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        if !env_flag("ID_AUTH_EMAIL_VERIFY_PILOT_ENABLED", false)? {
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
            bail!("unqualified Rust email verification is restricted to local debug YDB");
        }
        if !env_flag("ID_AUTH_FORM_TOKEN_ENABLED", false)? {
            bail!("email verification requires Rust form-token issuance");
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
                    bail!("invalid trusted origin for email verification");
                }
                Ok(url.origin().ascii_serialization())
            })
            .collect::<Result<Vec<_>>>()?;
        let table = env::var("YDB_CACHE_TABLE").unwrap_or_else(|_| "id_shared_cache".into());
        let cache = CacheStore::new(client.clone(), &table, "", 1)?;
        let resend_enabled = env_flag("ID_AUTH_EMAIL_RESEND_ENABLED", false)?;
        Ok(Some(Arc::new(Self {
            client,
            cache,
            key: VerifyKey::from_env()?,
            codec: resend_enabled.then(session_codec_from_env).transpose()?,
            resend_enabled,
            session_cookie_name: env::var("SESSION_COOKIE_NAME")
                .unwrap_or_else(|_| "sessionid".into()),
            csrf_cookie_name: env::var("CSRF_COOKIE_NAME").unwrap_or_else(|_| "csrftoken".into()),
            trusted_origins,
        })))
    }
}

pub fn router(config: Arc<EmailVerifyHttpConfig>) -> Router {
    Router::new()
        .route(
            "/api/v1/auth/email/verification/request",
            post(request).options(preflight),
        )
        .route(
            "/api/v1/auth/email/verification/confirm",
            post(confirm).options(preflight),
        )
        .route("/api/v1/auth/email/resend", post(resend).options(preflight))
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
    let Some(origin) = input.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
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
            HeaderValue::from_static("content-type, x-csrftoken, x-session-token, authorization"),
        );
        output.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("POST, OPTIONS"),
        );
    }
}

async fn preflight(
    State(config): State<Arc<EmailVerifyHttpConfig>>,
    headers: HeaderMap,
) -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

async fn body(request: Request) -> Result<Vec<u8>, Box<Response>> {
    let json = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
        });
    if !json {
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
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|v| !v.is_empty() && v.len() <= 128)
        .map(str::to_owned)
        .or_else(|| peer.map(|p| p.ip().to_string()))
        .unwrap_or_else(|| "unknown".into())
}

async fn limited(cache: &CacheStore, key: &str, maximum: i64, now: SystemTime) -> Result<bool> {
    Ok(cache.advance_window(key, WINDOW, now).await?.count > maximum)
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

async fn resend(State(config): State<Arc<EmailVerifyHttpConfig>>, headers: HeaderMap) -> Response {
    let mut response = resend_inner(&config, &headers).await;
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

async fn resend_inner(config: &EmailVerifyHttpConfig, headers: &HeaderMap) -> Response {
    if !config.resend_enabled {
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
    let Some(codec) = config.codec.as_ref() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "SERVICE_UNAVAILABLE",
            "Временно недоступно",
        );
    };
    let now = SystemTime::now();
    let status = match email_status::read(&config.client, codec.clone(), token, now).await {
        Ok(Some(status)) => status,
        Ok(None) => {
            return error(
                StatusCode::UNAUTHORIZED,
                if explicit.is_some() {
                    "INVALID_OR_EXPIRED_TOKEN"
                } else {
                    "UNAUTHORIZED"
                },
                "Недействительная сессия",
            );
        }
        Err(failure) => {
            tracing::error!(?failure, "Rust email resend session check failed");
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            );
        }
    };
    let email_digest = hex::encode(Sha256::digest(status.email.to_lowercase().as_bytes()));
    match limited(
        &config.cache,
        &format!("rl:email_verification:email:{email_digest}"),
        5,
        now,
    )
    .await
    {
        Ok(true) => return rate_response(),
        Ok(false) => {}
        Err(failure) => {
            tracing::error!(?failure, "Rust email resend rate limit failed");
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            );
        }
    }
    match email_verify::request(&config.client, &status.email, now).await {
        Ok(()) => json_response(
            StatusCode::OK,
            json!({"ok":true,"message":"Письмо с подтверждением отправлено"}),
        ),
        Err(failure) => {
            tracing::error!(?failure, "Rust email resend failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            )
        }
    }
}

async fn request(State(config): State<Arc<EmailVerifyHttpConfig>>, request: Request) -> Response {
    let headers = request.headers().clone();
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|v| v.0);
    let mut response = request_inner(&config, request, &headers, peer).await;
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

async fn request_inner(
    config: &EmailVerifyHttpConfig,
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
        Ok(v) => v,
        Err(r) => return *r,
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
        "email_verification",
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
    let blocked_ip = limited(
        &config.cache,
        &format!("rl:email_verification:ip:{ip}"),
        5,
        now,
    )
    .await;
    let blocked_email = limited(
        &config.cache,
        &format!("rl:email_verification:email:{email_digest}"),
        5,
        now,
    )
    .await;
    match (blocked_ip, blocked_email) {
        (Ok(true), _) | (_, Ok(true)) => return rate_response(),
        (Ok(false), Ok(false)) => {}
        _ => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            );
        }
    }
    match email_verify::request(&config.client, &payload.email, now).await {
        Ok(()) => json_response(
            StatusCode::OK,
            json!({"ok":true,"message":"Если адрес ожидает подтверждения, вы получите письмо со ссылкой."}),
        ),
        Err(failure) => {
            tracing::error!(?failure, "Rust email verification request failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            )
        }
    }
}

async fn confirm(State(config): State<Arc<EmailVerifyHttpConfig>>, request: Request) -> Response {
    let headers = request.headers().clone();
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|v| v.0);
    let mut response = confirm_inner(&config, request, &headers, peer).await;
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

async fn confirm_inner(
    config: &EmailVerifyHttpConfig,
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
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Ok(payload) = serde_json::from_slice::<ConfirmIn>(&bytes) else {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "Invalid request body",
        );
    };
    if payload.key.is_empty() || payload.key.len() > 512 {
        return error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Неверные данные для подтверждения email",
        );
    }
    let now = SystemTime::now();
    let ip = client_ip(headers, peer);
    match limited(
        &config.cache,
        &format!("rl:email_verification_confirm:ip:{ip}"),
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
    match email_verify::confirm(&config.client, &config.key, &payload.key, now).await {
        Ok(ConfirmResult::Verified) => json_response(
            StatusCode::OK,
            json!({"ok":true,"message":"Email подтверждён. Теперь можно войти в аккаунт."}),
        ),
        Ok(ConfirmResult::Invalid) => error(
            StatusCode::BAD_REQUEST,
            "INVALID_RECOVERY_LINK",
            "Ссылка недействительна или уже использована. Запросите новое письмо.",
        ),
        Err(failure) => {
            tracing::error!(?failure, "Rust email verification confirmation failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            )
        }
    }
}
