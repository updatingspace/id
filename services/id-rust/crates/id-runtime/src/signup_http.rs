//! Opt-in public signup. No session is returned before email verification.

use crate::{
    cache_store::CacheStore,
    form_token_consume::consume_form_token,
    logout_http::csrf_allowed,
    me_http::env_flag,
    signup::{self, SignupInput, SignupResult},
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
use chrono::{NaiveDate, Utc};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{env, net::SocketAddr, sync::Arc, time::SystemTime};
use tokio::sync::Semaphore;
use url::Url;
use ydb::Client;

const MAX_BODY: usize = 16 * 1024;

pub struct SignupHttpConfig {
    client: Arc<Client>,
    cache: CacheStore,
    hash_slots: Semaphore,
    csrf_cookie_name: String,
    trusted_origins: Vec<String>,
}

impl SignupHttpConfig {
    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        if !env_flag("ID_AUTH_SIGNUP_PILOT_ENABLED", false)? {
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
            bail!("unqualified Rust signup is restricted to local debug YDB");
        }
        if !env_flag("ID_AUTH_FORM_TOKEN_ENABLED", false)?
            || !env_flag("ID_AUTH_EMAIL_VERIFY_PILOT_ENABLED", false)?
        {
            bail!("signup requires form-token issuance and email verification");
        }
        let trusted_origins = env::var("CSRF_TRUSTED_ORIGINS")
            .unwrap_or_else(|_| "http://id.localhost,http://localhost:5175".into())
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|raw| {
                let url = Url::parse(raw)?;
                if !matches!(url.scheme(), "http" | "https")
                    || url.path() != "/"
                    || url.query().is_some()
                    || url.fragment().is_some()
                    || !url.username().is_empty()
                    || url.password().is_some()
                {
                    bail!("invalid trusted origin for signup");
                }
                Ok(url.origin().ascii_serialization())
            })
            .collect::<Result<Vec<_>>>()?;
        if trusted_origins.is_empty() {
            bail!("signup requires a trusted origin");
        }
        let table = env::var("YDB_CACHE_TABLE").unwrap_or_else(|_| "id_shared_cache".into());
        Ok(Some(Arc::new(Self {
            cache: CacheStore::new(client.clone(), &table, "", 1)?,
            client,
            hash_slots: Semaphore::new(2),
            csrf_cookie_name: env::var("CSRF_COOKIE_NAME").unwrap_or_else(|_| "csrftoken".into()),
            trusted_origins,
        })))
    }
}

pub fn router(config: Arc<SignupHttpConfig>) -> Router {
    Router::new()
        .route("/api/v1/auth/signup", post(signup).options(preflight))
        .with_state(config)
}

#[derive(Deserialize)]
struct SignupBody {
    username: Option<String>,
    email: Option<String>,
    password: String,
    form_token: Option<String>,
    language: Option<String>,
    timezone: Option<String>,
    consent_data_processing: Option<bool>,
    consent_marketing: Option<bool>,
    is_minor: Option<bool>,
    guardian_email: Option<String>,
    guardian_consent: Option<bool>,
    birth_date: Option<String>,
}

fn json_response(status: StatusCode, value: serde_json::Value) -> Response {
    let mut response = (status, Json(value)).into_response();
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
            HeaderValue::from_static("content-type, x-csrftoken"),
        );
        output.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("POST, OPTIONS"),
        );
    }
}

async fn preflight(State(config): State<Arc<SignupHttpConfig>>, headers: HeaderMap) -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

async fn signup(State(config): State<Arc<SignupHttpConfig>>, request: Request) -> Response {
    let headers = request.headers().clone();
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|v| v.0);
    let mut response = signup_inner(&config, request, &headers, peer).await;
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

async fn signup_inner(
    config: &SignupHttpConfig,
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
    let json_content = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
        });
    if !json_content {
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
    let Ok(payload) = serde_json::from_slice::<SignupBody>(&bytes) else {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "Invalid request body",
        );
    };
    let birth_date = match payload
        .birth_date
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        Some(value) => match NaiveDate::parse_from_str(value, "%Y-%m-%d") {
            Ok(date) if date <= Utc::now().date_naive() => Some(date),
            _ => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "VALIDATION_ERROR",
                    "Неверный формат birth_date (YYYY-MM-DD)",
                );
            }
        },
        None => None,
    };
    let is_minor = signup::requires_guardian(payload.is_minor.unwrap_or(false), birth_date);
    if is_minor && payload.guardian_consent != Some(true) {
        return error(
            StatusCode::BAD_REQUEST,
            "PARENTAL_CONSENT_REQUIRED",
            "Для пользователей младше 18 требуется согласие родителя/опекуна",
        );
    }
    if is_minor
        && payload
            .guardian_email
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
    {
        return error(
            StatusCode::BAD_REQUEST,
            "GUARDIAN_EMAIL_REQUIRED",
            "Укажите email родителя/опекуна",
        );
    }
    if payload.consent_data_processing != Some(true) {
        return error(
            StatusCode::BAD_REQUEST,
            "CONSENT_REQUIRED",
            "Требуется согласие на обработку персональных данных",
        );
    }
    let mut input = SignupInput {
        username: payload
            .username
            .unwrap_or_else(|| payload.email.clone().unwrap_or_default()),
        email: payload.email.unwrap_or_default(),
        password: payload.password,
        language: payload.language.unwrap_or_else(|| "en".into()),
        timezone: payload.timezone.unwrap_or_default(),
        consent_data_processing: true,
        consent_marketing: payload.consent_marketing.unwrap_or(false),
        is_minor,
        guardian_email: payload.guardian_email,
        guardian_consent: payload.guardian_consent.unwrap_or(false),
        birth_date,
    };
    if signup::validate(&mut input).is_err() {
        return error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Проверьте данные регистрации",
        );
    }
    let now = SystemTime::now();
    match consume_form_token(
        &config.cache,
        payload.form_token.as_deref(),
        "register",
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
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .map(str::to_owned)
        .or_else(|| peer.map(|addr| addr.ip().to_string()))
        .unwrap_or_else(|| "unknown".into());
    let email_hash = hex::encode(Sha256::digest(input.email.as_bytes()));
    let ip_budget = config
        .cache
        .advance_window(&format!("rl:register:ip:{ip}"), 600, now)
        .await;
    let email_budget = config
        .cache
        .advance_window(&format!("rl:register:email:{email_hash}"), 600, now)
        .await;
    match (ip_budget, email_budget) {
        (Ok(ip), Ok(email)) if ip.count <= 10 && email.count <= 5 => {}
        (Ok(_), Ok(_)) => {
            return error(
                StatusCode::TOO_MANY_REQUESTS,
                "SIGNUP_RATE_LIMITED",
                "Слишком много запросов",
            );
        }
        _ => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            );
        }
    }
    match signup::create(&config.client, &config.hash_slots, input, now).await {
        Ok(SignupResult::Created) => json_response(
            StatusCode::CREATED,
            json!({"meta":{"session_token":""},"verification_required":true}),
        ),
        Ok(SignupResult::EmailExists) => error(
            StatusCode::CONFLICT,
            "EMAIL_ALREADY_EXISTS",
            "Пользователь с таким e-mail уже зарегистрирован",
        ),
        Ok(SignupResult::UsernameExists) => error(
            StatusCode::CONFLICT,
            "USERNAME_ALREADY_EXISTS",
            "Имя пользователя уже занято",
        ),
        Err(failure) => {
            tracing::error!(?failure, "Rust signup failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            )
        }
    }
}
