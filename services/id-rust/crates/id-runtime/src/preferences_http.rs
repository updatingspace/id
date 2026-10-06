//! Local-only account preferences and timezone HTTP compatibility pilot.

use crate::{
    consent_store::{ConsentOperation, ConsentResult, account_consents},
    logout_http::{cookie_value, csrf_allowed},
    me_http::env_flag,
    preferences_domain::timezone_catalogue,
    preferences_store::{PreferenceChanges, get_or_update_preferences},
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
use serde_json::{Map, Value, json};
use std::{env, sync::Arc, time::SystemTime};
use url::Url;
use ydb::Client;

const MAX_BODY: usize = 16 * 1024;

pub struct PreferencesHttpConfig {
    client: Arc<Client>,
    codec: Arc<SessionCodec>,
    session_cookie_name: String,
    csrf_cookie_name: String,
    trusted_origins: Vec<String>,
}

impl PreferencesHttpConfig {
    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        let local_pilot = env_flag("ID_AUTH_PREFERENCES_PILOT_ENABLED", false)?;
        let production_rollout = env_flag("ID_AUTH_PREFERENCES_ROLLOUT_ENABLED", false)?;
        if !local_pilot && !production_rollout {
            return Ok(None);
        }
        let endpoint = Url::parse(&env::var("YDB_ENDPOINT")?)?;
        let local_ydb = env_flag("DJANGO_DEBUG", false)?
            && matches!(
                endpoint.host_str(),
                Some("localhost" | "127.0.0.1" | "[::1]")
            )
            && env::var("YDB_DATABASE")?.as_str() == "/local";
        if local_pilot && !local_ydb {
            bail!("incomplete Rust preferences pilot is restricted to local debug YDB");
        }
        if production_rollout && !local_ydb && !env_flag("ID_RUST_EARLY_ROLLOUT_ENABLED", false)? {
            bail!("Rust preferences rollout requires ID_RUST_EARLY_ROLLOUT_ENABLED");
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
                    bail!("invalid trusted origin for preferences pilot");
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

pub fn router(config: Arc<PreferencesHttpConfig>) -> Router {
    Router::new()
        .route(
            "/api/v1/auth/preferences",
            get(read).patch(update).options(preflight),
        )
        .route("/api/v1/auth/timezones", get(timezones))
        .route(
            "/api/v1/auth/consents",
            get(consents_read).options(preflight),
        )
        .route(
            "/api/v1/auth/consents/revoke",
            axum::routing::post(consents_revoke).options(preflight),
        )
        .with_state(config)
}

#[derive(Deserialize)]
struct PreferencesUpdateIn {
    language: Option<String>,
    timezone: Option<String>,
    marketing_opt_in: Option<bool>,
    privacy_scope_defaults: Option<Map<String, Value>>,
}

async fn read(State(config): State<Arc<PreferencesHttpConfig>>, request: Request) -> Response {
    let headers = request.headers().clone();
    let mut response = read_or_update(&config, request, false).await;
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

async fn update(State(config): State<Arc<PreferencesHttpConfig>>, request: Request) -> Response {
    let headers = request.headers().clone();
    let mut response = read_or_update(&config, request, true).await;
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

async fn read_or_update(
    config: &PreferencesHttpConfig,
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
                "Сессия недействительна, пожалуйста, войдите заново",
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
    let changes = if mutation {
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
            Ok(value) if value.len() <= MAX_BODY => value,
            _ => {
                return error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "VALIDATION_ERROR",
                    "Invalid request body",
                );
            }
        };
        let Ok(payload) = serde_json::from_slice::<PreferencesUpdateIn>(&bytes) else {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_ERROR",
                "Invalid request body",
            );
        };
        Some(PreferenceChanges {
            language: payload.language,
            timezone: payload.timezone,
            marketing_opt_in: payload.marketing_opt_in,
            privacy_scope_defaults: payload.privacy_scope_defaults,
        })
    } else {
        None
    };
    match get_or_update_preferences(
        &config.client,
        config.codec.clone(),
        &token,
        changes,
        SystemTime::now(),
    )
    .await
    {
        Ok(Some(value)) => json_response(StatusCode::OK, json!(value)),
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
            tracing::error!(?failure, "Rust preferences operation failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            )
        }
    }
}

async fn timezones() -> Response {
    json_response(StatusCode::OK, json!({"timezones": timezone_catalogue()}))
}

async fn consents_read(
    State(config): State<Arc<PreferencesHttpConfig>>,
    request: Request,
) -> Response {
    let headers = request.headers().clone();
    let mut response = consent_request(&config, request, false).await;
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

async fn consents_revoke(
    State(config): State<Arc<PreferencesHttpConfig>>,
    request: Request,
) -> Response {
    let headers = request.headers().clone();
    let mut response = consent_request(&config, request, true).await;
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

async fn consent_request(
    config: &PreferencesHttpConfig,
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
    let operation = if mutation {
        let kinds: Vec<String> =
            url::form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes())
                .filter(|(key, _)| key == "kind")
                .map(|(_, value)| value.into_owned())
                .collect();
        if kinds.len() != 1
            || kinds[0].is_empty()
            || kinds[0].len() > 32
            || kinds[0].chars().any(char::is_control)
        {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_ERROR",
                "Invalid consent kind",
            );
        }
        ConsentOperation::Revoke(kinds[0].clone())
    } else {
        ConsentOperation::List
    };
    let explicit_present = explicit.is_some();
    match account_consents(
        &config.client,
        config.codec.clone(),
        token,
        operation,
        SystemTime::now(),
    )
    .await
    {
        Ok(Some(ConsentResult::Listed(items))) => {
            json_response(StatusCode::OK, json!({"consents":items}))
        }
        Ok(Some(ConsentResult::Revoked(true))) => json_response(
            StatusCode::OK,
            json!({"ok":true,"message":"Согласие отозвано"}),
        ),
        Ok(Some(ConsentResult::Revoked(false))) => error(
            StatusCode::BAD_REQUEST,
            "CONSENT_NOT_FOUND",
            "Согласие не найдено",
        ),
        Ok(Some(ConsentResult::Required)) => error(
            StatusCode::BAD_REQUEST,
            "CONSENT_REQUIRED",
            "Отзыв согласия на обработку данных требует удаления аккаунта",
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
            tracing::error!(?failure, "Rust account consent operation failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            )
        }
    }
}

async fn preflight(
    State(config): State<Arc<PreferencesHttpConfig>>,
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
        json!({
            "code":code,"message":message,"details":null,"errors":null,"fields":null,
            "detail":format!("{{'code': '{code}', 'message': '{message}'}}"),"status":status.as_u16(),
        }),
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
            HeaderValue::from_static("GET, PATCH, POST, OPTIONS"),
        );
        output.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Content-Type, X-CSRFToken, X-Session-Token, Authorization"),
        );
    }
}
