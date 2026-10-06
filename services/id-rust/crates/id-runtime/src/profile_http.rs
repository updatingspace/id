//! Local-only HTTP pilot for the legacy profile update contract.

use crate::{
    logout_http::{cookie_value, csrf_allowed},
    me_http::env_flag,
    profile_update::{ProfileChanges, update_profile},
    session_store::session_codec_from_env,
};
use anyhow::{Result, bail};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::patch,
};
use chrono::NaiveDate;
use id_compat::{headers::session_token, session::SessionCodec};
use serde::Deserialize;
use serde_json::json;
use std::{env, sync::Arc, time::SystemTime};
use url::Url;
use ydb::Client;

const MAX_BODY: usize = 16 * 1024;

pub struct ProfileHttpConfig {
    client: Arc<Client>,
    codec: Arc<SessionCodec>,
    session_cookie_name: String,
    csrf_cookie_name: String,
    trusted_origins: Vec<String>,
}

impl ProfileHttpConfig {
    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        let local_pilot = env_flag("ID_AUTH_PROFILE_PILOT_ENABLED", false)?;
        let production_rollout = env_flag("ID_AUTH_PROFILE_ROLLOUT_ENABLED", false)?;
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
            bail!("incomplete Rust profile pilot is restricted to local debug YDB");
        }
        if production_rollout && !local_ydb && !env_flag("ID_RUST_EARLY_ROLLOUT_ENABLED", false)? {
            bail!("Rust profile rollout requires ID_RUST_EARLY_ROLLOUT_ENABLED");
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
                    bail!("invalid trusted origin for profile pilot");
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

pub fn router(config: Arc<ProfileHttpConfig>) -> Router {
    Router::new()
        .route("/api/v1/auth/profile", patch(profile).options(preflight))
        .with_state(config)
}

#[derive(Deserialize)]
struct ProfileUpdateIn {
    first_name: Option<String>,
    last_name: Option<String>,
    phone_number: Option<String>,
    birth_date: Option<String>,
}

async fn profile(State(config): State<Arc<ProfileHttpConfig>>, request: Request) -> Response {
    let headers = request.headers().clone();
    let mut result = profile_result(&config, request).await;
    add_cors(result.headers_mut(), &headers, &config.trusted_origins);
    result
}

async fn profile_result(config: &ProfileHttpConfig, request: Request) -> Response {
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
    let Ok(payload) = serde_json::from_slice::<ProfileUpdateIn>(&bytes) else {
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
        Some(value) if parse_birth_date(value).is_none() => {
            return error(
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                "Неверный формат birth_date (YYYY-MM-DD)",
            );
        }
        Some(value) => parse_birth_date(value),
        None => None,
    };
    let ensure_profile = payload.phone_number.is_some() || payload.birth_date.is_some();
    let changes = ProfileChanges {
        first_name: payload.first_name.map(|value| value.trim().to_owned()),
        last_name: payload.last_name.map(|value| value.trim().to_owned()),
        phone_number: payload.phone_number.map(|value| value.trim().to_owned()),
        birth_date,
        ensure_profile,
    };
    match update_profile(
        &config.client,
        config.codec.clone(),
        &token,
        changes,
        SystemTime::now(),
    )
    .await
    {
        Ok(true) => json_response(
            StatusCode::OK,
            json!({"ok":true,"message":"Профиль обновлён"}),
        ),
        Ok(false) => error(
            StatusCode::UNAUTHORIZED,
            if explicit_present {
                "INVALID_OR_EXPIRED_TOKEN"
            } else {
                "UNAUTHORIZED"
            },
            "Сессия недействительна, пожалуйста, войдите заново",
        ),
        Err(failure) => {
            tracing::error!(?failure, "Rust profile update failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            )
        }
    }
}

fn parse_birth_date(value: &str) -> Option<String> {
    // Python date.fromisoformat accepts basic and ISO week forms as well as
    // YYYY-MM-DD; normalize before CAST to YDB Date.
    let bytes = value.as_bytes();
    let digits = |part: &[u8]| part.iter().all(u8::is_ascii_digit);
    if bytes.len() == 8
        && bytes[4] == b'-'
        && bytes[5] == b'W'
        && digits(&bytes[..4])
        && digits(&bytes[6..])
    {
        return NaiveDate::parse_from_str(&format!("{value}-1"), "%G-W%V-%u")
            .ok()
            .map(|date| date.format("%Y-%m-%d").to_string());
    }
    if matches!(bytes.len(), 7 | 8)
        && bytes[4] == b'W'
        && digits(&bytes[..4])
        && digits(&bytes[5..])
    {
        let weekday = if bytes.len() == 8 {
            bytes[7] as char
        } else {
            '1'
        };
        let normalized = format!("{}-W{}-{}", &value[..4], &value[5..7], weekday);
        return NaiveDate::parse_from_str(&normalized, "%G-W%V-%u")
            .ok()
            .map(|date| date.format("%Y-%m-%d").to_string());
    }
    let format = match bytes {
        [y0, y1, y2, y3, b'-', m0, m1, b'-', d0, d1]
            if [y0, y1, y2, y3, m0, m1, d0, d1]
                .iter()
                .all(|byte| byte.is_ascii_digit()) =>
        {
            "%Y-%m-%d"
        }
        [y0, y1, y2, y3, m0, m1, d0, d1]
            if [y0, y1, y2, y3, m0, m1, d0, d1]
                .iter()
                .all(|byte| byte.is_ascii_digit()) =>
        {
            "%Y%m%d"
        }
        [y0, y1, y2, y3, b'-', b'W', w0, w1, b'-', d0]
            if [y0, y1, y2, y3, w0, w1, d0]
                .iter()
                .all(|byte| byte.is_ascii_digit()) =>
        {
            "%G-W%V-%u"
        }
        _ => return None,
    };
    NaiveDate::parse_from_str(value, format)
        .ok()
        .map(|date| date.format("%Y-%m-%d").to_string())
}

async fn preflight(State(config): State<Arc<ProfileHttpConfig>>, headers: HeaderMap) -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

pub(crate) fn json_response(status: StatusCode, body: serde_json::Value) -> Response {
    let mut result = (status, Json(body)).into_response();
    result.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    result
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Cookie, origin"));
    result
}

pub(crate) fn error(status: StatusCode, code: &str, message: &str) -> Response {
    json_response(
        status,
        json!({
            "code":code,"message":message,"details":null,"errors":null,"fields":null,
            "detail":format!("{{'code': '{code}', 'message': '{message}'}}"),"status":status.as_u16(),
        }),
    )
}

pub(crate) fn add_cors(output: &mut HeaderMap, input: &HeaderMap, origins: &[String]) {
    add_cors_methods(output, input, origins, "PATCH, OPTIONS");
}

pub(crate) fn add_cors_methods(
    output: &mut HeaderMap,
    input: &HeaderMap,
    origins: &[String],
    methods: &'static str,
) {
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
            HeaderValue::from_static(methods),
        );
        output.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Content-Type, X-CSRFToken, X-Session-Token, Authorization"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::parse_birth_date;

    #[test]
    fn accepts_legacy_python_iso_date_forms() {
        for value in ["2024-01-02", "20240102", "2024-W01-2", "2024W012"] {
            assert_eq!(parse_birth_date(value).as_deref(), Some("2024-01-02"));
        }
        for value in ["2024-W01", "2024W01"] {
            assert_eq!(parse_birth_date(value).as_deref(), Some("2024-01-01"));
        }
        for value in ["2024-02-30", "2024-1-2", "2024-01-02 "] {
            assert!(parse_birth_date(value).is_none());
        }
    }
}
