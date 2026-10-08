//! Logout compatible with the legacy session and refresh-token contract.

use crate::{
    logout_store::revoke_current_session,
    me_http::{cookie_domain, env_flag, make_cookie, new_csrf_secret, response, same_site},
    session_store::session_codec_from_env,
};
use anyhow::{Result, bail};
use axum::{
    Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use cookie::{Cookie, SameSite};
use id_compat::{csrf, headers::session_token, session::SessionCodec};
use serde_json::json;
use std::{env, sync::Arc, time::SystemTime};
use url::Url;
use ydb::Client;

pub struct LogoutHttpConfig {
    client: Arc<Client>,
    codec: Arc<SessionCodec>,
    session_cookie_name: String,
    csrf_cookie_name: String,
    session_cookie_secure: bool,
    csrf_cookie_secure: bool,
    session_same_site: SameSite,
    csrf_same_site: SameSite,
    session_cookie_domain: Option<String>,
    csrf_cookie_domain: Option<String>,
    trusted_origins: Vec<String>,
}

impl LogoutHttpConfig {
    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        let local_pilot = env_flag("ID_AUTH_LOGOUT_PILOT_ENABLED", false)?;
        let production_rollout = env_flag("ID_AUTH_LOGOUT_ROLLOUT_ENABLED", false)?;
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
            bail!("incomplete Rust logout pilot is restricted to local debug YDB");
        }
        if production_rollout && !local_ydb && !env_flag("ID_RUST_EARLY_ROLLOUT_ENABLED", false)? {
            bail!("Rust logout rollout requires ID_RUST_EARLY_ROLLOUT_ENABLED");
        }
        let trusted_origins = env::var("CSRF_TRUSTED_ORIGINS")
            .unwrap_or_else(|_| {
                "http://id.localhost,http://id.localhost:5175,http://localhost:5175".into()
            })
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| Url::parse(value).map(|url| url.origin().ascii_serialization()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(Arc::new(Self {
            client,
            codec: session_codec_from_env()?,
            session_cookie_name: env::var("SESSION_COOKIE_NAME")
                .unwrap_or_else(|_| "sessionid".into()),
            csrf_cookie_name: env::var("CSRF_COOKIE_NAME").unwrap_or_else(|_| "csrftoken".into()),
            session_cookie_secure: env_flag("SESSION_COOKIE_SECURE", true)?,
            csrf_cookie_secure: env_flag("CSRF_COOKIE_SECURE", true)?,
            session_same_site: same_site("SESSION_COOKIE_SAMESITE")?,
            csrf_same_site: same_site("CSRF_COOKIE_SAMESITE")?,
            session_cookie_domain: cookie_domain("SESSION_COOKIE_DOMAIN")?,
            csrf_cookie_domain: cookie_domain("CSRF_COOKIE_DOMAIN")?,
            trusted_origins,
        })))
    }
}

pub fn router(config: Arc<LogoutHttpConfig>) -> Router {
    Router::new()
        .route("/api/v1/auth/logout", post(logout).options(preflight))
        .with_state(config)
}

async fn logout(State(config): State<Arc<LogoutHttpConfig>>, headers: HeaderMap) -> Response {
    let mut result = logout_result(&config, &headers).await;
    add_cors(result.headers_mut(), &headers, &config.trusted_origins);
    result
}

async fn preflight(State(config): State<Arc<LogoutHttpConfig>>, headers: HeaderMap) -> Response {
    let mut result = StatusCode::NO_CONTENT.into_response();
    add_cors(result.headers_mut(), &headers, &config.trusted_origins);
    result
}

async fn logout_result(config: &LogoutHttpConfig, headers: &HeaderMap) -> Response {
    let csrf_cookie = make_cookie(
        &config.csrf_cookie_name,
        &new_csrf_secret(),
        config.csrf_cookie_secure,
        false,
        config.csrf_same_site,
        config.csrf_cookie_domain.as_deref(),
        Some(31_449_600),
    );
    let explicit = match session_token(headers) {
        Ok(token) => token,
        Err(_) => {
            return error(
                StatusCode::UNAUTHORIZED,
                "INVALID_OR_EXPIRED_TOKEN",
                csrf_cookie,
            );
        }
    };
    let browser_token = cookie_value(headers, &config.session_cookie_name);
    let Some(token) = explicit.or(browser_token.as_deref()) else {
        return error(
            StatusCode::UNAUTHORIZED,
            "INVALID_OR_EXPIRED_TOKEN",
            csrf_cookie,
        );
    };
    if explicit.is_none()
        && !csrf_allowed(headers, &config.csrf_cookie_name, &config.trusted_origins)
    {
        return error(StatusCode::FORBIDDEN, "CSRF_FAILED", csrf_cookie);
    }
    match revoke_current_session(
        &config.client,
        config.codec.clone(),
        token,
        SystemTime::now(),
    )
    .await
    {
        Ok(Some(())) => {
            let cleared = make_cookie(
                &config.session_cookie_name,
                "",
                config.session_cookie_secure,
                true,
                config.session_same_site,
                config.session_cookie_domain.as_deref(),
                Some(0),
            );
            response(
                StatusCode::OK,
                json!({"ok":true,"message":"logged out"}),
                csrf_cookie,
                Some(cleared),
            )
        }
        Ok(None) => error(
            StatusCode::UNAUTHORIZED,
            "INVALID_OR_EXPIRED_TOKEN",
            csrf_cookie,
        ),
        Err(failure) => {
            tracing::error!(?failure, "Rust logout transaction failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                csrf_cookie,
            )
        }
    }
}

fn add_cors(output: &mut HeaderMap, input: &HeaderMap, trusted_origins: &[String]) {
    let origin = input
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok());
    let canonical = origin
        .and_then(|raw| Url::parse(raw).ok())
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

pub(crate) fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|raw| Cookie::split_parse(raw.to_owned()).flatten())
        .find(|cookie| cookie.name() == name)
        .map(|cookie| cookie.value().to_owned())
}

pub(crate) fn csrf_allowed(
    headers: &HeaderMap,
    csrf_cookie_name: &str,
    trusted_origins: &[String],
) -> bool {
    let origin = headers
        .get(header::ORIGIN)
        .or_else(|| headers.get(header::REFERER))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Url::parse(value).ok())
        .filter(|url| {
            matches!(url.scheme(), "http" | "https")
                && url.username().is_empty()
                && url.password().is_none()
        })
        .map(|url| url.origin().ascii_serialization());
    if origin
        .as_ref()
        .is_some_and(|value| !trusted_origins.contains(value))
    {
        return false;
    }
    if headers.contains_key("sec-fetch-site") && origin.is_none() {
        return false;
    }
    let cookie = cookie_value(headers, csrf_cookie_name);
    let provided = headers
        .get("x-csrftoken")
        .and_then(|value| value.to_str().ok());
    cookie
        .as_deref()
        .zip(provided)
        .and_then(|(cookie, provided)| csrf::matches(cookie, provided).ok())
        .unwrap_or(false)
}

fn error(status: StatusCode, code: &str, csrf_cookie: String) -> Response {
    let message = match code {
        "CSRF_FAILED" => "CSRF verification failed",
        "SERVICE_UNAVAILABLE" => "Временно недоступно",
        _ => "Сессия недействительна, пожалуйста, войдите заново",
    };
    response(
        status,
        json!({
            "code": code, "message": message,
            "details": null, "errors": null, "fields": null,
            "detail": format!("{{'code': '{code}', 'message': '{message}'}}"),
            "status": status.as_u16(),
        }),
        csrf_cookie,
        None,
    )
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn browser_logout_requires_matching_csrf_and_trusted_origin() {
        let trusted = vec!["http://id.localhost:5175".to_owned()];
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            axum::http::HeaderValue::from_static(
                "sessionid=session; csrftoken=abcdefghijklmnopqrstuvwxyzABCDEF",
            ),
        );
        headers.insert(
            "x-csrftoken",
            axum::http::HeaderValue::from_static("abcdefghijklmnopqrstuvwxyzABCDEF"),
        );
        assert!(csrf_allowed(&headers, "csrftoken", &trusted));
        headers.insert(
            header::ORIGIN,
            axum::http::HeaderValue::from_static("https://attacker.invalid"),
        );
        assert!(!csrf_allowed(&headers, "csrftoken", &trusted));
        headers.insert(
            header::ORIGIN,
            axum::http::HeaderValue::from_static("http://id.localhost:5175"),
        );
        assert!(csrf_allowed(&headers, "csrftoken", &trusted));
        headers.insert("x-csrftoken", axum::http::HeaderValue::from_static("wrong"));
        assert!(!csrf_allowed(&headers, "csrftoken", &trusted));
        headers.remove("x-csrftoken");
        assert!(!csrf_allowed(&headers, "csrftoken", &trusted));
        let mut response = HeaderMap::new();
        add_cors(&mut response, &headers, &trusted);
        assert_eq!(
            response[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            "http://id.localhost:5175"
        );
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://attacker.invalid"),
        );
        let mut response = HeaderMap::new();
        add_cors(&mut response, &headers, &trusted);
        assert!(!response.contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
    }
}
