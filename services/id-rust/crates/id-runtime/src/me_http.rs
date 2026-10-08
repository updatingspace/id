//! Opt-in HTTP boundary for the first Rust account route.

use crate::{
    me_store::restore_django_profile,
    media_url::MediaUrl,
    profile_response::CurrentUserOut,
    session_store::{LEGACY_BACKENDS, session_codec_from_env},
};
use anyhow::{Result, bail};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use cookie::{Cookie, SameSite};
use id_compat::{csrf, headers::session_token, session::SessionCodec};
use rand::{Rng, distr::Alphanumeric};
use serde::Serialize;
use serde_json::json;
use std::{env, sync::Arc, time::SystemTime};
use ydb::Client;

const INVALID_MESSAGE: &str = "Сессия недействительна, пожалуйста, войдите заново";

pub struct MeHttpConfig {
    client: Arc<Client>,
    codec: Arc<SessionCodec>,
    media: MediaUrl,
    session_cookie_name: String,
    csrf_cookie_name: String,
    session_cookie_secure: bool,
    csrf_cookie_secure: bool,
    session_same_site: SameSite,
    csrf_same_site: SameSite,
    session_cookie_domain: Option<String>,
    csrf_cookie_domain: Option<String>,
    session_cookie_age: u64,
    session_browser_close: bool,
}

impl MeHttpConfig {
    /// An unset flag leaves the existing API routes untouched. Private media
    /// URLs use the configured S3 signing credentials.
    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        if !env_flag("ID_AUTH_ME_ENABLED", false)? {
            return Ok(None);
        }
        let codec = session_codec_from_env()?;
        let media_base = if let Ok(base) = env::var("MEDIA_PUBLIC_BASE_URL") {
            base
        } else if let Ok(base) = env::var("MEDIA_URL") {
            if base.starts_with('/') {
                let origin = url::Url::parse(
                    &env::var("ID_ACTIVATION_BASE_URL")
                        .unwrap_or_else(|_| "http://id.localhost".into()),
                )?;
                origin.join(&base)?.to_string()
            } else {
                base
            }
        } else {
            let mut origin = url::Url::parse(
                &env::var("ID_ACTIVATION_BASE_URL")
                    .unwrap_or_else(|_| "http://id.localhost".into()),
            )?;
            origin.set_path("/media/");
            origin.to_string()
        };
        let media = MediaUrl::from_env(&media_base)?;
        let session_cookie_name =
            env::var("SESSION_COOKIE_NAME").unwrap_or_else(|_| "sessionid".into());
        let csrf_cookie_name = env::var("CSRF_COOKIE_NAME").unwrap_or_else(|_| "csrftoken".into());
        for name in [&session_cookie_name, &csrf_cookie_name] {
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            {
                bail!("invalid cookie name in Rust /me configuration");
            }
        }
        let config = Self {
            client,
            codec,
            media,
            session_cookie_name,
            csrf_cookie_name,
            session_cookie_secure: env_flag("SESSION_COOKIE_SECURE", true)?,
            csrf_cookie_secure: env_flag("CSRF_COOKIE_SECURE", true)?,
            session_same_site: same_site("SESSION_COOKIE_SAMESITE")?,
            csrf_same_site: same_site("CSRF_COOKIE_SAMESITE")?,
            session_cookie_domain: cookie_domain("SESSION_COOKIE_DOMAIN")?,
            csrf_cookie_domain: cookie_domain("CSRF_COOKIE_DOMAIN")?,
            session_cookie_age: env::var("SESSION_COOKIE_AGE")
                .ok()
                .map(|value| value.parse())
                .transpose()?
                .unwrap_or(1_209_600),
            session_browser_close: env_flag("SESSION_EXPIRE_AT_BROWSER_CLOSE", false)?,
        };
        Ok(Some(Arc::new(config)))
    }
}

pub fn router(config: Arc<MeHttpConfig>) -> Router {
    Router::new()
        .route("/api/v1/auth/me", get(me))
        .with_state(config)
}

async fn me(State(config): State<Arc<MeHttpConfig>>, headers: HeaderMap) -> Response {
    let cookies = request_cookies(&headers, &config);
    let csrf_secret = cookies
        .csrf
        .as_deref()
        .and_then(|value| csrf::cookie_secret(value).ok())
        .unwrap_or_else(new_csrf_secret);
    let csrf_cookie = make_cookie(
        &config.csrf_cookie_name,
        &csrf_secret,
        config.csrf_cookie_secure,
        false,
        config.csrf_same_site,
        config.csrf_cookie_domain.as_deref(),
        Some(31_449_600),
    );
    let explicit = match session_token(&headers) {
        Ok(value) => value,
        Err(_) => return invalid_session(csrf_cookie),
    };
    let token = explicit.or(cookies.session.as_deref());
    let Some(token) = token else {
        return response(StatusCode::OK, CurrentUserOut::guest(), csrf_cookie, None);
    };
    let profile = match restore_django_profile(
        &config.client,
        config.codec.clone(),
        token,
        LEGACY_BACKENDS,
        SystemTime::now(),
    )
    .await
    {
        Ok(Some(profile)) => profile,
        Ok(None) if explicit.is_some() => return invalid_session(csrf_cookie),
        Ok(None) => return response(StatusCode::OK, CurrentUserOut::guest(), csrf_cookie, None),
        Err(_) => {
            tracing::error!("Rust /me profile restore failed");
            return unavailable(csrf_cookie);
        }
    };
    let avatar_url = profile
        .details
        .profile
        .as_ref()
        .and_then(|fields| fields.avatar_key.as_deref())
        .and_then(|key| config.media.avatar_url(key).ok());
    let cookie_expiry = profile.cookie_expiry;
    let body = match CurrentUserOut::authenticated(profile.details, avatar_url) {
        Ok(body) => body,
        Err(_) => {
            tracing::error!("Rust /me profile assembly failed");
            return unavailable(csrf_cookie);
        }
    };
    let session_cookie = if explicit.is_some() && cookies.session.as_deref() != Some(token) {
        let age = cookie_expiry.max_age(
            SystemTime::now(),
            config.session_cookie_age,
            config.session_browser_close,
        );
        Some(make_cookie(
            &config.session_cookie_name,
            token,
            config.session_cookie_secure,
            true,
            config.session_same_site,
            config.session_cookie_domain.as_deref(),
            age,
        ))
    } else {
        None
    };
    response(StatusCode::OK, body, csrf_cookie, session_cookie)
}

struct RequestCookies {
    session: Option<String>,
    csrf: Option<String>,
}

fn request_cookies(headers: &HeaderMap, config: &MeHttpConfig) -> RequestCookies {
    let mut parsed = RequestCookies {
        session: None,
        csrf: None,
    };
    for header in headers.get_all(header::COOKIE).iter() {
        let Ok(raw) = header.to_str() else { continue };
        for cookie in Cookie::split_parse(raw.to_owned()).flatten() {
            if cookie.name() == config.session_cookie_name {
                parsed.session = Some(cookie.value().to_owned());
            } else if cookie.name() == config.csrf_cookie_name {
                parsed.csrf = Some(cookie.value().to_owned());
            }
        }
    }
    parsed
}

pub(crate) fn new_csrf_secret() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

pub(crate) fn make_cookie(
    name: &str,
    value: &str,
    secure: bool,
    http_only: bool,
    same_site: SameSite,
    domain: Option<&str>,
    max_age: Option<u64>,
) -> String {
    let mut builder = Cookie::build((name.to_owned(), value.to_owned()))
        .path("/")
        .secure(secure)
        .http_only(http_only)
        .same_site(same_site);
    if let Some(domain) = domain {
        builder = builder.domain(domain.to_owned());
    }
    if let Some(age) = max_age {
        let age = cookie::time::Duration::seconds(i64::try_from(age).unwrap_or(i64::MAX));
        builder = builder
            .max_age(age)
            .expires(cookie::time::OffsetDateTime::now_utc() + age);
    }
    builder.build().to_string()
}

pub(crate) fn response<T: Serialize>(
    status: StatusCode,
    body: T,
    csrf_cookie: String,
    session_cookie: Option<String>,
) -> Response {
    let mut response = (status, Json(body)).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(header::VARY, HeaderValue::from_static("Cookie, origin"));
    if let Ok(value) = HeaderValue::from_str(&csrf_cookie) {
        headers.append(header::SET_COOKIE, value);
    }
    if let Some(cookie) = session_cookie
        && let Ok(value) = HeaderValue::from_str(&cookie)
    {
        headers.append(header::SET_COOKIE, value);
    }
    response
}

fn invalid_session(csrf_cookie: String) -> Response {
    response(
        StatusCode::UNAUTHORIZED,
        json!({
            "code": "INVALID_OR_EXPIRED_TOKEN",
            "message": INVALID_MESSAGE,
            "details": null, "errors": null, "fields": null,
            "detail": format!("{{'code': 'INVALID_OR_EXPIRED_TOKEN', 'message': '{INVALID_MESSAGE}'}}"),
            "status": 401,
        }),
        csrf_cookie,
        None,
    )
}

fn unavailable(csrf_cookie: String) -> Response {
    response(
        StatusCode::SERVICE_UNAVAILABLE,
        json!({
            "code": "SERVICE_UNAVAILABLE", "message": "Временно недоступно"
        }),
        csrf_cookie,
        None,
    )
}

pub(crate) fn env_flag(name: &str, default: bool) -> Result<bool> {
    match env::var(name) {
        Ok(value) if matches!(value.to_ascii_lowercase().as_str(), "true" | "1") => Ok(true),
        Ok(value) if matches!(value.to_ascii_lowercase().as_str(), "false" | "0") => Ok(false),
        Ok(_) => bail!("{name} must be true/false"),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn same_site(name: &str) -> Result<SameSite> {
    match env::var(name)
        .unwrap_or_else(|_| "Lax".into())
        .to_ascii_lowercase()
        .as_str()
    {
        "lax" => Ok(SameSite::Lax),
        "strict" => Ok(SameSite::Strict),
        "none" => Ok(SameSite::None),
        _ => bail!("{name} must be Lax, Strict or None"),
    }
}

pub(crate) fn cookie_domain(name: &str) -> Result<Option<String>> {
    let value = env::var(name).ok().filter(|value| !value.is_empty());
    if value.as_ref().is_some_and(|domain| {
        !domain
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    }) {
        bail!("{name} contains an invalid cookie domain");
    }
    Ok(value)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn csrf_cookie_is_readable_and_reuses_valid_secret() {
        let secret = new_csrf_secret();
        assert_eq!(secret.len(), 32);
        assert!(secret.bytes().all(|byte| byte.is_ascii_alphanumeric()));
        let cookie = make_cookie(
            "csrftoken",
            &secret,
            true,
            false,
            SameSite::Lax,
            None,
            Some(31_449_600),
        );
        assert!(cookie.contains("Secure"));
        assert!(!cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert_eq!(csrf::cookie_secret(&secret).as_deref(), Ok(secret.as_str()));
    }

    #[test]
    fn invalid_header_error_has_django_body_and_cache_headers() {
        let response = invalid_session("csrftoken=synthetic; Path=/".into());
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
        assert_eq!(response.headers()[header::VARY], "Cookie, origin");
        assert!(response.headers().get(header::SET_COOKIE).is_some());
    }
}
