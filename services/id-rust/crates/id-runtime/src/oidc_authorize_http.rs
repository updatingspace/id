//! Local-only silent SSO for OIDC clients with remembered consent.

use crate::{
    logout_http::{cookie_value, csrf_allowed},
    me_http::{cookie_domain, env_flag, make_cookie, new_csrf_secret, same_site},
    oidc_authorize::{
        Authorization, authorize_remembered, parse_authorization_query, prepare_authorization,
    },
    oidc_consent::{Decision, DecisionOutcome, decide},
    session_store::session_codec_from_env,
};
use anyhow::{Result, bail};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use cookie::SameSite;
use id_compat::{headers::session_token, session::SessionCodec};
use serde::Deserialize;
use serde_json::json;
use std::{env, sync::Arc, time::SystemTime};
use url::Url;
use ydb::Client;

pub struct OidcAuthorizeHttpConfig {
    client: Arc<Client>,
    codec: Arc<SessionCodec>,
    session_cookie_name: String,
    csrf_cookie_name: String,
    csrf_cookie_secure: bool,
    csrf_same_site: SameSite,
    csrf_cookie_domain: Option<String>,
    trusted_origins: Vec<String>,
}

impl OidcAuthorizeHttpConfig {
    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        let local_pilot = env_flag("ID_OIDC_AUTHORIZE_PILOT_ENABLED", false)?;
        let production_rollout = env_flag("ID_OIDC_AUTHORIZE_ROLLOUT_ENABLED", false)?;
        if !local_pilot && !production_rollout {
            return Ok(None);
        }
        if !env_flag("ID_OIDC_TOKEN_PILOT_ENABLED", false)?
            && !env_flag("ID_OIDC_TOKEN_ROLLOUT_ENABLED", false)?
        {
            bail!("Rust OIDC authorization requires the opt-in token endpoint");
        }
        let endpoint = Url::parse(&env::var("YDB_ENDPOINT")?)?;
        let local_ydb = env_flag("DJANGO_DEBUG", false)?
            && matches!(
                endpoint.host_str(),
                Some("localhost" | "127.0.0.1" | "[::1]")
            )
            && env::var("YDB_DATABASE")?.as_str() == "/local";
        if local_pilot && !local_ydb {
            bail!("incomplete Rust OIDC authorization is restricted to local debug YDB");
        }
        if production_rollout && !local_ydb && !env_flag("ID_RUST_EARLY_ROLLOUT_ENABLED", false)? {
            bail!("Rust OIDC authorization rollout requires ID_RUST_EARLY_ROLLOUT_ENABLED");
        }
        Ok(Some(Arc::new(Self {
            client,
            codec: session_codec_from_env()?,
            session_cookie_name: env::var("SESSION_COOKIE_NAME")
                .unwrap_or_else(|_| "sessionid".into()),
            csrf_cookie_name: env::var("CSRF_COOKIE_NAME").unwrap_or_else(|_| "csrftoken".into()),
            csrf_cookie_secure: env_flag("CSRF_COOKIE_SECURE", true)?,
            csrf_same_site: same_site("CSRF_COOKIE_SAMESITE")?,
            csrf_cookie_domain: cookie_domain("CSRF_COOKIE_DOMAIN")?,
            trusted_origins: env::var("CSRF_TRUSTED_ORIGINS")
                .unwrap_or_else(|_| "http://id.localhost,http://localhost:5175".into())
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| Url::parse(value).map(|url| url.origin().ascii_serialization()))
                .collect::<std::result::Result<Vec<_>, _>>()?,
        })))
    }
}

pub fn router(config: Arc<OidcAuthorizeHttpConfig>) -> Router {
    Router::new()
        .route("/oauth/authorize", get(authorize).post(authorize))
        .route("/oauth/authorize/prepare", get(prepare))
        .route("/oauth/authorize/approve", post(approve))
        .route("/oauth/authorize/deny", post(deny))
        .with_state(config)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionIn {
    request_id: String,
    scopes: Option<Vec<String>>,
    #[serde(default = "remember_default")]
    remember: bool,
}

fn remember_default() -> bool {
    true
}

async fn approve(State(config): State<Arc<OidcAuthorizeHttpConfig>>, request: Request) -> Response {
    decision_http(config, request, true).await
}

async fn deny(State(config): State<Arc<OidcAuthorizeHttpConfig>>, request: Request) -> Response {
    decision_http(config, request, false).await
}

async fn decision_http(
    config: Arc<OidcAuthorizeHttpConfig>,
    request: Request,
    approving: bool,
) -> Response {
    let headers = request.headers();
    let explicit = match session_token(headers) {
        Ok(value) => value,
        Err(_) => return error(StatusCode::UNAUTHORIZED, "invalid_session"),
    };
    let cookie = cookie_value(headers, &config.session_cookie_name);
    let Some(token) = explicit.or(cookie.as_deref()).map(str::to_owned) else {
        return error(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    if explicit.is_none()
        && !csrf_allowed(headers, &config.csrf_cookie_name, &config.trusted_origins)
    {
        return error(StatusCode::FORBIDDEN, "csrf_failed");
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
        return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "invalid_request");
    }
    let bytes = match to_bytes(request.into_body(), 4097).await {
        Ok(value) if value.len() <= 4096 => value,
        _ => return error(StatusCode::PAYLOAD_TOO_LARGE, "invalid_request"),
    };
    let Ok(payload) = serde_json::from_slice::<DecisionIn>(&bytes) else {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_request");
    };
    if !approving && (payload.scopes.is_some() || !payload.remember) {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_request");
    }
    let decision = if approving {
        Decision::Approve {
            scopes: payload.scopes,
            remember: payload.remember,
        }
    } else {
        Decision::Deny
    };
    match decide(
        &config.client,
        config.codec.clone(),
        &token,
        &payload.request_id,
        decision,
        SystemTime::now(),
    )
    .await
    {
        Ok(DecisionOutcome::Redirect(url)) => {
            json_response(StatusCode::OK, json!({"redirect_uri":url}))
        }
        Ok(DecisionOutcome::Unauthorized) => error(StatusCode::UNAUTHORIZED, "unauthorized"),
        Ok(DecisionOutcome::NotFound) => error(StatusCode::NOT_FOUND, "request_not_found"),
        Ok(DecisionOutcome::Expired) => error(StatusCode::BAD_REQUEST, "request_expired"),
        Ok(DecisionOutcome::InvalidScope) => error(StatusCode::BAD_REQUEST, "invalid_scope"),
        Ok(DecisionOutcome::InvalidClient) => error(StatusCode::BAD_REQUEST, "invalid_client"),
        Err(failure) => {
            tracing::error!(?failure, "Rust OIDC decision failed");
            error(StatusCode::SERVICE_UNAVAILABLE, "server_error")
        }
    }
}

async fn authorize(
    State(config): State<Arc<OidcAuthorizeHttpConfig>>,
    request: Request,
) -> Response {
    let headers = request.headers().clone();
    let (request_uri_query, params) = if request.method() == Method::POST {
        let form = headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| {
                value
                    .trim()
                    .eq_ignore_ascii_case("application/x-www-form-urlencoded")
            });
        if !form {
            return error(StatusCode::BAD_REQUEST, "invalid_request");
        }
        let body = match to_bytes(request.into_body(), 16_385).await {
            Ok(body) if body.len() <= 16_384 => body,
            _ => return error(StatusCode::BAD_REQUEST, "invalid_request"),
        };
        let Ok(raw) = std::str::from_utf8(&body) else {
            return error(StatusCode::BAD_REQUEST, "invalid_request");
        };
        let Some(params) = parse_authorization_query(raw) else {
            return error(StatusCode::BAD_REQUEST, "invalid_request");
        };
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.extend_pairs(params.iter());
        (query.finish(), params)
    } else {
        let raw = request.uri().query().unwrap_or("");
        let Some(params) = parse_authorization_query(raw) else {
            return error(StatusCode::BAD_REQUEST, "invalid_request");
        };
        (raw.to_owned(), params)
    };
    let explicit = match session_token(&headers) {
        Ok(value) => value,
        Err(_) => return error(StatusCode::UNAUTHORIZED, "invalid_session"),
    };
    let cookie = cookie_value(&headers, &config.session_cookie_name);
    let session = explicit.or(cookie.as_deref());
    let silent = params.get("prompt").is_some_and(|value| value == "none");
    let redirect_uri = params.get("redirect_uri").cloned().unwrap_or_default();
    let state = params.get("state").cloned().unwrap_or_default();
    let result = authorize_remembered(
        &config.client,
        config.codec.clone(),
        session,
        params,
        SystemTime::now(),
    )
    .await;
    match result {
        Ok(Authorization::Redirect(url)) => redirect(&url),
        Ok(Authorization::ConsentRequired(url)) if silent => redirect(&url),
        Ok(Authorization::ConsentRequired(_)) => {
            let next = format!("/oauth/consent?{}", request_uri_query.as_str());
            redirect(&next)
        }
        Ok(Authorization::Prepared(_)) => error(StatusCode::SERVICE_UNAVAILABLE, "server_error"),
        Ok(Authorization::LoginRequired) if silent => {
            let Ok(mut url) = Url::parse(&redirect_uri) else {
                return error(StatusCode::BAD_REQUEST, "invalid_request");
            };
            // The store validates the exact redirect before returning LoginRequired.
            url.query_pairs_mut()
                .append_pair("error", "login_required")
                .append_pair("state", &state);
            redirect(url.as_str())
        }
        Ok(Authorization::LoginRequired) => {
            let next = format!("/oauth/consent?{}", request_uri_query.as_str());
            let encoded: String = url::form_urlencoded::byte_serialize(next.as_bytes()).collect();
            redirect(&format!("/login?next={encoded}"))
        }
        Ok(Authorization::InvalidClient) => error(StatusCode::NOT_FOUND, "invalid_client"),
        Ok(Authorization::InvalidRedirect | Authorization::InvalidRequest) => {
            error(StatusCode::BAD_REQUEST, "invalid_request")
        }
        Err(failure) => {
            tracing::error!(?failure, "Rust OIDC authorize failed");
            error(StatusCode::SERVICE_UNAVAILABLE, "server_error")
        }
    }
}

async fn prepare(State(config): State<Arc<OidcAuthorizeHttpConfig>>, request: Request) -> Response {
    let csrf_cookie = if cookie_value(request.headers(), &config.csrf_cookie_name).is_none() {
        Some(make_cookie(
            &config.csrf_cookie_name,
            &new_csrf_secret(),
            config.csrf_cookie_secure,
            false,
            config.csrf_same_site,
            config.csrf_cookie_domain.as_deref(),
            Some(31_449_600),
        ))
    } else {
        None
    };
    let Some(params) = request.uri().query().and_then(parse_authorization_query) else {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let explicit = match session_token(request.headers()) {
        Ok(value) => value,
        Err(_) => return error(StatusCode::UNAUTHORIZED, "invalid_session"),
    };
    let cookie = cookie_value(request.headers(), &config.session_cookie_name);
    let result = prepare_authorization(
        &config.client,
        config.codec.clone(),
        explicit.or(cookie.as_deref()),
        params,
        SystemTime::now(),
    )
    .await;
    let mut response = match result {
        Ok(Authorization::Prepared(prepared)) => {
            let scopes: Vec<_> = prepared
                .scopes
                .iter()
                .map(|scope| {
                    json!({
                        "name": scope, "description": scope_description(scope),
                        "required": scope == "openid", "granted": true,
                    })
                })
                .collect();
            json_response(
                StatusCode::OK,
                json!({
                    "action":"consent", "request_id":prepared.request_id,
                    "client":{"client_id":prepared.client_id,"name":prepared.client_name,"logo_url":prepared.client_logo_url},
                    "scopes":scopes,"consent_required":true,"state":prepared.state,
                    "redirect_uri":prepared.redirect_uri,
                }),
            )
        }
        Ok(Authorization::Redirect(url) | Authorization::ConsentRequired(url)) => json_response(
            StatusCode::OK,
            json!({"action":"redirect","redirect_uri":url}),
        ),
        Ok(Authorization::LoginRequired) => {
            json_response(StatusCode::OK, json!({"action":"login"}))
        }
        Ok(Authorization::InvalidClient) => error(StatusCode::NOT_FOUND, "invalid_client"),
        Ok(Authorization::InvalidRedirect | Authorization::InvalidRequest) => {
            error(StatusCode::BAD_REQUEST, "invalid_request")
        }
        Err(failure) => {
            tracing::error!(?failure, "Rust OIDC prepare failed");
            error(StatusCode::SERVICE_UNAVAILABLE, "server_error")
        }
    };
    if let Some(cookie) = csrf_cookie.and_then(|value| HeaderValue::from_str(&value).ok()) {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}

fn scope_description(scope: &str) -> &'static str {
    match scope {
        "openid" => "Идентификатор пользователя",
        "email" => "Адрес электронной почты",
        "profile" => "Базовый профиль",
        "profile_basic" => "Имя и аватар",
        "profile_extended" => "Расширенный профиль (дата рождения, язык, имя, аватар)",
        "phone" => "Номер телефона",
        "address" => "Почтовый адрес",
        "offline_access" => "Доступ без присутствия пользователя",
        _ => "",
    }
}

fn json_response(status: StatusCode, body: serde_json::Value) -> Response {
    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

fn redirect(url: &str) -> Response {
    let Ok(location) = HeaderValue::from_str(url) else {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let mut response = StatusCode::FOUND.into_response();
    response.headers_mut().insert(header::LOCATION, location);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

fn error(status: StatusCode, code: &str) -> Response {
    let mut response = (status, Json(json!({"error": code}))).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}
