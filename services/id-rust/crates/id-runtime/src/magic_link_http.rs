//! Browser and API consumption of Portal magic links.

use crate::{
    cache_store::CacheStore,
    magic_link_consume::{self, ConsumeFailure, ConsumeRequest},
    magic_link_request,
    me_http::env_flag,
};
use anyhow::{Result, bail, ensure};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use std::{collections::BTreeMap, env, sync::Arc, time::SystemTime};
use url::Url;
use uuid::Uuid;
use ydb::Client;

const PATH: &str = "/api/v1/auth/magic-link/consume";
const REQUEST_PATH: &str = "/api/v1/auth/magic-link/request";

pub struct MagicLinkHttpConfig {
    client: Arc<Client>,
    cache: CacheStore,
    token_secret: Vec<u8>,
    redirect_origins: Vec<Url>,
    request_enabled: bool,
    consume_enabled: bool,
    default_redirect: Option<String>,
}

impl MagicLinkHttpConfig {
    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        let enabled = env_flag("ID_AUTH_MAGIC_LINK_CONSUME_PILOT_ENABLED", false)?;
        let rollout = env_flag("ID_AUTH_MAGIC_LINK_CONSUME_ROLLOUT_ENABLED", false)?;
        let request_enabled = env_flag("ID_AUTH_MAGIC_LINK_REQUEST_PILOT_ENABLED", false)?;
        if !enabled && !rollout && !request_enabled {
            return Ok(None);
        }
        if request_enabled && !enabled && !rollout {
            bail!("magic-link request requires Rust consume");
        }
        if rollout && !env_flag("ID_RUST_EARLY_ROLLOUT_ENABLED", false)? {
            bail!("magic-link rollout requires the early rollout gate");
        }
        let secret = env::var("ID_TOKEN_HASH_SECRET").or_else(|_| env::var("DJANGO_SECRET_KEY"))?;
        ensure!(secret.len() >= 32, "magic-link token secret is too short");
        let table = env::var("YDB_CACHE_TABLE").unwrap_or_else(|_| "id_shared_cache".into());
        let origins = env::var("ID_MAGIC_LINK_REDIRECT_ORIGINS").unwrap_or_default();
        let redirect_origins = origins
            .split(',')
            .filter(|value| !value.trim().is_empty())
            .map(|value| {
                let url = Url::parse(value.trim())?;
                ensure!(
                    url.scheme() == "https"
                        && url.host_str().is_some()
                        && url.path() == "/"
                        && url.query().is_none()
                        && url.fragment().is_none()
                        && url.username().is_empty()
                        && url.password().is_none(),
                    "invalid magic-link redirect origin"
                );
                Ok(url)
            })
            .collect::<Result<Vec<_>>>()?;
        let default_redirect = env::var("ID_MAGIC_LINK_DEFAULT_REDIRECT")
            .ok()
            .filter(|value| !value.trim().is_empty());
        if request_enabled {
            ensure!(
                !redirect_origins.is_empty(),
                "magic-link redirect allowlist is required"
            );
            let public_url = env::var("ID_MAGIC_LINK_PUBLIC_URL")?;
            ensure!(
                public_url.starts_with("https://"),
                "magic-link public URL must be HTTPS"
            );
            magic_link_request::MailConfig::new(secret.as_bytes().to_vec(), &public_url)?;
            if let Some(value) = &default_redirect {
                ensure!(
                    allowed_redirect(value, &redirect_origins).is_some(),
                    "invalid default magic-link redirect"
                );
            }
        }
        Ok(Some(Arc::new(Self {
            cache: CacheStore::new(client.clone(), &table, "", 1)?,
            client,
            token_secret: secret.into_bytes(),
            redirect_origins,
            request_enabled,
            consume_enabled: enabled || rollout,
            default_redirect,
        })))
    }

    pub fn new(
        client: Arc<Client>,
        cache: CacheStore,
        token_secret: Vec<u8>,
        redirect_origins: Vec<Url>,
        request_enabled: bool,
    ) -> Result<Arc<Self>> {
        ensure!(
            token_secret.len() >= 32,
            "magic-link token secret is too short"
        );
        Ok(Arc::new(Self {
            client,
            cache,
            token_secret,
            redirect_origins,
            request_enabled,
            consume_enabled: true,
            default_redirect: None,
        }))
    }
}

pub fn router(config: Arc<MagicLinkHttpConfig>) -> Router {
    let mut router = Router::new();
    if config.consume_enabled {
        router = router.route(PATH, get(consume_get).post(consume_post));
    }
    if config.request_enabled {
        router = router.route(REQUEST_PATH, axum::routing::post(request_link));
    }
    router.with_state(config)
}

#[derive(Deserialize)]
struct RequestIn {
    email: String,
    redirect_to: Option<String>,
}

async fn request_link(
    State(config): State<Arc<MagicLinkHttpConfig>>,
    request: Request,
) -> Response {
    let context = match context(request.headers()) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let body = match to_bytes(request.into_body(), 4096).await {
        Ok(value) => value,
        Err(_) => {
            return error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "INVALID_BODY",
                "Request body too large",
            );
        }
    };
    let Ok(input) = serde_json::from_slice::<RequestIn>(&body) else {
        return error(StatusCode::BAD_REQUEST, "INVALID_BODY", "Invalid JSON body");
    };
    let email = input.email.trim().to_lowercase();
    if email.len() > 254 || !crate::password_mail::valid_recipient(&email) {
        return error(StatusCode::BAD_REQUEST, "INVALID_EMAIL", "Invalid email");
    }
    let redirect = input
        .redirect_to
        .filter(|value| !value.trim().is_empty())
        .or_else(|| config.default_redirect.clone());
    let Some(redirect) = redirect else {
        return error(
            StatusCode::BAD_REQUEST,
            "INVALID_REDIRECT",
            "Redirect is required",
        );
    };
    if allowed_redirect(&redirect, &config.redirect_origins).is_none() {
        return error(
            StatusCode::BAD_REQUEST,
            "INVALID_REDIRECT",
            "Redirect is not allowed",
        );
    }
    let mut key_mac = match Hmac::<Sha256>::new_from_slice(&config.token_secret) {
        Ok(value) => value,
        Err(_) => return unavailable(),
    };
    key_mac.update(email.as_bytes());
    key_mac.update(b"\n");
    key_mac.update(context.ip.as_bytes());
    let rate_key = format!(
        "usid:ml:rl:{}",
        hex::encode(key_mac.finalize().into_bytes())
    );
    let now = SystemTime::now();
    match config.cache.advance_window(&rate_key, 15 * 60, now).await {
        Ok(window) if window.count > 5 => {
            return error(
                StatusCode::TOO_MANY_REQUESTS,
                "RATE_LIMITED",
                "Too many requests",
            );
        }
        Err(failure) => {
            tracing::error!(?failure, "magic-link rate limit unavailable");
            return unavailable();
        }
        Ok(_) => {}
    }
    let input = magic_link_request::Request {
        email,
        tenant_id: context.tenant_id,
        tenant_slug: context.tenant_slug,
        redirect_to: redirect,
    };
    match magic_link_request::request(&config.client, &config.token_secret, input, now).await {
        Ok(()) => response(
            StatusCode::OK,
            json!({"ok":true,"sent":true,"dev_magic_link":null}),
        ),
        Err(failure) => {
            tracing::error!(?failure, "magic-link request unavailable");
            unavailable()
        }
    }
}

#[derive(Deserialize)]
struct ConsumeIn {
    token: String,
}

async fn consume_post(
    State(config): State<Arc<MagicLinkHttpConfig>>,
    request: Request,
) -> Response {
    let context = match context(request.headers()) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let body = match to_bytes(request.into_body(), 4096).await {
        Ok(body) => body,
        Err(_) => {
            return error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "INVALID_BODY",
                "Request body too large",
            );
        }
    };
    let Ok(input) = serde_json::from_slice::<ConsumeIn>(&body) else {
        return error(StatusCode::BAD_REQUEST, "INVALID_BODY", "Invalid JSON body");
    };
    consume_result(
        &config,
        ConsumeRequest {
            token: input.token,
            issue_exchange: false,
            ..context
        },
        None,
    )
    .await
}

async fn consume_get(State(config): State<Arc<MagicLinkHttpConfig>>, request: Request) -> Response {
    let Some(query) = request.uri().query() else {
        return error(StatusCode::BAD_REQUEST, "INVALID_QUERY", "Missing query");
    };
    let mut params = BTreeMap::new();
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if params
            .insert(key.into_owned(), value.into_owned())
            .is_some()
        {
            return error(
                StatusCode::BAD_REQUEST,
                "INVALID_QUERY",
                "Duplicate query parameter",
            );
        }
    }
    let (Some(token), Some(redirect), Some(tenant_id), Some(tenant_slug), Some(signature)) = (
        params.remove("token"),
        params.remove("redirect_to"),
        params.remove("tenant_id"),
        params.remove("tenant_slug"),
        params.remove("tenant_sig"),
    ) else {
        return error(
            StatusCode::BAD_REQUEST,
            "INVALID_QUERY",
            "Missing magic-link parameters",
        );
    };
    let Ok(tenant_id) = Uuid::parse_str(&tenant_id) else {
        return error(
            StatusCode::BAD_REQUEST,
            "INVALID_QUERY",
            "Invalid tenant ID",
        );
    };
    let Some(target) = allowed_redirect(&redirect, &config.redirect_origins) else {
        return error(
            StatusCode::BAD_REQUEST,
            "INVALID_REDIRECT",
            "Redirect is not allowed",
        );
    };
    if !verify_link_signature(
        &config.token_secret,
        &token,
        tenant_id,
        &tenant_slug,
        &redirect,
        &signature,
    ) {
        return error(
            StatusCode::FORBIDDEN,
            "INVALID_LINK",
            "Magic link is invalid",
        );
    }
    let ip = request_ip(request.headers());
    let user_agent = unique_header(request.headers(), "user-agent")
        .unwrap_or_default()
        .to_owned();
    consume_result(
        &config,
        ConsumeRequest {
            token,
            tenant_id,
            tenant_slug,
            ip,
            user_agent,
            issue_exchange: true,
        },
        Some(target),
    )
    .await
}

/// Bind the browser link's tenant and callback to the one-time token. The
/// request route uses this exact function when constructing a new link.
pub fn link_signature(
    secret: &[u8],
    token: &str,
    tenant_id: Uuid,
    tenant_slug: &str,
    redirect: &str,
) -> Result<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)?;
    mac.update(
        format!("updspace-magic-link-v1\n{token}\n{tenant_id}\n{tenant_slug}\n{redirect}")
            .as_bytes(),
    );
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn verify_link_signature(
    secret: &[u8],
    token: &str,
    tenant_id: Uuid,
    tenant_slug: &str,
    redirect: &str,
    signature: &str,
) -> bool {
    let Ok(bytes) = hex::decode(signature) else {
        return false;
    };
    if bytes.len() != 32 {
        return false;
    }
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret) else {
        return false;
    };
    mac.update(
        format!("updspace-magic-link-v1\n{token}\n{tenant_id}\n{tenant_slug}\n{redirect}")
            .as_bytes(),
    );
    mac.verify_slice(&bytes).is_ok()
}

async fn consume_result(
    config: &MagicLinkHttpConfig,
    request: ConsumeRequest,
    target: Option<Url>,
) -> Response {
    match magic_link_consume::consume(
        &config.client,
        &config.cache,
        &config.token_secret,
        request,
        SystemTime::now(),
    )
    .await
    {
        Ok(Ok(consumed)) => match target {
            Some(mut target) => {
                let Some(code) = consumed.exchange_code else {
                    return unavailable();
                };
                target.query_pairs_mut().append_pair("code", &code);
                let Ok(location) = HeaderValue::from_str(target.as_str()) else {
                    return unavailable();
                };
                let mut result = StatusCode::SEE_OTHER.into_response();
                result.headers_mut().insert(header::LOCATION, location);
                result
                    .headers_mut()
                    .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
                result
            }
            None => response(
                StatusCode::OK,
                json!({"ok":true,"user_id":consumed.user_id,"session_token":consumed.session_token}),
            ),
        },
        Ok(Err(failure)) => failure_response(failure),
        Err(failure) => {
            tracing::error!(?failure, "magic-link consume unavailable");
            unavailable()
        }
    }
}

fn allowed_redirect(raw: &str, allowlist: &[Url]) -> Option<Url> {
    if raw.len() > 2048 {
        return None;
    }
    let url = Url::parse(raw).ok()?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query_pairs().any(|(key, _)| key == "code")
    {
        return None;
    }
    allowlist
        .iter()
        .any(|allowed| url.origin() == allowed.origin())
        .then_some(url)
}

fn context(headers: &HeaderMap) -> std::result::Result<ConsumeRequest, Box<Response>> {
    if !unique_header(headers, "x-request-id")
        .is_some_and(|value| !value.is_empty() && value.len() <= 128)
    {
        return Err(Box::new(error(
            StatusCode::BAD_REQUEST,
            "MISSING_REQUEST_ID",
            "X-Request-Id is required",
        )));
    }
    let Some(tenant_id) =
        unique_header(headers, "x-tenant-id").and_then(|value| Uuid::parse_str(value).ok())
    else {
        return Err(Box::new(error(
            StatusCode::BAD_REQUEST,
            "MISSING_TENANT",
            "X-Tenant-Id is required",
        )));
    };
    let Some(tenant_slug) = unique_header(headers, "x-tenant-slug")
        .filter(|value| !value.is_empty() && value.len() <= 64)
    else {
        return Err(Box::new(error(
            StatusCode::BAD_REQUEST,
            "MISSING_TENANT",
            "X-Tenant-Slug is required",
        )));
    };
    let ip = request_ip(headers);
    let user_agent = unique_header(headers, "user-agent")
        .unwrap_or_default()
        .to_owned();
    Ok(ConsumeRequest {
        token: String::new(),
        tenant_id,
        tenant_slug: tenant_slug.to_owned(),
        ip,
        user_agent,
        issue_exchange: false,
    })
}

fn request_ip(headers: &HeaderMap) -> String {
    unique_header(headers, "x-forwarded-for")
        .and_then(|value| value.split(',').next())
        .unwrap_or_default()
        .trim()
        .to_owned()
}

fn unique_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(first)
}

fn failure_response(failure: ConsumeFailure) -> Response {
    match failure {
        ConsumeFailure::InvalidToken => error(
            StatusCode::BAD_REQUEST,
            "INVALID_TOKEN",
            "Invalid magic-link token",
        ),
        ConsumeFailure::NotFound => error(
            StatusCode::NOT_FOUND,
            "TOKEN_NOT_FOUND",
            "Magic link token not found",
        ),
        ConsumeFailure::Used => error(StatusCode::CONFLICT, "TOKEN_USED", "Token already used"),
        ConsumeFailure::Expired => error(StatusCode::GONE, "TOKEN_EXPIRED", "Token expired"),
        ConsumeFailure::ContextMismatch => error(
            StatusCode::FORBIDDEN,
            "TOKEN_CONTEXT_MISMATCH",
            "Magic link context mismatch",
        ),
        ConsumeFailure::InactiveIdentity
        | ConsumeFailure::UnverifiedEmail
        | ConsumeFailure::InactiveMembership => {
            error(StatusCode::FORBIDDEN, "FORBIDDEN", "Access denied")
        }
        ConsumeFailure::InvalidTenant => error(
            StatusCode::CONFLICT,
            "TENANT_MISMATCH",
            "Tenant is unavailable",
        ),
    }
}

fn response(status: StatusCode, body: Value) -> Response {
    let mut result = (status, Json(body)).into_response();
    result
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    result
}

fn error(status: StatusCode, code: &str, message: &str) -> Response {
    response(status, json!({"code":code,"message":message}))
}
fn unavailable() -> Response {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "SERVICE_UNAVAILABLE",
        "Временно недоступно",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn redirect_origin_is_allowlisted_and_code_cannot_be_overridden() -> Result<()> {
        let allow = vec![Url::parse("https://portal.example.invalid/")?];
        assert!(
            allowed_redirect("https://portal.example.invalid/callback?state=abc", &allow).is_some()
        );
        for value in [
            "https://portal.example.invalid.evil.invalid/callback",
            "http://portal.example.invalid/callback",
            "https://portal.example.invalid/callback?code=stolen",
            "https://user@portal.example.invalid/callback",
            "https://portal.example.invalid/callback#fragment",
        ] {
            assert!(
                allowed_redirect(value, &allow).is_none(),
                "accepted {value}"
            );
        }
        Ok(())
    }

    #[test]
    fn signed_browser_link_binds_tenant_and_redirect() -> Result<()> {
        let key = b"synthetic-magic-link-hash-key-32-bytes";
        let tenant = Uuid::new_v4();
        let signature = link_signature(
            key,
            "token",
            tenant,
            "portal",
            "https://portal.example.invalid/callback",
        )?;
        assert!(verify_link_signature(
            key,
            "token",
            tenant,
            "portal",
            "https://portal.example.invalid/callback",
            &signature
        ));
        assert!(!verify_link_signature(
            key,
            "token",
            tenant,
            "other",
            "https://portal.example.invalid/callback",
            &signature
        ));
        assert!(!verify_link_signature(
            key,
            "token",
            tenant,
            "portal",
            "https://portal.example.invalid/other",
            &signature
        ));
        Ok(())
    }
}
