//! Opt-in, Django-compatible issuance of one-time form tokens in shared YDB.

use crate::{
    cache_store::CacheStore,
    me_http::{cookie_domain, env_flag, make_cookie, new_csrf_secret, response, same_site},
};
use anyhow::{Result, bail};
use axum::{
    Router,
    extract::{RawQuery, State},
    http::{HeaderMap, StatusCode, header},
    response::Response,
    routing::get,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cookie::{Cookie, SameSite};
use id_compat::{cache::CacheValue, csrf};
use serde_json::json;
use std::{
    collections::BTreeMap,
    env,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use ydb::Client;

const TTL_SECONDS: u64 = 900;

pub struct FormTokenConfig {
    cache: CacheStore,
    csrf_cookie_name: String,
    csrf_cookie_secure: bool,
    csrf_same_site: SameSite,
    csrf_cookie_domain: Option<String>,
}

impl FormTokenConfig {
    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        if !env_flag("ID_AUTH_FORM_TOKEN_ENABLED", false)? {
            return Ok(None);
        }
        let table = env::var("YDB_CACHE_TABLE").unwrap_or_else(|_| "id_shared_cache".into());
        let cache = CacheStore::new(client, &table, "", 1)?;
        Self::new(
            cache,
            env::var("CSRF_COOKIE_NAME").unwrap_or_else(|_| "csrftoken".into()),
            env_flag("CSRF_COOKIE_SECURE", true)?,
            same_site("CSRF_COOKIE_SAMESITE")?,
            cookie_domain("CSRF_COOKIE_DOMAIN")?,
        )
        .map(|config| Some(Arc::new(config)))
    }

    pub fn new(
        cache: CacheStore,
        csrf_cookie_name: String,
        csrf_cookie_secure: bool,
        csrf_same_site: SameSite,
        csrf_cookie_domain: Option<String>,
    ) -> Result<Self> {
        if csrf_cookie_name.is_empty()
            || !csrf_cookie_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            bail!("invalid CSRF cookie name");
        }
        Ok(Self {
            cache,
            csrf_cookie_name,
            csrf_cookie_secure,
            csrf_same_site,
            csrf_cookie_domain,
        })
    }

    fn csrf_cookie(&self, headers: &HeaderMap) -> String {
        let existing = headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|raw| Cookie::split_parse(raw.to_owned()).flatten())
            .find(|cookie| cookie.name() == self.csrf_cookie_name)
            .and_then(|cookie| csrf::cookie_secret(cookie.value()).ok());
        make_cookie(
            &self.csrf_cookie_name,
            &existing.unwrap_or_else(new_csrf_secret),
            self.csrf_cookie_secure,
            false,
            self.csrf_same_site,
            self.csrf_cookie_domain.as_deref(),
            Some(31_449_600),
        )
    }
}

pub fn router(config: Arc<FormTokenConfig>) -> Router {
    Router::new()
        .route("/api/v1/auth/form_token", get(form_token))
        .with_state(config)
}

async fn form_token(
    State(config): State<Arc<FormTokenConfig>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let csrf_cookie = config.csrf_cookie(&headers);
    let purpose = query.as_deref().and_then(|query| {
        url::form_urlencoded::parse(query.as_bytes())
            .filter(|(key, _)| key == "purpose")
            .map(|(_, value)| value.into_owned())
            .last()
    });
    let Some(purpose) = purpose else {
        return response(
            StatusCode::UNPROCESSABLE_ENTITY,
            json!({"detail":[{"type":"missing","loc":["query","purpose"],"msg":"Field required"}]}),
            csrf_cookie,
            None,
        );
    };
    if !matches!(
        purpose.as_str(),
        "login" | "register" | "password_reset" | "email_verification"
    ) {
        return response(
            StatusCode::BAD_REQUEST,
            json!({
                "code":"VALIDATION_ERROR", "message":"Недопустимое значение purpose",
                "details":null, "errors":null, "fields":null,
                "detail":"{'code': 'VALIDATION_ERROR', 'message': 'Недопустимое значение purpose'}",
                "status":400
            }),
            csrf_cookie,
            None,
        );
    }
    let now = SystemTime::now();
    let result = issue_token(&config.cache, &purpose, &headers, now).await;
    match result {
        Ok(token) => response(
            StatusCode::OK,
            json!({"form_token":token,"expires_in":TTL_SECONDS}),
            csrf_cookie,
            None,
        ),
        Err(_) => {
            tracing::error!("Rust form token issuance failed");
            response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"code":"SERVICE_UNAVAILABLE","message":"Временно недоступно"}),
                csrf_cookie,
                None,
            )
        }
    }
}

async fn issue_token(
    cache: &CacheStore,
    purpose: &str,
    headers: &HeaderMap,
    now: SystemTime,
) -> Result<String> {
    let issued_at = i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?;
    let expires_at = now + Duration::from_secs(TTL_SECONDS);
    let expires_at_seconds = issued_at + i64::try_from(TTL_SECONDS)?;
    let client_ip = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(',').next().unwrap_or("").trim().to_owned())
        .filter(|value| !value.is_empty());
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let payload = CacheValue::Map(BTreeMap::from([
        ("purpose".into(), CacheValue::String(purpose.to_owned())),
        ("issued_at".into(), CacheValue::Int(issued_at)),
        ("expires_at".into(), CacheValue::Int(expires_at_seconds)),
        (
            "client_ip".into(),
            client_ip.map_or(CacheValue::Null, CacheValue::String),
        ),
        (
            "user_agent".into(),
            user_agent.map_or(CacheValue::Null, CacheValue::String),
        ),
        ("used".into(), CacheValue::Bool(false)),
    ]));
    for _ in 0..3 {
        let token = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        if cache
            .add(
                &format!("formtoken:{token}"),
                &payload,
                Some(expires_at),
                now,
            )
            .await?
        {
            return Ok(token);
        }
    }
    bail!("form token collision limit reached")
}
