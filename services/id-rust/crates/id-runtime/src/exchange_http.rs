//! BFF-only exchange of the short-lived code issued by the magic-link flow.

use crate::{cache_store::CacheStore, me_http::env_flag};
use anyhow::{Result, ensure};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use id_compat::{
    cache::CacheValue,
    internal_hmac::{SignedRequest, verify},
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::{
    env,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use ydb::Client;

const PATH: &str = "/api/v1/auth/exchange";
const DEFAULT_TTL_SECONDS: i64 = 14 * 24 * 60 * 60;

pub struct ExchangeHttpConfig {
    cache: CacheStore,
    secret: Vec<u8>,
}

impl ExchangeHttpConfig {
    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        let local = env_flag("ID_AUTH_EXCHANGE_PILOT_ENABLED", false)?;
        let rollout = env_flag("ID_AUTH_EXCHANGE_ROLLOUT_ENABLED", false)?;
        if !local && !rollout {
            return Ok(None);
        }
        if rollout {
            ensure!(
                env_flag("ID_RUST_EARLY_ROLLOUT_ENABLED", false)?,
                "Rust exchange rollout requires the early rollout gate"
            );
        }
        let secret = env::var("BFF_INTERNAL_HMAC_SECRET")?;
        ensure!(secret.len() >= 32, "internal HMAC secret is too short");
        let table = env::var("YDB_CACHE_TABLE").unwrap_or_else(|_| "id_shared_cache".into());
        Ok(Some(Arc::new(Self {
            cache: CacheStore::new(client, &table, "", 1)?,
            secret: secret.into_bytes(),
        })))
    }

    pub fn new(cache: CacheStore, secret: Vec<u8>) -> Result<Arc<Self>> {
        ensure!(secret.len() >= 32, "internal HMAC secret is too short");
        Ok(Arc::new(Self { cache, secret }))
    }
}

pub fn router(config: Arc<ExchangeHttpConfig>) -> Router {
    Router::new().route(PATH, post(exchange)).with_state(config)
}

#[derive(Deserialize)]
struct ExchangeIn {
    code: String,
}

async fn exchange(State(config): State<Arc<ExchangeHttpConfig>>, request: Request) -> Response {
    let headers = request.headers().clone();
    let Some(request_id) = unique_header(&headers, "x-request-id")
        .filter(|value| !value.is_empty() && value.len() <= 128)
    else {
        return error(
            StatusCode::BAD_REQUEST,
            "MISSING_REQUEST_ID",
            "X-Request-Id is required",
        );
    };
    let Some(timestamp) = unique_header(&headers, "x-updspace-timestamp") else {
        return error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Missing internal signature",
        );
    };
    let Some(signature) = unique_header(&headers, "x-updspace-signature") else {
        return error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Missing internal signature",
        );
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
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_secs() as i64);
    let signed = SignedRequest {
        method: "POST",
        path: PATH,
        body: &body,
        request_id,
        timestamp,
        signature,
    };
    if !matches!(verify(&config.secret, &signed, now), Ok(true)) {
        return error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Invalid internal signature",
        );
    }
    let Ok(payload) = serde_json::from_slice::<ExchangeIn>(&body) else {
        return error(StatusCode::BAD_REQUEST, "INVALID_BODY", "Invalid JSON body");
    };
    if payload.code.is_empty() || payload.code.len() > 256 {
        return error(StatusCode::BAD_REQUEST, "INVALID_BODY", "Invalid code");
    }
    let key = format!("usid:exchange:{}", payload.code);
    match config.cache.take(&key, SystemTime::now()).await {
        Ok(Some(raw)) => match exchange_payload(raw) {
            Some(body) => response(StatusCode::OK, body),
            None => error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "SERVER_ERROR",
                "Malformed exchange payload",
            ),
        },
        Ok(None) => error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Invalid or expired code",
        ),
        Err(failure) => {
            tracing::error!(?failure, "exchange cache unavailable");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            )
        }
    }
}

fn exchange_payload(raw: CacheValue) -> Option<Value> {
    let CacheValue::Map(mut fields) = raw else {
        return None;
    };
    let CacheValue::String(user_id) = fields.remove("user_id")? else {
        return None;
    };
    Uuid::parse_str(&user_id).ok()?;
    let ttl_seconds = match fields.remove("ttl_seconds") {
        Some(CacheValue::Int(ttl)) if ttl > 0 => ttl,
        _ => DEFAULT_TTL_SECONDS,
    };
    let master_flags = match fields.remove("master_flags") {
        Some(CacheValue::Map(flags)) => flags
            .into_iter()
            .filter_map(|(key, value)| {
                if let CacheValue::Bool(value) = value {
                    Some((key, Value::Bool(value)))
                } else {
                    None
                }
            })
            .collect::<Map<String, Value>>(),
        _ => Map::new(),
    };
    Some(json!({"ok":true,"user_id":user_id,"master_flags":master_flags,"ttl_seconds":ttl_seconds}))
}

fn unique_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn decodes_legacy_exchange_fields_without_exposing_extra_cache_data() {
        let flags = BTreeMap::from([
            ("email_verified".into(), CacheValue::Bool(true)),
            ("system_admin".into(), CacheValue::Bool(false)),
        ]);
        let value = CacheValue::Map(BTreeMap::from([
            (
                "user_id".into(),
                CacheValue::String("0d5e5f5a-7fd8-4a8f-a327-778b0e537fcb".into()),
            ),
            ("master_flags".into(), CacheValue::Map(flags)),
            ("ttl_seconds".into(), CacheValue::Int(120)),
            ("issued_at".into(), CacheValue::String("private".into())),
        ]));
        assert_eq!(
            exchange_payload(value),
            Some(json!({
                "ok":true,
                "user_id":"0d5e5f5a-7fd8-4a8f-a327-778b0e537fcb",
                "master_flags":{"email_verified":true,"system_admin":false},
                "ttl_seconds":120
            }))
        );
    }

    #[test]
    fn malformed_identity_is_not_issued_to_bff() {
        let value = CacheValue::Map(BTreeMap::from([(
            "user_id".into(),
            CacheValue::String("not-a-uuid".into()),
        )]));
        assert!(exchange_payload(value).is_none());
    }
}
