//! Owner-scoped routes for creating, reading and downloading private exports.

use crate::{
    cache_store::CacheStore,
    data_export_escrow::{self, ExportEscrowKey},
    data_export_operation::{self, AuthenticatedExportRequest, AuthenticatedExportResult},
    data_export_s3::S3Export,
    logout_http::{cookie_value, csrf_allowed},
    me_http::env_flag,
    me_store::restore_django_profile,
    mfa_secret,
    session_store::{LEGACY_BACKENDS, session_codec_from_env},
};
use anyhow::{Result, bail};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Path, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use id_compat::{headers::session_token, mfa_seal::MfaSealKey, session::SessionCodec};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{env, sync::Arc, time::SystemTime};
use tokio::sync::Semaphore;
use url::Url;
use ydb::Client;

pub struct ExportHttpConfig {
    client: Arc<Client>,
    codec: Arc<SessionCodec>,
    storage: S3Export,
    operation_key: Vec<u8>,
    cache: CacheStore,
    seal_key: Option<Arc<MfaSealKey>>,
    escrow_key: Option<Arc<ExportEscrowKey>>,
    hashing_slots: Arc<Semaphore>,
    session_cookie_name: String,
    csrf_cookie_name: String,
    trusted_origins: Vec<String>,
}

pub struct ExportHttpSettings {
    pub operation_key: Vec<u8>,
    pub cache: CacheStore,
    pub seal_key: Option<Arc<MfaSealKey>>,
    pub escrow_key: Option<Arc<ExportEscrowKey>>,
    pub session_cookie_name: String,
    pub csrf_cookie_name: String,
    pub trusted_origins: Vec<String>,
}

impl ExportHttpConfig {
    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        let local_pilot = env_flag("ID_EXPORT_API_PILOT_ENABLED", false)?;
        let production_rollout = env_flag("ID_EXPORT_API_ROLLOUT_ENABLED", false)?;
        if !local_pilot && !production_rollout {
            return Ok(None);
        }
        let endpoint = Url::parse(&env::var("YDB_ENDPOINT")?)?;
        let local_ydb = env_flag("DJANGO_DEBUG", false)?
            && matches!(
                endpoint.host_str(),
                Some("localhost" | "127.0.0.1" | "[::1]")
            )
            && env::var("YDB_DATABASE")? == "/local";
        if local_pilot && !local_ydb {
            bail!("export pilot requires local debug YDB");
        }
        if production_rollout && !local_ydb && !env_flag("ID_RUST_EARLY_ROLLOUT_ENABLED", false)? {
            bail!("export rollout requires ID_RUST_EARLY_ROLLOUT_ENABLED");
        }
        let delayed_pilot = env_flag("ID_EXPORT_DELAYED_PILOT_ENABLED", false)?;
        if delayed_pilot && !local_ydb {
            bail!("incomplete delayed export pilot requires local debug YDB");
        }
        let delayed_rollout = env_flag("ID_EXPORT_DELAYED_ROLLOUT_ENABLED", false)?;
        if delayed_rollout
            && (!production_rollout || !env_flag("ID_RUST_EARLY_ROLLOUT_ENABLED", false)?)
        {
            bail!("delayed export rollout requires Rust export API rollout");
        }
        let escrow_key = if delayed_pilot || delayed_rollout {
            Some(Arc::new(ExportEscrowKey::from_base64(&env::var(
                "ID_EXPORT_ESCROW_KEY",
            )?)?))
        } else {
            None
        };
        let trusted_origins = env::var("CSRF_TRUSTED_ORIGINS")
            .unwrap_or_else(|_| {
                "http://id.localhost,http://id.localhost:5175,http://localhost:5175".into()
            })
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|value| {
                let url = Url::parse(value)?;
                if !matches!(url.scheme(), "http" | "https")
                    || url.path() != "/"
                    || url.query().is_some()
                    || url.fragment().is_some()
                    || !url.username().is_empty()
                    || url.password().is_some()
                {
                    bail!("invalid export trusted origin");
                }
                Ok(url.origin().ascii_serialization())
            })
            .collect::<Result<Vec<_>>>()?;
        let operation_key = env::var("ID_EXPORT_OPERATION_KEY")?.into_bytes();
        let cache_table = env::var("YDB_CACHE_TABLE").unwrap_or_else(|_| "id_shared_cache".into());
        let cache = CacheStore::new(client.clone(), &cache_table, "", 1)?;
        let session_cookie_name =
            env::var("SESSION_COOKIE_NAME").unwrap_or_else(|_| "sessionid".into());
        let csrf_cookie_name = env::var("CSRF_COOKIE_NAME").unwrap_or_else(|_| "csrftoken".into());
        Ok(Some(Arc::new(Self::new(
            client,
            session_codec_from_env()?,
            S3Export::from_env()?,
            ExportHttpSettings {
                operation_key,
                cache,
                seal_key: mfa_secret::key_from_env()?,
                escrow_key,
                session_cookie_name,
                csrf_cookie_name,
                trusted_origins,
            },
        )?)))
    }

    pub fn new(
        client: Arc<Client>,
        codec: Arc<SessionCodec>,
        storage: S3Export,
        settings: ExportHttpSettings,
    ) -> Result<Self> {
        let ExportHttpSettings {
            operation_key,
            cache,
            seal_key,
            escrow_key,
            session_cookie_name,
            csrf_cookie_name,
            trusted_origins,
        } = settings;
        if operation_key.len() < 32 || trusted_origins.is_empty() {
            bail!("incomplete export HTTP configuration");
        }
        if [&session_cookie_name, &csrf_cookie_name]
            .iter()
            .any(|name| {
                name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            })
        {
            bail!("invalid export cookie name");
        }
        Ok(Self {
            client,
            codec,
            storage,
            operation_key,
            cache,
            seal_key,
            escrow_key,
            hashing_slots: Arc::new(Semaphore::new(2)),
            session_cookie_name,
            csrf_cookie_name,
            trusted_origins,
        })
    }
}

pub fn router(config: Arc<ExportHttpConfig>) -> Router {
    Router::new()
        .route("/api/v1/auth/data/exports", post(create).options(preflight))
        .route(
            "/api/v1/auth/data/exports/{id}",
            get(status).options(preflight),
        )
        .route(
            "/api/v1/auth/data/exports/{id}/download",
            get(download).options(preflight),
        )
        .route(
            "/api/v1/auth/data/exports/{id}/redeem",
            post(redeem).options(preflight),
        )
        .with_state(config)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedeemInput {
    token: String,
}

async fn redeem(
    State(config): State<Arc<ExportHttpConfig>>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let Some(key) = config.escrow_key.as_deref() else {
        return error(StatusCode::NOT_FOUND, "NOT_FOUND");
    };
    if !request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
        })
    {
        return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "UNSUPPORTED_MEDIA_TYPE");
    }
    let Ok(body) = to_bytes(request.into_body(), 1024).await else {
        return error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR");
    };
    let Ok(input) = serde_json::from_slice::<RedeemInput>(&body) else {
        return error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR");
    };
    let object_key = match data_export_escrow::downloadable_key(
        &config.client,
        key,
        &id,
        &input.token,
        SystemTime::now(),
    )
    .await
    {
        Ok(Some(value)) => value,
        Ok(None) => return error(StatusCode::NOT_FOUND, "NOT_FOUND"),
        Err(failure) => {
            tracing::error!(?failure, "export capability lookup failed");
            return error(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE");
        }
    };
    match config.storage.download_url(&object_key) {
        Ok(url) => response(
            StatusCode::OK,
            json!({"download_url":url,"expires_in_seconds":60}),
        ),
        Err(failure) => {
            tracing::error!(?failure, "export capability signing failed");
            error(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE")
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportInput {
    password: String,
    mfa_code: Option<String>,
    recovery_code: Option<String>,
}

async fn create(State(config): State<Arc<ExportHttpConfig>>, request: Request) -> Response {
    let headers = request.headers().clone();
    let mut response = create_inner(&config, request).await;
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

async fn create_inner(config: &ExportHttpConfig, request: Request) -> Response {
    let headers = request.headers().clone();
    let (token, explicit) = match credential(config, &headers) {
        Ok(Some(value)) => value,
        Ok(None) => return error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
        Err(()) => return error(StatusCode::UNAUTHORIZED, "INVALID_OR_EXPIRED_TOKEN"),
    };
    if !explicit && !csrf_allowed(&headers, &config.csrf_cookie_name, &config.trusted_origins) {
        return error(StatusCode::FORBIDDEN, "CSRF_FAILED");
    }
    let Some(key) = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
    else {
        return error(StatusCode::BAD_REQUEST, "IDEMPOTENCY_KEY_REQUIRED");
    };
    let key = key.to_owned();
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
        return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "UNSUPPORTED_MEDIA_TYPE");
    }
    let body = match to_bytes(request.into_body(), 16 * 1024).await {
        Ok(body) => body,
        Err(_) => return error(StatusCode::PAYLOAD_TOO_LARGE, "VALIDATION_ERROR"),
    };
    let Ok(input) = serde_json::from_slice::<ExportInput>(&body) else {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "VALIDATION_ERROR");
    };
    if input.password.is_empty()
        || input.password.len() > 4096
        || input
            .mfa_code
            .as_ref()
            .is_some_and(|value| value.len() > 128)
        || input
            .recovery_code
            .as_ref()
            .is_some_and(|value| value.len() > 128)
        || key.is_empty()
        || key.len() > 128
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "VALIDATION_ERROR");
    }
    let Some(owner) = (match owner(config, &token).await {
        Ok(value) => value,
        Err(status) => return error(status, "SERVICE_UNAVAILABLE"),
    }) else {
        return error(StatusCode::UNAUTHORIZED, "INVALID_OR_EXPIRED_TOKEN");
    };
    // A stolen session must not provide an unlimited online password/MFA oracle.
    // The YDB counter is shared across cold starts and all API instances.
    let budget = config
        .cache
        .advance_window(
            &format!("rl:data_export:user:{owner}"),
            300,
            SystemTime::now(),
        )
        .await;
    match budget {
        Ok(window) if window.count <= 10 => {}
        Ok(_) => return error(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMIT_EXCEEDED"),
        Err(failure) => {
            tracing::warn!(?failure, "export reauthentication budget unavailable");
            return error(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE");
        }
    }
    let (hash_owner, password_hash) = match data_export_operation::password_hash_for_session(
        &config.client,
        config.codec.clone(),
        &token,
        SystemTime::now(),
    )
    .await
    {
        Ok(Some(value)) => value,
        Ok(None) => return error(StatusCode::UNAUTHORIZED, "INVALID_OR_EXPIRED_TOKEN"),
        Err(failure) => {
            tracing::warn!(?failure, "export reauthentication preflight failed");
            return error(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE");
        }
    };
    if hash_owner != owner {
        return error(StatusCode::UNAUTHORIZED, "INVALID_OR_EXPIRED_TOKEN");
    }
    let permit = match config.hashing_slots.clone().try_acquire_owned() {
        Ok(value) => value,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE"),
    };
    let password = input.password;
    let hash_for_check = password_hash.clone();
    let verified = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        id_compat::password::verify(&password, &hash_for_check)
    })
    .await;
    match verified {
        Ok(Ok(true)) => {}
        Ok(Ok(false)) => return error(StatusCode::BAD_REQUEST, "INVALID_PASSWORD"),
        _ => return error(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE"),
    }
    let code = input
        .mfa_code
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .or(input.recovery_code.as_deref());
    match data_export_operation::request_authenticated(
        &config.client,
        config.codec.clone(),
        config.cache.clone(),
        config.seal_key.clone(),
        AuthenticatedExportRequest {
            token: &token,
            account_id: owner,
            password_hash: &password_hash,
            mfa_code: code,
            key: &key,
            secret: &config.operation_key,
            escrow_key: config.escrow_key.as_deref(),
            now: SystemTime::now(),
        },
    )
    .await
    {
        Ok(AuthenticatedExportResult::Accepted(operation)) => {
            let release_at = if config.escrow_key.is_some() {
                match data_export_escrow::release_at(&config.client, &operation.id, owner).await {
                    Ok(Some(value)) => {
                        Some(chrono::DateTime::<chrono::Utc>::from(value).to_rfc3339())
                    }
                    _ => return error(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE"),
                }
            } else {
                None
            };
            response(
                StatusCode::ACCEPTED,
                json!({"id":operation.id,"status":operation.status,"release_at":release_at}),
            )
        }
        Ok(AuthenticatedExportResult::Unauthorized) => {
            error(StatusCode::UNAUTHORIZED, "INVALID_OR_EXPIRED_TOKEN")
        }
        Ok(AuthenticatedExportResult::Stale) => error(StatusCode::CONFLICT, "PASSWORD_CHANGED"),
        Ok(AuthenticatedExportResult::MfaRequired) => {
            error(StatusCode::BAD_REQUEST, "MFA_REQUIRED")
        }
        Ok(AuthenticatedExportResult::WrongMfa) => {
            error(StatusCode::BAD_REQUEST, "INVALID_MFA_CODE")
        }
        Ok(AuthenticatedExportResult::EmailUnverified) => {
            error(StatusCode::CONFLICT, "VERIFIED_EMAIL_REQUIRED")
        }
        Err(failure) => {
            tracing::warn!(?failure, "export request failed");
            error(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE")
        }
    }
}

async fn status(
    State(config): State<Arc<ExportHttpConfig>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let mut response = status_inner(&config, &id, &headers).await;
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

async fn status_inner(config: &ExportHttpConfig, id: &str, headers: &HeaderMap) -> Response {
    let owner = match authenticated_owner(config, headers).await {
        Ok(Some(owner)) => owner,
        Ok(None) => return error(StatusCode::UNAUTHORIZED, "INVALID_OR_EXPIRED_TOKEN"),
        Err(status) => return error(status, "SERVICE_UNAVAILABLE"),
    };
    match data_export_operation::read_owned(&config.client, owner, id).await {
        Ok(Some(operation)) => {
            let delayed = matches!(
                operation.status.as_str(),
                "pending_delayed" | "running_delayed" | "cooldown"
            );
            let release_at = if delayed {
                match data_export_escrow::release_at(&config.client, id, owner).await {
                    Ok(Some(value)) => {
                        Some(chrono::DateTime::<chrono::Utc>::from(value).to_rfc3339())
                    }
                    _ => return error(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE"),
                }
            } else {
                None
            };
            let expiry = operation
                .expires_at
                .map(|value| chrono::DateTime::<chrono::Utc>::from(value).to_rfc3339());
            let status = if operation.status == "cooldown" {
                match data_export_escrow::delivery_sent(&config.client, id, owner).await {
                    Ok(Some(true)) => "ready",
                    Ok(Some(false)) => "cooldown",
                    _ => return error(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE"),
                }
            } else {
                operation.status.as_str()
            };
            response(
                StatusCode::OK,
                json!({"id":operation.id,"status":status,"manifest":operation.manifest,"expires_at":expiry,"release_at":release_at}),
            )
        }
        Ok(None) => error(StatusCode::NOT_FOUND, "NOT_FOUND"),
        Err(failure) if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) => {
            let _ = failure;
            error(StatusCode::NOT_FOUND, "NOT_FOUND")
        }
        Err(failure) => {
            tracing::error!(?failure, "export status failed");
            error(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE")
        }
    }
}

async fn download(
    State(config): State<Arc<ExportHttpConfig>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let mut response = download_inner(&config, &id, &headers).await;
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

async fn download_inner(config: &ExportHttpConfig, id: &str, headers: &HeaderMap) -> Response {
    let owner = match authenticated_owner(config, headers).await {
        Ok(Some(owner)) => owner,
        Ok(None) => return error(StatusCode::UNAUTHORIZED, "INVALID_OR_EXPIRED_TOKEN"),
        Err(status) => return error(status, "SERVICE_UNAVAILABLE"),
    };
    let key =
        match data_export_operation::download_key(&config.client, owner, id, SystemTime::now())
            .await
        {
            Ok(Some(key)) => key,
            Ok(None) => return error(StatusCode::NOT_FOUND, "NOT_FOUND"),
            Err(failure) if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) => {
                let _ = failure;
                return error(StatusCode::NOT_FOUND, "NOT_FOUND");
            }
            Err(failure) => {
                tracing::error!(?failure, "export download failed");
                return error(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE");
            }
        };
    match config.storage.download_url(&key) {
        Ok(url) => {
            let mut response = response(StatusCode::SEE_OTHER, json!({"status":"redirect"}));
            match HeaderValue::from_str(&url) {
                Ok(value) => {
                    response.headers_mut().insert(header::LOCATION, value);
                }
                Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE"),
            }
            response.headers_mut().insert(
                header::REFERRER_POLICY,
                HeaderValue::from_static("no-referrer"),
            );
            response
        }
        Err(failure) => {
            tracing::error!(?failure, "export download signing failed");
            error(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE")
        }
    }
}

fn credential(
    config: &ExportHttpConfig,
    headers: &HeaderMap,
) -> Result<Option<(String, bool)>, ()> {
    let explicit = session_token(headers).map_err(|_| ())?;
    Ok(explicit
        .map(|token| (token.to_owned(), true))
        .or_else(|| cookie_value(headers, &config.session_cookie_name).map(|token| (token, false))))
}

async fn owner(config: &ExportHttpConfig, token: &str) -> Result<Option<i32>, StatusCode> {
    match restore_django_profile(
        &config.client,
        config.codec.clone(),
        token,
        LEGACY_BACKENDS,
        SystemTime::now(),
    )
    .await
    {
        Ok(Some(profile)) => i32::try_from(profile.principal.account_id.get())
            .map(Some)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE),
        Ok(None) => Ok(None),
        Err(failure) => {
            tracing::error!(?failure, "export session restore failed");
            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

async fn authenticated_owner(
    config: &ExportHttpConfig,
    headers: &HeaderMap,
) -> Result<Option<i32>, StatusCode> {
    let Some((token, _)) = credential(config, headers).ok().flatten() else {
        return Ok(None);
    };
    owner(config, &token).await
}

async fn preflight(State(config): State<Arc<ExportHttpConfig>>, headers: HeaderMap) -> Response {
    let mut response = response(StatusCode::NO_CONTENT, json!({}));
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

fn response(status: StatusCode, value: Value) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")], Json(value)).into_response()
}

fn error(status: StatusCode, code: &str) -> Response {
    response(status, json!({"error":code}))
}

fn add_cors(target: &mut HeaderMap, request: &HeaderMap, trusted: &[String]) {
    let Some(origin) = request
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return;
    };
    if !trusted.iter().any(|candidate| candidate == origin) {
        return;
    }
    if let Ok(value) = HeaderValue::from_str(origin) {
        target.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
        target.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
        target.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, OPTIONS"),
        );
        target.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Content-Type, Idempotency-Key, X-CSRFToken, X-Session-Token"),
        );
        target.insert(header::VARY, HeaderValue::from_static("Origin"));
    }
}
