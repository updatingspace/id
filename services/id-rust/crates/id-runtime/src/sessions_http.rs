//! Account session inventory and independently gated mutation routes.

use crate::{
    logout_http::{cookie_value, csrf_allowed},
    me_http::{cookie_domain, env_flag, make_cookie, same_site},
    session_revoke::{Outcome, Selection, TouchContext, revoke_sessions},
    session_store::session_codec_from_env,
    sessions_store::list_sessions,
};
use anyhow::{Result, bail};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Path, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use cookie::SameSite;
use id_compat::{headers::session_token, session::SessionCodec};
use serde_json::json;
use std::{env, sync::Arc, time::SystemTime};
use url::Url;
use ydb::Client;

pub struct SessionsHttpConfig {
    client: Arc<Client>,
    codec: Arc<SessionCodec>,
    cookie_name: String,
    csrf_cookie_name: String,
    session_cookie_secure: bool,
    session_same_site: SameSite,
    session_cookie_domain: Option<String>,
    trusted_origins: Vec<String>,
    mutations_enabled: bool,
}

impl SessionsHttpConfig {
    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        let local_mutations = env_flag("ID_AUTH_SESSIONS_PILOT_ENABLED", false)?;
        let rollout_mutations = env_flag("ID_AUTH_SESSIONS_MUTATIONS_ROLLOUT_ENABLED", false)?;
        let mutations_enabled = local_mutations || rollout_mutations;
        let read_enabled = env_flag("ID_AUTH_SESSIONS_READ_ENABLED", false)?;
        if !mutations_enabled && !read_enabled {
            return Ok(None);
        }
        let endpoint = Url::parse(&env::var("YDB_ENDPOINT")?)?;
        let local_pilot = env_flag("DJANGO_DEBUG", false)?
            && matches!(
                endpoint.host_str(),
                Some("localhost" | "127.0.0.1" | "[::1]")
            )
            && env::var("YDB_DATABASE")?.as_str() == "/local";
        if local_mutations && !local_pilot {
            bail!("incomplete Rust sessions pilot is restricted to local debug YDB");
        }
        if (read_enabled || rollout_mutations)
            && !local_pilot
            && !env_flag("ID_RUST_EARLY_ROLLOUT_ENABLED", false)?
        {
            bail!("Rust sessions rollout requires ID_RUST_EARLY_ROLLOUT_ENABLED");
        }
        let cookie_name = env::var("SESSION_COOKIE_NAME").unwrap_or_else(|_| "sessionid".into());
        if cookie_name.is_empty()
            || !cookie_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            bail!("invalid session cookie name");
        }
        let trusted_origins = env::var("CSRF_TRUSTED_ORIGINS")
            .unwrap_or_else(|_| {
                "http://id.localhost,http://id.localhost:5175,http://localhost:5175".into()
            })
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
                    bail!("invalid trusted origin for sessions pilot");
                }
                Ok(url.origin().ascii_serialization())
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(Arc::new(Self {
            client,
            codec: session_codec_from_env()?,
            cookie_name,
            csrf_cookie_name: env::var("CSRF_COOKIE_NAME").unwrap_or_else(|_| "csrftoken".into()),
            session_cookie_secure: env_flag("SESSION_COOKIE_SECURE", true)?,
            session_same_site: same_site("SESSION_COOKIE_SAMESITE")?,
            session_cookie_domain: cookie_domain("SESSION_COOKIE_DOMAIN")?,
            trusted_origins,
            mutations_enabled,
        })))
    }
}

pub fn router(config: Arc<SessionsHttpConfig>) -> Router {
    let mut routes = Router::new().route("/api/v1/auth/sessions", get(sessions).options(preflight));
    if config.mutations_enabled {
        routes = routes
            .route("/api/v1/auth/sessions/bulk", post(bulk).options(preflight))
            .route("/api/v1/auth/sessions/_bulk", post(bulk).options(preflight))
            .route(
                "/api/v1/auth/sessions/{sid}",
                delete(single).options(preflight),
            );
    }
    routes.with_state(config)
}

async fn sessions(State(config): State<Arc<SessionsHttpConfig>>, headers: HeaderMap) -> Response {
    let mut result = sessions_result(&config, &headers).await;
    add_cors(result.headers_mut(), &headers, &config.trusted_origins);
    result
}

async fn sessions_result(config: &SessionsHttpConfig, headers: &HeaderMap) -> Response {
    let (token, explicit) = match credential(config, headers) {
        Ok(value) => value,
        Err(failure) => return credential_error(failure),
    };
    let touch = touch_context(headers);
    match list_sessions(
        &config.client,
        config.codec.clone(),
        &token,
        touch.x_session_header,
        Some(&touch.ip),
        &touch.user_agent,
        SystemTime::now(),
    )
    .await
    {
        Ok(Some(sessions)) => response(StatusCode::OK, json!({"sessions":sessions})),
        Ok(None) if explicit => error(
            StatusCode::UNAUTHORIZED,
            "INVALID_OR_EXPIRED_TOKEN",
            "Сессия недействительна, пожалуйста, войдите заново",
        ),
        Ok(None) => error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Требуется авторизация",
        ),
        Err(failure) => {
            tracing::error!(?failure, "Rust sessions inventory failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            )
        }
    }
}

fn touch_context(headers: &HeaderMap) -> TouchContext {
    let ip = ["x-real-ip", "x-forwarded-for"]
        .iter()
        .find_map(|name| headers.get(*name).and_then(|value| value.to_str().ok()))
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .unwrap_or("");
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    TouchContext {
        x_session_header: headers.contains_key("x-session-token"),
        ip: ip.to_owned(),
        user_agent: user_agent.to_owned(),
    }
}

enum CredentialError {
    Invalid,
    Missing,
}

fn credential(
    config: &SessionsHttpConfig,
    headers: &HeaderMap,
) -> std::result::Result<(String, bool), CredentialError> {
    let explicit = session_token(headers).map_err(|_| CredentialError::Invalid)?;
    let browser = cookie_value(headers, &config.cookie_name);
    let token = explicit
        .or(browser.as_deref())
        .ok_or(CredentialError::Missing)?;
    Ok((token.to_owned(), explicit.is_some()))
}

fn credential_error(failure: CredentialError) -> Response {
    match failure {
        CredentialError::Invalid => invalid_credential(true),
        CredentialError::Missing => invalid_credential(false),
    }
}

#[derive(Default)]
struct BulkIn {
    ids: Option<Vec<String>>,
    all_except_current: bool,
    reason: Option<String>,
}

fn bulk_validation(errors: Vec<serde_json::Value>) -> Response {
    response(StatusCode::UNPROCESSABLE_ENTITY, json!({"detail": errors}))
}

fn bulk_field_error(field: &str, kind: &str, message: &str) -> serde_json::Value {
    json!({"loc": ["body", "payload", field], "type": kind, "msg": message})
}

fn parse_bulk_body(bytes: &[u8]) -> std::result::Result<BulkIn, Box<Response>> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Err(Box::new(bulk_validation(vec![json!({
            "loc": ["body", "payload"], "type": "missing", "msg": "Field required"
        })])));
    }
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| {
        Box::new(error(
            StatusCode::BAD_REQUEST,
            "HTTP_ERROR",
            "Cannot parse request body",
        ))
    })?;
    // Django Ninja treats a non-object JSON value as an empty Schema payload.
    let Some(object) = value.as_object() else {
        return Ok(BulkIn::default());
    };
    let mut payload = BulkIn::default();
    let mut errors = Vec::new();
    if let Some(value) = object.get("ids") {
        match value {
            serde_json::Value::Null => {}
            serde_json::Value::Array(values) => {
                let mut ids = Vec::new();
                for (index, value) in values.iter().enumerate() {
                    if let Some(id) = value.as_str() {
                        ids.push(id.to_owned());
                    } else {
                        errors.push(json!({"loc": ["body", "payload", "ids", index],
                            "type": "string_type", "msg": "Input should be a valid string"}));
                    }
                }
                payload.ids = Some(ids);
            }
            _ => errors.push(bulk_field_error(
                "ids",
                "list_type",
                "Input should be a valid list",
            )),
        }
    }
    if let Some(value) = object.get("all_except_current") {
        match pydantic_bool(value) {
            Ok(value) => payload.all_except_current = value,
            Err(kind) => errors.push(bulk_field_error(
                "all_except_current",
                kind,
                if kind == "bool_parsing" {
                    "Input should be a valid boolean, unable to interpret input"
                } else {
                    "Input should be a valid boolean"
                },
            )),
        }
    }
    if let Some(value) = object.get("reason") {
        match value {
            serde_json::Value::Null => {}
            serde_json::Value::String(reason) => payload.reason = Some(reason.clone()),
            _ => errors.push(bulk_field_error(
                "reason",
                "string_type",
                "Input should be a valid string",
            )),
        }
    }
    if !errors.is_empty() {
        return Err(Box::new(bulk_validation(errors)));
    }
    Ok(payload)
}

fn pydantic_bool(value: &serde_json::Value) -> std::result::Result<bool, &'static str> {
    match value {
        serde_json::Value::Bool(value) => Ok(*value),
        serde_json::Value::Number(value) if value.as_i64() == Some(0) => Ok(false),
        serde_json::Value::Number(value) if value.as_i64() == Some(1) => Ok(true),
        serde_json::Value::Number(_) => Err("bool_parsing"),
        serde_json::Value::String(value) => match value.to_ascii_lowercase().as_str() {
            "1" | "true" | "t" | "on" | "yes" | "y" => Ok(true),
            "0" | "false" | "f" | "off" | "no" | "n" => Ok(false),
            _ => Err("bool_parsing"),
        },
        _ => Err("bool_type"),
    }
}

async fn bulk(State(config): State<Arc<SessionsHttpConfig>>, request: Request) -> Response {
    let headers = request.headers().clone();
    let result = bulk_result(&config, request).await;
    with_cors(result, &headers, &config.trusted_origins)
}

async fn bulk_result(config: &SessionsHttpConfig, request: Request) -> Response {
    let headers = request.headers().clone();
    let (token, explicit) = match credential(config, &headers) {
        Ok(value) => value,
        Err(failure) => return credential_error(failure),
    };
    if !explicit && !csrf_allowed(&headers, &config.csrf_cookie_name, &config.trusted_origins) {
        return error(
            StatusCode::FORBIDDEN,
            "CSRF_FAILED",
            "CSRF verification failed",
        );
    }
    let bytes = match to_bytes(request.into_body(), 1_000_000).await {
        Ok(value) => value,
        Err(_) => {
            return error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "VALIDATION_ERROR",
                "Invalid request body",
            );
        }
    };
    let payload = match parse_bulk_body(&bytes) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let reason = payload
        .reason
        .filter(|reason| !reason.is_empty())
        .unwrap_or_else(|| "bulk_except_current".into());
    let outcome = revoke_sessions(
        &config.client,
        config.codec.clone(),
        &token,
        Selection::Bulk {
            ids: payload.ids,
            all_except_current: payload.all_except_current,
        },
        &reason,
        touch_context(&headers),
        SystemTime::now(),
    )
    .await;
    match outcome {
        Ok(Outcome::Bulk {
            reason,
            current,
            revoked_ids,
            skipped_ids,
        }) => {
            let current_revoked = revoked_ids.contains(&current);
            let count = revoked_ids.len();
            let mut result = response(
                StatusCode::OK,
                json!({"ok":true,"reason":reason,
                "current":current,"revoked_ids":revoked_ids,"skipped_ids":skipped_ids,
                "count":count,"id":null,"revoked_reason":null,"revoked_at":null}),
            );
            if current_revoked {
                clear_cookie(&mut result, config);
            }
            result
        }
        Ok(Outcome::Unauthorized) => invalid_credential(explicit),
        Ok(_) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "SERVICE_UNAVAILABLE",
            "Временно недоступно",
        ),
        Err(failure) => {
            tracing::error!(?failure, "Rust bulk session revoke failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            )
        }
    }
}

async fn single(
    State(config): State<Arc<SessionsHttpConfig>>,
    Path(sid): Path<String>,
    request: Request,
) -> Response {
    let headers = request.headers().clone();
    let result = single_result(&config, &sid, &headers, request.uri().query()).await;
    with_cors(result, &headers, &config.trusted_origins)
}

async fn single_result(
    config: &SessionsHttpConfig,
    sid: &str,
    headers: &HeaderMap,
    query: Option<&str>,
) -> Response {
    let (token, explicit) = match credential(config, headers) {
        Ok(value) => value,
        Err(failure) => return credential_error(failure),
    };
    if !explicit && !csrf_allowed(headers, &config.csrf_cookie_name, &config.trusted_origins) {
        return error(
            StatusCode::FORBIDDEN,
            "CSRF_FAILED",
            "CSRF verification failed",
        );
    }
    let reason = query
        .and_then(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .find(|(name, _)| name == "reason")
                .map(|(_, value)| value.into_owned())
        })
        .filter(|reason| !reason.is_empty())
        .unwrap_or_else(|| "manual".into());
    match revoke_sessions(
        &config.client,
        config.codec.clone(),
        &token,
        Selection::One(sid.to_owned()),
        &reason,
        touch_context(headers),
        SystemTime::now(),
    )
    .await
    {
        Ok(Outcome::One {
            id,
            reason,
            revoked_at,
        }) => {
            let mut result = response(
                StatusCode::OK,
                json!({"ok":true,"reason":null,
                "current":null,"revoked_ids":null,"skipped_ids":null,"count":null,
                "id":id,"revoked_reason":reason,
                "revoked_at":chrono::DateTime::<chrono::Utc>::from(revoked_at)
                    .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)}),
            );
            if id == token {
                clear_cookie(&mut result, config);
            }
            result
        }
        Ok(Outcome::Missing) => error(StatusCode::NOT_FOUND, "HTTP_ERROR", "session not found"),
        Ok(Outcome::Unauthorized) => invalid_credential(explicit),
        Ok(_) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "SERVICE_UNAVAILABLE",
            "Временно недоступно",
        ),
        Err(failure) => {
            tracing::error!(?failure, "Rust single session revoke failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            )
        }
    }
}

fn invalid_credential(explicit: bool) -> Response {
    if explicit {
        error(
            StatusCode::UNAUTHORIZED,
            "INVALID_OR_EXPIRED_TOKEN",
            "Сессия недействительна, пожалуйста, войдите заново",
        )
    } else {
        error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Требуется авторизация",
        )
    }
}

fn clear_cookie(response: &mut Response, config: &SessionsHttpConfig) {
    let cleared = make_cookie(
        &config.cookie_name,
        "",
        config.session_cookie_secure,
        true,
        config.session_same_site,
        config.session_cookie_domain.as_deref(),
        Some(0),
    );
    if let Ok(value) = HeaderValue::from_str(&cleared) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

fn with_cors(mut result: Response, headers: &HeaderMap, trusted_origins: &[String]) -> Response {
    add_cors(result.headers_mut(), headers, trusted_origins);
    result
}

async fn preflight(State(config): State<Arc<SessionsHttpConfig>>, headers: HeaderMap) -> Response {
    let mut result = StatusCode::NO_CONTENT.into_response();
    add_cors(result.headers_mut(), &headers, &config.trusted_origins);
    result
}

fn response(status: StatusCode, body: serde_json::Value) -> Response {
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

fn error(status: StatusCode, code: &str, message: &str) -> Response {
    let detail = if code == "HTTP_ERROR" {
        message.to_owned()
    } else {
        format!("{{'code': '{code}', 'message': '{message}'}}")
    };
    response(
        status,
        json!({
            "code":code, "message":message,
            "details":null, "errors":null, "fields":null,
            "detail":detail,
            "status":status.as_u16(),
        }),
    )
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
        && let Ok(value) = HeaderValue::from_str(origin)
    {
        output.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
        output.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
        output.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, DELETE, OPTIONS"),
        );
        output.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Content-Type, X-CSRFToken, X-Session-Token, Authorization"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    #[tokio::test]
    async fn bulk_body_preserves_django_ninja_validation_contract() -> anyhow::Result<()> {
        for (bytes, status, expected) in [
            (
                b"".as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
                json!({"detail":[{"loc":["body","payload"],"type":"missing","msg":"Field required"}]}),
            ),
            (
                b"{".as_slice(),
                StatusCode::BAD_REQUEST,
                json!({"code":"HTTP_ERROR","message":"Cannot parse request body",
                    "details":null,"errors":null,"fields":null,"detail":"Cannot parse request body","status":400}),
            ),
            (
                br#"{"ids":"one"}"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
                json!({"detail":[{"loc":["body","payload","ids"],"type":"list_type",
                    "msg":"Input should be a valid list"}]}),
            ),
            (
                br#"{"ids":[1]}"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
                json!({"detail":[{"loc":["body","payload","ids",0],"type":"string_type",
                    "msg":"Input should be a valid string"}]}),
            ),
            (
                br#"{"all_except_current":"oops"}"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
                json!({"detail":[{"loc":["body","payload","all_except_current"],
                    "type":"bool_parsing","msg":"Input should be a valid boolean, unable to interpret input"}]}),
            ),
            (
                br#"{"reason":1}"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
                json!({"detail":[{"loc":["body","payload","reason"],"type":"string_type",
                    "msg":"Input should be a valid string"}]}),
            ),
        ] {
            let response = match parse_bulk_body(bytes) {
                Err(response) => response,
                Ok(_) => return Err(anyhow!("invalid bulk payload accepted")),
            };
            assert_eq!(response.status(), status);
            let body = to_bytes((*response).into_body(), 1_000_000).await?;
            let value: serde_json::Value = serde_json::from_slice(&body)?;
            assert_eq!(value, expected);
        }
        for bytes in [
            b"[]".as_slice(),
            b"[1]",
            b"null",
            b"42",
            b"true",
            br#""hello""#,
        ] {
            let parsed = parse_bulk_body(bytes).map_err(|response| {
                anyhow!("valid bulk payload rejected: {}", response.status())
            })?;
            assert!(parsed.ids.is_none() && !parsed.all_except_current && parsed.reason.is_none());
        }
        let parsed =
            parse_bulk_body(br#"{"ids":["s"],"all_except_current":"yes","reason":"Manual"}"#)
                .map_err(|response| {
                    anyhow!("valid bulk payload rejected: {}", response.status())
                })?;
        assert_eq!(parsed.ids, Some(vec!["s".to_owned()]));
        assert!(parsed.all_except_current);
        assert_eq!(parsed.reason.as_deref(), Some("Manual"));
        Ok(())
    }
}
