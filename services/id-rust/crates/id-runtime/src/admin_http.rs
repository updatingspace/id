//! Operator lookup, with an independently gated suspension action. The web UI
//! does not query YDB or decide roles.

use crate::{
    account_deletion,
    admin_oidc_client::{self, LookupOutcome},
    admin_oidc_client_edit::{self, RedirectUpdate, UpdateOutcome},
    admin_suspend::{self, Preflight, SuspendInput, SuspendResult, SuspensionReason},
    cache_store::CacheStore,
    data_export_operation,
    ids::PublicSubject,
    logout_http::{cookie_value, csrf_allowed},
    me_http::env_flag,
    me_store::restore_django_profile,
    session_store::{LEGACY_BACKENDS, session_codec_from_env},
};
use anyhow::{Context, Result, ensure};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Path, Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use id_compat::{headers::session_token, session::SessionCodec};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    env,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::sync::Semaphore;
use url::Url;
use ydb::{Client, Transaction, TxMode, closure};

enum EmailLookupOutcome {
    Found(AccountSnapshot),
    NotFound,
    Ambiguous,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmailLookupRequest {
    email: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientLookupRequest {
    client_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedirectUpdateRequest {
    client_id: String,
    expected_revision: String,
    redirect_uris: Vec<String>,
    current_password: String,
}

pub struct AdminReadConfig {
    client: Arc<Client>,
    codec: Arc<SessionCodec>,
    session_cookie_name: String,
    csrf_cookie_name: String,
    trusted_origins: Vec<String>,
    suspend_enabled: bool,
    client_redirects_enabled: bool,
    suspension_budget: CacheStore,
    hashing_slots: Arc<Semaphore>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuspendRequest {
    expected_subject: String,
    current_password: String,
    reason: SuspensionReason,
}

#[derive(Serialize)]
struct AccountSnapshot {
    id: i32,
    email: String,
    is_active: bool,
    is_staff: bool,
    is_superuser: bool,
    has_mfa: bool,
    identity_id: Option<uuid::Uuid>,
    public_subject: Option<String>,
    access_state: AccessState,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum AccessState {
    Active,
    DeletionPending,
    AccountDisabled,
    IdentityInactive,
    NeedsReview,
}

impl AdminReadConfig {
    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        let read_enabled = env_flag("ID_AUTH_ADMIN_READ_ENABLED", false)?;
        let suspend_enabled = env_flag("ID_AUTH_ADMIN_SUSPEND_ENABLED", false)?;
        let client_redirects_enabled = env_flag("ID_AUTH_ADMIN_CLIENT_REDIRECTS_ENABLED", false)?;
        ensure!(
            read_enabled || (!suspend_enabled && !client_redirects_enabled),
            "operator mutations require operator lookup"
        );
        if !read_enabled {
            return Ok(None);
        }
        let trusted_origins = env::var("CSRF_TRUSTED_ORIGINS")
            .unwrap_or_else(|_| "http://id.localhost,http://localhost:5175".into())
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                let url = Url::parse(value)?;
                ensure!(
                    matches!(url.scheme(), "http" | "https")
                        && url.path() == "/"
                        && url.query().is_none()
                        && url.fragment().is_none()
                        && url.username().is_empty()
                        && url.password().is_none(),
                    "invalid operator CSRF origin"
                );
                Ok(url.origin().ascii_serialization())
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            !(suspend_enabled || client_redirects_enabled) || !trusted_origins.is_empty(),
            "operator mutations require a trusted origin"
        );
        if (suspend_enabled || client_redirects_enabled) && !env_flag("DJANGO_DEBUG", false)? {
            ensure!(
                trusted_origins
                    .iter()
                    .all(|origin| origin.starts_with("https://")),
                "production operator mutations require HTTPS origins"
            );
        }
        let cache_table = env::var("YDB_CACHE_TABLE").unwrap_or_else(|_| "id_shared_cache".into());
        let name = env::var("SESSION_COOKIE_NAME").unwrap_or_else(|_| "sessionid".into());
        ensure!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
            "invalid admin session cookie name"
        );
        Ok(Some(Arc::new(Self {
            suspension_budget: CacheStore::new(client.clone(), &cache_table, "", 1)?,
            client,
            codec: session_codec_from_env()?,
            session_cookie_name: name,
            csrf_cookie_name: env::var("CSRF_COOKIE_NAME").unwrap_or_else(|_| "csrftoken".into()),
            trusted_origins,
            suspend_enabled,
            client_redirects_enabled,
            hashing_slots: Arc::new(Semaphore::new(2)),
        })))
    }
}

pub fn router(config: Arc<AdminReadConfig>) -> Router {
    let mut app = Router::new()
        .route("/api/v1/auth/admin/me", get(operator_session))
        .route("/api/v1/auth/admin/accounts/search", post(account_by_email))
        .route("/api/v1/auth/admin/clients/search", post(client_by_id))
        .route("/api/v1/auth/admin/accounts/{id}", get(account_status))
        .route("/api/v1/auth/admin/deletions/{id}", get(deletion_status))
        .route("/api/v1/auth/admin/exports/{id}", get(export_status));
    if config.suspend_enabled {
        app = app.route(
            "/api/v1/auth/admin/accounts/{id}/suspend",
            post(suspend_account),
        );
    }
    if config.client_redirects_enabled {
        app = app.route(
            "/api/v1/auth/admin/clients/redirects",
            post(update_client_redirects),
        );
    }
    app.with_state(config)
}

async fn update_client_redirects(
    State(config): State<Arc<AdminReadConfig>>,
    request: Request,
) -> Response {
    let headers = request.headers();
    if let Err(response) = authorize(&config, headers).await {
        return *response;
    }
    let explicit = match session_token(headers) {
        Ok(value) => value,
        Err(_) => return error(StatusCode::UNAUTHORIZED, "INVALID_OR_EXPIRED_TOKEN"),
    };
    if explicit.is_none()
        && !csrf_allowed(headers, &config.csrf_cookie_name, &config.trusted_origins)
    {
        return error(StatusCode::FORBIDDEN, "CSRF_FAILED");
    }
    let cookie = cookie_value(headers, &config.session_cookie_name);
    let Some(token) = explicit.or(cookie.as_deref()) else {
        return error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED");
    };
    let token = token.to_owned();
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_none_or(|value| !value.trim().eq_ignore_ascii_case("application/json"))
    {
        return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "INVALID_CONTENT_TYPE");
    }
    let Ok(body) = to_bytes(request.into_body(), 24 * 1024).await else {
        return error(StatusCode::PAYLOAD_TOO_LARGE, "INVALID_REQUEST");
    };
    let Ok(input) = serde_json::from_slice::<RedirectUpdateRequest>(&body) else {
        return error(StatusCode::BAD_REQUEST, "INVALID_REQUEST");
    };
    if input.client_id.trim() != input.client_id
        || input.client_id.is_empty()
        || input.client_id.len() > 64
        || input.client_id.chars().any(char::is_control)
        || input.expected_revision.len() != 64
        || !input
            .expected_revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || input.current_password.is_empty()
        || input.current_password.len() > 512
        || !admin_oidc_client_edit::valid_redirects(&input.redirect_uris)
    {
        return error(StatusCode::BAD_REQUEST, "INVALID_REDIRECT_UPDATE");
    }
    let now = SystemTime::now();
    let preflight =
        match admin_suspend::preflight(&config.client, config.codec.clone(), &token, now).await {
            Ok(value) => value,
            Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "ADMIN_UNAVAILABLE"),
        };
    let (actor_id, password_hash) = match preflight {
        Preflight::Ready {
            actor_id,
            password_hash,
        } => (actor_id, password_hash),
        Preflight::Unauthorized => {
            return error(StatusCode::UNAUTHORIZED, "INVALID_OR_EXPIRED_TOKEN");
        }
        Preflight::Forbidden => return error(StatusCode::FORBIDDEN, "OPERATOR_ACCESS_REQUIRED"),
    };
    let budget = config
        .suspension_budget
        .advance_window(
            &format!("rl:admin_client_redirects:operator:{actor_id}"),
            300,
            now,
        )
        .await;
    match budget {
        Ok(value) if value.count <= 6 => {}
        Ok(_) => return error(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMIT_EXCEEDED"),
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "ADMIN_UNAVAILABLE"),
    }
    let Ok(permit) = config.hashing_slots.clone().try_acquire_owned() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "ADMIN_UNAVAILABLE");
    };
    let password = input.current_password;
    let hash_for_check = password_hash.clone();
    let verified = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        id_compat::password::verify(&password, &hash_for_check)
    })
    .await;
    match verified {
        Ok(Ok(true)) => {}
        Ok(Ok(false)) => return error(StatusCode::BAD_REQUEST, "INVALID_PASSWORD"),
        _ => return error(StatusCode::SERVICE_UNAVAILABLE, "ADMIN_UNAVAILABLE"),
    }
    let result = admin_oidc_client_edit::update(
        &config.client,
        config.codec.clone(),
        RedirectUpdate {
            token,
            actor_id,
            password_hash,
            client_id: input.client_id,
            expected_revision: input.expected_revision,
            redirect_uris: input.redirect_uris,
            now,
        },
    )
    .await;
    match result {
        Ok(UpdateOutcome::Updated { revision }) => json_response(
            StatusCode::OK,
            json!({"status":"updated","redirect_revision":revision}),
        ),
        Ok(UpdateOutcome::Unauthorized) => {
            error(StatusCode::UNAUTHORIZED, "INVALID_OR_EXPIRED_TOKEN")
        }
        Ok(UpdateOutcome::Forbidden) => error(StatusCode::FORBIDDEN, "OPERATOR_ACCESS_REQUIRED"),
        Ok(UpdateOutcome::PasswordChanged) => error(StatusCode::CONFLICT, "PASSWORD_CHANGED"),
        Ok(UpdateOutcome::ClientNotFound) => error(StatusCode::NOT_FOUND, "CLIENT_NOT_FOUND"),
        Ok(UpdateOutcome::Ambiguous) => error(StatusCode::CONFLICT, "CLIENT_ID_AMBIGUOUS"),
        Ok(UpdateOutcome::StaleReview) => error(StatusCode::CONFLICT, "REVIEW_STALE"),
        Err(failure) => {
            tracing::error!(error = %failure, "operator OIDC redirect commit result unknown");
            error(StatusCode::SERVICE_UNAVAILABLE, "STATE_UNCERTAIN")
        }
    }
}

async fn suspend_account(
    State(config): State<Arc<AdminReadConfig>>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let headers = request.headers();
    if let Err(response) = authorize(&config, headers).await {
        return *response;
    }
    let Ok(target_id) = id.parse::<i32>() else {
        return error(StatusCode::BAD_REQUEST, "INVALID_ACCOUNT_ID");
    };
    if target_id <= 0 {
        return error(StatusCode::BAD_REQUEST, "INVALID_ACCOUNT_ID");
    }
    let explicit = match session_token(headers) {
        Ok(value) => value,
        Err(_) => return error(StatusCode::UNAUTHORIZED, "INVALID_OR_EXPIRED_TOKEN"),
    };
    if explicit.is_none()
        && !csrf_allowed(headers, &config.csrf_cookie_name, &config.trusted_origins)
    {
        return error(StatusCode::FORBIDDEN, "CSRF_FAILED");
    }
    let cookie = cookie_value(headers, &config.session_cookie_name);
    let Some(token) = explicit.or(cookie.as_deref()) else {
        return error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED");
    };
    let token = token.to_owned();
    if !headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    {
        return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "INVALID_CONTENT_TYPE");
    }
    let Ok(body) = to_bytes(request.into_body(), 5 * 1024).await else {
        return error(StatusCode::PAYLOAD_TOO_LARGE, "INVALID_REQUEST");
    };
    let Ok(input) = serde_json::from_slice::<SuspendRequest>(&body) else {
        return error(StatusCode::BAD_REQUEST, "INVALID_REQUEST");
    };
    if input.expected_subject.is_empty()
        || input.expected_subject.len() > 128
        || input.current_password.is_empty()
        || input.current_password.len() > 4096
    {
        return error(StatusCode::BAD_REQUEST, "INVALID_REQUEST");
    }
    let now = SystemTime::now();
    let preflight =
        match admin_suspend::preflight(&config.client, config.codec.clone(), &token, now).await {
            Ok(value) => value,
            Err(failure) => {
                tracing::error!(error = %failure, "operator suspension preflight failed");
                return error(StatusCode::SERVICE_UNAVAILABLE, "ADMIN_UNAVAILABLE");
            }
        };
    let (actor_id, password_hash) = match preflight {
        Preflight::Ready {
            actor_id,
            password_hash,
        } => (actor_id, password_hash),
        Preflight::Unauthorized => {
            return error(StatusCode::UNAUTHORIZED, "INVALID_OR_EXPIRED_TOKEN");
        }
        Preflight::Forbidden => return error(StatusCode::FORBIDDEN, "OPERATOR_ACCESS_REQUIRED"),
    };
    let budget = config
        .suspension_budget
        .advance_window(&format!("rl:admin_suspend:operator:{actor_id}"), 300, now)
        .await;
    match budget {
        Ok(value) if value.count <= 6 => {}
        Ok(_) => return error(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMIT_EXCEEDED"),
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "ADMIN_UNAVAILABLE"),
    }
    let Ok(permit) = config.hashing_slots.clone().try_acquire_owned() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "ADMIN_UNAVAILABLE");
    };
    let password = input.current_password;
    let hash_for_check = password_hash.clone();
    let verified = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        id_compat::password::verify(&password, &hash_for_check)
    })
    .await;
    match verified {
        Ok(Ok(true)) => {}
        Ok(Ok(false)) => return error(StatusCode::BAD_REQUEST, "INVALID_PASSWORD"),
        _ => return error(StatusCode::SERVICE_UNAVAILABLE, "ADMIN_UNAVAILABLE"),
    }
    let result = admin_suspend::suspend(
        &config.client,
        config.codec.clone(),
        SuspendInput {
            token: &token,
            actor_id,
            password_hash: &password_hash,
            target_id,
            expected_subject: &input.expected_subject,
            reason: input.reason,
            now,
        },
    )
    .await;
    match result {
        Ok(SuspendResult::Suspended) => {
            json_response(StatusCode::OK, json!({"status":"suspended"}))
        }
        Ok(SuspendResult::Unauthorized) => {
            error(StatusCode::UNAUTHORIZED, "INVALID_OR_EXPIRED_TOKEN")
        }
        Ok(SuspendResult::Forbidden) => error(StatusCode::FORBIDDEN, "OPERATOR_ACCESS_REQUIRED"),
        Ok(SuspendResult::WrongPassword) => error(StatusCode::CONFLICT, "PASSWORD_CHANGED"),
        Ok(SuspendResult::TargetMissing) => error(StatusCode::NOT_FOUND, "ACCOUNT_NOT_FOUND"),
        Ok(SuspendResult::SelfTarget) => error(StatusCode::FORBIDDEN, "SELF_SUSPENSION_FORBIDDEN"),
        Ok(SuspendResult::ProtectedTarget) => error(StatusCode::FORBIDDEN, "PROTECTED_ACCOUNT"),
        Ok(SuspendResult::StaleReview) => error(StatusCode::CONFLICT, "REVIEW_STALE"),
        Ok(SuspendResult::AlreadyClosed) => error(StatusCode::CONFLICT, "ACCOUNT_ALREADY_CLOSED"),
        Err(failure) => {
            tracing::error!(error = %failure, "operator suspension commit result unknown");
            error(StatusCode::SERVICE_UNAVAILABLE, "STATE_UNCERTAIN")
        }
    }
}

async fn operator_session(
    State(config): State<Arc<AdminReadConfig>>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authorize(&config, &headers).await {
        return *response;
    }
    json_response(StatusCode::OK, json!({"operator": true}))
}

async fn deletion_status(
    State(config): State<Arc<AdminReadConfig>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authorize(&config, &headers).await {
        return *response;
    }
    let Ok(id) = id.parse::<i64>() else {
        return error(StatusCode::BAD_REQUEST, "INVALID_OPERATION_ID");
    };
    if id <= 0 {
        return error(StatusCode::BAD_REQUEST, "INVALID_OPERATION_ID");
    }
    match account_deletion::read_status(&config.client, id).await {
        Ok(Some(operation)) => json_response(StatusCode::OK, json!({"operation": operation})),
        Ok(None) => error(StatusCode::NOT_FOUND, "OPERATION_NOT_FOUND"),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "OPERATION_UNAVAILABLE"),
    }
}

async fn export_status(
    State(config): State<Arc<AdminReadConfig>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authorize(&config, &headers).await {
        return *response;
    }
    if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return error(StatusCode::BAD_REQUEST, "INVALID_OPERATION_ID");
    }
    match data_export_operation::read_operator_status(&config.client, &id).await {
        Ok(Some(operation)) => json_response(StatusCode::OK, json!({"operation": operation})),
        Ok(None) => error(StatusCode::NOT_FOUND, "OPERATION_NOT_FOUND"),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "OPERATION_UNAVAILABLE"),
    }
}

async fn account_status(
    State(config): State<Arc<AdminReadConfig>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authorize(&config, &headers).await {
        return *response;
    }
    let Ok(id) = id.parse::<i32>() else {
        return error(StatusCode::BAD_REQUEST, "INVALID_ACCOUNT_ID");
    };
    if id <= 0 {
        return error(StatusCode::BAD_REQUEST, "INVALID_ACCOUNT_ID");
    }
    match read_account(&config.client, id).await {
        Ok(Some(account)) => json_response(StatusCode::OK, json!({"account": account})),
        Ok(None) => error(StatusCode::NOT_FOUND, "ACCOUNT_NOT_FOUND"),
        Err(err) => {
            tracing::error!(error = %err, "operator account lookup failed");
            error(StatusCode::SERVICE_UNAVAILABLE, "ACCOUNT_UNAVAILABLE")
        }
    }
}

async fn account_by_email(
    State(config): State<Arc<AdminReadConfig>>,
    request: Request,
) -> Response {
    if let Err(response) = authorize(&config, request.headers()).await {
        return *response;
    }
    if request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_none_or(|value| !value.trim().eq_ignore_ascii_case("application/json"))
    {
        return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "INVALID_CONTENT_TYPE");
    }
    let Ok(body) = to_bytes(request.into_body(), 513).await else {
        return error(StatusCode::BAD_REQUEST, "INVALID_EMAIL");
    };
    let Ok(EmailLookupRequest { email }) = serde_json::from_slice::<EmailLookupRequest>(&body)
    else {
        return error(StatusCode::BAD_REQUEST, "INVALID_EMAIL");
    };
    let email = email.trim().to_lowercase();
    if email.len() > 320
        || email.is_empty()
        || email.bytes().filter(|byte| *byte == b'@').count() != 1
        || email.chars().any(char::is_control)
    {
        return error(StatusCode::BAD_REQUEST, "INVALID_EMAIL");
    }
    match read_account_by_email(&config.client, email).await {
        Ok(EmailLookupOutcome::Found(account)) => {
            json_response(StatusCode::OK, json!({"account": account}))
        }
        Ok(EmailLookupOutcome::NotFound) => error(StatusCode::NOT_FOUND, "ACCOUNT_NOT_FOUND"),
        Ok(EmailLookupOutcome::Ambiguous) => error(StatusCode::CONFLICT, "ACCOUNT_EMAIL_AMBIGUOUS"),
        Err(err) => {
            tracing::error!(error = %err, "operator email lookup failed");
            error(StatusCode::SERVICE_UNAVAILABLE, "ACCOUNT_UNAVAILABLE")
        }
    }
}

async fn client_by_id(State(config): State<Arc<AdminReadConfig>>, request: Request) -> Response {
    if let Err(response) = authorize(&config, request.headers()).await {
        return *response;
    }
    if request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_none_or(|value| !value.trim().eq_ignore_ascii_case("application/json"))
    {
        return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "INVALID_CONTENT_TYPE");
    }
    let Ok(body) = to_bytes(request.into_body(), 256).await else {
        return error(StatusCode::BAD_REQUEST, "INVALID_CLIENT_ID");
    };
    let Ok(ClientLookupRequest { client_id }) =
        serde_json::from_slice::<ClientLookupRequest>(&body)
    else {
        return error(StatusCode::BAD_REQUEST, "INVALID_CLIENT_ID");
    };
    let client_id = client_id.trim();
    if client_id.is_empty() || client_id.len() > 64 || client_id.chars().any(char::is_control) {
        return error(StatusCode::BAD_REQUEST, "INVALID_CLIENT_ID");
    }
    match admin_oidc_client::by_client_id(&config.client, client_id.to_owned()).await {
        Ok(LookupOutcome::Found(client)) => {
            json_response(StatusCode::OK, json!({"client": client}))
        }
        Ok(LookupOutcome::NotFound) => error(StatusCode::NOT_FOUND, "CLIENT_NOT_FOUND"),
        Ok(LookupOutcome::Ambiguous) => error(StatusCode::CONFLICT, "CLIENT_ID_AMBIGUOUS"),
        Err(err) => {
            tracing::error!(error = %err, "operator OIDC client lookup failed");
            error(StatusCode::SERVICE_UNAVAILABLE, "CLIENT_UNAVAILABLE")
        }
    }
}

async fn read_account(client: &Client, id: i32) -> Result<Option<AccountSnapshot>> {
    client
        .query_client()
        .retry_tx(closure!([id], async |tx: &mut Transaction| {
            read_account_tx(tx, *id).await
        }))
        .isolation(TxMode::SnapshotReadOnly)
        .timeout(Duration::from_secs(5))
        .await
        .context("read operator account snapshot")
}

async fn read_account_by_email(client: &Client, email: String) -> Result<EmailLookupOutcome> {
    client.query_client()
        .retry_tx(closure!([email], async |tx: &mut Transaction| {
            let mut stream = tx.query("SELECT user_id FROM accounts_accountemaillookup VIEW acct_email_key_idx WHERE email_key = $email LIMIT 2")
                .param("$email", email.clone()).await?;
            let mut ids = Vec::with_capacity(2);
            while let Some(rows) = stream.next_result_set().await? {
                for mut row in rows { ids.push(row.remove_field_by_name("user_id")?.try_into()?); }
            }
            stream.close().await?;
            if ids.len() > 1 { return Ok(EmailLookupOutcome::Ambiguous) }
            let Some(id) = ids.pop() else { return Ok(EmailLookupOutcome::NotFound) };
            let Some(account) = read_account_tx(tx, id).await? else {
                return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("operator email lookup points to missing account")))
            };
            if account.email.trim().to_lowercase() != *email {
                return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("operator email lookup disagrees with account")))
            }
            let mut verified = tx.query("SELECT verified FROM account_emailaddress VIEW account_emailaddress_user_id_2c513194 WHERE user_id = $id AND primary = true AND Unicode::ToLower(email) = $email LIMIT 2")
                .param("$id", id).param("$email", email.clone()).await?;
            let mut rows = Vec::with_capacity(2);
            while let Some(result) = verified.next_result_set().await? {
                for mut row in result { rows.push(row.remove_field_by_name("verified")?.try_into()?); }
            }
            verified.close().await?;
            match rows.as_slice() {
                [true] => Ok(EmailLookupOutcome::Found(account)),
                [] | [false] => Ok(EmailLookupOutcome::NotFound),
                _ => Ok(EmailLookupOutcome::Ambiguous),
            }
        }))
        .isolation(TxMode::SnapshotReadOnly)
        .timeout(Duration::from_secs(5))
        .await
        .context("read operator verified email snapshot")
}

async fn read_account_tx(
    tx: &mut Transaction,
    id: i32,
) -> ydb::YdbResultWithCustomerErr<Option<AccountSnapshot>> {
    let Some(mut account) = tx
        .query_row("SELECT email, is_active, is_staff, is_superuser FROM auth_user WHERE id = $id")
        .param("$id", id)
        .optional()
        .await?
    else {
        return Ok(None);
    };
    let email: String = account.remove_field_by_name("email")?.try_into()?;
    let active: bool = account.remove_field_by_name("is_active")?.try_into()?;
    let staff: bool = account.remove_field_by_name("is_staff")?.try_into()?;
    let superuser: bool = account.remove_field_by_name("is_superuser")?.try_into()?;
    let binding = tx
        .query_row(
            "SELECT identity_id, public_subject FROM accounts_accountidentity WHERE user_id = $id",
        )
        .param("$id", id)
        .optional()
        .await?;
    let (identity_id, public_subject) = if let Some(mut binding) = binding {
        let identity_id: Option<uuid::Uuid> =
            binding.remove_field_by_name("identity_id")?.try_into()?;
        let public_subject: String = binding.remove_field_by_name("public_subject")?.try_into()?;
        (identity_id, Some(public_subject))
    } else {
        (None, None)
    };
    let has_mfa = tx.query_row("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $id LIMIT 1")
        .param("$id", id).optional().await?.is_some();
    let deletion_pending = tx
        .query_row("SELECT id FROM accounts_accountdeletionrequest VIEW accounts_accountdeletionrequest_user_id_6a166c52 WHERE user_id = $id AND status != 'canceled' LIMIT 1")
        .param("$id", id)
        .optional()
        .await?
        .is_some();
    let identity_status: Option<String> = if let Some(identity_id) = identity_id {
        let row = tx
            .query_row("SELECT status FROM usid_user WHERE user_id = $identity_id")
            .param("$identity_id", identity_id)
            .optional()
            .await?;
        match row {
            Some(mut row) => Some(row.remove_field_by_name("status")?.try_into()?),
            None => None,
        }
    } else {
        None
    };
    let access_state = if deletion_pending {
        AccessState::DeletionPending
    } else if !active {
        AccessState::AccountDisabled
    } else if identity_id.is_none()
        || public_subject
            .as_ref()
            .and_then(|value| PublicSubject::parse(value.clone()))
            .is_none()
        || identity_status.is_none()
    {
        AccessState::NeedsReview
    } else if identity_status.as_deref() != Some("active") {
        AccessState::IdentityInactive
    } else {
        AccessState::Active
    };
    Ok(Some(AccountSnapshot {
        id,
        email,
        is_active: active,
        is_staff: staff,
        is_superuser: superuser,
        has_mfa,
        identity_id,
        public_subject,
        access_state,
    }))
}

async fn authorize(
    config: &AdminReadConfig,
    headers: &HeaderMap,
) -> std::result::Result<(), Box<Response>> {
    let explicit = match session_token(headers) {
        Ok(value) => value,
        Err(_) => {
            return Err(Box::new(error(
                StatusCode::UNAUTHORIZED,
                "INVALID_OR_EXPIRED_TOKEN",
            )));
        }
    };
    let cookie = cookie_value(headers, &config.session_cookie_name);
    let Some(token) = explicit.or(cookie.as_deref()) else {
        return Err(Box::new(error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED")));
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
        Ok(None) => {
            return Err(Box::new(error(
                StatusCode::UNAUTHORIZED,
                "INVALID_OR_EXPIRED_TOKEN",
            )));
        }
        Err(_) => {
            return Err(Box::new(error(
                StatusCode::SERVICE_UNAVAILABLE,
                "AUTH_UNAVAILABLE",
            )));
        }
    };
    let account = profile.details.account.as_ref();
    if !operator_allowed(
        account.is_some_and(|value| value.is_staff),
        account.is_some_and(|value| value.is_superuser),
        profile.details.has_mfa,
    ) {
        return Err(Box::new(error(
            StatusCode::FORBIDDEN,
            "OPERATOR_ACCESS_REQUIRED",
        )));
    }
    Ok(())
}

fn operator_allowed(is_staff: bool, is_superuser: bool, has_mfa: bool) -> bool {
    is_staff && is_superuser && has_mfa
}

fn error(status: StatusCode, code: &'static str) -> Response {
    json_response(status, json!({"code": code}))
}

fn json_response(status: StatusCode, body: Value) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        Json(body),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_requires_staff_superuser_and_mfa() {
        assert!(operator_allowed(true, true, true));
        for (staff, superuser, mfa) in [
            (false, true, true),
            (true, false, true),
            (true, true, false),
            (false, false, false),
        ] {
            assert!(!operator_allowed(staff, superuser, mfa));
        }
    }

    #[test]
    fn errors_do_not_expose_account_details_or_cache() {
        let response = error(StatusCode::FORBIDDEN, "OPERATOR_ACCESS_REQUIRED");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
}
