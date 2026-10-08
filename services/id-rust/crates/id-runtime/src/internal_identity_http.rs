//! Portal/BFF identity lookup authenticated by the existing raw-request HMAC.

use crate::{
    me_http::env_flag,
    media_url::MediaUrl,
    profile_store::{ProfileDetails, ProfileRows, finish_profile_rows, read_profile_details_tx},
};
use anyhow::{Context, Result, ensure};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{DateTime, SecondsFormat, Utc};
use cookie::Cookie;
use id_compat::internal_hmac::{SignedRequest, verify};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    env,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use ydb::{Client, Transaction, TxMode, closure};

const PATH: &str = "/api/v1/internal/identity/me";
const PORTAL_PATH: &str = "/api/v1/me";

pub struct InternalIdentityConfig {
    client: Arc<Client>,
    secret: Vec<u8>,
    media: MediaUrl,
    internal_enabled: bool,
    portal_enabled: bool,
}

impl InternalIdentityConfig {
    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        let internal_enabled = env_flag("ID_INTERNAL_IDENTITY_ENABLED", false)?;
        let portal_enabled = env_flag("ID_PORTAL_ME_ENABLED", false)?;
        if !internal_enabled && !portal_enabled {
            return Ok(None);
        }
        let secret = env::var("BFF_INTERNAL_HMAC_SECRET")?;
        ensure!(secret.len() >= 32, "internal HMAC secret is too short");
        let media = MediaUrl::from_env(&env::var("MEDIA_PUBLIC_BASE_URL")?)?;
        Ok(Some(Arc::new(Self {
            client,
            secret: secret.into_bytes(),
            media,
            internal_enabled,
            portal_enabled,
        })))
    }
}

pub fn router(config: Arc<InternalIdentityConfig>) -> Router {
    let mut router = Router::new();
    if config.internal_enabled {
        router = router.route(PATH, get(identity_me));
    }
    if config.portal_enabled {
        router = router.route(PORTAL_PATH, get(portal_me));
    }
    router.with_state(config)
}

#[derive(Debug)]
struct MasterIdentity {
    id: Uuid,
    username: String,
    display_name: String,
    email: String,
    email_verified: bool,
    status: String,
    system_admin: bool,
    created_at: SystemTime,
}

struct IdentitySnapshot {
    master: MasterIdentity,
    account: Option<ProfileDetails>,
    deleting: bool,
}

#[derive(Serialize)]
struct IdentityUserOut {
    user_id: String,
    username: String,
    display_name: String,
    email: String,
    email_verified: bool,
    status: String,
    system_admin: bool,
    created_at: String,
    first_name: Option<String>,
    last_name: Option<String>,
    phone_number: Option<String>,
    phone_verified: Option<bool>,
    birth_date: Option<String>,
    language: Option<String>,
    timezone: Option<String>,
    avatar_url: Option<String>,
    avatar_source: Option<String>,
    avatar_gravatar_enabled: Option<bool>,
}

#[derive(Clone)]
enum PortalPrincipal {
    Signed(Uuid),
    Session(String),
}

#[derive(Serialize)]
struct PortalMembership {
    tenant_id: String,
    tenant_slug: String,
    status: String,
    base_role: String,
}

enum PortalReadRows {
    InvalidSession,
    MissingIdentity,
    TenantMismatch,
    NoMembership,
    Found(Box<IdentityRows>, PortalMembership),
}

enum PortalRead {
    InvalidSession,
    MissingIdentity,
    TenantMismatch,
    NoMembership,
    Found(Box<IdentitySnapshot>, PortalMembership),
}

async fn identity_me(
    State(config): State<Arc<InternalIdentityConfig>>,
    request: Request,
) -> Response {
    let headers = request.headers().clone();
    let request_id = match unique_header(&headers, "x-request-id") {
        Some(value) if !value.is_empty() && value.len() <= 128 => value,
        _ => {
            return error(
                StatusCode::BAD_REQUEST,
                "MISSING_REQUEST_ID",
                "X-Request-Id is required",
                "",
            );
        }
    };
    let Some(timestamp) = unique_header(&headers, "x-updspace-timestamp") else {
        return error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Missing internal signature",
            request_id,
        );
    };
    let Some(signature) = unique_header(&headers, "x-updspace-signature") else {
        return error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Missing internal signature",
            request_id,
        );
    };
    let body = match to_bytes(request.into_body(), 4096).await {
        Ok(body) => body,
        Err(_) => {
            return error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "INVALID_BODY",
                "Request body too large",
                request_id,
            );
        }
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_secs() as i64);
    let signed = SignedRequest {
        method: "GET",
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
            request_id,
        );
    }
    let Some(raw_id) = unique_header(&headers, "x-user-id") else {
        return error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "X-User-Id is required",
            request_id,
        );
    };
    let Ok(identity_id) = Uuid::parse_str(raw_id) else {
        return error(
            StatusCode::BAD_REQUEST,
            "INVALID_USER_ID",
            "X-User-Id must be a UUID",
            request_id,
        );
    };
    let snapshot = match read_identity(&config.client, identity_id).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "User not found",
                request_id,
            );
        }
        Err(failure) => {
            tracing::error!(?failure, "internal identity lookup unavailable");
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
                request_id,
            );
        }
    };
    if let Some((code, message)) = denied_status(&snapshot) {
        return error(StatusCode::FORBIDDEN, code, message, request_id);
    }
    match assemble(snapshot, &config.media) {
        Ok(user) => response(StatusCode::OK, json!({"user":user})),
        Err(failure) => {
            tracing::error!(?failure, "internal identity response unavailable");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
                request_id,
            )
        }
    }
}

async fn portal_me(
    State(config): State<Arc<InternalIdentityConfig>>,
    request: Request,
) -> Response {
    let headers = request.headers().clone();
    let request_id = match unique_header(&headers, "x-request-id") {
        Some(value) if !value.is_empty() && value.len() <= 128 => value,
        _ => {
            return error(
                StatusCode::BAD_REQUEST,
                "MISSING_REQUEST_ID",
                "X-Request-Id is required",
                "",
            );
        }
    };
    let (Some(tenant_id), Some(tenant_slug)) = (
        unique_header(&headers, "x-tenant-id"),
        unique_header(&headers, "x-tenant-slug"),
    ) else {
        return error(
            StatusCode::BAD_REQUEST,
            "MISSING_TENANT",
            "X-Tenant-Id and X-Tenant-Slug are required",
            request_id,
        );
    };
    let Ok(tenant_id) = Uuid::parse_str(tenant_id) else {
        return error(
            StatusCode::BAD_REQUEST,
            "INVALID_TENANT_ID",
            "X-Tenant-Id must be a UUID",
            request_id,
        );
    };
    if tenant_slug.is_empty() || tenant_slug.len() > 64 {
        return error(
            StatusCode::BAD_REQUEST,
            "MISSING_TENANT",
            "X-Tenant-Id and X-Tenant-Slug are required",
            request_id,
        );
    }
    let signed_mode = headers.contains_key("x-updspace-timestamp")
        || headers.contains_key("x-updspace-signature");
    let principal = if signed_mode {
        let (Some(timestamp), Some(signature)) = (
            unique_header(&headers, "x-updspace-timestamp"),
            unique_header(&headers, "x-updspace-signature"),
        ) else {
            return error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Missing internal signature",
                request_id,
            );
        };
        let body = match to_bytes(request.into_body(), 4096).await {
            Ok(body) => body,
            Err(_) => {
                return error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "INVALID_BODY",
                    "Request body too large",
                    request_id,
                );
            }
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |time| time.as_secs() as i64);
        let signed = SignedRequest {
            method: "GET",
            path: PORTAL_PATH,
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
                request_id,
            );
        }
        let Some(raw_id) = unique_header(&headers, "x-user-id") else {
            return error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "X-User-Id is required",
                request_id,
            );
        };
        let Ok(identity_id) = Uuid::parse_str(raw_id) else {
            return error(
                StatusCode::BAD_REQUEST,
                "INVALID_USER_ID",
                "X-User-Id must be a UUID",
                request_id,
            );
        };
        PortalPrincipal::Signed(identity_id)
    } else {
        let Some(token) = portal_cookie(&headers) else {
            return error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Missing session",
                request_id,
            );
        };
        PortalPrincipal::Session(token)
    };
    let read = match read_portal(&config.client, principal, tenant_id, tenant_slug).await {
        Ok(value) => value,
        Err(failure) => {
            tracing::error!(?failure, "portal identity lookup unavailable");
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
                request_id,
            );
        }
    };
    let (snapshot, membership) = match read {
        PortalRead::InvalidSession => {
            return error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Invalid session",
                request_id,
            );
        }
        PortalRead::MissingIdentity => {
            return error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "User not found",
                request_id,
            );
        }
        PortalRead::TenantMismatch => {
            return error(
                StatusCode::CONFLICT,
                "TENANT_MISMATCH",
                "Tenant slug does not match tenant id",
                request_id,
            );
        }
        PortalRead::NoMembership => {
            return error(
                StatusCode::FORBIDDEN,
                "TENANT_FORBIDDEN",
                "No access to tenant",
                request_id,
            );
        }
        PortalRead::Found(snapshot, membership) => (snapshot, membership),
    };
    if let Some((code, message)) = denied_status(&snapshot) {
        return error(StatusCode::FORBIDDEN, code, message, request_id);
    }
    match assemble(*snapshot, &config.media) {
        Ok(user) => response(
            StatusCode::OK,
            json!({"user":user,"memberships":[membership]}),
        ),
        Err(failure) => {
            tracing::error!(?failure, "portal identity response unavailable");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
                request_id,
            )
        }
    }
}

fn portal_cookie(headers: &HeaderMap) -> Option<String> {
    let mut token = None;
    for header in headers.get_all(header::COOKIE).iter() {
        let raw = header.to_str().ok()?;
        for cookie in Cookie::split_parse(raw.to_owned()) {
            let cookie = cookie.ok()?;
            if cookie.name() == "updspace_session" {
                if token.is_some() || cookie.value().is_empty() || cookie.value().len() > 128 {
                    return None;
                }
                token = Some(cookie.value().to_owned());
            }
        }
    }
    token
}

fn denied_status(snapshot: &IdentitySnapshot) -> Option<(&'static str, &'static str)> {
    match snapshot.master.status.as_str() {
        "suspended" => return Some(("ACCOUNT_SUSPENDED", "Account is suspended")),
        "banned" => return Some(("ACCOUNT_BANNED", "Account is banned")),
        "active" => (),
        _ => return Some(("ACCOUNT_INACTIVE", "Account is inactive")),
    }
    if snapshot.deleting
        || snapshot.account.as_ref().is_some_and(|details| {
            details
                .account
                .as_ref()
                .is_none_or(|account| !account.is_active)
        })
    {
        return Some(("ACCOUNT_INACTIVE", "Account is inactive"));
    }
    None
}

fn unique_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(first)
}

async fn read_identity(client: &Client, identity_id: Uuid) -> Result<Option<IdentitySnapshot>> {
    let rows = client
        .query_client()
        .retry_tx(closure!([identity_id], async |tx: &mut Transaction| {
            read_identity_rows_tx(tx, *identity_id).await
        }))
        .isolation(TxMode::SnapshotReadOnly)
        .timeout(Duration::from_secs(5))
        .await
        .context("read internal identity snapshot")?;
    let Some((master, binding_count, profile, deleting)) = rows else {
        return Ok(None);
    };
    ensure!(binding_count <= 1, "identity has multiple account bindings");
    let account = profile.map(finish_profile_rows).transpose()?;
    Ok(Some(IdentitySnapshot {
        master,
        account,
        deleting,
    }))
}

async fn read_portal(
    client: &Client,
    principal: PortalPrincipal,
    tenant_id: Uuid,
    tenant_slug: &str,
) -> Result<PortalRead> {
    let tenant_slug = tenant_slug.to_owned();
    let now = SystemTime::now();
    let rows = client.query_client().retry_tx(closure!([principal, tenant_id, tenant_slug], async |tx: &mut Transaction| {
        let identity_id = match principal {
            PortalPrincipal::Signed(id) => *id,
            PortalPrincipal::Session(token) => {
                let Some(mut session) = tx.query_row("SELECT user_id, expires_at, revoked_at FROM usid_session WHERE token = $token")
                    .param("$token", token.clone()).optional().await? else { return Ok(PortalReadRows::InvalidSession); };
                let expires_at: SystemTime = session.remove_field_by_name("expires_at")?.try_into()?;
                let revoked_at: Option<SystemTime> = session.remove_field_by_name("revoked_at")?.try_into()?;
                if revoked_at.is_some() || expires_at <= now {
                    return Ok(PortalReadRows::InvalidSession);
                }
                session.remove_field_by_name("user_id")?.try_into()?
            }
        };
        let Some(identity) = read_identity_rows_tx(tx, identity_id).await? else {
            return Ok(PortalReadRows::MissingIdentity);
        };
        let Some(mut tenant) = tx.query_row("SELECT id FROM usid_tenant WHERE slug = $slug LIMIT 1")
            .param("$slug", tenant_slug.clone()).optional().await? else {
            return Ok(PortalReadRows::NoMembership);
        };
        let actual_tenant_id: Uuid = tenant.remove_field_by_name("id")?.try_into()?;
        if actual_tenant_id != *tenant_id {
            return Ok(PortalReadRows::TenantMismatch);
        }
        let Some(mut membership) = tx.query_row("SELECT status, base_role FROM usid_tenant_membership WHERE user_id = $user_id AND tenant_id = $tenant_id LIMIT 1")
            .param("$user_id", identity_id).param("$tenant_id", *tenant_id).optional().await? else {
            return Ok(PortalReadRows::NoMembership);
        };
        let status: String = membership.remove_field_by_name("status")?.try_into()?;
        if status != "active" {
            return Ok(PortalReadRows::NoMembership);
        }
        let base_role: String = membership.remove_field_by_name("base_role")?.try_into()?;
        Ok(PortalReadRows::Found(Box::new(identity), PortalMembership {
            tenant_id: tenant_id.to_string(),
            tenant_slug: tenant_slug.clone(),
            status,
            base_role,
        }))
    }))
        .isolation(TxMode::SnapshotReadOnly)
        .timeout(Duration::from_secs(5))
        .await
        .context("read portal identity snapshot")?;
    Ok(match rows {
        PortalReadRows::InvalidSession => PortalRead::InvalidSession,
        PortalReadRows::MissingIdentity => PortalRead::MissingIdentity,
        PortalReadRows::TenantMismatch => PortalRead::TenantMismatch,
        PortalReadRows::NoMembership => PortalRead::NoMembership,
        PortalReadRows::Found(identity, membership) => {
            let (master, binding_count, profile, deleting) = *identity;
            ensure!(binding_count <= 1, "identity has multiple account bindings");
            let account = profile.map(finish_profile_rows).transpose()?;
            PortalRead::Found(
                Box::new(IdentitySnapshot {
                    master,
                    account,
                    deleting,
                }),
                membership,
            )
        }
    })
}

type IdentityRows = (MasterIdentity, usize, Option<ProfileRows>, bool);

async fn read_identity_rows_tx(
    tx: &mut Transaction,
    identity_id: Uuid,
) -> ydb::YdbResultWithCustomerErr<Option<IdentityRows>> {
    let Some(mut row) = tx.query_row("SELECT username, display_name, email, email_verified, status, system_admin, created_at FROM usid_user WHERE user_id = $id")
        .param("$id", identity_id).optional().await? else { return Ok(None); };
    let master = MasterIdentity {
        id: identity_id,
        username: row.remove_field_by_name("username")?.try_into()?,
        display_name: row.remove_field_by_name("display_name")?.try_into()?,
        email: row.remove_field_by_name("email")?.try_into()?,
        email_verified: row.remove_field_by_name("email_verified")?.try_into()?,
        status: row.remove_field_by_name("status")?.try_into()?,
        system_admin: row.remove_field_by_name("system_admin")?.try_into()?,
        created_at: row.remove_field_by_name("created_at")?.try_into()?,
    };
    let mut stream = tx
        .query("SELECT user_id FROM accounts_accountidentity WHERE identity_id = $id LIMIT 2")
        .param("$id", identity_id)
        .await?;
    let mut bindings = Vec::new();
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            bindings.push(i32::try_from(row.remove_field_by_name("user_id")?)?);
        }
    }
    stream.close().await?;
    let profile = if bindings.len() == 1 {
        Some(read_profile_details_tx(tx, bindings[0]).await?)
    } else {
        None
    };
    let deleting = if bindings.len() == 1 {
        tx.query_row("SELECT id FROM accounts_accountdeletionrequest VIEW accounts_accountdeletionrequest_user_id_6a166c52 WHERE user_id = $id AND status IN ('pending', 'running') LIMIT 1")
            .param("$id", bindings[0]).optional().await?.is_some()
    } else {
        false
    };
    Ok(Some((master, bindings.len(), profile, deleting)))
}

fn assemble(snapshot: IdentitySnapshot, media: &MediaUrl) -> Result<IdentityUserOut> {
    let master = snapshot.master;
    let details = snapshot.account;
    let account = details.as_ref().and_then(|value| value.account.as_ref());
    let profile = details.as_ref().and_then(|value| value.profile.as_ref());
    let preferences = details
        .as_ref()
        .and_then(|value| value.preferences.as_ref());
    let avatar_url = profile
        .and_then(|value| value.avatar_key.as_deref())
        .filter(|key| !key.is_empty())
        .map(|key| media.avatar_url(key))
        .transpose()?;
    Ok(IdentityUserOut {
        user_id: master.id.to_string(),
        username: master.username,
        display_name: master.display_name,
        email: master.email,
        email_verified: master.email_verified,
        status: master.status,
        system_admin: account.map_or(master.system_admin, |value| {
            value.is_staff || value.is_superuser
        }),
        created_at: DateTime::<Utc>::from(master.created_at)
            .to_rfc3339_opts(SecondsFormat::Secs, true),
        first_name: account
            .and_then(|value| (!value.first_name.is_empty()).then(|| value.first_name.clone())),
        last_name: account
            .and_then(|value| (!value.last_name.is_empty()).then(|| value.last_name.clone())),
        phone_number: profile.map(|value| value.phone_number.clone()),
        phone_verified: profile.map(|value| value.phone_verified),
        birth_date: profile.and_then(|value| value.birth_date.clone()),
        language: preferences.map(|value| value.language.clone()),
        timezone: preferences.map(|value| value.timezone.clone()),
        avatar_url,
        avatar_source: profile.map(|value| value.avatar_source.clone()),
        avatar_gravatar_enabled: profile.map(|value| value.gravatar_enabled),
    })
}

fn response(status: StatusCode, body: Value) -> Response {
    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn error(status: StatusCode, code: &str, message: &str, request_id: &str) -> Response {
    response(
        status,
        json!({"error":{"code":code,"message":message,"details":null,"request_id":request_id}}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile_store::{AccountFields, ProfileFields};
    use anyhow::Result;
    use axum::{body::Body, http::Request};
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

    const SECRET: &[u8] = b"synthetic-internal-identity-test-secret-32";

    #[test]
    fn empty_legacy_avatar_is_absent() -> Result<()> {
        let snapshot = IdentitySnapshot {
            master: MasterIdentity {
                id: Uuid::nil(),
                username: "owner".into(),
                display_name: "Owner".into(),
                email: "owner@example.invalid".into(),
                email_verified: true,
                status: "active".into(),
                system_admin: false,
                created_at: UNIX_EPOCH,
            },
            account: Some(ProfileDetails {
                account: Some(AccountFields {
                    username: "owner".into(),
                    email: "owner@example.invalid".into(),
                    first_name: String::new(),
                    last_name: String::new(),
                    is_staff: false,
                    is_superuser: false,
                    is_active: true,
                }),
                profile: Some(ProfileFields {
                    avatar_key: Some(String::new()),
                    ..ProfileFields::default()
                }),
                preferences: None,
                has_mfa: false,
                oauth_providers: Vec::new(),
                email_verified: true,
            }),
            deleting: false,
        };
        let user = assemble(snapshot, &MediaUrl::new("https://example.invalid/media/")?)?;
        assert!(user.avatar_url.is_none());
        assert!(user.first_name.is_none());
        assert!(user.last_name.is_none());
        assert_eq!(user.created_at, "1970-01-01T00:00:00Z");
        Ok(())
    }

    async fn get(app: &Router, id: Uuid, signed: bool) -> Result<(StatusCode, Value)> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let request_id = Uuid::new_v4().to_string();
        let canonical = format!(
            "GET\n{PATH}\n{}\n{request_id}\n{timestamp}",
            hex::encode(Sha256::digest([]))
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(SECRET)?;
        mac.update(canonical.as_bytes());
        let signature = if signed {
            hex::encode(mac.finalize().into_bytes())
        } else {
            "0".repeat(64)
        };
        let request = Request::builder()
            .uri(PATH)
            .header("x-request-id", request_id)
            .header("x-user-id", id.to_string())
            .header("x-updspace-timestamp", timestamp.to_string())
            .header("x-updspace-signature", signature)
            .body(Body::empty())?;
        let response = app.clone().oneshot(request).await?;
        let status = response.status();
        let body = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
        Ok((status, body))
    }

    async fn portal_get(
        app: &Router,
        id: Uuid,
        tenant_id: Uuid,
        tenant_slug: &str,
        cookie: Option<&str>,
    ) -> Result<(StatusCode, Value)> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let request_id = Uuid::new_v4().to_string();
        let canonical = format!(
            "GET\n{PORTAL_PATH}\n{}\n{request_id}\n{timestamp}",
            hex::encode(Sha256::digest([]))
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(SECRET)?;
        mac.update(canonical.as_bytes());
        let mut request = Request::builder()
            .uri(PORTAL_PATH)
            .header("x-request-id", request_id)
            .header("x-tenant-id", tenant_id.to_string())
            .header("x-tenant-slug", tenant_slug);
        request = if let Some(cookie) = cookie {
            request.header("cookie", format!("updspace_session={cookie}"))
        } else {
            request
                .header("x-user-id", id.to_string())
                .header("x-updspace-timestamp", timestamp.to_string())
                .header(
                    "x-updspace-signature",
                    hex::encode(mac.finalize().into_bytes()),
                )
        };
        let response = app.clone().oneshot(request.body(Body::empty())?).await?;
        let status = response.status();
        let body = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
        Ok((status, body))
    }

    #[test]
    fn duplicate_portal_cookie_fails_closed() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("updspace_session=a; updspace_session=b"),
        );
        assert_eq!(portal_cookie(&headers), None);
    }

    #[tokio::test]
    #[ignore = "requires migrated local YDB"]
    async fn portal_me_checks_membership_and_legacy_cookie() -> Result<()> {
        ensure!(
            std::env::var("YDB_DATABASE")? == "/local",
            "local YDB required"
        );
        let client = Arc::new(crate::connect_ydb().await?);
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
        let id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let other_tenant_id = Uuid::new_v4();
        let membership_id = -i64::try_from(stamp)?;
        let token = format!("test-portal-{id}");
        let email = format!("portal-{id}@example.invalid");
        let slug = format!("portal-{id}");
        let app = router(Arc::new(InternalIdentityConfig {
            client: client.clone(),
            secret: SECRET.to_vec(),
            media: MediaUrl::new("https://example.invalid/media/")?,
            internal_enabled: false,
            portal_enabled: true,
        }));
        client.query_client().exec("UPSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, 'owner', 'Owner', $email, true, 'active', false, CurrentUtcDatetime())")
            .param("$id", id).param("$email", email).await?;
        client.query_client().exec("UPSERT INTO usid_tenant (id, slug, created_at) VALUES ($id, $slug, CurrentUtcDatetime())")
            .param("$id", tenant_id).param("$slug", slug.clone()).await?;
        let result: Result<()> = async {
            let (status, body) = portal_get(&app, id, tenant_id, &slug, None).await?;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(body["error"]["code"], "TENANT_FORBIDDEN");
            client.query_client().exec("UPSERT INTO usid_tenant_membership (id, user_id, tenant_id, status, base_role, source, created_at) VALUES ($id, $user_id, $tenant_id, 'active', 'member', 'native', CurrentUtcDatetime())")
                .param("$id", membership_id).param("$user_id", id).param("$tenant_id", tenant_id).await?;
            let (status, body) = portal_get(&app, id, tenant_id, &slug, None).await?;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["memberships"][0]["tenant_id"], tenant_id.to_string());
            assert_eq!(body["memberships"][0]["base_role"], "member");
            let (status, body) = portal_get(&app, id, other_tenant_id, &slug, None).await?;
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(body["error"]["code"], "TENANT_MISMATCH");
            client.query_client().exec("UPSERT INTO usid_session (token, user_id, created_at, expires_at, ip_hash, ua_hash) VALUES ($token, $user_id, CurrentUtcDatetime(), CAST($expires_at AS Datetime), $empty, $empty)")
                .param("$token", token.clone()).param("$user_id", id)
                .param("$expires_at", SystemTime::now() + Duration::from_secs(3600))
                .param("$empty", String::new()).await?;
            let (status, body) = portal_get(&app, id, tenant_id, &slug, Some(&token)).await?;
            assert_eq!(status, StatusCode::OK, "{body}");
            client.query_client().exec("UPDATE usid_session SET revoked_at = CurrentUtcDatetime() WHERE token = $token")
                .param("$token", token.clone()).await?;
            let (status, body) = portal_get(&app, id, tenant_id, &slug, Some(&token)).await?;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(body["error"]["code"], "UNAUTHORIZED");
            client.query_client().exec("UPDATE usid_tenant_membership SET status = 'inactive' WHERE id = $id")
                .param("$id", membership_id).await?;
            let (status, _) = portal_get(&app, id, tenant_id, &slug, None).await?;
            assert_eq!(status, StatusCode::FORBIDDEN);
            Ok(())
        }.await;
        client
            .query_client()
            .exec("DELETE FROM usid_session WHERE token = $token")
            .param("$token", token)
            .await
            .ok();
        client
            .query_client()
            .exec("DELETE FROM usid_tenant_membership WHERE id = $id")
            .param("$id", membership_id)
            .await
            .ok();
        client
            .query_client()
            .exec("DELETE FROM usid_tenant WHERE id = $id")
            .param("$id", tenant_id)
            .await
            .ok();
        client
            .query_client()
            .exec("DELETE FROM usid_user WHERE user_id = $id")
            .param("$id", id)
            .await
            .ok();
        result
    }

    #[tokio::test]
    #[ignore = "requires migrated local YDB"]
    async fn signed_lookup_rejects_unknown_banned_and_inactive_accounts() -> Result<()> {
        ensure!(
            std::env::var("YDB_DATABASE")? == "/local",
            "local YDB required"
        );
        let client = Arc::new(crate::connect_ydb().await?);
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
        let id = Uuid::new_v4();
        let account_id = -i32::try_from(stamp % 1_000_000_000 + 1)?;
        let deletion_id = -i64::try_from(stamp)?;
        let email = format!("internal-{id}@example.invalid");
        let app = router(Arc::new(InternalIdentityConfig {
            client: client.clone(),
            secret: SECRET.to_vec(),
            media: MediaUrl::new("https://example.invalid/media/")?,
            internal_enabled: true,
            portal_enabled: false,
        }));
        let (status, _) = get(&app, id, true).await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        client.query_client().exec("UPSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, 'owner', 'Owner', $email, true, 'active', false, CurrentUtcDatetime())")
            .param("$id", id).param("$email", email.clone()).await?;
        let result: Result<()> = async {
            let (status, body) = get(&app, id, false).await?;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(body["error"]["code"], "UNAUTHORIZED");
            let (status, body) = get(&app, id, true).await?;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["user"]["user_id"], id.to_string());
            assert_eq!(body["user"]["email"], email);
            assert!(body["user"]["first_name"].is_null());
            assert!(body.get("memberships").is_none());
            client.query_client().exec("UPDATE usid_user SET status = 'banned' WHERE user_id = $id")
                .param("$id", id).await?;
            let (status, body) = get(&app, id, true).await?;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(body["error"]["code"], "ACCOUNT_BANNED");
            client.query_client().exec("UPDATE usid_user SET status = 'active' WHERE user_id = $id")
                .param("$id", id).await?;
            client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, 'unusable', false, 'owner', 'First', 'Last', $email, false, false, CurrentUtcDatetime())")
                .param("$id", account_id).param("$email", email).await?;
            client.query_client().exec("UPSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($id, $identity, $subject, CurrentUtcDatetime())")
                .param("$id", account_id).param("$identity", id).param("$subject", id.to_string()).await?;
            let (status, body) = get(&app, id, true).await?;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(body["error"]["code"], "ACCOUNT_INACTIVE");
            client.query_client().exec("UPDATE auth_user SET is_active = true WHERE id = $id")
                .param("$id", account_id).await?;
            let (status, body) = get(&app, id, true).await?;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["user"]["first_name"], "First");
            assert_eq!(body["user"]["last_name"], "Last");
            client.query_client().exec("UPSERT INTO accounts_accountdeletionrequest (id, user_id, status, requested_at, reason) VALUES ($id, $user_id, 'pending', CurrentUtcDatetime(), '')")
                .param("$id", deletion_id).param("$user_id", account_id).await?;
            let (status, body) = get(&app, id, true).await?;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(body["error"]["code"], "ACCOUNT_INACTIVE");
            Ok(())
        }.await;
        client
            .query_client()
            .exec("DELETE FROM accounts_accountdeletionrequest WHERE id = $id")
            .param("$id", deletion_id)
            .await
            .ok();
        client
            .query_client()
            .exec("DELETE FROM accounts_accountidentity WHERE user_id = $id")
            .param("$id", account_id)
            .await
            .ok();
        client
            .query_client()
            .exec("DELETE FROM auth_user WHERE id = $id")
            .param("$id", account_id)
            .await
            .ok();
        client
            .query_client()
            .exec("DELETE FROM usid_user WHERE user_id = $id")
            .param("$id", id)
            .await
            .ok();
        result
    }
}
