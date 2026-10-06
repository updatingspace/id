//! API client for SSR account pages. Authentication and data access remain in id-api.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::{env, time::Duration};
use url::Url;

const MAX_ME_BODY: usize = 64 * 1024;
const MAX_SESSIONS_BODY: usize = 1024 * 1024;
const MAX_PREFERENCES_BODY: usize = 64 * 1024;
const MAX_CONSENTS_BODY: usize = 1024 * 1024;
const MAX_TIMEZONES_BODY: usize = 512 * 1024;
const MAX_APPS_BODY: usize = 1024 * 1024;
const MAX_SECURITY_BODY: usize = 1024 * 1024;
const MAX_HISTORY_BODY: usize = 256 * 1024;
const MAX_EMAIL_BODY: usize = 16 * 1024;

#[derive(Deserialize)]
pub(super) struct MeResponse {
    pub(super) user: Option<User>,
}

#[derive(Deserialize)]
pub(super) struct User {
    pub(super) username: String,
    pub(super) email: String,
    pub(super) first_name: Option<String>,
    pub(super) last_name: Option<String>,
    pub(super) phone_number: Option<String>,
    pub(super) birth_date: Option<String>,
    pub(super) email_verified: bool,
    pub(super) has_2fa: bool,
    pub(super) avatar_url: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct SessionsResponse {
    pub(super) sessions: Vec<SessionRow>,
}

#[derive(Deserialize)]
pub(super) struct HistoryResponse {
    pub(super) events: Vec<LoginEventRow>,
}

#[derive(Deserialize)]
pub(super) struct LoginEventRow {
    pub(super) status: String,
    pub(super) ip_address: Option<String>,
    pub(super) user_agent: Option<String>,
    pub(super) is_new_device: bool,
    pub(super) reason: Option<String>,
    pub(super) created_at: String,
}

#[derive(Deserialize)]
pub(super) struct SessionRow {
    pub(super) id: String,
    pub(super) user_agent: Option<String>,
    pub(super) ip: Option<String>,
    pub(super) current: bool,
    pub(super) revoked: bool,
}

#[derive(Deserialize)]
pub(super) struct Preferences {
    pub(super) language: String,
    pub(super) timezone: String,
    pub(super) marketing_opt_in: bool,
    pub(super) privacy_scope_defaults: std::collections::BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
pub(super) struct ConsentsResponse {
    pub(super) consents: Vec<ConsentRow>,
}

#[derive(Deserialize)]
pub(super) struct ConsentRow {
    pub(super) kind: String,
    pub(super) version: String,
    pub(super) granted_at: String,
    pub(super) revoked_at: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct TimezonesResponse {
    pub(super) timezones: Vec<TimezoneRow>,
}

#[derive(Deserialize)]
pub(super) struct TimezoneRow {
    pub(super) name: String,
    pub(super) display_name: String,
}

#[derive(Deserialize)]
pub(super) struct AuthorizedAppsResponse {
    pub(super) items: Vec<AuthorizedApp>,
}

#[derive(Deserialize)]
pub(super) struct AuthorizedApp {
    pub(super) client_id: String,
    pub(super) name: String,
    pub(super) scopes: Vec<String>,
    pub(super) last_used_at: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct SecurityResponse {
    pub(super) mfa: MfaStatus,
    pub(super) authenticators: Vec<PasskeyRow>,
}

#[derive(Deserialize)]
pub(super) struct EmailStatus {
    pub(super) email: String,
    pub(super) verified: bool,
    pub(super) pending_email: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct MfaStatus {
    pub(super) has_totp: bool,
    pub(super) has_webauthn: bool,
    pub(super) has_recovery_codes: bool,
    pub(super) recovery_codes_left: usize,
}

#[derive(Deserialize)]
pub(super) struct PasskeyRow {
    #[serde(default)]
    pub(super) id: String,
    pub(super) name: Option<String>,
    pub(super) is_passwordless: bool,
}

pub(super) enum Profile {
    Guest(Vec<String>),
    User(User, Vec<String>),
}

#[derive(Deserialize)]
pub(super) struct ExportStatus {
    pub(super) id: String,
    pub(super) status: String,
    pub(super) manifest: Option<ExportManifest>,
    pub(super) expires_at: Option<String>,
    pub(super) release_at: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct ExportManifest {
    pub(super) format: String,
    pub(super) categories: Vec<ExportCategory>,
    pub(super) excluded: Vec<String>,
    pub(super) consistency: String,
}

#[derive(Deserialize)]
pub(super) struct ExportCategory {
    pub(super) category: String,
    pub(super) records: u64,
}

pub(crate) struct AccountApi {
    pub(super) client: reqwest::Client,
    pub(super) me_url: Url,
    pub(super) sessions_url: Url,
    pub(super) preferences_url: Url,
    pub(super) consents_url: Url,
    pub(super) timezones_url: Url,
    pub(super) apps_url: Url,
    pub(super) security_url: Url,
    pub(super) history_url: Url,
    pub(super) email_url: Url,
    pub(super) exports_url: Url,
    pub(super) sessions_enabled: bool,
    pub(super) logout_enabled: bool,
    pub(super) profile_enabled: bool,
    pub(super) preferences_enabled: bool,
    pub(super) consents_enabled: bool,
    pub(super) apps_enabled: bool,
    pub(super) security_enabled: bool,
    pub(super) history_enabled: bool,
    pub(super) totp_enabled: bool,
    pub(super) passkey_management_enabled: bool,
    pub(super) passkey_registration_enabled: bool,
    pub(super) password_change_enabled: bool,
    pub(super) email_management_enabled: bool,
    pub(super) exports_enabled: bool,
}

impl AccountApi {
    pub(crate) fn from_env() -> Result<Self> {
        let origin = env::var("ID_WEB_API_ORIGIN").context("ID_WEB_API_ORIGIN is required")?;
        let me_url = me_url(&origin)?;
        let mut sessions_url = me_url.clone();
        sessions_url.set_path("/api/v1/auth/sessions");
        let mut preferences_url = me_url.clone();
        preferences_url.set_path("/api/v1/auth/preferences");
        let mut consents_url = me_url.clone();
        consents_url.set_path("/api/v1/auth/consents");
        let mut timezones_url = me_url.clone();
        timezones_url.set_path("/api/v1/auth/timezones");
        let mut apps_url = me_url.clone();
        apps_url.set_path("/api/v1/auth/oauth/apps");
        let mut security_url = me_url.clone();
        security_url.set_path("/api/v1/auth/security");
        let mut history_url = me_url.clone();
        history_url.set_path("/api/v1/auth/login-history");
        let mut email_url = me_url.clone();
        email_url.set_path("/api/v1/auth/email");
        let mut exports_url = me_url.clone();
        exports_url.set_path("/api/v1/auth/data/exports");
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            client,
            me_url,
            sessions_url,
            preferences_url,
            consents_url,
            timezones_url,
            apps_url,
            security_url,
            history_url,
            email_url,
            exports_url,
            sessions_enabled: env::var("ID_WEB_SESSIONS_PILOT_ENABLED").as_deref() == Ok("true"),
            logout_enabled: env::var("ID_WEB_LOGOUT_PILOT_ENABLED").as_deref() == Ok("true"),
            profile_enabled: env::var("ID_WEB_PROFILE_PILOT_ENABLED").as_deref() == Ok("true"),
            preferences_enabled: env::var("ID_WEB_PREFERENCES_PILOT_ENABLED").as_deref()
                == Ok("true"),
            consents_enabled: env::var("ID_WEB_CONSENTS_PILOT_ENABLED").as_deref() == Ok("true"),
            apps_enabled: env::var("ID_WEB_APPS_PILOT_ENABLED").as_deref() == Ok("true"),
            security_enabled: env::var("ID_WEB_SECURITY_PILOT_ENABLED").as_deref() == Ok("true"),
            history_enabled: env::var("ID_WEB_LOGIN_HISTORY_PILOT_ENABLED").as_deref()
                == Ok("true"),
            totp_enabled: env::var("ID_WEB_TOTP_PILOT_ENABLED").as_deref() == Ok("true")
                || env::var("ID_WEB_TOTP_ENABLED").as_deref() == Ok("true"),
            passkey_management_enabled: env::var("ID_WEB_PASSKEY_MANAGEMENT_ENABLED").as_deref()
                == Ok("true")
                || env::var("ID_WEB_TOTP_PILOT_ENABLED").as_deref() == Ok("true")
                || env::var("ID_WEB_TOTP_ENABLED").as_deref() == Ok("true"),
            passkey_registration_enabled: env::var("ID_WEB_PASSKEY_REGISTRATION_ENABLED")
                .as_deref()
                == Ok("true"),
            password_change_enabled: env::var("ID_WEB_PASSWORD_CHANGE_PILOT_ENABLED").as_deref()
                == Ok("true"),
            email_management_enabled: env::var("ID_WEB_EMAIL_MANAGEMENT_ENABLED").as_deref()
                == Ok("true"),
            exports_enabled: env::var("ID_WEB_EXPORTS_ENABLED").as_deref() == Ok("true"),
        })
    }
}

pub(super) fn me_url(origin: &str) -> Result<Url> {
    let mut url = Url::parse(origin)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.scheme(), "http" | "https")
        || (url.scheme() == "http" && !matches!(url.host_str(), Some("127.0.0.1" | "localhost")))
    {
        bail!("ID_WEB_API_ORIGIN must be an HTTPS origin or local HTTP origin");
    }
    url.set_path("/api/v1/auth/me");
    Ok(url)
}

pub(super) async fn profile(api: &AccountApi, cookie: Option<&str>) -> Result<Profile> {
    let mut request = api.client.get(api.me_url.clone());
    if let Some(cookie) = cookie {
        request = request.header(reqwest::header::COOKIE, cookie);
    }
    let mut response = request.send().await?;
    if !response.status().is_success() {
        bail!("/me returned {}", response.status());
    }
    let cookies = response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().map(str::to_owned))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > MAX_ME_BODY {
            bail!("/me response is too large");
        }
        body.extend_from_slice(&chunk);
    }
    let parsed: MeResponse = serde_json::from_slice(&body)?;
    Ok(match parsed.user {
        Some(user) => Profile::User(user, cookies),
        None => Profile::Guest(cookies),
    })
}

pub(super) async fn sessions(
    api: &AccountApi,
    cookie: Option<&str>,
    user_agent: Option<&str>,
) -> Result<Vec<SessionRow>> {
    let mut request = api.client.get(api.sessions_url.clone());
    if let Some(cookie) = cookie {
        request = request.header(reqwest::header::COOKIE, cookie);
    }
    if let Some(user_agent) = user_agent {
        request = request.header(reqwest::header::USER_AGENT, user_agent);
    }
    let mut response = request.send().await?;
    if !response.status().is_success() {
        bail!("/sessions returned {}", response.status());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > MAX_SESSIONS_BODY {
            bail!("/sessions response is too large");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice::<SessionsResponse>(&body)?.sessions)
}

pub(super) async fn preferences(api: &AccountApi, cookie: Option<&str>) -> Result<Preferences> {
    let mut request = api.client.get(api.preferences_url.clone());
    if let Some(cookie) = cookie {
        request = request.header(reqwest::header::COOKIE, cookie);
    }
    let mut response = request.send().await?;
    if !response.status().is_success() {
        bail!("/preferences returned {}", response.status());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > MAX_PREFERENCES_BODY {
            bail!("preferences response is too large");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&body)?)
}

pub(super) async fn consents(api: &AccountApi, cookie: Option<&str>) -> Result<Vec<ConsentRow>> {
    let mut request = api.client.get(api.consents_url.clone());
    if let Some(cookie) = cookie {
        request = request.header(reqwest::header::COOKIE, cookie);
    }
    let mut response = request.send().await?;
    if !response.status().is_success() {
        bail!("/consents returned {}", response.status());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > MAX_CONSENTS_BODY {
            bail!("consents response is too large");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice::<ConsentsResponse>(&body)?.consents)
}

pub(super) async fn timezones(api: &AccountApi) -> Result<Vec<TimezoneRow>> {
    let mut response = api.client.get(api.timezones_url.clone()).send().await?;
    if !response.status().is_success() {
        bail!("/timezones returned {}", response.status());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > MAX_TIMEZONES_BODY {
            bail!("timezones response is too large");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice::<TimezonesResponse>(&body)?.timezones)
}

pub(super) async fn authorized_apps(
    api: &AccountApi,
    cookie: Option<&str>,
) -> Result<Vec<AuthorizedApp>> {
    let mut request = api.client.get(api.apps_url.clone());
    if let Some(cookie) = cookie {
        request = request.header(reqwest::header::COOKIE, cookie);
    }
    let mut response = request.send().await?;
    if !response.status().is_success() {
        bail!("/oauth/apps returned {}", response.status());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > MAX_APPS_BODY {
            bail!("OAuth apps response is too large");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice::<AuthorizedAppsResponse>(&body)?.items)
}

pub(super) async fn security(api: &AccountApi, cookie: Option<&str>) -> Result<SecurityResponse> {
    let mut request = api.client.get(api.security_url.clone());
    if let Some(cookie) = cookie {
        request = request.header(reqwest::header::COOKIE, cookie);
    }
    let mut response = request.send().await?;
    if !response.status().is_success() {
        bail!("/security returned {}", response.status());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > MAX_SECURITY_BODY {
            bail!("security response is too large");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&body)?)
}

pub(super) async fn login_history(
    api: &AccountApi,
    cookie: Option<&str>,
) -> Result<Vec<LoginEventRow>> {
    let mut request = api.client.get(api.history_url.clone());
    if let Some(cookie) = cookie {
        request = request.header(reqwest::header::COOKIE, cookie);
    }
    let mut response = request.send().await?;
    if !response.status().is_success() {
        bail!("/login-history returned {}", response.status());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > MAX_HISTORY_BODY {
            bail!("login history response is too large");
        }
        body.extend_from_slice(&chunk);
    }
    let history: HistoryResponse = serde_json::from_slice(&body)?;
    if history.events.len() > 100 {
        bail!("login history exceeded 100 events");
    }
    Ok(history.events)
}

pub(super) async fn email_status(api: &AccountApi, cookie: Option<&str>) -> Result<EmailStatus> {
    let mut request = api.client.get(api.email_url.clone());
    if let Some(cookie) = cookie {
        request = request.header(reqwest::header::COOKIE, cookie);
    }
    let mut response = request.send().await?;
    if !response.status().is_success() {
        bail!("/email returned {}", response.status());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > MAX_EMAIL_BODY {
            bail!("email status response is too large");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&body)?)
}

pub(super) async fn export_status(
    api: &AccountApi,
    cookie: Option<&str>,
    id: &str,
) -> Result<Option<ExportStatus>> {
    if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(None);
    }
    let mut url = api.exports_url.clone();
    url.set_path(&format!("/api/v1/auth/data/exports/{id}"));
    let mut request = api.client.get(url);
    if let Some(cookie) = cookie {
        request = request.header(reqwest::header::COOKIE, cookie);
    }
    let mut response = request.send().await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status().is_success() {
        bail!("export status returned {}", response.status());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > 64 * 1024 {
            bail!("export status response is too large");
        }
        body.extend_from_slice(&chunk);
    }
    let status: ExportStatus = serde_json::from_slice(&body)?;
    if status.id != id {
        bail!("export status ID mismatch");
    }
    Ok(Some(status))
}
