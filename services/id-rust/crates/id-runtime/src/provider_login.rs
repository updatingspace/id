//! Provider browser login for previously linked accounts. No signup or email linking.
use crate::{
    cache_store::CacheStore,
    form_token_consume::consume_login_form_token,
    login_http::{self, LoginHttpConfig},
    login_preflight::{VerifiedAccount, verified_credential_owner},
    login_rate_limit::login_attempt,
    logout_http::{cookie_value, csrf_allowed},
    me_http::{env_flag, make_cookie},
    session_issuer::{IssueTiming, SessionClient, issue_provider_login},
    session_store::active_principal_tx,
};
use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cookie::SameSite;
use id_compat::cache::CacheValue;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use url::Url;
use uuid::Uuid;
use ydb::{Transaction, TxMode, closure};

const TTL: Duration = Duration::from_secs(300);
const MAX_BODY: usize = 16_384;

// Provider selection and browser/MFA/issuance policy are shared. Steam wire
// verification lives separately because it is OpenID 2.0 rather than OAuth2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Provider {
    Github,
    Discord,
    Steam,
}

impl Provider {
    const ALL: [Self; 3] = [Self::Github, Self::Discord, Self::Steam];

    fn id(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Discord => "discord",
            Self::Steam => "steam",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Github => "GitHub",
            Self::Discord => "Discord",
            Self::Steam => "Steam",
        }
    }

    fn callback_path(self) -> String {
        format!("/api/v1/auth/oauth/callback/{}", self.id())
    }

    fn login_path(self) -> String {
        format!("/api/v1/auth/oauth/login/{}", self.id())
    }

    fn flow_cookie(self) -> &'static str {
        match self {
            Self::Github => "__Host-id_github_flow",
            Self::Discord => "__Host-id_discord_flow",
            Self::Steam => "__Host-id_steam_flow",
        }
    }

    fn mfa_cookie(self) -> &'static str {
        match self {
            Self::Github => "__Host-id_github_mfa",
            Self::Discord => "__Host-id_discord_mfa",
            Self::Steam => "__Host-id_steam_mfa",
        }
    }

    fn cache_key(self, purpose: &str, opaque: &str) -> String {
        format!("{}-{purpose}:{opaque}", self.id())
    }

    fn endpoints(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Github => (
                "https://github.com/login/oauth/authorize",
                "https://github.com/login/oauth/access_token",
                "https://api.github.com/user",
            ),
            Self::Steam => (
                crate::steam_openid::ENDPOINT,
                crate::steam_openid::ENDPOINT,
                crate::steam_openid::DISCOVERY,
            ),
            Self::Discord => (
                "https://discord.com/oauth2/authorize",
                "https://discord.com/api/v10/oauth2/token",
                "https://discord.com/api/v10/users/@me",
            ),
        }
    }

    fn scope(self) -> &'static str {
        match self {
            Self::Github => "read:user",
            Self::Discord => "identify",
            Self::Steam => "",
        }
    }

    fn subject(self, user: &Value) -> Result<String> {
        match self {
            Self::Steam => anyhow::bail!("Steam uses OpenID assertions, not OAuth user info"),
            Self::Github => user
                .get("id")
                .and_then(Value::as_u64)
                .filter(|id| *id > 0)
                .map(|id| id.to_string())
                .context("invalid GitHub user ID"),
            Self::Discord => {
                let id = user
                    .get("id")
                    .and_then(Value::as_str)
                    .context("invalid Discord user ID")?;
                // Discord HTTP snowflakes are uint64 decimal strings. Reject
                // alternative encodings instead of normalizing an identity key.
                let parsed = id.parse::<u64>().context("invalid Discord snowflake")?;
                ensure!(
                    parsed > 0 && parsed.to_string() == id,
                    "noncanonical Discord user ID"
                );
                Ok(id.to_owned())
            }
        }
    }
}

pub struct ProviderLoginConfig {
    provider: Provider,
    login: Arc<LoginHttpConfig>,
    http: reqwest::Client,
    client_id: String,
    client_secret: String,
    callback_url: String,
    next_paths: Vec<String>,
    authorize_url: String,
    token_url: String,
    user_url: String,
}

impl ProviderLoginConfig {
    pub fn github_from_env(client: Arc<ydb::Client>) -> Result<Option<Arc<Self>>> {
        Self::from_env(client, Provider::Github)
    }

    pub fn discord_from_env(client: Arc<ydb::Client>) -> Result<Option<Arc<Self>>> {
        Self::from_env(client, Provider::Discord)
    }

    pub fn steam_from_env(client: Arc<ydb::Client>) -> Result<Option<Arc<Self>>> {
        Self::from_env(client, Provider::Steam)
    }

    fn from_env(client: Arc<ydb::Client>, provider: Provider) -> Result<Option<Arc<Self>>> {
        let env_prefix = provider.id().to_ascii_uppercase();
        if !env_flag(&format!("ID_AUTH_{env_prefix}_LOGIN_ENABLED"), false)? {
            return Ok(None);
        }
        ensure!(
            env_flag("ID_AUTH_FORM_TOKEN_ENABLED", false)?,
            "{} login requires form-token issuance",
            provider.name()
        );
        let login =
            LoginHttpConfig::from_env(client)?.context("provider login requires Rust login")?;
        let config = Self::new(
            provider,
            login,
            if provider == Provider::Steam {
                String::new()
            } else {
                env::var(format!("{env_prefix}_CLIENT_ID"))?
            },
            if provider == Provider::Steam {
                String::new()
            } else {
                env::var(format!("{env_prefix}_CLIENT_SECRET"))?
            },
            env::var(format!("ID_{env_prefix}_CALLBACK_URL"))?,
            serde_json::from_str(
                &env::var(format!("ID_{env_prefix}_LOGIN_NEXT_PATHS"))
                    .unwrap_or_else(|_| "[\"/account\"]".into()),
            )?,
        )?;
        // The sole callback is configuration-owned, never supplied by the browser.
        ensure!(
            config.callback_url.starts_with("https://"),
            "{} callback must use HTTPS",
            provider.name()
        );
        ensure!(
            config.login.options.session_cookie_secure && config.login.options.csrf_cookie_secure,
            "{} browser login requires secure cookies",
            provider.name()
        );
        Ok(Some(Arc::new(config)))
    }

    pub fn github(
        login: Arc<LoginHttpConfig>,
        client_id: String,
        client_secret: String,
        callback_url: String,
        next_paths: Vec<String>,
    ) -> Result<Self> {
        Self::new(
            Provider::Github,
            login,
            client_id,
            client_secret,
            callback_url,
            next_paths,
        )
    }

    pub fn discord(
        login: Arc<LoginHttpConfig>,
        client_id: String,
        client_secret: String,
        callback_url: String,
        next_paths: Vec<String>,
    ) -> Result<Self> {
        Self::new(
            Provider::Discord,
            login,
            client_id,
            client_secret,
            callback_url,
            next_paths,
        )
    }

    pub fn steam(
        login: Arc<LoginHttpConfig>,
        callback_url: String,
        next_paths: Vec<String>,
    ) -> Result<Self> {
        Self::new(
            Provider::Steam,
            login,
            String::new(),
            String::new(),
            callback_url,
            next_paths,
        )
    }

    fn new(
        provider: Provider,
        login: Arc<LoginHttpConfig>,
        client_id: String,
        client_secret: String,
        callback_url: String,
        next_paths: Vec<String>,
    ) -> Result<Self> {
        ensure!(
            provider == Provider::Steam
                || (!client_id.is_empty()
                    && client_id.len() <= 256
                    && !client_secret.is_empty()
                    && client_secret.len() <= 4096),
            "missing or invalid {} credentials",
            provider.name()
        );
        let url = Url::parse(&callback_url)?;
        let local = login.client.database() == "/local" && loopback(&url);
        ensure!(
            (url.scheme() == "https" || local)
                && url.host_str().is_some()
                && url.path() == provider.callback_path()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.username().is_empty()
                && url.password().is_none(),
            "invalid {} callback URL",
            provider.name()
        );
        ensure!(
            login
                .options
                .trusted_origins
                .contains(&url.origin().ascii_serialization()),
            "{} callback origin must be trusted",
            provider.name()
        );
        ensure!(
            !next_paths.is_empty()
                && next_paths.len() <= 32
                && next_paths.iter().all(|path| safe_next(path)),
            "invalid {} return path allowlist",
            provider.name()
        );
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .user_agent("UpdSpace-ID")
            .build()?;
        let (authorize_url, token_url, user_url) = provider.endpoints();
        Ok(Self {
            provider,
            login,
            http,
            client_id,
            client_secret,
            callback_url,
            next_paths,
            authorize_url: authorize_url.into(),
            token_url: token_url.into(),
            user_url: user_url.into(),
        })
    }

    /// Local YDB integration tests only: no environment-controlled endpoint override.
    #[cfg(debug_assertions)]
    pub fn with_loopback_provider(mut self, origin: &str) -> Result<Self> {
        let url = Url::parse(origin)?;
        ensure!(
            self.login.client.database() == "/local"
                && loopback(&url)
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none()
                && url.username().is_empty()
                && url.password().is_none(),
            "loopback provider requires local YDB"
        );
        if self.provider == Provider::Steam {
            self.authorize_url = url.join("openid/login")?.to_string();
            self.token_url = self.authorize_url.clone();
            self.user_url = url.join("openid/id/")?.to_string();
            return Ok(self);
        }
        self.authorize_url = url.join("authorize")?.to_string();
        self.token_url = url.join("token")?.to_string();
        self.user_url = url.join("user")?.to_string();
        Ok(self)
    }
}

fn loopback(url: &Url) -> bool {
    url.scheme() == "http"
        && url
            .host_str()
            .is_some_and(|host| matches!(host, "127.0.0.1" | "[::1]"))
}

fn safe_next(path: &str) -> bool {
    path.starts_with('/')
        && path.is_ascii()
        && !path.starts_with("//")
        && path.len() <= 2048
        && !path
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, '\\' | '#'))
        && !path.contains('%')
}

pub fn router(config: Arc<ProviderLoginConfig>) -> Router {
    let path = config.provider.login_path();
    Router::new()
        .route(&path, post(start).options(preflight))
        .route(&config.provider.callback_path(), get(callback))
        .route(
            &format!("{path}/complete"),
            post(complete).options(preflight),
        )
        .route(&format!("{path}/pending"), get(pending_context))
        .route(&format!("{path}/cancel"), post(cancel).options(preflight))
        .with_state(config)
}

#[derive(Serialize, Deserialize)]
struct Flow {
    provider: Provider,
    browser_hash: String,
    verifier: String,
    session_hash: String,
    callback: String,
    next: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Binding {
    account_id: i32,
    identity_id: Uuid,
    social_id: Option<i32>,
    external_id: Option<i64>,
}

enum BindingResolution {
    Unlinked,
    Conflict,
    Linked(Binding),
}

/// Constructed only after server-side OAuth exchange or Steam OpenID verification.
/// The serializable pending representation contains no password hash or provider token.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct ProviderProof {
    provider: Provider,
    subject: String,
    binding: Binding,
    account_hash: String,
    email: String,
    public_subject: String,
    authenticated_at: u64,
    once: String,
    browser_hash: String,
    session_hash: String,
}

pub(crate) struct ProviderEvidence<'a> {
    pub proof: &'a ProviderProof,
    pub cache: &'a CacheStore,
    pub code: Option<&'a str>,
}

impl ProviderProof {
    pub(crate) fn provider_id(&self) -> &'static str {
        self.provider.id()
    }

    pub(crate) fn authenticated_at(&self) -> u64 {
        self.authenticated_at
    }

    pub(crate) async fn valid_in_tx(
        &self,
        tx: &mut Transaction,
        cache: &CacheStore,
        account_id: i32,
        identity_id: Uuid,
        now: SystemTime,
    ) -> ydb::YdbResultWithCustomerErr<bool> {
        let seconds = now
            .duration_since(UNIX_EPOCH)
            .map_err(ydb::YdbOrCustomerError::from_err)?
            .as_secs();
        if self.binding.account_id != account_id
            || self.binding.identity_id != identity_id
            || !self
                .once
                .strip_prefix(&self.provider.cache_key("issued", ""))
                .is_some_and(valid_opaque)
            || seconds < self.authenticated_at
            || seconds - self.authenticated_at >= TTL.as_secs()
            || cache.contains_live_in_tx(tx, &self.once, now).await?
            || cache
                .contains_live_in_tx(
                    tx,
                    &self.provider.cache_key("canceled", &self.browser_hash),
                    now,
                )
                .await?
        {
            return Ok(false);
        }
        Ok(
            matches!(resolve_binding(tx, self.provider, &self.subject).await?, BindingResolution::Linked(binding) if binding == self.binding),
        )
    }

    pub(crate) async fn consume_in_tx(
        &self,
        tx: &mut Transaction,
        cache: &CacheStore,
        now: SystemTime,
    ) -> ydb::YdbResultWithCustomerErr<()> {
        if !cache
            .claim_in_tx(
                tx,
                &self.once,
                UNIX_EPOCH + Duration::from_secs(self.authenticated_at) + TTL,
                now,
            )
            .await?
        {
            return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
                "provider proof already consumed",
            )));
        }
        if let Some(id) = self.binding.social_id {
            tx.exec("UPDATE socialaccount_socialaccount SET last_login = CAST($now AS Datetime) WHERE id = $id")
                .param("$id", id).param("$now", now).await?;
        }
        if let Some(id) = self.binding.external_id {
            tx.exec("UPDATE usid_external_identity SET last_used_at = CAST($now AS Datetime) WHERE id = $id")
                .param("$id", id).param("$now", now).await?;
        }
        Ok(())
    }
}

// ponytail: legacy tables lack a subject index; bounded results but scans remain.
// Add a reconciled (provider, subject) primary-key index before enabling link writers at scale.
async fn resolve_binding(
    tx: &mut Transaction,
    provider: Provider,
    subject: &str,
) -> ydb::YdbResultWithCustomerErr<BindingResolution> {
    let mut rows = tx.query("SELECT id, user_id FROM socialaccount_socialaccount WHERE provider = $provider AND uid = $subject LIMIT 2")
        .param("$provider", provider.id().to_owned()).param("$subject", subject.to_owned()).await?;
    let mut social: Vec<(i32, i32)> = Vec::new();
    while let Some(set) = rows.next_result_set().await? {
        for mut row in set {
            social.push((
                row.remove_field_by_name("id")?.try_into()?,
                row.remove_field_by_name("user_id")?.try_into()?,
            ));
        }
    }
    rows.close().await?;
    let mut rows = tx.query("SELECT id, user_id FROM usid_external_identity VIEW usid_ext_provider_idx WHERE provider = $provider AND subject = $subject LIMIT 2")
        .param("$provider", provider.id().to_owned()).param("$subject", subject.to_owned()).await?;
    let mut external: Vec<(i64, Uuid)> = Vec::new();
    while let Some(set) = rows.next_result_set().await? {
        for mut row in set {
            external.push((
                row.remove_field_by_name("id")?.try_into()?,
                row.remove_field_by_name("user_id")?.try_into()?,
            ));
        }
    }
    rows.close().await?;
    if social.len() > 1 || external.len() > 1 {
        return Ok(BindingResolution::Conflict);
    }
    if social.is_empty() && external.is_empty() {
        return Ok(BindingResolution::Unlinked);
    }
    let account_id = if let Some((_, owner)) = social.first() {
        *owner
    } else {
        let mut rows = tx.query("SELECT user_id FROM accounts_accountidentity WHERE identity_id = $identity LIMIT 2")
            .param("$identity", external[0].1).await?;
        let mut owners: Vec<i32> = Vec::new();
        while let Some(set) = rows.next_result_set().await? {
            for mut row in set {
                owners.push(row.remove_field_by_name("user_id")?.try_into()?);
            }
        }
        rows.close().await?;
        if owners.len() != 1 {
            return Ok(BindingResolution::Conflict);
        }
        owners[0]
    };
    let Some(principal) = active_principal_tx(tx, account_id).await? else {
        return Ok(BindingResolution::Unlinked);
    };
    let identity_id = principal.identity_id.get();
    if external
        .first()
        .is_some_and(|(_, owner)| *owner != identity_id)
    {
        return Ok(BindingResolution::Conflict);
    }
    let mut rows = tx
        .query("SELECT user_id FROM accounts_accountidentity WHERE identity_id = $identity LIMIT 2")
        .param("$identity", identity_id)
        .await?;
    let mut owners: Vec<i32> = Vec::new();
    while let Some(set) = rows.next_result_set().await? {
        for mut row in set {
            owners.push(row.remove_field_by_name("user_id")?.try_into()?);
        }
    }
    rows.close().await?;
    if owners != [account_id] {
        return Ok(BindingResolution::Conflict);
    }
    Ok(BindingResolution::Linked(Binding {
        account_id,
        identity_id,
        social_id: social.first().map(|row| row.0),
        external_id: external.first().map(|row| row.0),
    }))
}

#[derive(Serialize, Deserialize)]
struct Pending {
    proof: ProviderProof,
    next: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartIn {
    form_token: Option<String>,
    next: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteIn {
    mfa_code: Option<String>,
    recovery_code: Option<String>,
}

fn opaque() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}
fn valid_opaque(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|ch| ch.is_ascii_hexdigit())
}
fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn json_response(
    config: &ProviderLoginConfig,
    headers: &HeaderMap,
    status: StatusCode,
    body: Value,
) -> Response {
    login_http::json_response(
        headers,
        &config.login.options,
        status,
        body,
        login_http::make_csrf_cookie(headers, &config.login.options, false),
        None,
    )
}
fn error(
    config: &ProviderLoginConfig,
    headers: &HeaderMap,
    status: StatusCode,
    code: &str,
) -> Response {
    json_response(config, headers, status, json!({"code":code,"message":code}))
}
fn unavailable(config: &ProviderLoginConfig, headers: &HeaderMap) -> Response {
    error(
        config,
        headers,
        StatusCode::SERVICE_UNAVAILABLE,
        "SERVICE_UNAVAILABLE",
    )
}
fn flow_cookie(response: &mut Response, name: &str, value: &str) {
    let cookie = make_cookie(
        name,
        value,
        true,
        true,
        SameSite::Lax,
        None,
        Some(if value.is_empty() { 0 } else { TTL.as_secs() }),
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}
fn redirect(mut response: Response, location: &str) -> Response {
    *response.status_mut() = StatusCode::SEE_OTHER;
    *response.body_mut() = Body::empty();
    response.headers_mut().remove(header::CONTENT_TYPE);
    response.headers_mut().remove("x-session-token");
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(location).unwrap_or(HeaderValue::from_static(
            "/login?provider_error=SERVICE_UNAVAILABLE",
        )),
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}
async fn preflight(State(config): State<Arc<ProviderLoginConfig>>, headers: HeaderMap) -> Response {
    json_response(&config, &headers, StatusCode::NO_CONTENT, Value::Null)
}
async fn read_json<T: DeserializeOwned>(
    config: &ProviderLoginConfig,
    request: Request,
) -> std::result::Result<T, (StatusCode, &'static str)> {
    let headers = request.headers();
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok());
    if !origin.is_some_and(|origin| {
        config
            .login
            .options
            .trusted_origins
            .iter()
            .any(|trusted| trusted == origin)
    }) || !csrf_allowed(
        headers,
        &config.login.options.csrf_cookie_name,
        &config.login.options.trusted_origins,
    ) {
        return Err((StatusCode::FORBIDDEN, "CSRF_FAILED"));
    }
    if !headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    {
        return Err((StatusCode::UNSUPPORTED_MEDIA_TYPE, "UNSUPPORTED_MEDIA_TYPE"));
    }
    let bytes = to_bytes(request.into_body(), MAX_BODY)
        .await
        .map_err(|_| (StatusCode::PAYLOAD_TOO_LARGE, "VALIDATION_ERROR"))?;
    serde_json::from_slice(&bytes).map_err(|_| (StatusCode::BAD_REQUEST, "VALIDATION_ERROR"))
}
async fn rate(
    config: &ProviderLoginConfig,
    headers: &HeaderMap,
    ip: &str,
    email: Option<&str>,
) -> Option<Response> {
    match login_attempt(
        &config.login.cache,
        Some(ip),
        email,
        config.login.options.login_ip_limit,
        SystemTime::now(),
    )
    .await
    {
        Ok(value) if !value.blocked => None,
        Ok(value) => {
            let mut response = error(
                config,
                headers,
                StatusCode::TOO_MANY_REQUESTS,
                "LOGIN_RATE_LIMITED",
            );
            response.headers_mut().insert(
                header::RETRY_AFTER,
                HeaderValue::from(value.retry_after_seconds),
            );
            Some(response)
        }
        Err(_) => Some(unavailable(config, headers)),
    }
}

async fn start(State(config): State<Arc<ProviderLoginConfig>>, request: Request) -> Response {
    let headers = request.headers().clone();
    let ip = login_http::request_ip(&request).unwrap_or_default();
    let payload: StartIn = match read_json(&config, request).await {
        Ok(value) => value,
        Err((status, code)) => return error(&config, &headers, status, code),
    };
    let next = payload.next.unwrap_or_else(|| config.next_paths[0].clone());
    if !config.next_paths.contains(&next) {
        return error(
            &config,
            &headers,
            StatusCode::BAD_REQUEST,
            "INVALID_REDIRECT",
        );
    }
    let now = SystemTime::now();
    match consume_login_form_token(&config.login.cache, payload.form_token.as_deref(), now).await {
        Ok(true) => {}
        Ok(false) => {
            return error(
                &config,
                &headers,
                StatusCode::BAD_REQUEST,
                "INVALID_FORM_TOKEN",
            );
        }
        Err(_) => return unavailable(&config, &headers),
    }
    if let Some(response) = rate(&config, &headers, &ip, None).await {
        return response;
    }
    let state = opaque();
    if cancel_existing(&config.login.cache, &headers)
        .await
        .is_err()
    {
        return unavailable(&config, &headers);
    }
    let browser = opaque();
    let verifier = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let flow = Flow {
        provider: config.provider,
        browser_hash: digest(&browser),
        verifier,
        session_hash: session_hash(&config, &headers),
        callback: config.callback_url.clone(),
        next,
    };
    let result = async {
        ensure!(
            config
                .login
                .cache
                .add(
                    &config.provider.cache_key("state", &state),
                    &CacheValue::String(serde_json::to_string(&flow)?),
                    Some(now + TTL),
                    now
                )
                .await?,
            "state collision"
        );
        if config.provider == Provider::Steam {
            return crate::steam_openid::authorize(
                &config.authorize_url,
                &config.callback_url,
                &state,
            );
        }
        let mut url = Url::parse(&config.authorize_url)?;
        url.query_pairs_mut()
            .append_pair("client_id", &config.client_id)
            .append_pair("redirect_uri", &config.callback_url)
            .append_pair("scope", config.provider.scope())
            .append_pair("state", &state)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        if config.provider == Provider::Discord {
            url.query_pairs_mut().append_pair("response_type", "code");
        }
        Ok::<_, anyhow::Error>(url)
    }
    .await;
    let Ok(url) = result else {
        return unavailable(&config, &headers);
    };
    let mut response = json_response(
        &config,
        &headers,
        StatusCode::OK,
        json!({"authorize_url":url.as_str(),"method":"GET"}),
    );
    for previous in Provider::ALL {
        if previous != config.provider {
            flow_cookie(&mut response, previous.flow_cookie(), "");
            flow_cookie(&mut response, previous.mfa_cookie(), "");
        }
    }
    flow_cookie(&mut response, config.provider.flow_cookie(), &browser);
    flow_cookie(&mut response, config.provider.mfa_cookie(), "");
    response
}

fn callback_params(raw: &str) -> Option<BTreeMap<String, String>> {
    if raw.len() > 8192 {
        return None;
    }
    let mut result = BTreeMap::new();
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        if !matches!(
            key.as_ref(),
            "state" | "code" | "error" | "error_description" | "error_uri"
        ) || result
            .insert(key.into_owned(), value.into_owned())
            .is_some()
        {
            return None;
        }
    }
    Some(result)
}

async fn response_json(mut response: reqwest::Response) -> Result<Value> {
    ensure!(response.status().is_success(), "provider rejected request");
    ensure!(
        response
            .content_length()
            .is_none_or(|length| length <= 65_536),
        "provider response too large"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= 65_536,
            "provider response too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&bytes)?)
}

async fn exchange(config: &ProviderLoginConfig, code: &str, verifier: &str) -> Result<String> {
    ensure!(
        !code.is_empty() && code.len() <= 2048,
        "invalid provider code"
    );
    let request = config
        .http
        .post(&config.token_url)
        .header("accept", "application/json");
    let request = match config.provider {
        Provider::Steam => anyhow::bail!("Steam is not an OAuth provider"),
        Provider::Github => request.form(&[
            ("client_id", config.client_id.as_str()),
            ("client_secret", config.client_secret.as_str()),
            ("code", code),
            ("redirect_uri", config.callback_url.as_str()),
            ("code_verifier", verifier),
        ]),
        Provider::Discord => request
            .basic_auth(&config.client_id, Some(&config.client_secret))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", config.callback_url.as_str()),
                ("code_verifier", verifier),
            ]),
    };
    // Both adapters require S256. A failed exchange never downgrades to a
    // second request without code_verifier or repeats the one-use code.
    let data = response_json(request.send().await?).await?;
    ensure!(data.get("error").is_none(), "provider rejected code");
    let token = data
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty() && token.len() <= 4096)
        .context("provider token missing")?;
    ensure!(
        data.get("token_type")
            .and_then(Value::as_str)
            .is_some_and(|kind| kind.eq_ignore_ascii_case("bearer")),
        "invalid provider token type"
    );
    if config.provider == Provider::Discord {
        ensure!(
            data.get("scope")
                .and_then(Value::as_str)
                .is_some_and(|scope| scope
                    .split_ascii_whitespace()
                    .any(|value| value == "identify")),
            "Discord token lacks identify scope"
        );
    }
    let request = config
        .http
        .get(&config.user_url)
        .bearer_auth(token)
        .header("accept", "application/json");
    let request = if config.provider == Provider::Github {
        request.header("x-github-api-version", "2022-11-28")
    } else {
        request
    };
    let user = response_json(request.send().await?).await?;
    config.provider.subject(&user)
}

async fn callback_inner(
    State(config): State<Arc<ProviderLoginConfig>>,
    request: Request,
) -> Response {
    let headers = request.headers().clone();
    let ip = login_http::request_ip(&request).unwrap_or_default();
    let invalid = || error(&config, &headers, StatusCode::BAD_REQUEST, "INVALID_STATE");
    let raw = request.uri().query().unwrap_or_default();
    let params = if config.provider == Provider::Steam {
        crate::steam_openid::parameters(raw)
    } else {
        callback_params(raw)
    };
    let Some(params) = params else {
        return invalid();
    };
    let Some(state) = params.get("state").filter(|value| valid_opaque(value)) else {
        return invalid();
    };
    let Some(browser) =
        cookie_value(&headers, config.provider.flow_cookie()).filter(|value| valid_opaque(value))
    else {
        return invalid();
    };
    let key = config.provider.cache_key("state", state);
    let now = SystemTime::now();
    let flow: Flow = match config.login.cache.get(&key, now).await {
        Ok(Some(CacheValue::String(value))) => match serde_json::from_str(&value) {
            Ok(value) => value,
            Err(_) => return unavailable(&config, &headers),
        },
        Ok(_) => return invalid(),
        Err(_) => return unavailable(&config, &headers),
    };
    if flow.provider != config.provider
        || flow.browser_hash != digest(&browser)
        || flow.session_hash != session_hash(&config, &headers)
        || flow.callback != config.callback_url
        || !config.next_paths.contains(&flow.next)
    {
        return invalid();
    }
    match config
        .login
        .cache
        .get(
            &config.provider.cache_key("canceled", &flow.browser_hash),
            now,
        )
        .await
    {
        Ok(None) => {}
        Ok(Some(_)) => return invalid(),
        Err(_) => return unavailable(&config, &headers),
    }
    if let Some(response) = rate(&config, &headers, &ip, None).await {
        return response;
    }
    // Consume before network I/O: a failed exchange requires a new browser flow.
    match config.login.cache.take(&key, now).await {
        Ok(Some(_)) => {}
        Ok(None) => return invalid(),
        Err(_) => return unavailable(&config, &headers),
    }
    if params.contains_key("error")
        || (config.provider == Provider::Steam && crate::steam_openid::denied(&params))
    {
        return error(
            &config,
            &headers,
            StatusCode::UNAUTHORIZED,
            "PROVIDER_DENIED",
        );
    }
    let verification = if config.provider == Provider::Steam {
        crate::steam_openid::verify(
            &config.http,
            &config.authorize_url,
            &config.user_url,
            &config.callback_url,
            state,
            &params,
            now,
        )
        .await
        .map(|assertion| {
            (
                assertion.subject,
                Some((assertion.nonce, assertion.expires)),
            )
        })
    } else {
        let Some(code) = params.get("code") else {
            return invalid();
        };
        exchange(&config, code, &flow.verifier)
            .await
            .map(|subject| (subject, None))
    };
    let (subject, nonce) = match verification {
        Ok(value) => value,
        Err(_) => {
            return error(
                &config,
                &headers,
                StatusCode::SERVICE_UNAVAILABLE,
                "PROVIDER_UNAVAILABLE",
            );
        }
    };
    if let Some((nonce, expiry)) = nonce {
        // State and the provider nonce are independent replay barriers. Shared YDB
        // enforces this even across API instances; ambiguity never permits issuance.
        match config
            .login
            .cache
            .add(
                &config.provider.cache_key("nonce", &digest(&nonce)),
                &CacheValue::Bool(true),
                Some(expiry),
                SystemTime::now(),
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => return invalid(),
            Err(_) => return unavailable(&config, &headers),
        }
    }
    let lookup_subject = subject.clone();
    let provider = config.provider;
    let binding = config
        .login
        .client
        .query_client()
        .retry_tx(closure!([lookup_subject], async |tx: &mut Transaction| {
            resolve_binding(tx, provider, lookup_subject).await
        }))
        .with_mode(TxMode::SnapshotReadOnly)
        .timeout(Duration::from_secs(5))
        .await;
    let binding = match binding {
        Ok(BindingResolution::Linked(value)) => value,
        Ok(BindingResolution::Unlinked) => {
            return error(
                &config,
                &headers,
                StatusCode::UNAUTHORIZED,
                "ACCOUNT_NOT_LINKED",
            );
        }
        Ok(BindingResolution::Conflict) => {
            return error(&config, &headers, StatusCode::CONFLICT, "IDENTITY_CONFLICT");
        }
        Err(_) => return unavailable(&config, &headers),
    };
    let account = match verified_credential_owner(&config.login.client, binding.account_id).await {
        Ok(Some(value)) if value.identity_id.get() == binding.identity_id => value,
        Ok(_) => {
            return error(
                &config,
                &headers,
                StatusCode::UNAUTHORIZED,
                "INVALID_CREDENTIALS",
            );
        }
        Err(_) => return unavailable(&config, &headers),
    };
    let proof = ProviderProof {
        provider: config.provider,
        subject,
        binding,
        account_hash: match config
            .login
            .session_codec
            .auth_hash(account.password_hash())
        {
            Ok(value) => value,
            Err(_) => return unavailable(&config, &headers),
        },
        email: account.email_key().into(),
        public_subject: account.public_subject.as_str().into(),
        authenticated_at: match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(value) => value.as_secs(),
            Err(_) => return unavailable(&config, &headers),
        },
        once: config.provider.cache_key("issued", state),
        browser_hash: flow.browser_hash,
        session_hash: flow.session_hash,
    };
    if account.has_mfa {
        let token = opaque();
        let pending = Pending {
            proof,
            next: flow.next,
        };
        let now = SystemTime::now();
        let result = async {
            config
                .login
                .cache
                .add(
                    &config.provider.cache_key("mfa", &token),
                    &CacheValue::String(serde_json::to_string(&pending)?),
                    Some(now + TTL),
                    now,
                )
                .await
        }
        .await;
        if !matches!(result, Ok(true)) {
            return unavailable(&config, &headers);
        }
        let mut response = redirect(
            json_response(&config, &headers, StatusCode::OK, Value::Null),
            &format!("/login?provider_mfa={}", config.provider.id()),
        );
        flow_cookie(&mut response, config.provider.flow_cookie(), &browser);
        flow_cookie(&mut response, config.provider.mfa_cookie(), &token);
        return response;
    }
    let response = finish(&config, &headers, &ip, &account, &proof, None).await;
    if response.status() != StatusCode::OK {
        return response;
    }
    let mut response = redirect(response, &flow.next);
    flow_cookie(&mut response, config.provider.flow_cookie(), "");
    flow_cookie(&mut response, config.provider.mfa_cookie(), "");
    response
}

async fn finish(
    config: &ProviderLoginConfig,
    headers: &HeaderMap,
    ip: &str,
    account: &VerifiedAccount,
    proof: &ProviderProof,
    code: Option<&str>,
) -> Response {
    let Ok(ip) = ip.parse() else {
        return unavailable(config, headers);
    };
    let client = SessionClient {
        ip,
        user_agent: headers
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .into(),
        device_fingerprint_salt: config.login.options.device_fingerprint_salt.clone(),
    };
    match issue_provider_login(
        &config.login.client,
        config.login.session_codec.clone(),
        &config.login.jwt_codec,
        account,
        &client,
        IssueTiming {
            now: SystemTime::now(),
            lifetime: Duration::from_secs(config.login.options.session_cookie_age),
        },
        ProviderEvidence {
            proof,
            cache: &config.login.cache,
            code,
        },
    )
    .await
    {
        Ok(Some(issued)) => {
            login_http::login_success(&config.login, headers, account, issued).await
        }
        Ok(None) => error(
            config,
            headers,
            StatusCode::UNAUTHORIZED,
            "INVALID_CREDENTIALS",
        ),
        Err(_) => unavailable(config, headers),
    }
}

async fn complete(State(config): State<Arc<ProviderLoginConfig>>, request: Request) -> Response {
    let headers = request.headers().clone();
    let ip = login_http::request_ip(&request).unwrap_or_default();
    let payload: CompleteIn = match read_json(&config, request).await {
        Ok(value) => value,
        Err((status, code)) => return error(&config, &headers, status, code),
    };
    let code = match (payload.mfa_code, payload.recovery_code) {
        (Some(code), None) | (None, Some(code)) => code.trim().replace(' ', ""),
        _ => return error(&config, &headers, StatusCode::BAD_REQUEST, "MFA_REQUIRED"),
    };
    if code.is_empty() || code.len() > 128 || !code.is_ascii() {
        return error(
            &config,
            &headers,
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
        );
    }
    let invalid = || {
        error(
            &config,
            &headers,
            StatusCode::UNAUTHORIZED,
            "INVALID_CREDENTIALS",
        )
    };
    let Some(token) =
        cookie_value(&headers, config.provider.mfa_cookie()).filter(|value| valid_opaque(value))
    else {
        return flow_expired(&config, &headers);
    };
    let now = SystemTime::now();
    let pending: Pending = match config
        .login
        .cache
        .get(&config.provider.cache_key("mfa", &token), now)
        .await
    {
        Ok(Some(CacheValue::String(value))) => match serde_json::from_str(&value) {
            Ok(value) => value,
            Err(_) => return unavailable(&config, &headers),
        },
        Ok(_) => return flow_expired(&config, &headers),
        Err(_) => return unavailable(&config, &headers),
    };
    if !config.next_paths.contains(&pending.next)
        || !same_browser(&config, &headers, &pending.proof)
    {
        return flow_expired(&config, &headers);
    }
    match proof_active(&config, &pending.proof, now).await {
        Ok(true) => {}
        Ok(false) => return flow_expired(&config, &headers),
        Err(_) => return unavailable(&config, &headers),
    }
    if let Some(response) = rate(&config, &headers, &ip, Some(&pending.proof.email)).await {
        return response;
    }
    let account =
        match verified_credential_owner(&config.login.client, pending.proof.binding.account_id)
            .await
        {
            Ok(Some(value)) => value,
            Ok(None) => return invalid(),
            Err(_) => return unavailable(&config, &headers),
        };
    if config
        .login
        .session_codec
        .auth_hash(account.password_hash())
        .ok()
        .as_deref()
        != Some(pending.proof.account_hash.as_str())
        || account.email_key() != pending.proof.email
        || account.public_subject.as_str() != pending.proof.public_subject
    {
        return invalid();
    }
    let response = finish(
        &config,
        &headers,
        &ip,
        &account,
        &pending.proof,
        Some(&code),
    )
    .await;
    if response.status() == StatusCode::UNAUTHORIZED {
        return error(&config, &headers, StatusCode::UNAUTHORIZED, "INVALID_MFA");
    }
    if response.status() != StatusCode::OK {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let body = match to_bytes(body, 1_000_000).await {
        Ok(value) => value,
        Err(_) => return unavailable(&config, &headers),
    };
    let mut body: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return unavailable(&config, &headers),
    };
    body["next"] = json!(pending.next);
    parts.headers.remove(header::CONTENT_LENGTH);
    let mut response = Response::from_parts(parts, Body::from(body.to_string()));
    flow_cookie(&mut response, config.provider.mfa_cookie(), "");
    flow_cookie(&mut response, config.provider.flow_cookie(), "");
    response
}

fn session_hash(config: &ProviderLoginConfig, headers: &HeaderMap) -> String {
    digest(&cookie_value(headers, &config.login.options.session_cookie_name).unwrap_or_default())
}

fn same_browser(config: &ProviderLoginConfig, headers: &HeaderMap, proof: &ProviderProof) -> bool {
    proof.provider == config.provider
        && cookie_value(headers, config.provider.flow_cookie())
            .filter(|value| valid_opaque(value))
            .is_some_and(|value| digest(&value) == proof.browser_hash)
        && session_hash(config, headers) == proof.session_hash
}

pub(crate) async fn cancel_existing(cache: &CacheStore, headers: &HeaderMap) -> Result<()> {
    for provider in Provider::ALL {
        if let Some(browser) =
            cookie_value(headers, provider.flow_cookie()).filter(|value| valid_opaque(value))
        {
            let now = SystemTime::now();
            cache
                .add(
                    &provider.cache_key("canceled", &digest(&browser)),
                    &CacheValue::Bool(true),
                    Some(now + TTL * 2),
                    now,
                )
                .await?;
        }
    }
    Ok(())
}

fn clear_flow_cookies(response: &mut Response) {
    for provider in Provider::ALL {
        flow_cookie(response, provider.flow_cookie(), "");
        flow_cookie(response, provider.mfa_cookie(), "");
    }
}

async fn cancel(State(config): State<Arc<ProviderLoginConfig>>, request: Request) -> Response {
    let headers = request.headers().clone();
    let _: BTreeMap<String, Value> = match read_json(&config, request).await {
        Ok(value) => value,
        Err((status, code)) => return error(&config, &headers, status, code),
    };
    if cancel_existing(&config.login.cache, &headers)
        .await
        .is_err()
    {
        return unavailable(&config, &headers);
    }
    let mut response = json_response(&config, &headers, StatusCode::OK, json!({"ok":true}));
    clear_flow_cookies(&mut response);
    response
}

fn flow_expired(config: &ProviderLoginConfig, headers: &HeaderMap) -> Response {
    json_response(
        config,
        headers,
        StatusCode::UNAUTHORIZED,
        json!({"code":"PROVIDER_FLOW_EXPIRED","active":false,"restart_required":true}),
    )
}

async fn proof_active(
    config: &ProviderLoginConfig,
    proof: &ProviderProof,
    now: SystemTime,
) -> Result<bool> {
    let proof = proof.clone();
    let cache = config.login.cache.clone();
    Ok(config
        .login
        .client
        .query_client()
        .retry_tx(closure!([proof, cache], async |tx: &mut Transaction| {
            proof
                .valid_in_tx(
                    tx,
                    cache,
                    proof.binding.account_id,
                    proof.binding.identity_id,
                    now,
                )
                .await
        }))
        .with_mode(TxMode::SnapshotReadOnly)
        .timeout(Duration::from_secs(5))
        .await?)
}

async fn pending_context(
    State(config): State<Arc<ProviderLoginConfig>>,
    headers: HeaderMap,
) -> Response {
    let Some(token) =
        cookie_value(&headers, config.provider.mfa_cookie()).filter(|value| valid_opaque(value))
    else {
        return flow_expired(&config, &headers);
    };
    let now = SystemTime::now();
    let pending: Pending = match config
        .login
        .cache
        .get(&config.provider.cache_key("mfa", &token), now)
        .await
    {
        Ok(Some(CacheValue::String(value))) => match serde_json::from_str(&value) {
            Ok(value) => value,
            Err(_) => return unavailable(&config, &headers),
        },
        Ok(_) => return flow_expired(&config, &headers),
        Err(_) => return unavailable(&config, &headers),
    };
    if !config.next_paths.contains(&pending.next)
        || !same_browser(&config, &headers, &pending.proof)
    {
        return flow_expired(&config, &headers);
    }
    match proof_active(&config, &pending.proof, now).await {
        Ok(true) => {}
        Ok(false) => return flow_expired(&config, &headers),
        Err(_) => return unavailable(&config, &headers),
    }
    let account =
        match verified_credential_owner(&config.login.client, pending.proof.binding.account_id)
            .await
        {
            Ok(Some(value)) => value,
            Ok(None) => return flow_expired(&config, &headers),
            Err(_) => return unavailable(&config, &headers),
        };
    if config
        .login
        .session_codec
        .auth_hash(account.password_hash())
        .ok()
        .as_deref()
        != Some(pending.proof.account_hash.as_str())
        || account.email_key() != pending.proof.email
        || account.public_subject.as_str() != pending.proof.public_subject
    {
        return flow_expired(&config, &headers);
    }
    let account_id = pending.proof.binding.account_id;
    let factors = config
        .login
        .client
        .query_client()
        .retry_tx(closure!([], async |tx: &mut Transaction| {
            crate::security_read::status_tx(tx, account_id).await
        }))
        .with_mode(TxMode::SnapshotReadOnly)
        .timeout(Duration::from_secs(5))
        .await;
    let Ok(factors) = factors else {
        return unavailable(&config, &headers);
    };
    let mut methods = Vec::new();
    if factors.has_totp {
        methods.push("totp")
    }
    if factors.recovery_codes_left > 0 {
        methods.push("recovery_codes")
    }
    json_response(
        &config,
        &headers,
        StatusCode::OK,
        json!({
            "active":true,"expires_at":pending.proof.authenticated_at + TTL.as_secs(),
            "methods":methods,"restart_required":methods.is_empty(),"next":pending.next,
        }),
    )
}

async fn callback(State(config): State<Arc<ProviderLoginConfig>>, request: Request) -> Response {
    let response = callback_inner(State(config.clone()), request).await;
    if response.status() == StatusCode::SEE_OTHER {
        return response;
    }
    let (parts, body) = response.into_parts();
    let body = to_bytes(body, MAX_BODY)
        .await
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    let code = body
        .as_ref()
        .and_then(|body| body.get("code"))
        .and_then(Value::as_str)
        .unwrap_or("SERVICE_UNAVAILABLE");
    let code = match code {
        "INVALID_STATE"
        | "PROVIDER_DENIED"
        | "PROVIDER_UNAVAILABLE"
        | "ACCOUNT_NOT_LINKED"
        | "IDENTITY_CONFLICT"
        | "INVALID_CREDENTIALS"
        | "LOGIN_RATE_LIMITED" => code,
        _ => "SERVICE_UNAVAILABLE",
    };
    redirect(
        Response::from_parts(parts, Body::empty()),
        &format!("/login?provider_error={code}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn return_paths_and_duplicate_callback_parameters_fail_closed() -> Result<()> {
        assert!(safe_next("/account?section=security"));
        for path in [
            "https://evil.invalid",
            "//evil.invalid",
            "/\\evil",
            "/%2f%2fevil",
            "/account#token",
            "/a\r\nLocation:x",
        ] {
            assert!(!safe_next(path));
        }
        assert!(callback_params("code=x&state=y").is_some());
        assert!(callback_params("state=x&state=y").is_none());
        assert!(callback_params("state=x&redirect_uri=https://evil.invalid").is_none());
        assert!(!loopback(&Url::parse("http://127.0.0.1.evil.invalid")?));
        Ok(())
    }
}
