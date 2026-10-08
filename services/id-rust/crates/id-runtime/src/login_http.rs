//! Local-only password/MFA login pilot. Public routing remains blocked until
//! production credential audits, login effects and Gateway/browser parity pass.

use crate::{
    cache_store::CacheStore,
    form_token_consume::consume_login_form_token,
    login_preflight::{LoginDecision, LoginPreflight, VerifiedAccount},
    login_rate_limit::{login_attempt, reset_verified_email},
    me_http::{cookie_domain, env_flag, make_cookie, new_csrf_secret, same_site},
    media_url::MediaUrl,
    profile_response::{CurrentUserOut, ProfileOut},
    profile_store::read_profile_details,
    session_issuer::{
        IssueTiming, IssuedPasswordLogin, MfaProof, SessionClient, issue_password_login,
        issue_password_login_with_mfa,
    },
    session_store::session_codec_from_env,
    ymq::YmqPublisher,
};
#[cfg(feature = "passkeys")]
use crate::{passkey_login, session_issuer::issue_passkey_login};
use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use cookie::{Cookie, SameSite};
use id_compat::{account_jwt::AccountJwtCodec, csrf, session::SessionCodec};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    env,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use url::Url;
#[cfg(feature = "passkeys")]
use webauthn_rs::prelude::{Url as WebauthnUrl, Webauthn, WebauthnBuilder};
use ydb::Client;

const MAX_LOGIN_BODY: usize = 16_384;
#[cfg(feature = "passkeys")]
const PASSKEY_CEREMONY_COOKIE: &str = "id_passkey_ceremony";

#[cfg(feature = "passkeys")]
struct PasskeyLoginConfig {
    webauthn: Arc<Webauthn>,
    rp_id: String,
    origin: String,
}

pub struct LoginHttpConfig {
    pub(crate) client: Arc<Client>,
    pub(crate) cache: CacheStore,
    preflight: LoginPreflight,
    pub(crate) session_codec: Arc<SessionCodec>,
    pub(crate) jwt_codec: AccountJwtCodec,
    media: MediaUrl,
    pub(crate) options: LoginHttpOptions,
    ymq: Option<Arc<YmqPublisher>>,
    #[cfg(feature = "passkeys")]
    passkey: Option<PasskeyLoginConfig>,
}

pub struct LoginHttpOptions {
    pub session_cookie_name: String,
    pub csrf_cookie_name: String,
    pub session_cookie_secure: bool,
    pub csrf_cookie_secure: bool,
    pub session_same_site: SameSite,
    pub csrf_same_site: SameSite,
    pub session_cookie_domain: Option<String>,
    pub csrf_cookie_domain: Option<String>,
    pub session_cookie_age: u64,
    pub login_ip_limit: i64,
    pub trusted_origins: Vec<String>,
    pub device_fingerprint_salt: String,
}

impl LoginHttpConfig {
    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        if !env_flag("ID_AUTH_LOGIN_PILOT_ENABLED", false)? {
            return Ok(None);
        }
        let endpoint = env::var("YDB_ENDPOINT")?;
        let endpoint = Url::parse(&endpoint)?;
        let local_pilot = env_flag("DJANGO_DEBUG", false)?
            && matches!(
                endpoint.host_str(),
                Some("localhost" | "127.0.0.1" | "[::1]")
            )
            && env::var("YDB_DATABASE")?.as_str() == "/local";
        if !local_pilot && !env_flag("ID_RUST_EARLY_ROLLOUT_ENABLED", false)? {
            bail!("incomplete Rust login pilot is restricted to local debug YDB");
        }
        let secret = env::var("DJANGO_SECRET_KEY")?;
        let codec = session_codec_from_env()?;
        let jwt = AccountJwtCodec::new(secret.as_bytes())?;
        let media = MediaUrl::from_env(
            &env::var("MEDIA_PUBLIC_BASE_URL")
                .context("MEDIA_PUBLIC_BASE_URL is required for login pilot")?,
        )?;
        let table = env::var("YDB_CACHE_TABLE").unwrap_or_else(|_| "id_shared_cache".into());
        let cache = CacheStore::new(client.clone(), &table, "", 1)?;
        let options = LoginHttpOptions {
            session_cookie_name: env::var("SESSION_COOKIE_NAME")
                .unwrap_or_else(|_| "sessionid".into()),
            csrf_cookie_name: env::var("CSRF_COOKIE_NAME").unwrap_or_else(|_| "csrftoken".into()),
            session_cookie_secure: env_flag("SESSION_COOKIE_SECURE", true)?,
            csrf_cookie_secure: env_flag("CSRF_COOKIE_SECURE", true)?,
            session_same_site: same_site("SESSION_COOKIE_SAMESITE")?,
            csrf_same_site: same_site("CSRF_COOKIE_SAMESITE")?,
            session_cookie_domain: cookie_domain("SESSION_COOKIE_DOMAIN")?,
            csrf_cookie_domain: cookie_domain("CSRF_COOKIE_DOMAIN")?,
            session_cookie_age: env::var("SESSION_COOKIE_AGE")
                .ok()
                .map(|value| value.parse())
                .transpose()?
                .unwrap_or(1_209_600),
            login_ip_limit: env::var("RATE_LIMIT_LOGIN_IP")
                .ok()
                .map(|value| value.parse())
                .transpose()?
                .unwrap_or(50),
            trusted_origins: env::var("CSRF_TRUSTED_ORIGINS")
                .unwrap_or_else(|_| {
                    "http://localhost:5175,http://id.localhost:5175,http://id.localhost".into()
                })
                .split(',')
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
                .collect(),
            device_fingerprint_salt: env::var("DEVICE_FINGERPRINT_SALT")
                .unwrap_or_else(|_| "device-salt".into()),
        };
        let mut config = Self::new(client, cache, codec, jwt, media, options)?;
        #[cfg(feature = "passkeys")]
        if env_flag("ID_AUTH_PASSKEY_LOGIN_PILOT_ENABLED", false)? {
            let rp_id = env::var("ID_WEBAUTHN_RP_ID").context("ID_WEBAUTHN_RP_ID required")?;
            let origin = env::var("ID_WEBAUTHN_ORIGIN").context("ID_WEBAUTHN_ORIGIN required")?;
            config = config.with_passkey(&rp_id, &origin)?;
        }
        if let Some(publisher) = YmqPublisher::from_env()? {
            config = config.with_ymq_publisher(publisher);
        }
        Ok(Some(Arc::new(config)))
    }

    pub fn new(
        client: Arc<Client>,
        cache: CacheStore,
        session_codec: Arc<SessionCodec>,
        jwt_codec: AccountJwtCodec,
        media: MediaUrl,
        mut options: LoginHttpOptions,
    ) -> Result<Self> {
        for name in [&options.session_cookie_name, &options.csrf_cookie_name] {
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            {
                bail!("invalid login cookie name");
            }
        }
        if options.session_cookie_age == 0
            || options.session_cookie_age > 2_592_000
            || options.login_ip_limit < 1
            || options.trusted_origins.is_empty()
            || options.device_fingerprint_salt.len() > 256
        {
            bail!("invalid login pilot limits or trusted origins");
        }
        options.trusted_origins = options
            .trusted_origins
            .iter()
            .map(|value| canonical_origin(value))
            .collect::<Result<Vec<_>>>()?;
        let preflight = LoginPreflight::new(client.clone(), 2)?;
        Ok(Self {
            client,
            cache,
            preflight,
            session_codec,
            jwt_codec,
            media,
            options,
            ymq: None,
            #[cfg(feature = "passkeys")]
            passkey: None,
        })
    }

    pub fn with_ymq_publisher(mut self, publisher: YmqPublisher) -> Self {
        self.ymq = Some(Arc::new(publisher));
        self
    }

    #[cfg(feature = "passkeys")]
    pub fn with_passkey(mut self, rp_id: &str, origin: &str) -> Result<Self> {
        let parsed = WebauthnUrl::parse(origin)?;
        let webauthn = WebauthnBuilder::new(rp_id, &parsed)?
            .rp_name("UpdSpace ID")
            .build()?;
        self.passkey = Some(PasskeyLoginConfig {
            webauthn: Arc::new(webauthn),
            rp_id: rp_id.to_owned(),
            origin: origin.to_owned(),
        });
        Ok(self)
    }
}

pub fn router(config: Arc<LoginHttpConfig>) -> Router {
    let router = Router::new().route("/api/v1/auth/login", post(login).options(preflight));
    #[cfg(feature = "passkeys")]
    let router = if config.passkey.is_some() {
        router
            .route(
                "/api/v1/auth/passkeys/login/begin",
                post(passkey_begin).options(preflight),
            )
            .route(
                "/api/v1/auth/passkeys/login/complete",
                post(passkey_complete).options(preflight),
            )
    } else {
        router
    };
    router.with_state(config)
}

fn canonical_origin(raw: &str) -> Result<String> {
    let url = Url::parse(raw)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        bail!("invalid CSRF trusted origin");
    }
    Ok(url.origin().ascii_serialization())
}

#[derive(Deserialize)]
struct LoginIn {
    email: String,
    password: String,
    #[serde(default)]
    form_token: Option<String>,
    #[serde(default)]
    mfa_code: Option<String>,
    #[serde(default)]
    recovery_code: Option<String>,
}

#[derive(Serialize)]
struct LoginOut {
    meta: LoginMeta,
    user: Option<ProfileOut>,
    access_token: String,
    refresh_token: String,
    recovery_codes: Option<Vec<String>>,
    verification_required: bool,
}

#[derive(Serialize)]
struct LoginMeta {
    session_token: String,
}

async fn preflight(State(config): State<Arc<LoginHttpConfig>>, headers: HeaderMap) -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    add_cors(response.headers_mut(), &headers, &config.options);
    response
}

async fn login(State(config): State<Arc<LoginHttpConfig>>, request: Request) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|value| value.0);
    let headers = request.headers().clone();
    let csrf_cookie = make_csrf_cookie(&headers, &config.options, false);
    if !is_json(&headers) {
        return error(
            &headers,
            &config.options,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "UNSUPPORTED_MEDIA_TYPE",
            "Content-Type must be application/json",
            csrf_cookie,
        );
    }
    if !csrf_allowed(&headers, &config.options) {
        return error(
            &headers,
            &config.options,
            StatusCode::FORBIDDEN,
            "CSRF_FAILED",
            "CSRF verification failed",
            csrf_cookie,
        );
    }
    let body = match to_bytes(request.into_body(), MAX_LOGIN_BODY + 1).await {
        Ok(body) => body,
        Err(_) => {
            return error(
                &headers,
                &config.options,
                StatusCode::PAYLOAD_TOO_LARGE,
                "VALIDATION_ERROR",
                "Тело запроса слишком велико",
                csrf_cookie,
            );
        }
    };
    if body.len() > MAX_LOGIN_BODY {
        return error(
            &headers,
            &config.options,
            StatusCode::PAYLOAD_TOO_LARGE,
            "VALIDATION_ERROR",
            "Тело запроса слишком велико",
            csrf_cookie,
        );
    }
    let Ok(payload) = serde_json::from_slice::<LoginIn>(&body) else {
        return error(
            &headers,
            &config.options,
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "Неверный формат запроса",
            csrf_cookie,
        );
    };
    if payload.password.len() > 4096 || payload.email.len() > 320 {
        return error(
            &headers,
            &config.options,
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "Неверный формат запроса",
            csrf_cookie,
        );
    }
    let started = Instant::now();
    let now = SystemTime::now();
    let form_token = payload
        .form_token
        .as_deref()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            headers
                .get("x-form-token")
                .and_then(|value| value.to_str().ok())
        });
    match consume_login_form_token(&config.cache, form_token, now).await {
        Ok(true) => {}
        Ok(false) => {
            return error(
                &headers,
                &config.options,
                StatusCode::BAD_REQUEST,
                "INVALID_FORM_TOKEN",
                "Неверный или просроченный токен формы",
                csrf_cookie,
            );
        }
        Err(_) => {
            tracing::error!("login form token storage unavailable");
            return unavailable(&headers, &config.options, csrf_cookie);
        }
    }
    let form_token_ms = started.elapsed().as_millis();
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| peer.map(|value| value.ip().to_string()));
    let rate = match login_attempt(
        &config.cache,
        ip.as_deref(),
        Some(&payload.email),
        config.options.login_ip_limit,
        now,
    )
    .await
    {
        Ok(value) => value,
        Err(_) => {
            tracing::error!("login rate-limit storage unavailable");
            return unavailable(&headers, &config.options, csrf_cookie);
        }
    };
    let rate_limit_ms = started.elapsed().as_millis() - form_token_ms;
    if rate.blocked {
        let mut response = error(
            &headers,
            &config.options,
            StatusCode::TOO_MANY_REQUESTS,
            "LOGIN_RATE_LIMITED",
            "Слишком много попыток входа, попробуйте позже",
            csrf_cookie,
        );
        response.headers_mut().insert(
            header::RETRY_AFTER,
            HeaderValue::from_str(&rate.retry_after_seconds.to_string())
                .unwrap_or(HeaderValue::from_static("0")),
        );
        return response;
    }
    let (verified, mfa_code) = match config
        .preflight
        .verify(&payload.email, &payload.password)
        .await
    {
        Ok(LoginDecision::Ready(value)) => (value, None),
        Ok(LoginDecision::InvalidCredentials) => {
            return error(
                &headers,
                &config.options,
                StatusCode::UNAUTHORIZED,
                "INVALID_CREDENTIALS",
                "Неверный логин или пароль",
                csrf_cookie,
            );
        }
        Ok(LoginDecision::EmailVerificationRequired) => {
            return error(
                &headers,
                &config.options,
                StatusCode::UNAUTHORIZED,
                "EMAIL_VERIFICATION_REQUIRED",
                "Подтвердите email перед входом. При необходимости запросите новое письмо.",
                csrf_cookie,
            );
        }
        Ok(LoginDecision::MfaRequired(value)) => {
            let code = payload
                .mfa_code
                .as_deref()
                .filter(|code| !code.is_empty())
                .or(payload.recovery_code.as_deref())
                .unwrap_or("")
                .trim()
                .replace(' ', "");
            if code.is_empty() {
                return error(
                    &headers,
                    &config.options,
                    StatusCode::UNAUTHORIZED,
                    "MFA_REQUIRED",
                    "Требуется код MFA",
                    csrf_cookie,
                );
            }
            (value, Some(code))
        }
        Err(_) => {
            tracing::error!("login password preflight unavailable");
            return unavailable(&headers, &config.options, csrf_cookie);
        }
    };
    let preflight_ms = started.elapsed().as_millis() - form_token_ms - rate_limit_ms;
    let Some(ip_addr) = ip
        .as_deref()
        .and_then(|value| value.parse::<IpAddr>().ok())
        .or_else(|| peer.map(|value| value.ip()))
    else {
        return unavailable(&headers, &config.options, csrf_cookie);
    };
    let request = SessionClient {
        ip: ip_addr,
        user_agent: headers
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_owned(),
        device_fingerprint_salt: config.options.device_fingerprint_salt.clone(),
    };
    let now = SystemTime::now();
    let lifetime = Duration::from_secs(config.options.session_cookie_age);
    if crate::provider_login::cancel_existing(&config.cache, &headers)
        .await
        .is_err()
    {
        return unavailable(&headers, &config.options, csrf_cookie);
    }
    let issued_result = if let Some(code) = mfa_code.as_deref() {
        issue_password_login_with_mfa(
            &config.client,
            config.session_codec.clone(),
            &config.jwt_codec,
            &verified,
            &request,
            IssueTiming { now, lifetime },
            MfaProof {
                cache: &config.cache,
                code,
            },
        )
        .await
    } else {
        issue_password_login(
            &config.client,
            config.session_codec.clone(),
            &config.jwt_codec,
            &verified,
            &request,
            now,
            lifetime,
        )
        .await
    };
    let issued = match issued_result {
        Ok(Some(value)) => value,
        Ok(None) => {
            return error(
                &headers,
                &config.options,
                StatusCode::UNAUTHORIZED,
                "INVALID_CREDENTIALS",
                if mfa_code.is_some() {
                    "Неверный код подтверждения"
                } else {
                    "Неверный логин или пароль"
                },
                csrf_cookie,
            );
        }
        Err(_) => {
            tracing::error!("login credential transaction unavailable");
            if mfa_code.is_some() {
                return error(
                    &headers,
                    &config.options,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "MFA_UNAVAILABLE",
                    "Не удалось проверить MFA, попробуйте позже",
                    csrf_cookie,
                );
            }
            return unavailable(&headers, &config.options, csrf_cookie);
        }
    };
    let issue_ms = started.elapsed().as_millis() - form_token_ms - rate_limit_ms - preflight_ms;
    let response = login_success(&config, &headers, &verified, issued).await;
    tracing::info!(
        target: "id_runtime::login_timing",
        form_token_ms,
        rate_limit_ms,
        preflight_ms,
        issue_ms,
        response_ms = started.elapsed().as_millis() - form_token_ms - rate_limit_ms - preflight_ms - issue_ms,
        total_ms = started.elapsed().as_millis(),
        "successful password login stage durations"
    );
    response
}

pub(crate) async fn login_success(
    config: &LoginHttpConfig,
    headers: &HeaderMap,
    verified: &VerifiedAccount,
    issued: IssuedPasswordLogin,
) -> Response {
    let csrf_cookie = make_csrf_cookie(headers, &config.options, false);
    if let (Some(event_id), Some(publisher)) =
        (issued.session.new_device_mail_event_id, config.ymq.clone())
    {
        // The intent already committed in YDB. Queue delivery is an accelerator;
        // a frozen process or ambiguous send is recovered by the jobs timer.
        tokio::spawn(async move {
            if publisher.send_new_device_mail(event_id).await.is_err() {
                tracing::warn!("new-device mail queue wakeup failed; timer will recover");
            }
        });
    }
    if let Err(error) = reset_verified_email(&config.cache, verified.email_key()).await {
        tracing::warn!(error = %error, "verified account login penalty could not be cleared");
    }
    let user = match read_profile_details(&config.client, verified.account_id).await {
        Ok(details) => {
            let avatar_url = details
                .profile
                .as_ref()
                .and_then(|profile| profile.avatar_key.as_deref())
                .and_then(|key| config.media.avatar_url(key).ok());
            CurrentUserOut::authenticated(details, avatar_url)
                .ok()
                .and_then(|result| result.user)
        }
        Err(_) => None,
    };
    let token = issued.session.token;
    let session_cookie = make_cookie(
        &config.options.session_cookie_name,
        &token,
        config.options.session_cookie_secure,
        true,
        config.options.session_same_site,
        config.options.session_cookie_domain.as_deref(),
        Some(config.options.session_cookie_age),
    );
    let body = LoginOut {
        meta: LoginMeta {
            session_token: token.clone(),
        },
        user,
        access_token: issued.access,
        refresh_token: issued.refresh,
        recovery_codes: None,
        verification_required: false,
    };
    let body = match serde_json::to_value(body) {
        Ok(body) => body,
        Err(_) => {
            tracing::error!("login response serialization failed");
            return unavailable(headers, &config.options, csrf_cookie);
        }
    };
    let mut response = json_response(
        headers,
        &config.options,
        StatusCode::OK,
        body,
        make_csrf_cookie(headers, &config.options, true),
        Some(session_cookie),
    );
    if let Ok(value) = HeaderValue::from_str(&token) {
        response.headers_mut().insert("x-session-token", value);
    }
    response
}

#[cfg(feature = "passkeys")]
async fn passkey_begin(State(config): State<Arc<LoginHttpConfig>>, request: Request) -> Response {
    let headers = request.headers().clone();
    let csrf_cookie = make_csrf_cookie(&headers, &config.options, false);
    if !csrf_allowed(&headers, &config.options) {
        return error(
            &headers,
            &config.options,
            StatusCode::FORBIDDEN,
            "CSRF_FAILED",
            "CSRF verification failed",
            csrf_cookie,
        );
    }
    let ip = request_ip(&request);
    let Some(passkey) = config.passkey.as_ref() else {
        return unavailable(&headers, &config.options, csrf_cookie);
    };
    let now = SystemTime::now();
    let rate = match login_attempt(
        &config.cache,
        ip.as_deref(),
        None,
        config.options.login_ip_limit,
        now,
    )
    .await
    {
        Ok(rate) => rate,
        Err(_) => return unavailable(&headers, &config.options, csrf_cookie),
    };
    if rate.blocked {
        let mut response = error(
            &headers,
            &config.options,
            StatusCode::TOO_MANY_REQUESTS,
            "LOGIN_RATE_LIMITED",
            "Слишком много попыток входа, попробуйте позже",
            csrf_cookie,
        );
        response.headers_mut().insert(
            header::RETRY_AFTER,
            HeaderValue::from_str(&rate.retry_after_seconds.to_string())
                .unwrap_or(HeaderValue::from_static("0")),
        );
        return response;
    }
    let (options, id) = match passkey_login::begin(&passkey.webauthn, &config.cache, now).await {
        Ok(value) => value,
        Err(_) => {
            tracing::error!("passkey login challenge unavailable");
            return unavailable(&headers, &config.options, csrf_cookie);
        }
    };
    let ceremony_cookie = make_cookie(
        PASSKEY_CEREMONY_COOKIE,
        &id,
        config.options.session_cookie_secure,
        true,
        config.options.session_same_site,
        config.options.session_cookie_domain.as_deref(),
        Some(300),
    );
    json_response(
        &headers,
        &config.options,
        StatusCode::OK,
        json!({"request_options":options}),
        csrf_cookie,
        Some(ceremony_cookie),
    )
}

#[cfg(feature = "passkeys")]
async fn passkey_complete(
    State(config): State<Arc<LoginHttpConfig>>,
    request: Request,
) -> Response {
    let headers = request.headers().clone();
    let csrf_cookie = make_csrf_cookie(&headers, &config.options, false);
    if !is_json(&headers) {
        return error(
            &headers,
            &config.options,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "UNSUPPORTED_MEDIA_TYPE",
            "Content-Type must be application/json",
            csrf_cookie,
        );
    }
    if !csrf_allowed(&headers, &config.options) {
        return error(
            &headers,
            &config.options,
            StatusCode::FORBIDDEN,
            "CSRF_FAILED",
            "CSRF verification failed",
            csrf_cookie,
        );
    }
    let Some(ceremony_id) = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|raw| Cookie::split_parse(raw.to_owned()).flatten())
        .find(|cookie| cookie.name() == PASSKEY_CEREMONY_COOKIE)
        .map(|cookie| cookie.value().to_owned())
    else {
        return error(
            &headers,
            &config.options,
            StatusCode::UNAUTHORIZED,
            "INVALID_PASSKEY",
            "Неверный или просроченный ключ входа",
            csrf_cookie,
        );
    };
    let ip = request_ip(&request);
    let Some(ip_addr) = ip.as_deref().and_then(|value| value.parse::<IpAddr>().ok()) else {
        return unavailable(&headers, &config.options, csrf_cookie);
    };
    let body = match to_bytes(request.into_body(), MAX_LOGIN_BODY + 1).await {
        Ok(body) if body.len() <= MAX_LOGIN_BODY => body,
        _ => {
            return error(
                &headers,
                &config.options,
                StatusCode::PAYLOAD_TOO_LARGE,
                "VALIDATION_ERROR",
                "Тело запроса слишком велико",
                csrf_cookie,
            );
        }
    };
    let Ok(payload) = serde_json::from_slice::<Value>(&body) else {
        return error(
            &headers,
            &config.options,
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "Неверный формат запроса",
            csrf_cookie,
        );
    };
    let Some(credential) = payload.get("credential").cloned() else {
        return error(
            &headers,
            &config.options,
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "Неверный формат запроса",
            csrf_cookie,
        );
    };
    let Some(passkey) = config.passkey.as_ref() else {
        return unavailable(&headers, &config.options, csrf_cookie);
    };
    let verified = match passkey_login::verify(
        passkey_login::PasskeyVerifier {
            client: &config.client,
            webauthn: &passkey.webauthn,
            cache: &config.cache,
            rp_id: &passkey.rp_id,
            origin: &passkey.origin,
        },
        &ceremony_id,
        credential,
        SystemTime::now(),
    )
    .await
    {
        Ok(Some(value)) => value,
        Ok(None) => {
            return error(
                &headers,
                &config.options,
                StatusCode::UNAUTHORIZED,
                "INVALID_PASSKEY",
                "Неверный или просроченный ключ входа",
                csrf_cookie,
            );
        }
        Err(_) => {
            tracing::error!("passkey login verification unavailable");
            return unavailable(&headers, &config.options, csrf_cookie);
        }
    };
    let request = SessionClient {
        ip: ip_addr,
        user_agent: headers
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_owned(),
        device_fingerprint_salt: config.options.device_fingerprint_salt.clone(),
    };
    if crate::provider_login::cancel_existing(&config.cache, &headers)
        .await
        .is_err()
    {
        return unavailable(&headers, &config.options, csrf_cookie);
    }
    let issued = match issue_passkey_login(
        &config.client,
        config.session_codec.clone(),
        &config.jwt_codec,
        &verified.account,
        &request,
        IssueTiming {
            now: SystemTime::now(),
            lifetime: Duration::from_secs(config.options.session_cookie_age),
        },
        &verified.proof,
    )
    .await
    {
        Ok(Some(value)) => value,
        Ok(None) => {
            return error(
                &headers,
                &config.options,
                StatusCode::UNAUTHORIZED,
                "INVALID_PASSKEY",
                "Неверный или просроченный ключ входа",
                csrf_cookie,
            );
        }
        Err(_) => {
            tracing::error!("passkey login issuance unavailable");
            return unavailable(&headers, &config.options, csrf_cookie);
        }
    };
    let mut response = login_success(&config, &headers, &verified.account, issued).await;
    let clear = make_cookie(
        PASSKEY_CEREMONY_COOKIE,
        "",
        config.options.session_cookie_secure,
        true,
        config.options.session_same_site,
        config.options.session_cookie_domain.as_deref(),
        Some(0),
    );
    if let Ok(value) = HeaderValue::from_str(&clear) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

pub(crate) fn request_ip(request: &Request) -> Option<String> {
    request
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            request
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|value| value.0.ip().to_string())
        })
}

fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
}

fn csrf_allowed(headers: &HeaderMap, options: &LoginHttpOptions) -> bool {
    if !headers.contains_key(header::ORIGIN) && !headers.contains_key("sec-fetch-site") {
        return true;
    }
    let origin = if let Some(raw) = headers.get(header::ORIGIN) {
        raw.to_str()
            .ok()
            .and_then(|value| canonical_origin(value).ok())
    } else {
        headers
            .get(header::REFERER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| Url::parse(value).ok())
            .filter(|url| {
                matches!(url.scheme(), "http" | "https")
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
            })
            .map(|url| url.origin().ascii_serialization())
    };
    origin
        .as_deref()
        .is_some_and(|origin| trusted_csrf_token(headers, options, origin))
}

fn trusted_csrf_token(headers: &HeaderMap, options: &LoginHttpOptions, origin: &str) -> bool {
    if !options
        .trusted_origins
        .iter()
        .any(|allowed| allowed == origin)
    {
        return false;
    }
    let cookie = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|raw| Cookie::split_parse(raw.to_owned()).flatten())
        .find(|cookie| cookie.name() == options.csrf_cookie_name)
        .map(|cookie| cookie.value().to_owned());
    let token = headers
        .get("x-csrftoken")
        .and_then(|value| value.to_str().ok());
    cookie
        .as_deref()
        .zip(token)
        .and_then(|(cookie, token)| csrf::matches(cookie, token).ok())
        .unwrap_or(false)
}

pub(crate) fn make_csrf_cookie(
    headers: &HeaderMap,
    options: &LoginHttpOptions,
    rotate: bool,
) -> String {
    let existing = if rotate {
        None
    } else {
        headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|raw| Cookie::split_parse(raw.to_owned()).flatten())
            .find(|cookie| cookie.name() == options.csrf_cookie_name)
            .and_then(|cookie| csrf::cookie_secret(cookie.value()).ok())
    };
    make_cookie(
        &options.csrf_cookie_name,
        &existing.unwrap_or_else(new_csrf_secret),
        options.csrf_cookie_secure,
        false,
        options.csrf_same_site,
        options.csrf_cookie_domain.as_deref(),
        Some(31_449_600),
    )
}

fn error(
    headers: &HeaderMap,
    options: &LoginHttpOptions,
    status: StatusCode,
    code: &str,
    message: &str,
    csrf_cookie: String,
) -> Response {
    json_response(
        headers,
        options,
        status,
        json!({
            "code":code, "message":message, "details":null, "errors":null, "fields":null,
            "detail":format!("{{'code': '{code}', 'message': '{message}'}}"), "status":status.as_u16(),
        }),
        csrf_cookie,
        None,
    )
}

fn unavailable(headers: &HeaderMap, options: &LoginHttpOptions, csrf_cookie: String) -> Response {
    error(
        headers,
        options,
        StatusCode::SERVICE_UNAVAILABLE,
        "SERVICE_UNAVAILABLE",
        "Временно недоступно",
        csrf_cookie,
    )
}

pub(crate) fn json_response(
    headers: &HeaderMap,
    options: &LoginHttpOptions,
    status: StatusCode,
    body: Value,
    csrf_cookie: String,
    session_cookie: Option<String>,
) -> Response {
    let mut response = (status, Json(body)).into_response();
    let output = response.headers_mut();
    output.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    output.insert(header::VARY, HeaderValue::from_static("Cookie, origin"));
    if let Ok(value) = HeaderValue::from_str(&csrf_cookie) {
        output.append(header::SET_COOKIE, value);
    }
    if let Some(session_cookie) = session_cookie
        && let Ok(value) = HeaderValue::from_str(&session_cookie)
    {
        output.append(header::SET_COOKIE, value);
    }
    add_cors(output, headers, options);
    response
}

fn add_cors(output: &mut HeaderMap, input: &HeaderMap, options: &LoginHttpOptions) {
    let origin = input
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok());
    if let Some(origin) = origin
        && let Ok(canonical) = canonical_origin(origin)
        && options
            .trusted_origins
            .iter()
            .any(|allowed| allowed == &canonical)
        && let Ok(value) = HeaderValue::from_str(origin)
    {
        output.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
        output.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
        output.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("POST, OPTIONS"),
        );
        output.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Content-Type, X-CSRFToken, X-Form-Token"),
        );
        output.insert(
            header::ACCESS_CONTROL_EXPOSE_HEADERS,
            HeaderValue::from_static("X-Session-Token"),
        );
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn options() -> LoginHttpOptions {
        LoginHttpOptions {
            session_cookie_name: "sessionid".into(),
            csrf_cookie_name: "csrftoken".into(),
            session_cookie_secure: false,
            csrf_cookie_secure: false,
            session_same_site: SameSite::Lax,
            csrf_same_site: SameSite::Lax,
            session_cookie_domain: None,
            csrf_cookie_domain: None,
            session_cookie_age: 1_209_600,
            login_ip_limit: 50,
            trusted_origins: vec!["http://id.localhost:5175".into()],
            device_fingerprint_salt: "device-salt".into(),
        }
    }

    #[test]
    fn browser_login_requires_trusted_origin_and_matching_csrf() -> Result<()> {
        let options = options();
        let mut headers = HeaderMap::new();
        assert!(csrf_allowed(&headers, &options));
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        assert!(is_json(&headers));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://id.localhost:5175"),
        );
        assert!(!csrf_allowed(&headers, &options));
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("csrftoken=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        );
        headers.insert(
            "x-csrftoken",
            HeaderValue::from_static("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        );
        assert!(csrf_allowed(&headers, &options));
        let mut cors = HeaderMap::new();
        add_cors(&mut cors, &headers, &options);
        assert_eq!(
            cors[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            "http://id.localhost:5175"
        );
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://attacker.invalid"),
        );
        assert!(!csrf_allowed(&headers, &options));
        let mut cors = HeaderMap::new();
        add_cors(&mut cors, &headers, &options);
        assert!(!cors.contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://id.localhost:5175"),
        );
        headers.insert(
            "x-csrftoken",
            HeaderValue::from_static("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        );
        assert!(!csrf_allowed(&headers, &options));
        headers.insert(
            "x-csrftoken",
            HeaderValue::from_static("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        );
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://id.localhost:5175/path"),
        );
        assert!(!csrf_allowed(&headers, &options));
        assert!(canonical_origin("https://user:password@example.invalid").is_err());
        Ok(())
    }
}
