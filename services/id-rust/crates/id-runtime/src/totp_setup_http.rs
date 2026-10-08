//! Local-only TOTP HTTP boundary and independently gated passkey management and registration.

#[cfg(feature = "passkeys")]
use crate::passkey_registration::{
    self, BeginOutcome as PasskeyBeginOutcome, CompleteOutcome as PasskeyCompleteOutcome,
};
use crate::{
    logout_http::{cookie_value, csrf_allowed},
    me_http::env_flag,
    mfa_secret,
    passkey_management::{self, Outcome as PasskeyOutcome},
    recovery_rotation::{self, RotationOutcome},
    session_store::session_codec_from_env,
    totp_setup::{self, BeginOutcome, ConfirmOutcome, DisableOutcome},
};
use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use id_compat::{headers::session_token, session::SessionCodec};
use qrcodegen::{QrCode, QrCodeEcc};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{env, sync::Arc, time::SystemTime};
use url::Url;
#[cfg(feature = "passkeys")]
use webauthn_rs::prelude::{Url as WebauthnUrl, Webauthn, WebauthnBuilder};
use ydb::Client;

pub struct TotpSetupHttpConfig {
    client: Arc<Client>,
    codec: Arc<SessionCodec>,
    session_cookie_name: String,
    csrf_cookie_name: String,
    trusted_origins: Vec<String>,
    issuer: String,
    totp_enabled: bool,
    passkey_management_enabled: bool,
    login_providers: Vec<Arc<crate::provider_login::ProviderLoginConfig>>,
    #[cfg(feature = "passkeys")]
    registration: Option<Arc<Webauthn>>,
}

impl TotpSetupHttpConfig {
    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        let local_totp = env_flag("ID_AUTH_TOTP_PILOT_ENABLED", false)?;
        let production_totp = env_flag("ID_AUTH_TOTP_ENABLED", false)?;
        let totp_enabled = local_totp || production_totp;
        let passkey_management_enabled =
            env_flag("ID_AUTH_PASSKEY_MANAGEMENT_ENABLED", false)? || totp_enabled;
        #[cfg(feature = "passkeys")]
        let local_registration = env_flag("ID_AUTH_PASSKEY_REGISTRATION_PILOT_ENABLED", false)?;
        #[cfg(feature = "passkeys")]
        let production_registration = env_flag("ID_AUTH_PASSKEY_REGISTRATION_ENABLED", false)?;
        #[cfg(feature = "passkeys")]
        if local_registration && !local_totp {
            bail!("passkey registration pilot requires local TOTP pilot")
        }
        #[cfg(feature = "passkeys")]
        if production_registration
            && (!passkey_management_enabled || !env_flag("ID_RUST_EARLY_ROLLOUT_ENABLED", false)?)
        {
            bail!("production passkey registration requires management and early rollout")
        }
        if !totp_enabled && !passkey_management_enabled {
            return Ok(None);
        }
        if local_totp {
            let endpoint = Url::parse(&env::var("YDB_ENDPOINT")?)?;
            if !env_flag("DJANGO_DEBUG", false)?
                || !matches!(
                    endpoint.host_str(),
                    Some("localhost" | "127.0.0.1" | "[::1]")
                )
                || env::var("YDB_DATABASE")? != "/local"
            {
                bail!("incomplete Rust TOTP enrollment is restricted to local debug YDB")
            }
        }
        if production_totp && !env_flag("ID_RUST_EARLY_ROLLOUT_ENABLED", false)? {
            bail!("production TOTP enrollment requires early rollout")
        }
        if totp_enabled {
            mfa_secret::key_from_env()?
                .context("ID_MFA_SEAL_KEY_B64 is required for TOTP enrollment")?;
        }
        let issuer = env::var("ID_MFA_TOTP_ISSUER").unwrap_or_else(|_| "UpdSpace ID".into());
        if issuer.is_empty() || issuer.len() > 128 || issuer.chars().any(char::is_control) {
            bail!("invalid TOTP issuer")
        }
        let trusted_origins = env::var("CSRF_TRUSTED_ORIGINS")
            .unwrap_or_else(|_| "http://id.localhost,http://localhost:5175".into())
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
                    bail!("invalid trusted TOTP origin")
                }
                Ok(url.origin().ascii_serialization())
            })
            .collect::<Result<Vec<_>>>()?;
        if production_totp
            && (trusted_origins.is_empty()
                || trusted_origins
                    .iter()
                    .any(|origin| !origin.starts_with("https://"))
                || !env_flag("SESSION_COOKIE_SECURE", false)?
                || !env_flag("CSRF_COOKIE_SECURE", false)?)
        {
            bail!("production TOTP enrollment requires HTTPS origins and secure cookies")
        }
        #[cfg(feature = "passkeys")]
        let registration = if local_registration || production_registration {
            mfa_secret::key_from_env()?
                .context("ID_MFA_SEAL_KEY_B64 is required for passkey registration")?;
            let rp_id = env::var("ID_WEBAUTHN_RP_ID").context("ID_WEBAUTHN_RP_ID required")?;
            let origin = env::var("ID_WEBAUTHN_ORIGIN").context("ID_WEBAUTHN_ORIGIN required")?;
            let origin = WebauthnUrl::parse(&origin)?;
            if production_registration && origin.scheme() != "https" {
                bail!("production passkey registration requires HTTPS origin")
            }
            let webauthn = WebauthnBuilder::new(&rp_id, &origin)?
                .rp_name(&issuer)
                .build()?;
            Some(Arc::new(webauthn))
        } else {
            None
        };
        Ok(Some(Arc::new(Self {
            login_providers: crate::provider_login::ProviderLoginConfig::available_from_env(
                client.clone(),
            ),
            client,
            codec: session_codec_from_env()?,
            session_cookie_name: env::var("SESSION_COOKIE_NAME")
                .unwrap_or_else(|_| "sessionid".into()),
            csrf_cookie_name: env::var("CSRF_COOKIE_NAME").unwrap_or_else(|_| "csrftoken".into()),
            trusted_origins,
            issuer,
            totp_enabled,
            passkey_management_enabled,
            #[cfg(feature = "passkeys")]
            registration,
        })))
    }
}

pub fn router(config: Arc<TotpSetupHttpConfig>) -> Router {
    let router = Router::new();
    let router = if config.totp_enabled {
        router
            .route(
                "/api/v1/auth/mfa/totp/begin",
                post(begin).options(preflight),
            )
            .route(
                "/api/v1/auth/mfa/totp/confirm",
                post(confirm).options(preflight),
            )
            .route(
                "/api/v1/auth/mfa/totp/disable",
                post(disable).options(preflight),
            )
            .route(
                "/api/v1/auth/mfa/recovery/regenerate",
                post(regenerate).options(preflight),
            )
    } else {
        router
    };
    let router = if config.passkey_management_enabled {
        router
            .route(
                "/api/v1/auth/passkeys/rename",
                post(rename_passkey).options(preflight),
            )
            .route(
                "/api/v1/auth/passkeys/delete",
                post(delete_passkeys).options(preflight),
            )
    } else {
        router
    };
    #[cfg(feature = "passkeys")]
    let router = if config.registration.is_some() {
        router
            .route(
                "/api/v1/auth/passkeys/begin",
                post(begin_passkey).options(preflight),
            )
            .route(
                "/api/v1/auth/passkeys/complete",
                post(complete_passkey).options(preflight),
            )
    } else {
        router
    };
    router.with_state(config)
}

#[cfg(feature = "passkeys")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BeginPasskeyIn {
    passwordless: bool,
}

#[cfg(feature = "passkeys")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletePasskeyIn {
    name: Option<String>,
    credential: Value,
    #[serde(default)]
    passwordless: bool,
}

#[cfg(feature = "passkeys")]
async fn begin_passkey(
    State(config): State<Arc<TotpSetupHttpConfig>>,
    request: Request,
) -> Response {
    let headers = request.headers().clone();
    let mut response = passkey_registration_inner(&config, request, false).await;
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

#[cfg(feature = "passkeys")]
async fn complete_passkey(
    State(config): State<Arc<TotpSetupHttpConfig>>,
    request: Request,
) -> Response {
    let headers = request.headers().clone();
    let mut response = passkey_registration_inner(&config, request, true).await;
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

#[cfg(feature = "passkeys")]
async fn passkey_registration_inner(
    config: &TotpSetupHttpConfig,
    request: Request,
    completing: bool,
) -> Response {
    let Some(webauthn) = &config.registration else {
        return error(StatusCode::NOT_FOUND, "NOT_FOUND", "Not found");
    };
    let token = match session_from_headers(config, request.headers()) {
        Ok(value) => value,
        Err(response) => return *response,
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
        return error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "UNSUPPORTED_MEDIA_TYPE",
            "Content-Type must be application/json",
        );
    }
    let bytes = match to_bytes(request.into_body(), 32769).await {
        Ok(bytes) if bytes.len() <= 32768 => bytes,
        _ => {
            return error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "VALIDATION_ERROR",
                "Invalid request body",
            );
        }
    };
    if completing {
        let Ok(payload) = serde_json::from_slice::<CompletePasskeyIn>(&bytes) else {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_ERROR",
                "Invalid request body",
            );
        };
        let name = payload.name.as_deref().unwrap_or("Passkey").trim();
        if name.is_empty()
            || name.chars().count() > 80
            || name.chars().any(char::is_control)
            || !payload.credential.is_object()
        {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_ERROR",
                "Invalid passkey name or credential",
            );
        }
        let _ = payload.passwordless; // The stored begin state controls this choice.
        match passkey_registration::complete(
            &config.client,
            config.codec.clone(),
            webauthn.clone(),
            &token,
            passkey_registration::RegistrationInput {
                name: name.to_owned(),
                credential: payload.credential,
            },
            SystemTime::now(),
        )
        .await
        {
            Ok(PasskeyCompleteOutcome::Registered {
                id,
                passwordless,
                recovery_codes,
            }) => json_response(
                StatusCode::OK,
                json!({"authenticator":{"id":id.to_string(),"name":name,"type":"webauthn","created_at":SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),"last_used_at":null,"is_passwordless":passwordless},"recovery_codes":recovery_codes}),
            ),
            Ok(PasskeyCompleteOutcome::Unauthorized) => error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Сессия недействительна",
            ),
            Ok(PasskeyCompleteOutcome::ReauthRequired) => error(
                StatusCode::UNAUTHORIZED,
                "REAUTH_REQUIRED",
                "Подтвердите вход заново",
            ),
            Ok(PasskeyCompleteOutcome::InvalidPasskey) => error(
                StatusCode::BAD_REQUEST,
                "INVALID_PASSKEY",
                "Не удалось проверить Passkey. Повторите добавление ключа.",
            ),
            Ok(PasskeyCompleteOutcome::Duplicate) => error(
                StatusCode::CONFLICT,
                "PASSKEY_EXISTS",
                "Ключ доступа уже зарегистрирован",
            ),
            Err(failure) => {
                tracing::error!(?failure, "Rust passkey registration failed");
                error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "SERVICE_UNAVAILABLE",
                    "Временно недоступно",
                )
            }
        }
    } else {
        let Ok(payload) = serde_json::from_slice::<BeginPasskeyIn>(&bytes) else {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_ERROR",
                "Invalid request body",
            );
        };
        match passkey_registration::begin(
            &config.client,
            config.codec.clone(),
            webauthn.clone(),
            &token,
            payload.passwordless,
            SystemTime::now(),
        )
        .await
        {
            Ok(PasskeyBeginOutcome::Started(options)) => {
                json_response(StatusCode::OK, json!({"creation_options":options}))
            }
            Ok(PasskeyBeginOutcome::Unauthorized) => error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Сессия недействительна",
            ),
            Ok(PasskeyBeginOutcome::ReauthRequired) => error(
                StatusCode::UNAUTHORIZED,
                "REAUTH_REQUIRED",
                "Подтвердите вход заново",
            ),
            Ok(PasskeyBeginOutcome::EmailVerificationRequired) => error(
                StatusCode::BAD_REQUEST,
                "EMAIL_VERIFICATION_REQUIRED",
                "Сначала подтвердите почту",
            ),
            Err(failure) => {
                tracing::error!(?failure, "Rust passkey registration begin failed");
                error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "SERVICE_UNAVAILABLE",
                    "Временно недоступно",
                )
            }
        }
    }
}

async fn begin(State(config): State<Arc<TotpSetupHttpConfig>>, request: Request) -> Response {
    handle(config, request, false).await
}

async fn confirm(State(config): State<Arc<TotpSetupHttpConfig>>, request: Request) -> Response {
    handle(config, request, true).await
}

async fn disable(State(config): State<Arc<TotpSetupHttpConfig>>, request: Request) -> Response {
    let headers = request.headers().clone();
    let mut response = disable_inner(&config, &headers).await;
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

async fn regenerate(State(config): State<Arc<TotpSetupHttpConfig>>, request: Request) -> Response {
    let headers = request.headers().clone();
    let mut response = regenerate_inner(&config, &headers).await;
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenamePasskeyIn {
    authenticator_id: String,
    new_name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeletePasskeysIn {
    ids: Vec<String>,
}

async fn rename_passkey(
    State(config): State<Arc<TotpSetupHttpConfig>>,
    request: Request,
) -> Response {
    let headers = request.headers().clone();
    let mut response = passkey_inner(&config, request, false).await;
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

async fn delete_passkeys(
    State(config): State<Arc<TotpSetupHttpConfig>>,
    request: Request,
) -> Response {
    let headers = request.headers().clone();
    let mut response = passkey_inner(&config, request, true).await;
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

async fn passkey_inner(config: &TotpSetupHttpConfig, request: Request, deleting: bool) -> Response {
    let headers = request.headers();
    let token = match session_from_headers(config, headers) {
        Ok(token) => token,
        Err(response) => return *response,
    };
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
        return error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "UNSUPPORTED_MEDIA_TYPE",
            "Content-Type must be application/json",
        );
    }
    let bytes = match to_bytes(request.into_body(), 4097).await {
        Ok(bytes) if bytes.len() <= 4096 => bytes,
        _ => {
            return error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "VALIDATION_ERROR",
                "Invalid request body",
            );
        }
    };
    let outcome = if deleting {
        let Ok(payload) = serde_json::from_slice::<DeletePasskeysIn>(&bytes) else {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_ERROR",
                "Invalid request body",
            );
        };
        if payload.ids.is_empty() || payload.ids.len() > 20 {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_ERROR",
                "Select 1 to 20 passkeys",
            );
        }
        let ids = payload
            .ids
            .iter()
            .map(|id| id.parse::<i64>())
            .collect::<std::result::Result<Vec<_>, _>>();
        let Ok(ids) = ids else {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_ERROR",
                "Invalid passkey ID",
            );
        };
        if ids.iter().any(|id| *id <= 0)
            || ids
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>()
                .len()
                != ids.len()
        {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_ERROR",
                "Invalid passkey IDs",
            );
        }
        passkey_management::delete(
            &config.client,
            config.codec.clone(),
            &token,
            &ids,
            SystemTime::now(),
            &config.login_providers,
        )
        .await
    } else {
        let Ok(payload) = serde_json::from_slice::<RenamePasskeyIn>(&bytes) else {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_ERROR",
                "Invalid request body",
            );
        };
        let Ok(id) = payload.authenticator_id.parse::<i64>() else {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_ERROR",
                "Invalid passkey ID",
            );
        };
        let name = payload.new_name.trim();
        if id <= 0
            || name.is_empty()
            || name.chars().count() > 128
            || name.chars().any(char::is_control)
        {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_ERROR",
                "Invalid passkey name or ID",
            );
        }
        passkey_management::rename(
            &config.client,
            config.codec.clone(),
            &token,
            id,
            name,
            SystemTime::now(),
        )
        .await
    };
    match outcome {
        Ok(PasskeyOutcome::Renamed) => json_response(
            StatusCode::OK,
            json!({"ok":true,"message":"Название обновлено"}),
        ),
        Ok(PasskeyOutcome::Deleted(count)) => json_response(
            StatusCode::OK,
            json!({"ok":true,"message":format!("Удалено {count} Passkey")}),
        ),
        Ok(PasskeyOutcome::Unauthorized) => error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Сессия недействительна",
        ),
        Ok(PasskeyOutcome::ReauthRequired) => error(
            StatusCode::UNAUTHORIZED,
            "REAUTH_REQUIRED",
            "Подтвердите вход заново",
        ),
        Ok(PasskeyOutcome::LastLoginMethod) => error(
            StatusCode::CONFLICT,
            "LAST_LOGIN_METHOD",
            "Добавьте другой способ входа, прежде чем удалять последний ключ доступа",
        ),
        Ok(PasskeyOutcome::NotFound) => {
            error(StatusCode::NOT_FOUND, "NOT_FOUND", "Ключ доступа не найден")
        }
        Err(failure) => {
            tracing::error!(?failure, "Rust passkey management failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            )
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmIn {
    code: String,
}

async fn handle(config: Arc<TotpSetupHttpConfig>, request: Request, confirming: bool) -> Response {
    let headers = request.headers().clone();
    let mut response = handle_inner(&config, request, confirming).await;
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

async fn handle_inner(
    config: &TotpSetupHttpConfig,
    request: Request,
    confirming: bool,
) -> Response {
    let headers = request.headers();
    let token = match session_from_headers(config, headers) {
        Ok(token) => token,
        Err(response) => return *response,
    };
    let code = if confirming {
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
            return error(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "UNSUPPORTED_MEDIA_TYPE",
                "Content-Type must be application/json",
            );
        }
        let bytes = match to_bytes(request.into_body(), 1025).await {
            Ok(bytes) if bytes.len() <= 1024 => bytes,
            _ => {
                return error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "VALIDATION_ERROR",
                    "Invalid request body",
                );
            }
        };
        let Ok(payload) = serde_json::from_slice::<ConfirmIn>(&bytes) else {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_ERROR",
                "Invalid request body",
            );
        };
        let cleaned: String = payload
            .code
            .chars()
            .filter(|ch| *ch != ' ' && *ch != '-')
            .collect();
        if cleaned.len() != 6 || !cleaned.bytes().all(|byte| byte.is_ascii_digit()) {
            return error(StatusCode::BAD_REQUEST, "INVALID_MFA_CODE", "Неверный код");
        }
        Some(cleaned)
    } else {
        None
    };
    if let Some(code) = code {
        match totp_setup::confirm(
            &config.client,
            config.codec.clone(),
            &token,
            &code,
            SystemTime::now(),
        )
        .await
        {
            Ok(ConfirmOutcome::Activated { recovery_codes }) => json_response(
                StatusCode::OK,
                json!({"ok":true,"recovery_codes":recovery_codes}),
            ),
            Ok(ConfirmOutcome::Unauthorized) => error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Сессия недействительна",
            ),
            Ok(ConfirmOutcome::ReauthRequired) => error(
                StatusCode::UNAUTHORIZED,
                "REAUTH_REQUIRED",
                "Подтвердите вход заново",
            ),
            Ok(ConfirmOutcome::SetupRequired) => error(
                StatusCode::BAD_REQUEST,
                "TOTP_SETUP_REQUIRED",
                "Начните настройку заново",
            ),
            Ok(ConfirmOutcome::InvalidCode) => {
                error(StatusCode::BAD_REQUEST, "INVALID_MFA_CODE", "Неверный код")
            }
            Ok(ConfirmOutcome::AlreadyEnabled) => error(
                StatusCode::BAD_REQUEST,
                "TOTP_ALREADY_ENABLED",
                "TOTP уже включена",
            ),
            Err(failure) => {
                tracing::error!(?failure, "Rust TOTP confirmation failed");
                error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "SERVICE_UNAVAILABLE",
                    "Временно недоступно",
                )
            }
        }
    } else {
        match totp_setup::begin(
            &config.client,
            config.codec.clone(),
            &token,
            SystemTime::now(),
        )
        .await
        {
            Ok(BeginOutcome::Started { secret, email }) => {
                match provisioning(&config.issuer, &email, &secret) {
                    Ok(body) => json_response(StatusCode::OK, body),
                    Err(failure) => {
                        tracing::error!(?failure, "TOTP QR rendering failed");
                        error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "SERVICE_UNAVAILABLE",
                            "Временно недоступно",
                        )
                    }
                }
            }
            Ok(BeginOutcome::Unauthorized) => error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Сессия недействительна",
            ),
            Ok(BeginOutcome::ReauthRequired) => error(
                StatusCode::UNAUTHORIZED,
                "REAUTH_REQUIRED",
                "Подтвердите вход заново",
            ),
            Ok(BeginOutcome::EmailVerificationRequired) => error(
                StatusCode::BAD_REQUEST,
                "EMAIL_VERIFICATION_REQUIRED",
                "Сначала подтвердите почту",
            ),
            Ok(BeginOutcome::AlreadyEnabled) => error(
                StatusCode::BAD_REQUEST,
                "TOTP_ALREADY_ENABLED",
                "TOTP уже включена",
            ),
            Err(failure) => {
                tracing::error!(?failure, "Rust TOTP setup failed");
                error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "SERVICE_UNAVAILABLE",
                    "Временно недоступно",
                )
            }
        }
    }
}

fn session_from_headers(
    config: &TotpSetupHttpConfig,
    headers: &HeaderMap,
) -> std::result::Result<String, Box<Response>> {
    let explicit = match session_token(headers) {
        Ok(token) => token,
        Err(_) => {
            return Err(Box::new(error(
                StatusCode::UNAUTHORIZED,
                "INVALID_OR_EXPIRED_TOKEN",
                "Сессия недействительна",
            )));
        }
    };
    let cookie = cookie_value(headers, &config.session_cookie_name);
    let Some(token) = explicit.or(cookie.as_deref()).map(str::to_owned) else {
        return Err(Box::new(error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Требуется авторизация",
        )));
    };
    if explicit.is_none()
        && !csrf_allowed(headers, &config.csrf_cookie_name, &config.trusted_origins)
    {
        return Err(Box::new(error(
            StatusCode::FORBIDDEN,
            "CSRF_FAILED",
            "CSRF verification failed",
        )));
    }
    Ok(token)
}

async fn disable_inner(config: &TotpSetupHttpConfig, headers: &HeaderMap) -> Response {
    let token = match session_from_headers(config, headers) {
        Ok(token) => token,
        Err(response) => return *response,
    };
    match totp_setup::disable(
        &config.client,
        config.codec.clone(),
        &token,
        SystemTime::now(),
    )
    .await
    {
        Ok(DisableOutcome::Disabled) => json_response(
            StatusCode::OK,
            json!({"ok":true,"message":"TOTP отключена"}),
        ),
        Ok(DisableOutcome::Unauthorized) => error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Сессия недействительна",
        ),
        Ok(DisableOutcome::ReauthRequired) => error(
            StatusCode::UNAUTHORIZED,
            "REAUTH_REQUIRED",
            "Подтвердите вход заново",
        ),
        Ok(DisableOutcome::NotFound) => error(
            StatusCode::NOT_FOUND,
            "TOTP_NOT_ENABLED",
            "TOTP не включена",
        ),
        Err(failure) => {
            tracing::error!(?failure, "Rust TOTP disable failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            )
        }
    }
}

async fn regenerate_inner(config: &TotpSetupHttpConfig, headers: &HeaderMap) -> Response {
    let token = match session_from_headers(config, headers) {
        Ok(token) => token,
        Err(response) => return *response,
    };
    let mut keys = headers.get_all("idempotency-key").iter();
    let Some(key) = keys.next().and_then(|value| value.to_str().ok()) else {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "Требуется Idempotency-Key",
        );
    };
    if keys.next().is_some() || !recovery_rotation::valid_idempotency_key(key) {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            "Некорректный Idempotency-Key",
        );
    }
    match recovery_rotation::regenerate(
        &config.client,
        config.codec.clone(),
        &token,
        key,
        SystemTime::now(),
    )
    .await
    {
        Ok(RotationOutcome::Rotated(codes) | RotationOutcome::Replayed(codes)) => {
            json_response(StatusCode::OK, json!({"ok":true,"recovery_codes":codes}))
        }
        Ok(RotationOutcome::Unauthorized) => error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Сессия недействительна",
        ),
        Ok(RotationOutcome::ReauthRequired) => error(
            StatusCode::UNAUTHORIZED,
            "REAUTH_REQUIRED",
            "Подтвердите вход заново",
        ),
        Ok(RotationOutcome::MfaRequired) => error(
            StatusCode::BAD_REQUEST,
            "MFA_REQUIRED",
            "Сначала включите MFA",
        ),
        Ok(RotationOutcome::Conflict) => error(
            StatusCode::CONFLICT,
            "ROTATION_IN_PROGRESS",
            "Набор кодов недавно обновлён",
        ),
        Ok(RotationOutcome::ReplayUnavailable) => error(
            StatusCode::CONFLICT,
            "ROTATION_REPLAY_UNAVAILABLE",
            "Код уже использован",
        ),
        Err(failure) => {
            tracing::error!(?failure, "Rust recovery-code rotation failed");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Временно недоступно",
            )
        }
    }
}

fn provisioning(issuer: &str, email: &str, secret: &str) -> Result<Value> {
    let mut url = Url::parse("otpauth://totp/")?;
    url.path_segments_mut()
        .map_err(|_| anyhow::anyhow!("invalid otpauth URL"))?
        .push(email);
    url.query_pairs_mut()
        .append_pair("secret", secret)
        .append_pair("issuer", issuer);
    let otpauth_url = url.to_string();
    let qr = QrCode::encode_text(&otpauth_url, QrCodeEcc::Medium)
        .map_err(|_| anyhow::anyhow!("TOTP URL is too long for QR"))?;
    let svg = qr_svg(&qr);
    let svg_data_uri = format!(
        "data:image/svg+xml;base64,{}",
        STANDARD.encode(svg.as_bytes())
    );
    Ok(
        json!({"ok":true,"secret":secret,"otpauth_url":otpauth_url,"svg":svg,"svg_data_uri":svg_data_uri}),
    )
}

fn qr_svg(qr: &QrCode) -> String {
    use std::fmt::Write as _;
    let size = qr.size() + 8;
    let mut path = String::new();
    for y in 0..qr.size() {
        for x in 0..qr.size() {
            if qr.get_module(x, y) {
                let _ = write!(path, "M{} {}h1v1h-1z", x + 4, y + 4);
            }
        }
    }
    format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {size} {size}\" role=\"img\"><rect width=\"{size}\" height=\"{size}\" fill=\"white\"/><path d=\"{path}\" fill=\"black\"/></svg>"
    )
}

async fn preflight(State(config): State<Arc<TotpSetupHttpConfig>>, headers: HeaderMap) -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    add_cors(response.headers_mut(), &headers, &config.trusted_origins);
    response
}

fn json_response(status: StatusCode, body: Value) -> Response {
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response.headers_mut().insert(
        header::VARY,
        HeaderValue::from_static("Cookie, Origin, X-Session-Token"),
    );
    response
}

fn error(status: StatusCode, code: &str, message: &str) -> Response {
    json_response(
        status,
        json!({"code":code,"message":message,"details":null,"errors":null,
        "fields":null,"detail":format!("{{'code': '{code}', 'message': '{message}'}}"),"status":status.as_u16()}),
    )
}

fn add_cors(output: &mut HeaderMap, input: &HeaderMap, origins: &[String]) {
    let Some(origin) = input
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return;
    };
    let Ok(url) = Url::parse(origin) else { return };
    if url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || !origins.contains(&url.origin().ascii_serialization())
    {
        return;
    }
    if let Ok(value) = HeaderValue::from_str(origin) {
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
            HeaderValue::from_static(
                "Content-Type, X-CSRFToken, X-Session-Token, Authorization, Idempotency-Key",
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisioning_svg_encodes_real_qr_without_embedding_raw_email() -> Result<()> {
        let body = provisioning("UpdSpace ID", "person@example.invalid", "JBSWY3DPEHPK3PXP")?;
        let svg = body["svg"].as_str().context("SVG missing")?;
        assert!(svg.contains("<svg") && svg.contains("<path"));
        assert!(!svg.contains("person@example.invalid"));
        assert!(
            body["otpauth_url"]
                .as_str()
                .is_some_and(|value| value.contains("secret=JBSWY3DPEHPK3PXP"))
        );
        Ok(())
    }
}
