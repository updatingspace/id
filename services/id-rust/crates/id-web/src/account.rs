//! Opt-in SSR account pages. Only the Rust API authenticates the session.

mod api;
mod data_export;

pub(crate) use api::AccountApi;
use api::{
    AuthorizedApp, ConsentRow, LoginEventRow, Preferences, Profile, SecurityResponse, SessionRow,
    TimezoneRow, authorized_apps, consents, email_status, login_history, preferences, profile,
    security, sessions, timezones,
};
pub(crate) use data_export::script as export_script;

use askama::Template;
use topcoat::{
    context::{Cx, app_context},
    router::{Body, request, response::Response, route},
};

#[derive(Template)]
#[template(path = "account-overview.html")]
struct AccountOverview<'a> {
    edit_mode: bool,
    features: OverviewFeatures,
    user: &'a api::User,
    display_name: &'a str,
    email_label: &'static str,
    mfa_status: &'static str,
    email_management: Option<&'a api::EmailStatus>,
    first_name: &'a str,
    last_name: &'a str,
    phone_number: &'a str,
    birth_date: &'a str,
    avatar_url: &'a str,
    has_avatar: bool,
}

struct OverviewFeatures {
    logout_enabled: bool,
    profile_enabled: bool,
    email_management_enabled: bool,
    sessions_enabled: bool,
    preferences_enabled: bool,
    exports_enabled: bool,
    apps_enabled: bool,
    security_enabled: bool,
    history_enabled: bool,
}

impl From<&AccountApi> for OverviewFeatures {
    fn from(api: &AccountApi) -> Self {
        Self {
            logout_enabled: api.logout_enabled,
            profile_enabled: api.profile_enabled,
            email_management_enabled: api.email_management_enabled,
            sessions_enabled: api.sessions_enabled,
            preferences_enabled: api.preferences_enabled,
            exports_enabled: api.exports_enabled,
            apps_enabled: api.apps_enabled,
            security_enabled: api.security_enabled,
            history_enabled: api.history_enabled,
        }
    }
}

#[derive(Template)]
#[template(path = "account-sessions.html")]
struct SessionsPage<'a> {
    sessions: &'a [SessionView<'a>],
    has_other: bool,
    logout_enabled: bool,
    preferences_enabled: bool,
    apps_enabled: bool,
}

struct SessionView<'a> {
    id: &'a str,
    user_agent: &'a str,
    ip: &'a str,
    current: bool,
    revoked: bool,
}

#[derive(Template)]
#[template(path = "account-history.html")]
struct HistoryPage<'a> {
    events: &'a [HistoryView<'a>],
}

struct HistoryView<'a> {
    status_label: &'static str,
    created_at: &'a str,
    user_agent: &'a str,
    ip: &'a str,
    is_new_device: bool,
    reason: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "account-apps.html")]
struct AppsPage<'a> {
    apps: &'a [AppView<'a>],
    logout_enabled: bool,
    sessions_enabled: bool,
    preferences_enabled: bool,
}

struct AppView<'a> {
    client_id: &'a str,
    name: &'a str,
    scopes: String,
    last_used_at: &'a str,
}

#[derive(Template)]
#[template(path = "account-privacy.html")]
struct PrivacyPage<'a> {
    logout_enabled: bool,
    sessions_enabled: bool,
    apps_enabled: bool,
    consents_enabled: bool,
    language_ru: bool,
    language_en: bool,
    timezone_empty: bool,
    timezones: &'a [TimezoneView<'a>],
    marketing_opt_in: bool,
    scopes: &'a [ScopePreference],
    consents: &'a [ConsentView<'a>],
}

struct TimezoneView<'a> {
    name: &'a str,
    display_name: &'a str,
    selected: bool,
}

struct ScopePreference {
    name: &'static str,
    label: &'static str,
    allow: bool,
    ask: bool,
    deny: bool,
}

struct ConsentView<'a> {
    kind: &'a str,
    version: &'a str,
    granted_at: &'a str,
    revoked: bool,
    revocable: bool,
}

#[derive(Template)]
#[template(path = "account-security.html")]
struct SecurityPage<'a> {
    logout_enabled: bool,
    password_change_enabled: bool,
    passkey_registration_enabled: bool,
    show_passkey_script: bool,
    show_totp_setup: bool,
    show_totp_disable: bool,
    show_recovery_rotation: bool,
    totp_status: &'static str,
    passkeys_status: &'static str,
    recovery_status: &'static str,
    recovery_left: usize,
    passkeys: &'a [PasskeyView<'a>],
}

struct PasskeyView<'a> {
    id: &'a str,
    name: &'a str,
    is_passwordless: bool,
    can_manage: bool,
}
#[route(GET "/account")]
pub(crate) async fn page(cx: &Cx) -> topcoat::Result<Response> {
    let api = app_context::<AccountApi>(cx);
    let cookie = request::headers(cx)
        .get("cookie")
        .and_then(|value| value.to_str().ok());
    let profile = match profile(api, cookie).await {
        Ok(value) => value,
        Err(_) => {
            return error_page("Не удалось загрузить кабинет. Попробуйте позже.");
        }
    };
    let (user, cookies) = match profile {
        Profile::Guest(cookies) => {
            let mut response = Response::builder()
                .status(303)
                .header("Location", "/login?next=%2Faccount")
                .header("Cache-Control", "no-store");
            for cookie in cookies {
                response = response.header("Set-Cookie", cookie);
            }
            return Ok(response.body(Body::empty())?);
        }
        Profile::User(user, cookies) => (user, cookies),
    };
    let session_section = api.sessions_enabled
        && request::uri(cx).query().is_some_and(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .any(|(key, value)| key == "section" && value == "sessions")
        });
    if session_section {
        let user_agent = request::headers(cx)
            .get("user-agent")
            .and_then(|value| value.to_str().ok());
        let sessions = match sessions(api, cookie, user_agent).await {
            Ok(value) => value,
            Err(_) => return error_page("Не удалось загрузить сессии. Попробуйте позже."),
        };
        return sessions_page(cx, sessions, cookies).await;
    }
    let privacy_section = api.preferences_enabled
        && request::uri(cx).query().is_some_and(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .any(|(key, value)| key == "section" && value == "privacy")
        });
    if privacy_section {
        let preferences = match preferences(api, cookie).await {
            Ok(value) => value,
            Err(_) => return error_page("Не удалось загрузить настройки. Попробуйте позже."),
        };
        let timezones = match timezones(api).await {
            Ok(value) => value,
            Err(_) => return error_page("Не удалось загрузить часовые пояса. Попробуйте позже."),
        };
        let consents = if api.consents_enabled {
            match consents(api, cookie).await {
                Ok(value) => value,
                Err(_) => return error_page("Не удалось загрузить согласия. Попробуйте позже."),
            }
        } else {
            Vec::new()
        };
        return privacy_page(cx, preferences, timezones, consents, cookies).await;
    }
    let apps_section = api.apps_enabled
        && request::uri(cx).query().is_some_and(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .any(|(key, value)| key == "section" && value == "apps")
        });
    if apps_section {
        let apps = match authorized_apps(api, cookie).await {
            Ok(value) => value,
            Err(_) => return error_page("Не удалось загрузить приложения. Попробуйте позже."),
        };
        return apps_page(cx, apps, cookies).await;
    }
    let security_section = api.security_enabled
        && request::uri(cx).query().is_some_and(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .any(|(key, value)| key == "section" && value == "security")
        });
    if security_section {
        let snapshot = match security(api, cookie).await {
            Ok(value) => value,
            Err(_) => {
                return error_page(
                    "Не удалось загрузить настройки безопасности. Попробуйте позже.",
                );
            }
        };
        return security_page(cx, snapshot, cookies).await;
    }
    let history_section = api.history_enabled
        && request::uri(cx).query().is_some_and(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .any(|(key, value)| key == "section" && value == "activity")
        });
    if history_section {
        let events = match login_history(api, cookie).await {
            Ok(value) => value,
            Err(_) => return error_page("Не удалось загрузить историю входов. Попробуйте позже."),
        };
        return history_page(cx, events, cookies).await;
    }
    let data_section = api.exports_enabled
        && request::uri(cx).query().is_some_and(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .any(|(key, value)| key == "section" && value == "data")
        });
    if data_section {
        let operation_id = request::uri(cx).query().and_then(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .find(|(key, _)| key == "export")
                .map(|(_, value)| value.into_owned())
        });
        let operation = match operation_id.as_deref() {
            Some(id) => match api::export_status(api, cookie, id).await {
                Ok(value) => value,
                Err(_) => return error_page("Не удалось загрузить экспорт. Попробуйте позже."),
            },
            None => None,
        };
        return data_export::page(
            cx,
            operation,
            operation_id.is_some(),
            user.has_2fa,
            &user.email,
            user.email_verified,
            cookies,
        )
        .await;
    }
    let full_name = [user.first_name.as_deref(), user.last_name.as_deref()]
        .into_iter()
        .flatten()
        .filter(|part| !part.trim().is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let display_name = if full_name.is_empty() {
        user.username.as_str()
    } else {
        full_name.as_str()
    };
    let email_label = if user.email_verified {
        "Подтверждена"
    } else {
        "Не подтверждена"
    };
    let edit_mode = request::uri(cx).query().is_some_and(|query| {
        url::form_urlencoded::parse(query.as_bytes())
            .any(|(key, value)| key == "section" && value == "profile")
    });
    let email_management = if edit_mode && api.email_management_enabled {
        match email_status(api, cookie).await {
            Ok(status) => Some(status),
            Err(_) => return error_page("Не удалось загрузить состояние почты. Попробуйте позже."),
        }
    } else {
        None
    };
    let mfa_status = if user.has_2fa {
        "Включена"
    } else {
        "Не включена"
    };
    let html = AccountOverview {
        edit_mode,
        features: OverviewFeatures::from(api),
        user: &user,
        display_name,
        email_label,
        mfa_status,
        email_management: email_management.as_ref(),
        first_name: user.first_name.as_deref().unwrap_or(""),
        last_name: user.last_name.as_deref().unwrap_or(""),
        phone_number: user.phone_number.as_deref().unwrap_or(""),
        birth_date: user.birth_date.as_deref().unwrap_or(""),
        avatar_url: user.avatar_url.as_deref().unwrap_or(""),
        has_avatar: user.avatar_url.is_some(),
    }
    .render()
    .map_err(|error| topcoat::Error::msg(error.to_string()))?;
    page_response(
        html,
        cookies,
        api.logout_enabled || (edit_mode && (api.profile_enabled || api.email_management_enabled)),
    )
}

async fn sessions_page(
    cx: &Cx,
    sessions: Vec<SessionRow>,
    cookies: Vec<String>,
) -> topcoat::Result<Response> {
    let has_other = sessions
        .iter()
        .any(|session| !session.current && !session.revoked);
    let logout_enabled = app_context::<AccountApi>(cx).logout_enabled;
    let preferences_enabled = app_context::<AccountApi>(cx).preferences_enabled;
    let apps_enabled = app_context::<AccountApi>(cx).apps_enabled;
    let rows = sessions
        .iter()
        .map(|session| SessionView {
            id: &session.id,
            user_agent: session
                .user_agent
                .as_deref()
                .filter(|value| !value.is_empty())
                .unwrap_or("Неизвестное устройство"),
            ip: session
                .ip
                .as_deref()
                .filter(|value| !value.is_empty())
                .unwrap_or("—"),
            current: session.current,
            revoked: session.revoked,
        })
        .collect::<Vec<_>>();
    let html = SessionsPage {
        sessions: &rows,
        has_other,
        logout_enabled,
        preferences_enabled,
        apps_enabled,
    }
    .render()
    .map_err(|error| topcoat::Error::msg(error.to_string()))?;
    page_response(html, cookies, true)
}

async fn history_page(
    _cx: &Cx,
    events: Vec<LoginEventRow>,
    cookies: Vec<String>,
) -> topcoat::Result<Response> {
    let rows = events
        .iter()
        .map(|event| HistoryView {
            status_label: if event.status == "success" {
                "Успешный вход"
            } else {
                "Неудачная попытка"
            },
            created_at: &event.created_at,
            user_agent: event
                .user_agent
                .as_deref()
                .filter(|value| !value.is_empty())
                .unwrap_or("Неизвестное устройство"),
            ip: event
                .ip_address
                .as_deref()
                .filter(|value| !value.is_empty())
                .unwrap_or("Адрес неизвестен"),
            is_new_device: event.is_new_device,
            reason: event.reason.as_deref().filter(|value| !value.is_empty()),
        })
        .collect::<Vec<_>>();
    let html = HistoryPage { events: &rows }
        .render()
        .map_err(|error| topcoat::Error::msg(error.to_string()))?;
    page_response(html, cookies, false)
}

async fn privacy_page(
    cx: &Cx,
    preferences: Preferences,
    timezones: Vec<TimezoneRow>,
    consents: Vec<ConsentRow>,
    cookies: Vec<String>,
) -> topcoat::Result<Response> {
    let api = app_context::<AccountApi>(cx);
    let scopes = [
        ("profile_basic", "Основные данные"),
        ("profile_extended", "Дополнительные данные"),
        ("email", "Адрес почты"),
        ("phone", "Телефон"),
    ]
    .map(|(name, label)| {
        let policy = preferences
            .privacy_scope_defaults
            .get(name)
            .and_then(serde_json::Value::as_str);
        ScopePreference {
            name,
            label,
            allow: policy == Some("allow"),
            ask: policy.unwrap_or("ask") == "ask",
            deny: policy == Some("deny"),
        }
    });
    let zones = timezones
        .iter()
        .map(|zone| TimezoneView {
            name: &zone.name,
            display_name: &zone.display_name,
            selected: zone.name == preferences.timezone,
        })
        .collect::<Vec<_>>();
    let rows = consents
        .iter()
        .map(|consent| ConsentView {
            kind: &consent.kind,
            version: &consent.version,
            granted_at: &consent.granted_at,
            revoked: consent.revoked_at.is_some(),
            revocable: consent.revoked_at.is_none() && consent.kind == "marketing",
        })
        .collect::<Vec<_>>();
    let html = PrivacyPage {
        logout_enabled: api.logout_enabled,
        sessions_enabled: api.sessions_enabled,
        apps_enabled: api.apps_enabled,
        consents_enabled: api.consents_enabled,
        language_ru: preferences.language == "ru",
        language_en: preferences.language == "en",
        timezone_empty: preferences.timezone.is_empty(),
        timezones: &zones,
        marketing_opt_in: preferences.marketing_opt_in,
        scopes: &scopes,
        consents: &rows,
    }
    .render()
    .map_err(|error| topcoat::Error::msg(error.to_string()))?;
    page_response(html, cookies, true)
}

async fn apps_page(
    cx: &Cx,
    apps: Vec<AuthorizedApp>,
    cookies: Vec<String>,
) -> topcoat::Result<Response> {
    let api = app_context::<AccountApi>(cx);
    let rows = apps
        .iter()
        .map(|app| AppView {
            client_id: &app.client_id,
            name: &app.name,
            scopes: app.scopes.join(", "),
            last_used_at: app.last_used_at.as_deref().unwrap_or("нет данных"),
        })
        .collect::<Vec<_>>();
    let html = AppsPage {
        apps: &rows,
        logout_enabled: api.logout_enabled,
        sessions_enabled: api.sessions_enabled,
        preferences_enabled: api.preferences_enabled,
    }
    .render()
    .map_err(|error| topcoat::Error::msg(error.to_string()))?;
    page_response(html, cookies, true)
}

async fn security_page(
    cx: &Cx,
    security: SecurityResponse,
    cookies: Vec<String>,
) -> topcoat::Result<Response> {
    let api = app_context::<AccountApi>(cx);
    let show_totp_setup = api.totp_enabled && !security.mfa.has_totp;
    let show_totp_disable = api.totp_enabled && security.mfa.has_totp;
    let show_recovery_rotation =
        api.totp_enabled && (security.mfa.has_totp || security.mfa.has_webauthn);
    let show_passkey_script = api.passkey_registration_enabled
        || (api.passkey_management_enabled && security.mfa.has_webauthn);
    let rows = security
        .authenticators
        .iter()
        .map(|key| PasskeyView {
            id: &key.id,
            name: key
                .name
                .as_deref()
                .filter(|name| !name.is_empty())
                .unwrap_or("Ключ доступа"),
            is_passwordless: key.is_passwordless,
            can_manage: api.passkey_management_enabled && !key.id.is_empty(),
        })
        .collect::<Vec<_>>();
    let html = SecurityPage {
        logout_enabled: api.logout_enabled,
        password_change_enabled: api.password_change_enabled,
        passkey_registration_enabled: api.passkey_registration_enabled,
        show_passkey_script,
        show_totp_setup,
        show_totp_disable,
        show_recovery_rotation,
        totp_status: if security.mfa.has_totp {
            "Включена"
        } else {
            "Не включена"
        },
        passkeys_status: if security.mfa.has_webauthn {
            "Есть"
        } else {
            "Нет"
        },
        recovery_status: if security.mfa.has_recovery_codes {
            "Есть"
        } else {
            "Нет"
        },
        recovery_left: security.mfa.recovery_codes_left,
        passkeys: &rows,
    }
    .render()
    .map_err(|error| topcoat::Error::msg(error.to_string()))?;
    page_response(
        html,
        cookies,
        api.logout_enabled
            || api.totp_enabled
            || api.passkey_management_enabled
            || api.passkey_registration_enabled
            || api.password_change_enabled,
    )
}

#[route(GET "/_id/password-change.js")]
pub(crate) async fn password_change_script() -> topcoat::Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/javascript; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(include_str!("../static/password-change.js")))?)
}

#[route(GET "/_id/totp.js")]
pub(crate) async fn totp_script() -> topcoat::Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/javascript; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(include_str!("../static/totp.js")))?)
}

#[route(GET "/_id/totp-disable.js")]
pub(crate) async fn totp_disable_script() -> topcoat::Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/javascript; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(include_str!("../static/totp-disable.js")))?)
}

#[route(GET "/_id/recovery-rotate.js")]
pub(crate) async fn recovery_rotate_script() -> topcoat::Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/javascript; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(include_str!("../static/recovery-rotate.js")))?)
}

#[route(GET "/_id/passkeys.js")]
pub(crate) async fn passkeys_script() -> topcoat::Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/javascript; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(include_str!("../static/passkeys.js")))?)
}

#[route(GET "/_id/account.js")]
pub(crate) async fn account_script() -> topcoat::Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/javascript; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(include_str!("../static/account.js")))?)
}

#[route(GET "/_id/profile.js")]
pub(crate) async fn profile_script() -> topcoat::Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/javascript; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(include_str!("../static/profile.js")))?)
}

#[route(GET "/_id/avatar.js")]
pub(crate) async fn avatar_script() -> topcoat::Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/javascript; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(include_str!("../static/avatar.js")))?)
}

#[route(GET "/_id/email.js")]
pub(crate) async fn email_script() -> topcoat::Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/javascript; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(include_str!("../static/email.js")))?)
}

#[route(GET "/_id/preferences.js")]
pub(crate) async fn preferences_script() -> topcoat::Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/javascript; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(include_str!("../static/preferences.js")))?)
}

#[route(GET "/_id/apps.js")]
pub(crate) async fn apps_script() -> topcoat::Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/javascript; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(include_str!("../static/apps.js")))?)
}

fn page_response(html: String, cookies: Vec<String>, script: bool) -> topcoat::Result<Response> {
    let csp = if script {
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: https://storage.yandexcloud.net; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"
    } else {
        "default-src 'none'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"
    };
    let mut response = Response::builder()
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "strict-origin-when-cross-origin")
        .header("Content-Security-Policy", csp);
    for cookie in cookies {
        response = response.header("Set-Cookie", cookie);
    }
    Ok(response.body(Body::from(html))?)
}

#[route(GET "/_id/sessions.js")]
pub(crate) async fn sessions_script() -> topcoat::Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/javascript; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(include_str!("../static/sessions.js")))?)
}

fn error_page(message: &str) -> topcoat::Result<Response> {
    Ok(Response::builder()
        .status(503)
        .header("Content-Type", "text/plain; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(message.to_owned()))?)
}

#[route(GET "/_id/account.css")]
pub(crate) async fn style() -> topcoat::Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/css; charset=utf-8")
        .header("Cache-Control", "public, max-age=3600")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(include_str!("../static/account.css")))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_template_keeps_mfa_and_passkey_hooks_and_escapes_names() -> Result<(), askama::Error>
    {
        let keys = [PasskeyView {
            id: "42\" onclick=\"bad",
            name: "<script>bad()</script>",
            is_passwordless: true,
            can_manage: true,
        }];
        let html = SecurityPage {
            logout_enabled: true,
            password_change_enabled: true,
            passkey_registration_enabled: true,
            show_passkey_script: true,
            show_totp_setup: false,
            show_totp_disable: true,
            show_recovery_rotation: true,
            totp_status: "Включена",
            passkeys_status: "Есть",
            recovery_status: "Есть",
            recovery_left: 8,
            passkeys: &keys,
        }
        .render()?;
        assert!(!html.contains("<script>bad()</script>"));
        assert!(!html.contains("data-passkey-rename=\"42\" onclick="));
        for hook in [
            "id=\"totp-disable\"",
            "id=\"recovery-rotate\"",
            "id=\"passkey-register\"",
            "id=\"password-change-form\"",
            "data-passkey-delete=",
        ] {
            assert!(html.contains(hook), "missing {hook}");
        }
        assert!(!html.contains("id=\"totp-setup\""));
        Ok(())
    }

    #[test]
    fn security_template_shows_totp_setup_without_existing_key() -> Result<(), askama::Error> {
        let html = SecurityPage {
            logout_enabled: false,
            password_change_enabled: false,
            passkey_registration_enabled: false,
            show_passkey_script: false,
            show_totp_setup: true,
            show_totp_disable: false,
            show_recovery_rotation: false,
            totp_status: "Не включена",
            passkeys_status: "Нет",
            recovery_status: "Нет",
            recovery_left: 0,
            passkeys: &[],
        }
        .render()?;
        assert!(html.contains("id=\"totp-confirm-form\""));
        assert!(html.contains("id=\"totp-recovery-codes\""));
        assert!(html.contains("Ключей доступа нет"));
        assert!(!html.contains("id=\"totp-disable\""));
        assert!(!html.contains("id=\"password-change-form\""));
        Ok(())
    }

    #[test]
    fn privacy_template_escapes_preferences_and_keeps_consent_actions() -> Result<(), askama::Error>
    {
        let zones = [TimezoneView {
            name: "zone\" onclick=\"bad",
            display_name: "<script>bad()</script>",
            selected: true,
        }];
        let scopes = [ScopePreference {
            name: "profile_basic",
            label: "Основные данные",
            allow: false,
            ask: true,
            deny: false,
        }];
        let consents = [ConsentView {
            kind: "marketing",
            version: "<img src=x>",
            granted_at: "2026-10-06",
            revoked: false,
            revocable: true,
        }];
        let html = PrivacyPage {
            logout_enabled: true,
            sessions_enabled: true,
            apps_enabled: true,
            consents_enabled: true,
            language_ru: true,
            language_en: false,
            timezone_empty: false,
            timezones: &zones,
            marketing_opt_in: true,
            scopes: &scopes,
            consents: &consents,
        }
        .render()?;
        assert!(!html.contains("<script>bad()</script>"));
        assert!(!html.contains("<img src=x>"));
        assert!(!html.contains("value=\"zone\" onclick="));
        assert!(html.contains("id=\"preferences-form\""));
        assert!(html.contains("id=\"scope-profile_basic\""));
        assert!(html.contains("data-kind=\"marketing\""));
        assert!(html.contains("id=\"consents-error\""));
        Ok(())
    }

    #[test]
    fn apps_template_escapes_client_data_and_keeps_revoke_control() -> Result<(), askama::Error> {
        let rows = [AppView {
            client_id: "client\" onclick=\"bad",
            name: "<script>bad()</script>",
            scopes: "openid, email".into(),
            last_used_at: "нет данных",
        }];
        let html = AppsPage {
            apps: &rows,
            logout_enabled: true,
            sessions_enabled: true,
            preferences_enabled: true,
        }
        .render()?;
        assert!(!html.contains("<script>bad()</script>"));
        assert!(!html.contains("data-revoke-app=\"client\" onclick="));
        assert!(html.contains("id=\"apps-message\""));
        assert!(html.contains("id=\"apps-error\""));
        assert!(html.contains("id=\"revoke-app-review\""));
        assert!(html.contains("id=\"revoke-app-confirm\""));
        assert!(html.contains("id=\"revoke-app-cancel\""));
        assert!(html.contains("/_id/apps.js"));
        Ok(())
    }

    #[test]
    fn sessions_template_escapes_device_data_and_keeps_revoke_controls() -> Result<(), askama::Error>
    {
        let rows = [
            SessionView {
                id: "other\" onmouseover=\"bad",
                user_agent: "<script>bad()</script>",
                ip: "192.0.2.1",
                current: false,
                revoked: false,
            },
            SessionView {
                id: "current",
                user_agent: "Current device",
                ip: "—",
                current: true,
                revoked: false,
            },
        ];
        let html = SessionsPage {
            sessions: &rows,
            has_other: true,
            logout_enabled: true,
            preferences_enabled: true,
            apps_enabled: true,
        }
        .render()?;
        assert!(!html.contains("<script>bad()</script>"));
        assert!(!html.contains("data-revoke-session=\"other\" onmouseover="));
        assert!(html.contains("id=\"session-message\""));
        assert!(html.contains("id=\"session-error\""));
        assert!(html.contains("id=\"revoke-others\""));
        assert_eq!(html.matches("data-revoke-session=").count(), 1);
        Ok(())
    }

    #[test]
    fn history_template_escapes_event_data() -> Result<(), askama::Error> {
        let rows = [HistoryView {
            status_label: "Неудачная попытка",
            created_at: "2026-10-06\" onclick=\"bad",
            user_agent: "<img src=x onerror=bad()>",
            ip: "192.0.2.2",
            is_new_device: true,
            reason: Some("<script>bad()</script>"),
        }];
        let html = HistoryPage { events: &rows }.render()?;
        assert!(!html.contains("<script>bad()</script>"));
        assert!(!html.contains("<img src=x onerror=bad()>"));
        assert!(!html.contains("datetime=\"2026-10-06\" onclick="));
        assert!(html.contains("Новое устройство"));
        Ok(())
    }

    #[test]
    fn profile_edit_template_escapes_data_and_preserves_form_hooks() -> Result<(), askama::Error> {
        let user = api::User {
            username: "owner".into(),
            email: "<script>alert(1)</script>@example.invalid".into(),
            first_name: Some("\" onfocus=\"evil".into()),
            last_name: None,
            phone_number: None,
            birth_date: None,
            email_verified: false,
            has_2fa: true,
            avatar_url: Some("https://storage.yandexcloud.net/avatar?a=1&b=2".into()),
        };
        let email = api::EmailStatus {
            email: "owner@example.invalid".into(),
            verified: false,
            pending_email: Some("pending@example.invalid".into()),
        };
        let html = AccountOverview {
            edit_mode: true,
            features: OverviewFeatures {
                logout_enabled: true,
                profile_enabled: true,
                email_management_enabled: true,
                sessions_enabled: true,
                preferences_enabled: true,
                exports_enabled: true,
                apps_enabled: true,
                security_enabled: true,
                history_enabled: true,
            },
            user: &user,
            display_name: user.first_name.as_deref().unwrap_or(""),
            email_label: "Не подтверждена",
            mfa_status: "Включена",
            email_management: Some(&email),
            first_name: user.first_name.as_deref().unwrap_or(""),
            last_name: "",
            phone_number: "",
            birth_date: "",
            avatar_url: user.avatar_url.as_deref().unwrap_or(""),
            has_avatar: true,
        }
        .render()?;
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(!html.contains("value=\"\" onfocus="));
        assert!(html.contains("id=\"profile-form\""));
        assert!(html.contains("id=\"avatar-form\""));
        assert!(html.contains("id=\"email-change-form\""));
        assert!(html.contains("id=\"email-change-cancel\""));
        assert!(html.contains("href=\"/account\""));
        assert!(html.contains("/_id/profile.js"));
        assert!(!html.contains("a=1&b=2"));
        Ok(())
    }

    #[test]
    fn overview_has_clear_tasks_without_edit_forms_or_legacy_jump() -> Result<(), askama::Error> {
        let user = api::User {
            username: "owner".into(),
            email: "owner@example.invalid".into(),
            first_name: None,
            last_name: None,
            phone_number: None,
            birth_date: None,
            email_verified: true,
            has_2fa: false,
            avatar_url: None,
        };
        let html = AccountOverview {
            edit_mode: false,
            features: OverviewFeatures {
                logout_enabled: true,
                profile_enabled: true,
                email_management_enabled: true,
                sessions_enabled: true,
                preferences_enabled: true,
                exports_enabled: true,
                apps_enabled: true,
                security_enabled: true,
                history_enabled: true,
            },
            user: &user,
            display_name: "owner",
            email_label: "Подтверждена",
            mfa_status: "Не включена",
            email_management: None,
            first_name: "",
            last_name: "",
            phone_number: "",
            birth_date: "",
            avatar_url: "",
            has_avatar: false,
        }
        .render()?;
        assert!(html.contains("href=\"/account?section=profile\""));
        assert!(html.contains("Подключённые приложения"));
        assert!(!html.contains("id=\"profile-form\""));
        assert!(!html.contains("/legacy/account"));
        assert!(html.contains("Кто имеет доступ"));
        assert!(html.contains("Защита входа"));
        assert!(html.contains("Ваши данные"));
        assert!(!html.contains("/_id/profile.js"));
        Ok(())
    }

    #[test]
    fn account_csp_allows_only_configured_private_avatar_origin() -> topcoat::Result<()> {
        let response = page_response("test".into(), Vec::new(), true)?;
        let csp = response
            .headers()
            .get("Content-Security-Policy")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        assert!(csp.contains("img-src 'self' data: https://storage.yandexcloud.net;"));
        assert!(!csp.contains("img-src *"));
        Ok(())
    }

    #[test]
    fn api_origin_is_fixed_and_https_outside_localhost() {
        assert!(api::me_url("https://id.example.invalid").is_ok());
        assert!(api::me_url("http://127.0.0.1:18080").is_ok());
        assert!(api::me_url("http://id.example.invalid").is_err());
        assert!(api::me_url("https://id.example.invalid/path").is_err());
        assert!(api::me_url("https://user@id.example.invalid").is_err());
        assert!(api::me_url("https://id.example.invalid?x=1").is_err());
    }

    #[test]
    fn legacy_scope_values_do_not_break_preferences_page() -> Result<(), serde_json::Error> {
        let preferences: Preferences = serde_json::from_value(serde_json::json!({
            "language": "ru",
            "timezone": "Europe/Moscow",
            "marketing_opt_in": false,
            "privacy_scope_defaults": {"email": null, "profile": "ask"}
        }))?;
        assert_eq!(
            preferences
                .privacy_scope_defaults
                .get("email")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("ask"),
            "ask"
        );
        Ok(())
    }
}
