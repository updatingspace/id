//! Same-origin Topcoat login page. The browser talks to id-api; this service
//! never holds session signing keys or identity database credentials.

use topcoat::{
    Result,
    context::Cx,
    router::{Body, request, response::Response, route},
};
use url::Url;

const LOGIN_HTML: &str = include_str!("../templates/login.html");

fn render_login(passkey: bool, recovery: bool, signup: bool, from_app: bool) -> String {
    LOGIN_HTML
        .replace(
            "{{LOGIN_TITLE}}",
            if from_app { "Войдите, чтобы продолжить" } else { "Войти в аккаунт" },
        )
        .replace(
            "{{LOGIN_INTRO}}",
            if from_app {
                "Вы открываете другой сервис через единый аккаунт UpdSpace ID."
            } else {
                "Продолжите работу с вашим аккаунтом UpdSpace."
            },
        )
        .replace("{{AUTH_CONTEXT_HIDDEN}}", if from_app { "" } else { "hidden" })
        .replace(
            "{{AUTH_CONTEXT}}",
            if from_app {
                "Это вход в ваш аккаунт. Затем мы покажем название приложения и запрошенные сведения. Разрешения вы выберете отдельно; без вашего решения данные приложению не передадутся."
            } else {
                ""
            },
        )
        .replace(
            "{{LOGIN_ACTION}}",
            if from_app { "Продолжить к разрешениям" } else { "Войти" },
        )
        .replace(
            "{{PASSKEY_ACTION}}",
            if passkey {
                include_str!("../templates/login-passkey.html")
            } else {
                ""
            },
        )
        .replace(
            "{{RECOVERY_LINK}}",
            if recovery {
                include_str!("../templates/login-recovery.html")
            } else {
                ""
            },
        )
        .replace(
            "{{SIGNUP_LINK}}",
            if signup {
                include_str!("../templates/login-signup.html")
            } else {
                ""
            },
        )
}

fn app_return(query: Option<&str>) -> bool {
    let Some(next) = query.and_then(|query| {
        url::form_urlencoded::parse(query.as_bytes())
            .find(|(key, _)| key == "next")
            .map(|(_, value)| value.into_owned())
    }) else {
        return false;
    };
    if next.len() > 16_384
        || next
            .bytes()
            .any(|byte| byte == b'\\' || byte.is_ascii_control())
    {
        return false;
    }
    let Ok(base) = Url::parse("https://id.local/") else {
        return false;
    };
    let Ok(target) = base.join(&next) else {
        return false;
    };
    target.origin() == base.origin()
        && matches!(target.path(), "/oauth/consent" | "/authorize")
        && target.query().is_some()
}

#[route(GET "/login")]
pub(crate) async fn page(cx: &Cx) -> Result<Response> {
    let passkey_enabled = std::env::var("ID_WEB_PASSKEY_PILOT_ENABLED").as_deref() == Ok("true");
    let recovery_enabled = std::env::var("ID_WEB_RECOVERY_PILOT_ENABLED").as_deref() == Ok("true");
    let signup_enabled = std::env::var("ID_WEB_SIGNUP_PILOT_ENABLED").as_deref() == Ok("true");
    let html = render_login(
        passkey_enabled,
        recovery_enabled,
        signup_enabled,
        app_return(request::uri(cx).query()),
    );
    Ok(Response::builder()
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "strict-origin-when-cross-origin")
        .header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        )
        .body(Body::from(html))?)
}

#[route(GET "/_id/login.js")]
pub(crate) async fn script() -> Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/javascript; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(include_str!("../static/login.js")))?)
}

#[route(GET "/_id/login.css")]
pub(crate) async fn style() -> Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/css; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(include_str!("../static/login.css")))?)
}

#[cfg(test)]
mod tests {
    use super::{app_return, render_login};

    #[test]
    fn login_template_keeps_required_form_and_enabled_actions() {
        let html = render_login(true, true, true, false);
        assert!(html.contains("id=\"login-form\""));
        assert!(html.contains("id=\"passkey-login\""));
        assert!(html.contains("href=\"/forgot-password\""));
        assert!(html.contains("href=\"/signup\""));
        assert!(!html.contains("{{"));
    }

    #[test]
    fn disabled_actions_are_absent_from_html() {
        let html = render_login(false, false, false, false);
        assert!(!html.contains("id=\"passkey-login\""));
        assert!(!html.contains("href=\"/forgot-password\""));
        assert!(!html.contains("href=\"/signup\""));
    }

    #[test]
    fn app_sign_in_explains_separate_consent_before_javascript() {
        let html = render_login(false, false, false, true);
        assert!(html.contains("Войдите, чтобы продолжить"));
        assert!(html.contains("Разрешения вы выберете отдельно"));
        assert!(html.contains("Продолжить к разрешениям"));
        assert!(!html.contains("id=\"auth-context\" role=\"status\" hidden"));
        assert!(!html.contains("{{"));
    }

    #[test]
    fn app_context_requires_a_same_origin_oauth_return() {
        assert!(app_return(Some(
            "next=%2Foauth%2Fconsent%3Fclient_id%3Dportal"
        )));
        assert!(!app_return(Some(
            "next=https%3A%2F%2Fevil.example%2Foauth%2Fconsent%3Fx%3D1"
        )));
        assert!(!app_return(Some(
            "next=%2F%2Fevil.example%2Foauth%2Fconsent%3Fx%3D1"
        )));
        assert!(!app_return(Some("next=%2Faccount")));
    }
}
