//! Same-origin Topcoat login page. The browser talks to id-api; this service
//! never holds session signing keys or identity database credentials.

use topcoat::{
    Result,
    context::Cx,
    router::{Body, response::Response, route},
};

const LOGIN_HTML: &str = include_str!("../templates/login.html");

fn render_login(passkey: bool, recovery: bool, signup: bool) -> String {
    LOGIN_HTML
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

#[route(GET "/login")]
pub(crate) async fn page(_cx: &Cx) -> Result<Response> {
    let passkey_enabled = std::env::var("ID_WEB_PASSKEY_PILOT_ENABLED").as_deref() == Ok("true");
    let recovery_enabled = std::env::var("ID_WEB_RECOVERY_PILOT_ENABLED").as_deref() == Ok("true");
    let signup_enabled = std::env::var("ID_WEB_SIGNUP_PILOT_ENABLED").as_deref() == Ok("true");
    let html = render_login(passkey_enabled, recovery_enabled, signup_enabled);
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
    use super::render_login;

    #[test]
    fn login_template_keeps_required_form_and_enabled_actions() {
        let html = render_login(true, true, true);
        assert!(html.contains("id=\"login-form\""));
        assert!(html.contains("id=\"passkey-login\""));
        assert!(html.contains("href=\"/forgot-password\""));
        assert!(html.contains("href=\"/signup\""));
        assert!(!html.contains("{{"));
    }

    #[test]
    fn disabled_actions_are_absent_from_html() {
        let html = render_login(false, false, false);
        assert!(!html.contains("id=\"passkey-login\""));
        assert!(!html.contains("href=\"/forgot-password\""));
        assert!(!html.contains("href=\"/signup\""));
    }
}
