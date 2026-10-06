//! Recovery page routing. Frontend authors own the HTML and browser code in
//! `templates/` and `static/`; the identity API owns credentials and state.

use topcoat::{
    Result,
    context::Cx,
    router::{Body, response::Response, route},
};

fn html_response(body: &'static str) -> Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "no-referrer")
        .header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        )
        .body(Body::from(body))?)
}

#[route(GET "/forgot-password")]
pub(crate) async fn forgot_page(_cx: &Cx) -> Result<Response> {
    html_response(include_str!("../templates/forgot-password.html"))
}

#[route(GET "/reset-password")]
pub(crate) async fn reset_page(_cx: &Cx) -> Result<Response> {
    html_response(include_str!("../templates/reset-password.html"))
}

#[route(GET "/verify-email")]
pub(crate) async fn verify_page(_cx: &Cx) -> Result<Response> {
    html_response(include_str!("../templates/verify-email.html"))
}

#[route(GET "/_id/recovery.js")]
pub(crate) async fn script() -> Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/javascript; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(include_str!("../static/recovery.js")))?)
}

#[cfg(test)]
mod tests {
    #[test]
    fn recovery_templates_keep_browser_contract_without_embedded_credentials() {
        let forgot = include_str!("../templates/forgot-password.html");
        let reset = include_str!("../templates/reset-password.html");
        let verify = include_str!("../templates/verify-email.html");
        for html in [forgot, reset, verify] {
            assert!(html.contains("/_id/recovery.js"));
            assert!(html.contains("id=\"status\""));
            assert!(html.contains("id=\"error\""));
            assert!(!html.contains("{{"));
        }
        assert!(forgot.contains("id=\"forgot-form\""));
        assert!(
            reset.contains("id=\"reset-form\" method=\"post\" action=\"/reset-password\" hidden")
        );
        assert!(
            verify.contains("id=\"verify-form\" method=\"post\" action=\"/verify-email\" hidden")
        );
        assert!(verify.contains("id=\"verify-request-form\""));
    }
}
