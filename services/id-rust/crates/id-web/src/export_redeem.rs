//! Public delivery page. The bearer secret lives only in the URL fragment and
//! is posted to the API; it is never rendered into HTML or logged by Gateway.

use topcoat::{
    Result,
    context::Cx,
    router::{Body, response::Response, route},
};

#[route(GET "/data/export")]
pub(crate) async fn page(_cx: &Cx) -> Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "no-referrer")
        .header("X-Robots-Tag", "noindex, nofollow")
        .header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        .body(Body::from(include_str!("../templates/export-redeem.html")))?)
}

#[route(GET "/_id/export-redeem.js")]
pub(crate) async fn script() -> Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/javascript; charset=utf-8")
        .header("Cache-Control", "public, max-age=3600")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(include_str!("../static/export-redeem.js")))?)
}

#[cfg(test)]
mod tests {
    #[test]
    fn page_has_no_credential_placeholder() {
        let html = include_str!("../templates/export-redeem.html");
        assert!(html.contains("export-download"));
        assert!(!html.contains("{{"));
    }
}
