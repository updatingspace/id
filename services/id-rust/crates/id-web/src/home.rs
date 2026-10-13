//! Public landing page, owned by the web UI rather than the identity API.

use topcoat::{
    Result,
    context::Cx,
    router::{Body, response::Response, route},
};

#[route(GET "/")]
pub(crate) async fn page(_cx: &Cx) -> Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Cache-Control", "public, max-age=60")
        .header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "strict-origin-when-cross-origin")
        .header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'",
        )
        .body(Body::from(include_str!("../templates/home.html")))?)
}

#[route(GET "/_id/home.css")]
pub(crate) async fn style() -> Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/css; charset=utf-8")
        .header("Cache-Control", "public, max-age=3600")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(include_str!("../static/home.css")))?)
}

/// Public operational information, separate from the final legal documents.
#[route(GET "/data")]
pub(crate) async fn data() -> Result<Response> {
    information_page(include_str!("../templates/data.html"))
}

#[route(GET "/privacy")]
pub(crate) async fn privacy() -> Result<Response> {
    information_page(include_str!("../templates/privacy.html"))
}

#[route(GET "/terms")]
pub(crate) async fn terms() -> Result<Response> {
    information_page(include_str!("../templates/terms.html"))
}

#[route(GET "/contacts")]
pub(crate) async fn contacts() -> Result<Response> {
    information_page(include_str!("../templates/contacts.html"))
}

fn information_page(html: &'static str) -> Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "no-referrer")
        .header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        .body(Body::from(html))?)
}
