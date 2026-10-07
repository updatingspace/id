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
