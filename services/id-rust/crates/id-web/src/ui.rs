//! Shared presentation assets. No identity state is cached by this service.
use topcoat::router::{Body, response::Response, route};

#[route(GET "/_id/ui.css")]
pub(crate) async fn style() -> topcoat::Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/css; charset=utf-8")
        .header("Cache-Control", "public, max-age=3600")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(include_str!("../static/ui.css")))?)
}

#[route(GET "/_id/ui.js")]
pub(crate) async fn script() -> topcoat::Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/javascript; charset=utf-8")
        .header("Cache-Control", "public, max-age=3600")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(include_str!("../static/ui.js")))?)
}

#[derive(askama::Template)]
#[template(path = "unavailable.html")]
struct Unavailable<'a> {
    message: &'a str,
    retryable: bool,
}

pub(crate) fn unavailable(message: &str, retryable: bool) -> topcoat::Result<Response> {
    use askama::Template;
    let html = Unavailable { message, retryable }
        .render()
        .map_err(|error| topcoat::Error::msg(error.to_string()))?;
    Ok(Response::builder()
        .status(if retryable { 503 } else { 400 })
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(html))?)
}
