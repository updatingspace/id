//! SSR signup shell. Credentials go from the browser to id-api on the same origin.

use topcoat::{
    Result,
    router::{Body, response::Response, route},
};

#[route(GET "/signup")]
pub(crate) async fn page() -> Result<Response> {
    let html = include_str!("../templates/signup.html");
    Ok(Response::builder()
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "no-referrer")
        .header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        )
        .body(Body::from(html))?)
}

#[route(GET "/_id/signup.js")]
pub(crate) async fn script() -> Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/javascript; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(include_str!("../static/signup.js")))?)
}

#[route(GET "/_id/signup.css")]
pub(crate) async fn style() -> Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/css; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(include_str!("../static/signup.css")))?)
}
