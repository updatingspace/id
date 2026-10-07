//! SSR consent page; only id-api reads sessions and creates OAuth credentials.

use anyhow::{Context, Result, bail};
use askama::Template;
use serde::Deserialize;
use std::{env, time::Duration};
use topcoat::{
    context::{Cx, app_context},
    router::{Body, request, response::Response, route},
};
use url::Url;

const MAX_PREPARE_BODY: usize = 64 * 1024;

pub(crate) struct ConsentApi {
    client: reqwest::Client,
    prepare_url: Url,
    csrf_cookie_name: String,
}

impl ConsentApi {
    pub(crate) fn from_env() -> Result<Self> {
        let origin = env::var("ID_WEB_API_ORIGIN").context("ID_WEB_API_ORIGIN is required")?;
        let mut prepare_url = Url::parse(&origin)?;
        if !prepare_url.username().is_empty()
            || prepare_url.password().is_some()
            || prepare_url.path() != "/"
            || prepare_url.query().is_some()
            || prepare_url.fragment().is_some()
            || !matches!(prepare_url.scheme(), "http" | "https")
            || (prepare_url.scheme() == "http"
                && !matches!(prepare_url.host_str(), Some("localhost" | "127.0.0.1")))
        {
            bail!("ID_WEB_API_ORIGIN must be HTTPS or a local HTTP origin");
        }
        prepare_url.set_path("/oauth/authorize/prepare");
        Ok(Self {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(10))
                .build()?,
            prepare_url,
            csrf_cookie_name: env::var("CSRF_COOKIE_NAME").unwrap_or_else(|_| "csrftoken".into()),
        })
    }
}

#[derive(Deserialize)]
struct PrepareResponse {
    action: String,
    request_id: Option<String>,
    client: Option<PreparedClient>,
    scopes: Option<Vec<PreparedScope>>,
    redirect_uri: Option<String>,
}

#[derive(Deserialize)]
struct PreparedClient {
    name: String,
}

#[derive(Deserialize)]
struct PreparedScope {
    name: String,
    description: String,
    required: bool,
}

#[derive(Template)]
#[template(path = "consent.html")]
struct ConsentPage<'a> {
    client_name: &'a str,
    destination: &'a str,
    request_id: &'a str,
    csrf_cookie_name: &'a str,
    scopes: &'a [PreparedScope],
}

async fn prepare(
    api: &ConsentApi,
    query: &str,
    cookie: Option<&str>,
) -> Result<(PrepareResponse, Option<String>)> {
    let mut url = api.prepare_url.clone();
    url.set_query(Some(query));
    let mut req = api
        .client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json");
    if let Some(cookie) = cookie {
        req = req.header(reqwest::header::COOKIE, cookie);
    }
    let mut response = req.send().await?;
    if !response.status().is_success() {
        bail!("OIDC prepare returned {}", response.status())
    }
    let csrf_cookie = response
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.starts_with(&format!("{}=", api.csrf_cookie_name)))
        .map(str::to_owned);
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > MAX_PREPARE_BODY {
            bail!("OIDC prepare response too large")
        }
        body.extend_from_slice(&chunk);
    }
    Ok((serde_json::from_slice(&body)?, csrf_cookie))
}

#[route(GET "/oauth/consent")]
pub(crate) async fn page(cx: &Cx) -> topcoat::Result<Response> {
    let Some(query) = request::uri(cx)
        .query()
        .filter(|query| !query.is_empty() && query.len() <= 16_384)
    else {
        return problem("Некорректный запрос приложения.");
    };
    let api = app_context::<ConsentApi>(cx);
    let cookie = request::headers(cx)
        .get("cookie")
        .and_then(|value| value.to_str().ok());
    let (result, csrf_cookie) = match prepare(api, query, cookie).await {
        Ok(value) => value,
        Err(_) => return problem("Не удалось проверить запрос приложения. Попробуйте позже."),
    };
    match result.action.as_str() {
        "login" => {
            let next = format!("/oauth/consent?{query}");
            let encoded: String = url::form_urlencoded::byte_serialize(next.as_bytes()).collect();
            return redirect(&format!("/login?next={encoded}"), csrf_cookie.as_deref());
        }
        "redirect" => {
            if let Some(url) = result.redirect_uri {
                return redirect(&url, csrf_cookie.as_deref());
            }
            return problem("Некорректный ответ сервиса авторизации.");
        }
        "consent" => {}
        _ => return problem("Некорректный ответ сервиса авторизации."),
    }
    let Some(request_id) = result.request_id else {
        return problem("Не найден запрос согласия.");
    };
    let Some(client) = result.client else {
        return problem("Не найдено приложение.");
    };
    let Some(scopes) = result.scopes else {
        return problem("Не найдены запрошенные права.");
    };
    // The API supplies the redirect only after exact client validation. Do not
    // expose callback paths or query parameters in the consent UI.
    let destination = display_destination(result.redirect_uri.as_deref());
    let html = match (ConsentPage {
        client_name: &client.name,
        destination: &destination,
        request_id: &request_id,
        csrf_cookie_name: &api.csrf_cookie_name,
        scopes: &scopes,
    })
    .render()
    {
        Ok(html) => html,
        Err(_) => return problem("Не удалось показать запрос приложения."),
    };
    let mut response = Response::builder().header("Content-Type", "text/html; charset=utf-8")
        .header("Cache-Control", "no-store").header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "no-referrer")
        .header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    if let Some(cookie) = csrf_cookie {
        response = response.header("Set-Cookie", cookie);
    }
    Ok(response.body(Body::from(html))?)
}

fn display_destination(redirect_uri: Option<&str>) -> String {
    redirect_uri
        .and_then(|value| Url::parse(value).ok())
        .filter(|url| matches!(url.scheme(), "http" | "https"))
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|| "адрес приложения".to_owned())
}

// Older clients link to the React consent document. Keep their query intact
// while sending them through the same Rust authorization checks as new clients.
#[route(GET "/authorize")]
pub(crate) async fn legacy_page(cx: &Cx) -> topcoat::Result<Response> {
    let Some(query) = request::uri(cx)
        .query()
        .filter(|query| !query.is_empty() && query.len() <= 16_384)
    else {
        return problem("Некорректный запрос приложения.");
    };
    redirect(&format!("/oauth/consent?{query}"), None)
}

fn redirect(location: &str, csrf_cookie: Option<&str>) -> topcoat::Result<Response> {
    let mut response = Response::builder()
        .status(303)
        .header("Location", location)
        .header("Cache-Control", "no-store");
    if let Some(cookie) = csrf_cookie {
        response = response.header("Set-Cookie", cookie);
    }
    Ok(response.body(Body::empty())?)
}

fn problem(message: &str) -> topcoat::Result<Response> {
    crate::ui::unavailable(message, false)
}

#[route(GET "/_id/consent.js")]
pub(crate) async fn script() -> topcoat::Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/javascript; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(include_str!("../static/consent.js")))?)
}

#[route(GET "/_id/consent.css")]
pub(crate) async fn style() -> topcoat::Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/css; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(include_str!("../static/consent.css")))?)
}

#[cfg(test)]
mod tests {
    use super::{ConsentPage, PreparedScope, display_destination};
    use askama::Template;

    #[test]
    fn consent_template_escapes_api_data_in_text_and_attributes() -> Result<(), askama::Error> {
        let scopes = [PreparedScope {
            name: "profile\" onfocus=\"alert(1)".into(),
            description: "<script>alert(1)</script>".into(),
            required: true,
        }];
        let html = ConsentPage {
            client_name: "<img src=x onerror=alert(1)>",
            destination: "<img src=x onerror=alert(1)>",
            request_id: "\" autofocus onfocus=alert(1)",
            csrf_cookie_name: "csrftoken",
            scopes: &scopes,
        }
        .render()?;

        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(!html.contains("<img src=x onerror=alert(1)>"));
        assert!(!html.contains("value=\"profile\" onfocus="));
        assert!(!html.contains("data-request-id=\"\" autofocus"));
        assert!(html.contains("name=\"required-scope\""));
        assert!(!html.contains("checked disabled"));
        Ok(())
    }

    #[test]
    fn consent_does_not_preselect_optional_access_or_remember_choice() -> Result<(), askama::Error>
    {
        let scopes = [
            PreparedScope {
                name: "openid".into(),
                description: "Вход".into(),
                required: true,
            },
            PreparedScope {
                name: "email".into(),
                description: "Адрес почты".into(),
                required: false,
            },
        ];
        let html = ConsentPage {
            client_name: "Приложение",
            destination: "https://example.com",
            request_id: "request",
            csrf_cookie_name: "csrftoken",
            scopes: &scopes,
        }
        .render()?;
        assert!(html.contains("name=\"required-scope\" value=\"openid\""));
        assert!(!html.contains("value=\"openid\" checked disabled"));
        assert!(html.contains("value=\"email\" />"));
        assert!(html.contains("https://example.com"));
        assert!(!html.contains("id=\"remember\" type=\"checkbox\" checked"));
        assert!(html.contains("Не предоставлять доступ"));
        assert!(html.contains("Разрешить выбранное"));
        Ok(())
    }

    #[test]
    fn destination_displays_only_verified_origin() {
        assert_eq!(
            display_destination(Some("https://portal.example/callback?code=secret")),
            "https://portal.example"
        );
        assert_eq!(
            display_destination(Some("javascript:alert(1)")),
            "адрес приложения"
        );
    }
}
