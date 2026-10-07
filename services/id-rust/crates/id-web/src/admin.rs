//! Server-rendered operator lookup. The Rust API owns authorization and YDB.

use anyhow::{Result, bail};
use askama::Template;
use serde::Deserialize;
use std::{env, time::Duration};
use topcoat::{
    context::{Cx, app_context},
    router::{Body, request, response::Response, route},
};
use url::Url;

pub(crate) struct AdminApi {
    client: reqwest::Client,
    operator_url: Url,
    deletion_url: Url,
    account_url: Url,
    account_search_url: Url,
}

impl AdminApi {
    pub(crate) fn from_env() -> Result<Self> {
        let origin = env::var("ID_WEB_API_ORIGIN")?;
        let mut operator_url = Url::parse(&origin)?;
        if !operator_url.username().is_empty()
            || operator_url.password().is_some()
            || operator_url.path() != "/"
            || operator_url.query().is_some()
            || operator_url.fragment().is_some()
            || !matches!(operator_url.scheme(), "http" | "https")
            || (operator_url.scheme() == "http"
                && !matches!(operator_url.host_str(), Some("localhost" | "127.0.0.1")))
        {
            bail!("ID_WEB_API_ORIGIN must be HTTPS or a local HTTP origin");
        }
        let mut deletion_url = operator_url.clone();
        let mut account_url = operator_url.clone();
        let mut account_search_url = operator_url.clone();
        operator_url.set_path("/api/v1/auth/admin/me");
        deletion_url.set_path("/api/v1/auth/admin/deletions/");
        account_url.set_path("/api/v1/auth/admin/accounts/");
        account_search_url.set_path("/api/v1/auth/admin/accounts/search");
        Ok(Self {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(10))
                .build()?,
            operator_url,
            deletion_url,
            account_url,
            account_search_url,
        })
    }
}

#[derive(Deserialize)]
struct DeletionResponse {
    operation: DeletionOperation,
}

#[derive(Deserialize)]
struct AccountResponse {
    account: OperatorAccount,
}

#[derive(Deserialize)]
struct OperatorAccount {
    id: i32,
    email: String,
    is_active: bool,
    is_staff: bool,
    is_superuser: bool,
    has_mfa: bool,
    identity_id: Option<String>,
    public_subject: Option<String>,
}

#[derive(Deserialize)]
struct DeletionOperation {
    id: String,
    status: String,
    cleanup_completed: bool,
}

impl DeletionOperation {
    fn status_label(&self) -> &'static str {
        match self.status.as_str() {
            "pending" => "Ожидает обработки",
            "running" => "Очистка выполняется",
            "succeeded" if self.cleanup_completed => "Очистка завершена",
            "failed" => "Нужна проверка оператора",
            _ => "Состояние требует проверки",
        }
    }

    fn next_step(&self) -> &'static str {
        match self.status.as_str() {
            "pending" => {
                "Заявка принята. Проверьте её позднее; пока не подтверждайте завершение очистки."
            }
            "running" => {
                "Очистка ещё идёт. Повторите проверку позднее, прежде чем отвечать пользователю."
            }
            "succeeded" if self.cleanup_completed => {
                "Обязательные этапы очистки подтверждены. Сверьте отдельные сроки хранения резервных копий по операторскому регламенту."
            }
            _ => {
                "Не сообщайте пользователю о завершении. Проверьте причину и дальнейшие действия в операторском журнале и idctl."
            }
        }
    }
}

#[derive(Template)]
#[template(path = "admin-deletions.html")]
struct AdminPage<'a> {
    lookup_id: &'a str,
    operation: Option<&'a DeletionOperation>,
    not_found: bool,
}

#[derive(Template)]
#[template(path = "admin-account.html")]
struct AccountPage<'a> {
    lookup_id: &'a str,
    lookup_email: &'a str,
    account: Option<&'a OperatorAccount>,
    not_found: bool,
    ambiguous: bool,
}

#[derive(Template)]
#[template(path = "admin-error.html")]
struct AdminErrorPage<'a> {
    title: &'static str,
    message: &'a str,
    retry: bool,
}

#[route(GET "/admin")]
pub(crate) async fn page(cx: &Cx) -> topcoat::Result<Response> {
    render_page(cx).await
}

#[route(GET "/admin/")]
pub(crate) async fn page_slash(cx: &Cx) -> topcoat::Result<Response> {
    render_page(cx).await
}

#[route(GET "/admin/accounts")]
pub(crate) async fn account_page(cx: &Cx) -> topcoat::Result<Response> {
    render_account_page(cx).await
}

#[route(GET "/admin/accounts/")]
pub(crate) async fn account_page_slash(cx: &Cx) -> topcoat::Result<Response> {
    render_account_page(cx).await
}

async fn render_account_page(cx: &Cx) -> topcoat::Result<Response> {
    let api = app_context::<AdminApi>(cx);
    let cookie = request::headers(cx)
        .get("cookie")
        .and_then(|value| value.to_str().ok());
    let operator = api
        .client
        .get(api.operator_url.clone())
        .header(reqwest::header::ACCEPT, "application/json");
    let operator = if let Some(cookie) = cookie {
        operator.header(reqwest::header::COOKIE, cookie)
    } else {
        operator
    };
    let operator = match operator.send().await {
        Ok(response) => response,
        Err(_) => return problem(503, "Не удалось проверить права. Попробуйте позже."),
    };
    match operator.status().as_u16() {
        200 => {}
        401 => return redirect_to_login("/login?next=%2Fadmin%2Faccounts%2F"),
        403 => return problem(403, "У вас нет доступа к операторскому разделу."),
        _ => return problem(503, "Не удалось проверить права. Попробуйте позже."),
    }
    let query = request::uri(cx).query();
    if query.is_some_and(|value| value.len() > 128) {
        return problem(400, "Слишком длинный поисковый запрос.");
    }
    let fields = query.map_or_else(Vec::new, |query| {
        url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect::<Vec<_>>()
    });
    if fields.is_empty() {
        return render_account("", "", None, false, false);
    }
    if fields.len() != 1 {
        return problem(400, "Укажите только один способ поиска.");
    }
    let (key, value) = &fields[0];
    let (lookup_id, lookup_email, url, expected_id) = if key == "id" {
        if value.is_empty() || value.len() > 10 || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return problem(400, "Укажите корректный ID аккаунта.");
        }
        let Ok(parsed) = value.parse::<i32>() else {
            return problem(400, "Укажите корректный ID аккаунта.");
        };
        if parsed <= 0 {
            return problem(400, "Укажите корректный ID аккаунта.");
        }
        let mut url = api.account_url.clone();
        url.set_path(&format!("/api/v1/auth/admin/accounts/{parsed}"));
        (value.as_str(), String::new(), url, Some(parsed))
    } else if key == "email" {
        let email = value.trim().to_lowercase();
        if email.is_empty()
            || email.len() > 320
            || email.bytes().filter(|byte| *byte == b'@').count() != 1
            || email.chars().any(char::is_control)
        {
            return problem(400, "Укажите корректный адрес электронной почты.");
        }
        let mut url = api.account_search_url.clone();
        url.query_pairs_mut().append_pair("email", &email);
        ("", email, url, None)
    } else {
        return problem(400, "Укажите ID или электронную почту.");
    };
    let lookup = api
        .client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json");
    let lookup = if let Some(cookie) = cookie {
        lookup.header(reqwest::header::COOKIE, cookie)
    } else {
        lookup
    };
    let mut lookup = match lookup.send().await {
        Ok(response) => response,
        Err(_) => return problem(503, "Не удалось загрузить аккаунт. Попробуйте позже."),
    };
    match lookup.status().as_u16() {
        200 => {}
        401 => return redirect_to_login("/login?next=%2Fadmin%2Faccounts%2F"),
        403 => return problem(403, "У вас нет доступа к операторскому разделу."),
        404 => return render_account(lookup_id, &lookup_email, None, true, false),
        409 => return render_account(lookup_id, &lookup_email, None, false, true),
        _ => return problem(503, "Не удалось загрузить аккаунт. Попробуйте позже."),
    }
    let mut body = Vec::new();
    loop {
        let chunk = match lookup.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(_) => return problem(503, "Не удалось загрузить аккаунт. Попробуйте позже."),
        };
        if body.len().saturating_add(chunk.len()) > 16 * 1024 {
            return problem(503, "Некорректный ответ сервиса аккаунтов.");
        }
        body.extend_from_slice(&chunk);
    }
    let result: AccountResponse = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return problem(503, "Некорректный ответ сервиса аккаунтов."),
    };
    if expected_id.is_some_and(|id| result.account.id != id)
        || (!lookup_email.is_empty() && result.account.email.trim().to_lowercase() != lookup_email)
    {
        return problem(503, "Некорректный ответ сервиса аккаунтов.");
    }
    render_account(
        lookup_id,
        &lookup_email,
        Some(&result.account),
        false,
        false,
    )
}

fn render_account(
    lookup_id: &str,
    lookup_email: &str,
    account: Option<&OperatorAccount>,
    not_found: bool,
    ambiguous: bool,
) -> topcoat::Result<Response> {
    let html = AccountPage {
        lookup_id,
        lookup_email,
        account,
        not_found,
        ambiguous,
    }
    .render()
    .map_err(|error| topcoat::Error::msg(error.to_string()))?;
    Ok(Response::builder()
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "no-referrer")
        .header("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        .body(Body::from(html))?)
}

async fn render_page(cx: &Cx) -> topcoat::Result<Response> {
    let api = app_context::<AdminApi>(cx);
    let cookie = request::headers(cx)
        .get("cookie")
        .and_then(|value| value.to_str().ok());
    let operator = api
        .client
        .get(api.operator_url.clone())
        .header(reqwest::header::ACCEPT, "application/json");
    let operator = if let Some(cookie) = cookie {
        operator.header(reqwest::header::COOKIE, cookie)
    } else {
        operator
    };
    let operator = match operator.send().await {
        Ok(response) => response,
        Err(_) => return problem(503, "Не удалось проверить права. Попробуйте позже."),
    };
    match operator.status().as_u16() {
        200 => {}
        401 => return redirect_to_login("/login?next=%2Fadmin%2F"),
        403 => return problem(403, "У вас нет доступа к операторскому разделу."),
        _ => return problem(503, "Не удалось проверить права. Попробуйте позже."),
    }

    let query = request::uri(cx).query();
    if query.is_some_and(|value| value.len() > 128) {
        return problem(400, "Слишком длинный поисковый запрос.");
    }
    let requested = query.and_then(|query| {
        url::form_urlencoded::parse(query.as_bytes())
            .find(|(key, _)| key == "deletion")
            .map(|(_, value)| value.into_owned())
    });
    let Some(id) = requested else {
        return render("", None, false);
    };
    if id.is_empty() || id.len() > 18 || !id.bytes().all(|byte| byte.is_ascii_digit()) {
        return problem(400, "Укажите корректный номер заявки.");
    }
    let Ok(parsed) = id.parse::<i64>() else {
        return problem(400, "Укажите корректный номер заявки.");
    };
    if parsed <= 0 {
        return problem(400, "Укажите корректный номер заявки.");
    }
    let mut url = api.deletion_url.clone();
    url.set_path(&format!("/api/v1/auth/admin/deletions/{parsed}"));
    let lookup = api
        .client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json");
    let lookup = if let Some(cookie) = cookie {
        lookup.header(reqwest::header::COOKIE, cookie)
    } else {
        lookup
    };
    let mut lookup = match lookup.send().await {
        Ok(response) => response,
        Err(_) => return problem(503, "Не удалось загрузить заявку. Попробуйте позже."),
    };
    match lookup.status().as_u16() {
        200 => {}
        401 => return redirect_to_login("/login?next=%2Fadmin%2F"),
        403 => return problem(403, "У вас нет доступа к операторскому разделу."),
        404 => return render(&id, None, true),
        _ => return problem(503, "Не удалось загрузить заявку. Попробуйте позже."),
    }
    let mut body = Vec::new();
    loop {
        let chunk = match lookup.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(_) => return problem(503, "Не удалось загрузить заявку. Попробуйте позже."),
        };
        if body.len().saturating_add(chunk.len()) > 16 * 1024 {
            return problem(503, "Некорректный ответ сервиса заявок.");
        }
        body.extend_from_slice(&chunk);
    }
    let result: DeletionResponse = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return problem(503, "Некорректный ответ сервиса заявок."),
    };
    if result.operation.id != parsed.to_string() {
        return problem(503, "Некорректный ответ сервиса заявок.");
    }
    render(&id, Some(&result.operation), false)
}

fn render(
    lookup_id: &str,
    operation: Option<&DeletionOperation>,
    not_found: bool,
) -> topcoat::Result<Response> {
    let html = AdminPage {
        lookup_id,
        operation,
        not_found,
    }
    .render()
    .map_err(|error| topcoat::Error::msg(error.to_string()))?;
    Ok(Response::builder()
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "no-referrer")
        .header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        )
        .body(Body::from(html))?)
}

fn redirect_to_login(location: &'static str) -> topcoat::Result<Response> {
    Ok(Response::builder()
        .status(303)
        .header("Location", location)
        .header("Cache-Control", "no-store")
        .body(Body::empty())?)
}

fn problem(status: u16, message: &str) -> topcoat::Result<Response> {
    let title = match status {
        400 => "Проверьте номер заявки",
        403 => "Операторский доступ недоступен",
        _ => "Сервис временно недоступен",
    };
    let html = AdminErrorPage {
        title,
        message,
        retry: status == 503,
    }
    .render()
    .map_err(|error| topcoat::Error::msg(error.to_string()))?;
    Ok(Response::builder()
        .status(status)
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "no-referrer")
        .header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'",
        )
        .body(Body::from(html))?)
}

#[route(GET "/_id/admin.css")]
pub(crate) async fn style() -> topcoat::Result<Response> {
    Ok(Response::builder()
        .header("Content-Type", "text/css; charset=utf-8")
        .header("Cache-Control", "public, max-age=3600")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(include_str!("../static/admin.css")))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_page_escapes_identity_fields_and_explains_read_only_scope() -> Result<()> {
        let account = OperatorAccount {
            id: 42,
            email: "<script>bad()</script>@example.invalid".into(),
            is_active: false,
            is_staff: false,
            is_superuser: false,
            has_mfa: true,
            identity_id: None,
            public_subject: Some("<script>subject</script>".into()),
        };
        let html = AccountPage {
            lookup_id: "42",
            lookup_email: "",
            account: Some(&account),
            not_found: false,
            ambiguous: false,
        }
        .render()?;
        assert!(!html.contains("<script>"));
        assert!(html.contains("Заблокирован"));
        assert!(html.contains("Связь не найдена"));
        assert!(html.contains("не блокирует вход"));
        Ok(())
    }

    #[test]
    fn ambiguous_email_never_selects_an_account_and_escapes_query() -> Result<()> {
        let html = AccountPage {
            lookup_id: "",
            lookup_email: "<script>@example.invalid",
            account: None,
            not_found: false,
            ambiguous: true,
        }
        .render()?;
        assert!(!html.contains("<script>"));
        assert!(html.contains("Поиск требует проверки"));
        assert!(html.contains("не выбирает владельца автоматически"));
        Ok(())
    }

    #[test]
    fn page_escapes_operation_fields_and_explains_incomplete_cleanup() -> Result<()> {
        let operation = DeletionOperation {
            id: "123".into(),
            status: "<script>bad()</script>".into(),
            cleanup_completed: false,
        };
        let html = AdminPage {
            lookup_id: "123",
            operation: Some(&operation),
            not_found: false,
        }
        .render()?;
        assert!(!html.contains("<script>bad()</script>"));
        assert!(html.contains("Очистка ещё не подтверждена"));
        assert!(html.contains("Состояние требует проверки"));
        Ok(())
    }

    #[test]
    fn operator_statuses_explain_the_next_step() {
        let mut operation = DeletionOperation {
            id: "123".into(),
            status: "pending".into(),
            cleanup_completed: false,
        };
        assert_eq!(operation.status_label(), "Ожидает обработки");
        operation.status = "running".into();
        assert!(operation.next_step().contains("ещё идёт"));
        operation.status = "succeeded".into();
        operation.cleanup_completed = true;
        assert_eq!(operation.status_label(), "Очистка завершена");
        operation.status = "failed".into();
        assert_eq!(operation.status_label(), "Нужна проверка оператора");
    }

    #[test]
    fn error_page_escapes_message_and_offers_retry_only_when_unavailable() -> Result<()> {
        let html = AdminErrorPage {
            title: "Сервис временно недоступен",
            message: "<script>bad()</script>",
            retry: true,
        }
        .render()?;
        assert!(!html.contains("<script>bad()</script>"));
        assert!(html.contains("Повторить проверку"));
        Ok(())
    }
}
