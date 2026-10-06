//! Public auth smoke; deliberately uses nonexistent identities and invalid links.

use anyhow::{Context, Result, ensure};
use reqwest::{
    Client, StatusCode, Url,
    header::{CACHE_CONTROL, CONTENT_TYPE, COOKIE, HOST, HeaderValue, SET_COOKIE, USER_AGENT},
};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::sync::Mutex;
use uuid::Uuid;

const MAX_RESPONSE: usize = 16 * 1024;

struct Probe {
    client: Client,
    base: Url,
    host: Option<HeaderValue>,
    csrf: Mutex<Option<String>>,
}

impl Probe {
    fn new(base_url: &str, host: Option<&str>) -> Result<Self> {
        let base = Url::parse(base_url).context("invalid SMOKE_BASE_URL")?;
        ensure!(
            matches!(base.scheme(), "http" | "https")
                && base.host_str().is_some()
                && base.username().is_empty()
                && base.password().is_none()
                && matches!(base.path(), "" | "/")
                && base.query().is_none()
                && base.fragment().is_none(),
            "SMOKE_BASE_URL must be a plain HTTP(S) origin"
        );
        let host = host
            .filter(|value| !value.is_empty())
            .map(HeaderValue::from_str)
            .transpose()?;
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            client,
            base,
            host,
            csrf: Mutex::new(None),
        })
    }

    async fn request(&self, path: &str, body: Option<Value>) -> Result<(StatusCode, Value)> {
        let url = self.base.join(path.trim_start_matches('/'))?;
        let mut request = match body.as_ref() {
            Some(_) => self.client.post(url),
            None => self.client.get(url),
        }
        .header(USER_AGENT, "UpdSpace-ID-deploy-smoke")
        .header(CACHE_CONTROL, "no-cache");
        if let Some(host) = self.host.as_ref() {
            request = request.header(HOST, host.clone());
        }
        if let Some(csrf) = self.csrf.lock().await.as_ref() {
            request = request
                .header(COOKIE, format!("csrftoken={csrf}"))
                .header("x-csrftoken", csrf);
        }
        if let Some(value) = body {
            request = request
                .header(CONTENT_TYPE, "application/json")
                .body(serde_json::to_vec(&value)?);
        }
        let response = request.send().await?;
        let status = response.status();
        for value in response.headers().get_all(SET_COOKIE) {
            if let Ok(raw) = value.to_str()
                && let Some(csrf) = parse_csrf_cookie(raw)
            {
                *self.csrf.lock().await = Some(csrf.to_owned());
            }
        }
        let body = response.bytes().await?;
        ensure!(
            body.len() <= MAX_RESPONSE,
            "smoke response too large for {path}"
        );
        let parsed = serde_json::from_slice(&body)
            .with_context(|| format!("smoke response is not JSON for {path}"))?;
        Ok((status, parsed))
    }

    async fn form_token(&self, purpose: &str) -> Result<String> {
        let path = format!("/api/v1/auth/form_token?purpose={purpose}");
        let (status, body) = self.request(&path, None).await?;
        ensure!(
            status == StatusCode::OK,
            "cannot issue {purpose} form token"
        );
        body.get("form_token")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .context("form-token response omitted form_token")
    }
}

fn parse_csrf_cookie(raw: &str) -> Option<&str> {
    let first = raw.split(';').next()?.trim();
    let value = first.strip_prefix("csrftoken=")?;
    (!value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric()))
    .then_some(value)
}

pub(super) async fn run(base_url: &str, host: Option<&str>) -> Result<()> {
    let probe = Probe::new(base_url, host)?;
    let run_id = Uuid::new_v4().simple().to_string();
    let email = format!("deploy-smoke-{run_id}@example.invalid");

    let token = probe.form_token("login").await?;
    let login = json!({"email":email,"password":"nonexistent-account-test","form_token":token});
    let (status, body) = probe
        .request("/api/v1/auth/login", Some(login.clone()))
        .await?;
    ensure!(
        status == StatusCode::UNAUTHORIZED && body["code"] == "INVALID_CREDENTIALS",
        "login did not reach credential validation: {status} {}",
        body["code"]
    );
    let (status, body) = probe.request("/api/v1/auth/login", Some(login)).await?;
    ensure!(
        status == StatusCode::BAD_REQUEST && body["code"] == "INVALID_FORM_TOKEN",
        "login accepted replayed form token"
    );

    let token = probe.form_token("register").await?;
    let (status, body) = probe
        .request(
            "/api/v1/auth/signup",
            Some(json!({
                "email":email,"username":format!("smoke-{run_id}"),"password":"x",
                "consent_data_processing":true,"form_token":token
            })),
        )
        .await?;
    ensure!(
        status == StatusCode::BAD_REQUEST && body["code"] != "INVALID_FORM_TOKEN",
        "signup form validation did not reject the short password: {status} {}",
        body["code"]
    );

    for (purpose, path) in [
        ("password_reset", "password/reset/request"),
        ("email_verification", "email/verification/request"),
    ] {
        let token = probe.form_token(purpose).await?;
        let path = format!("/api/v1/auth/{path}");
        let payload = json!({"email":email,"form_token":token});
        let (status, body) = probe.request(&path, Some(payload.clone())).await?;
        ensure!(
            status == StatusCode::OK && body["ok"] == true,
            "{purpose} request failed: {status} {}",
            body["code"]
        );
        let (status, body) = probe.request(&path, Some(payload)).await?;
        ensure!(
            status == StatusCode::BAD_REQUEST && body["code"] == "INVALID_FORM_TOKEN",
            "{purpose} accepted replayed form token"
        );
    }
    for (path, payload) in [
        (
            "password/reset/confirm",
            json!({"key":"invalid","password":"Unused-Password-123!"}),
        ),
        ("email/verification/confirm", json!({"key":"invalid"})),
    ] {
        let (status, body) = probe
            .request(&format!("/api/v1/auth/{path}"), Some(payload))
            .await?;
        ensure!(
            status == StatusCode::BAD_REQUEST && body["code"] == "INVALID_RECOVERY_LINK",
            "{path} accepted invalid link: {status} {}",
            body["code"]
        );
    }
    println!(
        "Auth smoke passed: login, signup, recovery requests, form-token replay and invalid links"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_cannot_add_path_or_credentials() -> Result<()> {
        ensure!(Probe::new("https://id.example.invalid/", None).is_ok());
        ensure!(Probe::new("https://id.example.invalid/proxy", None).is_err());
        ensure!(Probe::new("https://user@id.example.invalid/", None).is_err());
        ensure!(Probe::new("file:///tmp/id", None).is_err());
        ensure!(parse_csrf_cookie("csrftoken=abc123; Path=/") == Some("abc123"));
        ensure!(parse_csrf_cookie("sessionid=secret; Path=/").is_none());
        Ok(())
    }
}
