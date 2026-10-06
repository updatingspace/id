#![recursion_limit = "256"]
//! Real Axum/YDB issuance with only a uniquely named local scratch cache table.

use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
};
use cookie::SameSite;
use id_compat::cache::CacheValue;
use id_runtime::{
    cache_store::CacheStore,
    form_token_consume::consume_login_form_token,
    form_token_http::{self, FormTokenConfig},
};
use serde_json::Value;
use std::{
    process::{Command, Stdio},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;

async fn get(
    app: &Router,
    uri: &str,
    cookie: Option<&str>,
) -> Result<(StatusCode, HeaderMap, Value)> {
    let mut builder = Request::builder()
        .uri(uri)
        .method("GET")
        .header("user-agent", "rust-form-token-test")
        .header("x-forwarded-for", "192.0.2.5, 198.51.100.3");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    let response = app.clone().oneshot(builder.body(Body::empty())?).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await?)?;
    Ok((status, headers, body))
}

#[tokio::test]
#[ignore = "requires local YDB; creates and drops one synthetic cache table"]
async fn form_token_route_issues_python_compatible_one_time_value() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "form token test requires local YDB on port 2136"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let table = format!("id_formtoken_pilot_{}_{}", std::process::id(), stamp);
    client.query_client().exec(format!(
        "CREATE TABLE `{table}` (cache_key Utf8 NOT NULL, value String, expires_at Uint64, PRIMARY KEY(cache_key))"
    )).await?;
    let result: Result<()> = async {
        let cache = CacheStore::new(client.clone(), &table, "", 1)?;
        let app = form_token_http::router(Arc::new(FormTokenConfig::new(
            cache.clone(),
            "csrftoken".into(),
            false,
            SameSite::Lax,
            None,
        )?));
        let (status, headers, body) = get(&app, "/api/v1/auth/form_token", None).await?;
        ensure!(
            status == StatusCode::UNPROCESSABLE_ENTITY
                && body["detail"][0]["loc"] == serde_json::json!(["query", "purpose"])
        );
        ensure!(headers[header::CACHE_CONTROL] == "private, no-store");
        let (status, _, body) = get(&app, "/api/v1/auth/form_token?purpose=wrong", None).await?;
        ensure!(status == StatusCode::BAD_REQUEST && body["code"] == "VALIDATION_ERROR");

        let (status, headers, body) =
            get(&app, "/api/v1/auth/form_token?purpose=login", None).await?;
        ensure!(status == StatusCode::OK && body["expires_in"] == 900);
        let token = body["form_token"].as_str().context("missing form token")?;
        ensure!(
            token.len() == 43
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
        let csrf = headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with("csrftoken="))
            .context("missing CSRF cookie")?;
        ensure!(!csrf.contains("HttpOnly") && csrf.contains("SameSite=Lax"));
        let csrf_value = csrf.split(';').next().context("invalid CSRF cookie")?;
        let (again_status, again_headers, again_body) = get(
            &app,
            "/api/v1/auth/form_token?purpose=register",
            Some(csrf_value),
        )
        .await?;
        ensure!(again_status == StatusCode::OK && again_body["form_token"] != token);
        ensure!(
            again_headers
                .get_all(header::SET_COOKIE)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .any(|value| value.starts_with(csrf_value)),
            "valid CSRF secret changed"
        );

        let key = format!("formtoken:{token}");
        let value = cache
            .get(&key, SystemTime::now())
            .await?
            .context("issued token not stored")?;
        let CacheValue::Map(fields) = value else {
            anyhow::bail!("form token payload is not a map")
        };
        ensure!(fields.get("purpose") == Some(&CacheValue::String("login".into())));
        ensure!(fields.get("client_ip") == Some(&CacheValue::String("192.0.2.5".into())));
        ensure!(
            fields.get("user_agent") == Some(&CacheValue::String("rust-form-token-test".into()))
        );
        ensure!(fields.get("used") == Some(&CacheValue::Bool(false)));
        ensure!(fields.contains_key("expires_at") && fields.contains_key("issued_at"));
        ensure!(consume_login_form_token(&cache, Some(token), SystemTime::now()).await?);
        ensure!(
            !consume_login_form_token(&cache, Some(token), SystemTime::now()).await?,
            "Rust accepted a consumed form token"
        );
        let register_token = again_body["form_token"]
            .as_str()
            .context("missing register token")?;
        ensure!(
            !consume_login_form_token(&cache, Some(register_token), SystemTime::now()).await?,
            "Rust accepted a register token for login"
        );
        ensure!(
            cache
                .get(&format!("formtoken:{register_token}"), SystemTime::now())
                .await?
                .is_none(),
            "wrong-purpose token remained reusable"
        );

        if std::env::var("ID_PYTHON_FORM_TOKEN_CHECK").as_deref() == Ok("true") {
            let python_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../id")
                .canonicalize()?;
            let child = Command::new(python_dir.join(".venv/bin/python"))
                .arg("scripts/issue_python_form_token.py")
                .arg(&table)
                .current_dir(&python_dir)
                .env("PYTHONPATH", "src")
                .env("DJANGO_SETTINGS_MODULE", "app.settings")
                .env("DJANGO_DEBUG", "true")
                .env(
                    "DJANGO_SECRET_KEY",
                    "synthetic-local-secret-min-32-characters",
                )
                .env("DB_DRIVER", "ydb")
                .env("YDB_NAME", "default")
                .env("YDB_CREDENTIALS_MODE", "token")
                .env("YDB_TOKEN", "local-ydb-token")
                .env("REDIS_URL", "")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            let output = child.wait_with_output()?;
            ensure!(
                output.status.success(),
                "Python did not issue a local form token: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let issued_by_python = String::from_utf8(output.stdout)?;
            let issued_by_python = issued_by_python.trim();
            ensure!(
                consume_login_form_token(&cache, Some(issued_by_python), SystemTime::now()).await?,
                "Rust could not consume Python-issued form token"
            );
            ensure!(
                !consume_login_form_token(&cache, Some(issued_by_python), SystemTime::now())
                    .await?,
                "Rust accepted Python-issued token twice"
            );
        }
        Ok(())
    }
    .await;
    client
        .query_client()
        .exec(format!("DROP TABLE `{table}`"))
        .await?;
    result
}
