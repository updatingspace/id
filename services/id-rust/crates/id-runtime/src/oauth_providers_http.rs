//! Public provider inventory. This reads the same SocialApp registrations as
//! Django, while exposing only providers supported by the current ID stack.

use crate::me_http::env_flag;
use anyhow::Result;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use std::{sync::Arc, time::Duration};
use ydb::Client;

#[derive(Clone)]
pub struct ProvidersHttpConfig {
    client: Arc<Client>,
}

impl ProvidersHttpConfig {
    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        Ok(env_flag("ID_AUTH_OAUTH_PROVIDERS_ENABLED", false)?.then(|| Arc::new(Self { client })))
    }
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct Provider {
    id: &'static str,
    name: &'static str,
}

#[derive(Serialize)]
struct ProvidersOut {
    providers: Vec<Provider>,
}

pub fn router(config: Arc<ProvidersHttpConfig>) -> Router {
    Router::new()
        .route("/api/v1/auth/oauth/providers", get(list))
        .with_state(config)
}

async fn list(State(config): State<Arc<ProvidersHttpConfig>>) -> Response {
    match read_providers(&config.client).await {
        Ok(providers) => response(
            StatusCode::OK,
            serde_json::json!(ProvidersOut { providers }),
        ),
        Err(error) => {
            tracing::error!(?error, "OAuth provider inventory unavailable");
            response(
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({"code":"SERVICE_UNAVAILABLE","message":"Временно недоступно"}),
            )
        }
    }
}

async fn read_providers(client: &Client) -> Result<Vec<Provider>> {
    let mut query_client = client.query_client();
    let mut stream = query_client
        .query("SELECT provider FROM socialaccount_socialapp LIMIT 1001")
        .timeout(Duration::from_secs(5))
        .await?;
    let mut configured = Vec::new();
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            configured.push(row.remove_field_by_name("provider")?.try_into()?);
        }
    }
    stream.close().await?;
    anyhow::ensure!(configured.len() <= 1000, "too many SocialApp registrations");
    Ok(assemble(&configured))
}

fn assemble(configured: &[String]) -> Vec<Provider> {
    [
        ("discord", "Discord"),
        ("github", "GitHub"),
        ("steam", "Steam"),
    ]
    .into_iter()
    .filter(|(id, _)| configured.iter().any(|value| value == id))
    .map(|(id, name)| Provider { id, name })
    .collect()
}

fn response(status: StatusCode, body: serde_json::Value) -> Response {
    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn only_supported_configured_providers_are_public() {
        let providers = assemble(&[
            "steam".into(),
            "unknown".into(),
            "github".into(),
            "github".into(),
        ]);
        assert_eq!(
            providers,
            vec![
                Provider {
                    id: "github",
                    name: "GitHub"
                },
                Provider {
                    id: "steam",
                    name: "Steam"
                }
            ]
        );
    }

    #[tokio::test]
    #[ignore = "requires local YDB with the legacy SocialApp schema"]
    async fn empty_socialapp_table_returns_empty_inventory() -> Result<()> {
        anyhow::ensure!(
            std::env::var("YDB_DATABASE")? == "/local",
            "production YDB is not permitted for this test"
        );
        let client = crate::connect_ydb().await?;
        let providers = read_providers(&client).await?;
        assert!(providers.is_empty());
        Ok(())
    }
}
