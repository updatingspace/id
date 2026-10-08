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
    github_login_enabled: bool,
    discord_login_enabled: bool,
}

impl ProvidersHttpConfig {
    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        if !env_flag("ID_AUTH_OAUTH_PROVIDERS_ENABLED", false)? {
            return Ok(None);
        }
        let github_login_enabled =
            crate::provider_login::ProviderLoginConfig::github_from_env(client.clone())
                .is_ok_and(|config| config.is_some());
        let discord_login_enabled =
            crate::provider_login::ProviderLoginConfig::discord_from_env(client.clone())
                .is_ok_and(|config| config.is_some());
        Ok(Some(Arc::new(Self {
            client,
            github_login_enabled,
            discord_login_enabled,
        })))
    }
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct Provider {
    id: &'static str,
    name: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    login_enabled: Option<bool>,
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
    match read_providers(
        &config.client,
        config.github_login_enabled,
        config.discord_login_enabled,
    )
    .await
    {
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

async fn read_providers(
    client: &Client,
    github_login_enabled: bool,
    discord_login_enabled: bool,
) -> Result<Vec<Provider>> {
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
    Ok(assemble(
        &configured,
        github_login_enabled,
        discord_login_enabled,
    ))
}

fn assemble(
    configured: &[String],
    github_login_enabled: bool,
    discord_login_enabled: bool,
) -> Vec<Provider> {
    [
        ("discord", "Discord", discord_login_enabled),
        ("github", "GitHub", github_login_enabled),
        ("steam", "Steam", false),
    ]
    .into_iter()
    .filter(|(id, _, enabled)| configured.iter().any(|value| value == id) || *enabled)
    .map(|(id, name, enabled)| Provider {
        id,
        name,
        login_enabled: enabled.then_some(true),
    })
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
        let providers = assemble(
            &[
                "steam".into(),
                "unknown".into(),
                "github".into(),
                "github".into(),
            ],
            false,
            false,
        );
        assert_eq!(
            providers,
            vec![
                Provider {
                    id: "github",
                    name: "GitHub",
                    login_enabled: None
                },
                Provider {
                    id: "steam",
                    name: "Steam",
                    login_enabled: None
                }
            ]
        );
    }

    #[test]
    fn inventory_advertises_only_explicitly_enabled_github_login() -> Result<()> {
        let configured = vec!["github".into(), "discord".into(), "steam".into()];
        let disabled = serde_json::to_value(assemble(&configured, false, false))?;
        assert!(disabled.as_array().is_some_and(|providers| {
            providers
                .iter()
                .all(|provider| provider.get("login_enabled").is_none())
        }));
        let enabled = serde_json::to_value(assemble(&configured, true, false))?;
        assert_eq!(
            enabled[1],
            serde_json::json!({"id":"github","name":"GitHub","login_enabled":true})
        );
        assert!(enabled[0].get("login_enabled").is_none());
        assert!(enabled[2].get("login_enabled").is_none());
        assert_eq!(
            serde_json::to_value(assemble(&[], true, false))?,
            serde_json::json!([
                {"id":"github","name":"GitHub","login_enabled":true}
            ])
        );
        assert!(assemble(&[], false, false).is_empty());
        Ok(())
    }

    #[test]
    fn discord_capability_is_independent_of_github_and_socialapp_inventory() -> Result<()> {
        let configured = vec!["github".into(), "discord".into(), "steam".into()];
        let discord = serde_json::to_value(assemble(&configured, false, true))?;
        assert_eq!(
            discord[0],
            serde_json::json!({
                "id":"discord", "name":"Discord", "login_enabled":true
            })
        );
        assert!(discord[1].get("login_enabled").is_none());
        assert!(discord[2].get("login_enabled").is_none());
        assert_eq!(
            serde_json::to_value(assemble(&[], false, true))?,
            serde_json::json!([{"id":"discord","name":"Discord","login_enabled":true}])
        );
        let both = serde_json::to_value(assemble(&[], true, true))?;
        assert_eq!(both.as_array().map(Vec::len), Some(2));
        assert!(
            both.as_array()
                .unwrap()
                .iter()
                .all(|entry| entry["login_enabled"] == true)
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires local YDB with the legacy SocialApp schema"]
    async fn empty_socialapp_table_returns_empty_inventory() -> Result<()> {
        anyhow::ensure!(
            std::env::var("YDB_DATABASE")? == "/local",
            "production YDB is not permitted for this test"
        );
        let client = crate::connect_ydb().await?;
        let providers = read_providers(&client, false, false).await?;
        assert!(providers.is_empty());
        Ok(())
    }
}
