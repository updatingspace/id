//! Production-capable public JWKS slice, independent of the local token pilot.

use crate::{me_http::env_flag, oidc_discovery::OidcDiscovery, oidc_keys::OidcKeyRing};
use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use serde_json::{Value, json};
use std::{env, sync::Arc};

pub struct JwksHttpConfig {
    keys: Arc<OidcKeyRing>,
    discovery: Value,
}

impl JwksHttpConfig {
    pub fn from_env() -> Result<Option<Arc<Self>>> {
        if !env_flag("ID_OIDC_JWKS_ENABLED", false)? {
            return Ok(None);
        }
        if env_flag("ID_OIDC_TOKEN_PILOT_ENABLED", false)?
            || env_flag("ID_OIDC_TOKEN_ROLLOUT_ENABLED", false)?
        {
            bail!("standalone JWKS and OIDC token pilot must not register the same routes");
        }
        Ok(Some(Arc::new(Self {
            keys: Arc::new(OidcKeyRing::from_env()?),
            discovery: OidcDiscovery::from_env(
                &env::var("OIDC_ISSUER").context("OIDC_ISSUER is required for public JWKS")?,
            )?
            .document(),
        })))
    }
}

pub fn router(config: Arc<JwksHttpConfig>) -> Router {
    Router::new()
        .route("/oauth/jwks", get(jwks))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/.well-known/openid-configuration", get(discovery))
        .with_state(config)
}

async fn discovery(State(config): State<Arc<JwksHttpConfig>>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(config.discovery.clone()),
    )
}

async fn jwks(State(config): State<Arc<JwksHttpConfig>>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"keys": config.keys.jwks()})),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, ensure};
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use serde_json::Value;
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn both_public_paths_publish_only_matching_public_keys() -> Result<()> {
        let private = Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
            ])
            .output()?;
        ensure!(private.status.success(), "ephemeral RSA generation failed");
        let mut child = Command::new("openssl")
            .args(["pkey", "-pubout"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        child
            .stdin
            .take()
            .context("openssl stdin")?
            .write_all(&private.stdout)?;
        let public = child.wait_with_output()?;
        ensure!(
            public.status.success(),
            "ephemeral public key export failed"
        );
        let keys = OidcKeyRing::from_json(
            &json!({
                "private_key_pem": String::from_utf8(private.stdout)?,
                "public_key_pem": String::from_utf8(public.stdout)?,
                "kid": "synthetic-jwks-test"
            })
            .to_string(),
        )?;
        let config = Arc::new(JwksHttpConfig {
            keys: Arc::new(keys),
            discovery: OidcDiscovery::new(
                "https://id.example.invalid",
                "https://id.example.invalid",
            )?
            .document(),
        });
        for path in ["/oauth/jwks", "/.well-known/jwks.json"] {
            let response = router(config.clone())
                .oneshot(Request::builder().uri(path).body(Body::empty())?)
                .await?;
            ensure!(response.status() == StatusCode::OK, "JWKS route failed");
            ensure!(
                response
                    .headers()
                    .get(header::CACHE_CONTROL)
                    .is_some_and(|v| v == "no-store"),
                "JWKS cache policy changed"
            );
            let body: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 1_048_576).await?)?;
            ensure!(
                body["keys"].as_array().is_some_and(|v| v.len() == 1),
                "unexpected JWKS shape"
            );
            ensure!(
                body["keys"][0]["kid"] == "synthetic-jwks-test",
                "wrong JWKS key"
            );
            ensure!(
                body["keys"][0]["n"].as_str().is_some_and(|v| !v.is_empty()),
                "missing RSA modulus"
            );
            ensure!(
                body["keys"][0]["e"].as_str().is_some_and(|v| !v.is_empty()),
                "missing RSA exponent"
            );
            ensure!(
                !body.to_string().contains("PRIVATE KEY"),
                "private material leaked"
            );
        }
        let response = router(config)
            .oneshot(
                Request::builder()
                    .uri("/.well-known/openid-configuration")
                    .body(Body::empty())?,
            )
            .await?;
        ensure!(
            response.status() == StatusCode::OK,
            "OIDC discovery route failed"
        );
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1_048_576).await?)?;
        ensure!(
            body["issuer"] == "https://id.example.invalid"
                && body["scopes_supported"]
                    .as_array()
                    .is_some_and(|scopes| scopes.contains(&json!("phone"))),
            "OIDC discovery lost existing issuer or scopes"
        );
        Ok(())
    }
}
