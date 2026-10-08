//! Opt-in OAuth token, revoke, UserInfo and JWKS endpoints.

use crate::{
    me_http::env_flag,
    media_url::MediaUrl,
    oidc_code_exchange::{CodeExchange, ExchangeFailure, TokenResponse, exchange_code},
    oidc_discovery::OidcDiscovery,
    oidc_keys::OidcKeyRing,
    oidc_protocol::{MAX_REQUEST_BYTES, decode_form_component, parse_token_body},
    oidc_refresh::{RefreshRequest, rotate},
    oidc_revoke::{RevokeRequest, revoke},
    oidc_userinfo,
};
use anyhow::{Result, bail};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{collections::BTreeMap, env, sync::Arc, time::SystemTime};
use url::Url;
use ydb::Client;

pub struct OidcTokenHttpConfig {
    client: Arc<Client>,
    keys: Arc<OidcKeyRing>,
    issuer: String,
    discovery: Value,
    media: Option<MediaUrl>,
    refresh_salt: String,
}

enum OAuthInputError {
    InvalidRequest,
    InvalidBasicClient,
}

impl OAuthInputError {
    fn response(self) -> Response {
        match self {
            Self::InvalidRequest => invalid_request(),
            Self::InvalidBasicClient => oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "Client authentication failed",
                true,
            ),
        }
    }
}

impl OidcTokenHttpConfig {
    pub fn from_env(client: Arc<Client>) -> Result<Option<Arc<Self>>> {
        let local_pilot = env_flag("ID_OIDC_TOKEN_PILOT_ENABLED", false)?;
        let production_rollout = env_flag("ID_OIDC_TOKEN_ROLLOUT_ENABLED", false)?;
        if !local_pilot && !production_rollout {
            return Ok(None);
        }
        let endpoint = Url::parse(&env::var("YDB_ENDPOINT")?)?;
        let local_ydb = env_flag("DJANGO_DEBUG", false)?
            && matches!(
                endpoint.host_str(),
                Some("localhost" | "127.0.0.1" | "[::1]")
            )
            && env::var("YDB_DATABASE")?.as_str() == "/local";
        if local_pilot && !local_ydb {
            bail!("incomplete Rust OIDC token endpoint is restricted to local debug YDB");
        }
        if production_rollout && !local_ydb && !env_flag("ID_RUST_EARLY_ROLLOUT_ENABLED", false)? {
            bail!("Rust OIDC token rollout requires ID_RUST_EARLY_ROLLOUT_ENABLED");
        }
        let issuer = env::var("OIDC_ISSUER")?;
        let refresh_salt =
            env::var("OIDC_REFRESH_TOKEN_SALT").or_else(|_| env::var("DJANGO_SECRET_KEY"))?;
        if refresh_salt.is_empty() {
            bail!("OIDC refresh token salt is required");
        }
        let parsed = Url::parse(&issuer)?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            bail!("OIDC_ISSUER must be an HTTPS issuer URL");
        }
        let issuer = issuer.trim_end_matches('/').to_owned();
        let discovery = OidcDiscovery::from_env(&issuer)?.document();
        Ok(Some(Arc::new(Self {
            client,
            keys: Arc::new(OidcKeyRing::from_env()?),
            issuer,
            discovery,
            refresh_salt,
            media: env::var("MEDIA_PUBLIC_BASE_URL")
                .ok()
                .filter(|value| !value.is_empty())
                .map(|value| MediaUrl::from_env(&value))
                .transpose()?,
        })))
    }
}

pub fn router(config: Arc<OidcTokenHttpConfig>) -> Router {
    Router::new()
        .route("/oauth/token", post(token))
        .route("/oauth/revoke", post(revoke_http))
        .route("/oauth/userinfo", get(userinfo).post(userinfo))
        .route("/oauth/jwks", axum::routing::get(jwks))
        .route("/.well-known/jwks.json", axum::routing::get(jwks))
        .route("/.well-known/openid-configuration", get(discovery))
        .with_state(config)
}

async fn discovery(State(config): State<Arc<OidcTokenHttpConfig>>) -> Response {
    json_response(StatusCode::OK, config.discovery.clone())
}

async fn userinfo(State(config): State<Arc<OidcTokenHttpConfig>>, request: Request) -> Response {
    let mut authorization = request.headers().get_all(header::AUTHORIZATION).iter();
    let Some(value) = authorization.next() else {
        return invalid_bearer();
    };
    if authorization.next().is_some() {
        return invalid_bearer();
    }
    let Ok(value) = value.to_str() else {
        return invalid_bearer();
    };
    let Some((scheme, bearer)) = value.split_once(' ') else {
        return invalid_bearer();
    };
    if !scheme.eq_ignore_ascii_case("Bearer")
        || bearer.is_empty()
        || bearer.contains(char::is_whitespace)
    {
        return invalid_bearer();
    }
    match oidc_userinfo::userinfo(
        &config.client,
        &config.keys,
        &config.issuer,
        bearer,
        config.media.clone(),
        SystemTime::now(),
    )
    .await
    {
        Ok(Some(claims)) => json_response(StatusCode::OK, claims),
        Ok(None) => invalid_bearer(),
        Err(failure) => {
            tracing::error!(?failure, "Rust OIDC UserInfo failed");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Internal server error",
                false,
            )
        }
    }
}

fn invalid_bearer() -> Response {
    let mut response = oauth_error(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        "Invalid access token",
        false,
    );
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer error=\"invalid_token\""),
    );
    response
}

async fn jwks(State(config): State<Arc<OidcTokenHttpConfig>>) -> Response {
    json_response(StatusCode::OK, json!({"keys": config.keys.jwks()}))
}

async fn token(State(config): State<Arc<OidcTokenHttpConfig>>, request: Request) -> Response {
    let (headers, mut params) = match read_oauth_params(request).await {
        Ok(value) => value,
        Err(error) => return error.response(),
    };
    let (client_id, client_secret, used_basic) = match client_credentials(&headers, &mut params) {
        Ok(value) => value,
        Err(error) => return error.response(),
    };
    match params.remove("grant_type").as_deref() {
        Some("authorization_code") => {}
        Some("refresh_token") => {
            let request = RefreshRequest {
                client_id,
                client_secret,
                refresh_token: params.remove("refresh_token").unwrap_or_default(),
                scope: params.remove("scope"),
            };
            return token_result_response(
                rotate(
                    &config.client,
                    config.keys.clone(),
                    &config.issuer,
                    &config.refresh_salt,
                    request,
                    SystemTime::now(),
                )
                .await,
                used_basic,
            );
        }
        Some(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "Unsupported grant type",
                false,
            );
        }
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid OAuth request",
                false,
            );
        }
    }
    let request = CodeExchange {
        client_id,
        client_secret,
        code: params.remove("code").unwrap_or_default(),
        redirect_uri: params.remove("redirect_uri").unwrap_or_default(),
        code_verifier: params.remove("code_verifier").unwrap_or_default(),
    };
    token_result_response(
        exchange_code(
            &config.client,
            config.keys.clone(),
            &config.issuer,
            &config.refresh_salt,
            request,
            SystemTime::now(),
        )
        .await,
        used_basic,
    )
}

fn token_result_response(
    result: Result<std::result::Result<TokenResponse, ExchangeFailure>>,
    used_basic: bool,
) -> Response {
    match result {
        Ok(Ok(tokens)) => json_response(StatusCode::OK, json!(tokens)),
        Ok(Err(ExchangeFailure::InvalidClient)) => oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "Client authentication failed",
            used_basic,
        ),
        Ok(Err(ExchangeFailure::InvalidGrant)) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Invalid authorization grant",
            false,
        ),
        Ok(Err(ExchangeFailure::InvalidScope)) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "Invalid scope",
            false,
        ),
        Ok(Err(ExchangeFailure::UnsupportedGrant)) => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Unsupported grant type",
            false,
        ),
        Err(failure) => {
            tracing::error!(?failure, "Rust OIDC token exchange failed");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Internal server error",
                false,
            )
        }
    }
}

async fn revoke_http(State(config): State<Arc<OidcTokenHttpConfig>>, request: Request) -> Response {
    let (headers, mut params) = match read_oauth_params(request).await {
        Ok(value) => value,
        Err(error) => return error.response(),
    };
    let (client_id, client_secret, used_basic) = match client_credentials(&headers, &mut params) {
        Ok(value) => value,
        Err(error) => return error.response(),
    };
    let Some(token) = params
        .remove("token")
        .filter(|token| !token.is_empty() && token.len() <= 8192)
    else {
        return invalid_request();
    };
    let request = RevokeRequest {
        client_id,
        client_secret,
        token,
    };
    match revoke(
        &config.client,
        config.keys.clone(),
        &config.issuer,
        &config.refresh_salt,
        request,
        SystemTime::now(),
    )
    .await
    {
        Ok(Some(())) => json_response(StatusCode::OK, json!({"ok":true,"message":"revoked"})),
        Ok(None) => oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "Client authentication failed",
            used_basic,
        ),
        Err(failure) => {
            tracing::error!(?failure, "Rust OIDC revoke failed");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Internal server error",
                false,
            )
        }
    }
}

async fn read_oauth_params(
    request: Request,
) -> Result<(HeaderMap, BTreeMap<String, String>), OAuthInputError> {
    let headers = request.headers().clone();
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let body = to_bytes(request.into_body(), MAX_REQUEST_BYTES + 1)
        .await
        .map_err(|_| OAuthInputError::InvalidRequest)?;
    let params =
        parse_token_body(content_type, &body).map_err(|_| OAuthInputError::InvalidRequest)?;
    Ok((headers, params))
}

fn client_credentials(
    headers: &HeaderMap,
    params: &mut BTreeMap<String, String>,
) -> Result<(String, Option<String>, bool), OAuthInputError> {
    let mut basic = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = basic.next() else {
        return Ok((
            params.remove("client_id").unwrap_or_default(),
            params.remove("client_secret"),
            false,
        ));
    };
    if basic.next().is_some() {
        return Err(OAuthInputError::InvalidRequest);
    }
    let Ok(value) = value.to_str() else {
        return Err(OAuthInputError::InvalidRequest);
    };
    let Some((scheme, encoded)) = value.split_once(' ') else {
        return Err(OAuthInputError::InvalidBasicClient);
    };
    if !scheme.eq_ignore_ascii_case("basic")
        || params.contains_key("client_id")
        || params.contains_key("client_secret")
    {
        return Err(OAuthInputError::InvalidRequest);
    }
    let Ok(decoded) = STANDARD.decode(encoded.trim()) else {
        return Err(OAuthInputError::InvalidBasicClient);
    };
    let Some(position) = decoded.iter().position(|byte| *byte == b':') else {
        return Err(OAuthInputError::InvalidBasicClient);
    };
    let (Ok(id), Ok(secret)) = (
        decode_form_component(&decoded[..position]),
        decode_form_component(&decoded[position + 1..]),
    ) else {
        return Err(OAuthInputError::InvalidBasicClient);
    };
    Ok((id, Some(secret), true))
}

fn invalid_request() -> Response {
    oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "Invalid OAuth request",
        false,
    )
}

fn json_response(status: StatusCode, body: Value) -> Response {
    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

fn oauth_error(status: StatusCode, code: &str, description: &str, basic: bool) -> Response {
    let mut response = json_response(
        status,
        json!({"error":code,"error_description":description}),
    );
    if basic && status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"oauth\""),
        );
    }
    response
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use anyhow::{Context, ensure};
    use axum::body::Body;
    use base64::engine::general_purpose::STANDARD;
    use std::{
        io::Write,
        process::{Command, Stdio},
        time::Duration,
    };
    use tower::ServiceExt;

    #[test]
    fn basic_client_credentials_are_single_source_and_form_decoded() -> Result<()> {
        let mut headers = HeaderMap::new();
        let encoded = STANDARD.encode("client%3Aone:secret%2Bvalue");
        headers.insert(header::AUTHORIZATION, format!("Basic {encoded}").parse()?);
        let mut params = BTreeMap::new();
        let (id, secret, basic) = client_credentials(&headers, &mut params)
            .map_err(|_| anyhow::anyhow!("valid Basic client credentials rejected"))?;
        assert_eq!(id, "client:one");
        assert_eq!(secret.as_deref(), Some("secret+value"));
        assert!(basic);
        params.insert("client_id".into(), "another-client".into());
        assert!(client_credentials(&headers, &mut params).is_err());
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic YTpi"),
        );
        assert!(client_credentials(&headers, &mut BTreeMap::new()).is_err());
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires local YDB for the shared API client"]
    async fn serves_oidc_jwks_at_both_existing_paths() -> Result<()> {
        ensure!(
            matches!(
                std::env::var("YDB_ENDPOINT")?.as_str(),
                "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
            ) && std::env::var("YDB_DATABASE")? == "/local",
            "JWKS test requires local YDB"
        );
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
                "kid": "local-jwks-test"
            })
            .to_string(),
        )?;
        let config = Arc::new(OidcTokenHttpConfig {
            client: Arc::new(crate::connect_ydb().await?),
            keys: Arc::new(keys),
            issuer: "https://id.example.invalid".into(),
            discovery: OidcDiscovery::new(
                "https://id.example.invalid",
                "https://id.example.invalid",
            )?
            .document(),
            media: None,
            refresh_salt: "local-synthetic-refresh-salt".into(),
        });
        let response = router(config.clone())
            .oneshot(
                Request::builder()
                    .uri("/.well-known/openid-configuration")
                    .body(Body::empty())?,
            )
            .await?;
        ensure!(
            response.status() == StatusCode::OK,
            "discovery route failed"
        );
        ensure!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .is_some_and(|value| value == "no-store"),
            "discovery cache policy changed"
        );
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1_048_576).await?)?;
        ensure!(
            body["issuer"] == "https://id.example.invalid"
                && body["token_endpoint"] == "https://id.example.invalid/oauth/token"
                && body["jwks_uri"] == "https://id.example.invalid/.well-known/jwks.json"
                && body["revocation_endpoint"] == "https://id.example.invalid/oauth/revoke",
            "discovery endpoints changed"
        );
        for path in ["/oauth/jwks", "/.well-known/jwks.json"] {
            let response = router(config.clone())
                .oneshot(Request::builder().uri(path).body(Body::empty())?)
                .await?;
            ensure!(response.status() == StatusCode::OK, "JWKS route failed");
            ensure!(
                response
                    .headers()
                    .get(header::CACHE_CONTROL)
                    .is_some_and(|value| value == "no-store"),
                "JWKS cache policy changed"
            );
            let body: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 1_048_576).await?)?;
            ensure!(
                body["keys"].as_array().is_some_and(|keys| keys.len() == 1),
                "unexpected JWKS shape"
            );
            ensure!(
                body["keys"][0]["kid"] == "local-jwks-test" && body["keys"][0]["alg"] == "RS256",
                "unexpected JWKS key"
            );
            ensure!(
                body["keys"][0].get("private_key_pem").is_none(),
                "JWKS exposed private material"
            );
        }
        for method in ["GET", "POST"] {
            let response = router(config.clone())
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri("/oauth/userinfo")
                        .body(Body::empty())?,
                )
                .await?;
            ensure!(
                response.status() == StatusCode::UNAUTHORIZED,
                "missing bearer accepted"
            );
            ensure!(
                response
                    .headers()
                    .get(header::WWW_AUTHENTICATE)
                    .is_some_and(|value| value == "Bearer error=\"invalid_token\""),
                "UserInfo challenge changed"
            );
            let body: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 1_048_576).await?)?;
            ensure!(
                body["error"] == "invalid_token",
                "UserInfo OAuth error changed"
            );
        }
        let response = router(config.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/revoke")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("client_id=missing"))?,
            )
            .await?;
        ensure!(
            response.status() == StatusCode::BAD_REQUEST,
            "revoke accepted missing token"
        );
        let response = router(config.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/revoke")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("client_id=missing&token=opaque"))?,
            )
            .await?;
        ensure!(
            response.status() == StatusCode::UNAUTHORIZED,
            "revoke accepted unknown client"
        );
        let response = router(config.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "grant_type=refresh_token&client_id=missing&refresh_token=opaque",
                    ))?,
            )
            .await?;
        ensure!(
            response.status() == StatusCode::UNAUTHORIZED,
            "refresh accepted unknown client"
        );
        ensure!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .is_some_and(|value| value == "no-store"),
            "refresh error lost no-store"
        );
        basic_failures_preserve_codes_and_refresh(config).await?;
        Ok(())
    }

    async fn token_request(
        app: &Router,
        authorization: &str,
        body: &str,
        status: StatusCode,
        error: Option<&str>,
    ) -> Result<Value> {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/token")
                    .header(header::AUTHORIZATION, authorization)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body.to_owned()))?,
            )
            .await?;
        ensure!(
            response.status() == status,
            "unexpected OAuth HTTP status: {}",
            response.status()
        );
        ensure!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .is_some_and(|v| v == "no-store")
                && response
                    .headers()
                    .get(header::PRAGMA)
                    .is_some_and(|v| v == "no-cache"),
            "token response lost cache protection"
        );
        if status == StatusCode::UNAUTHORIZED {
            ensure!(
                response
                    .headers()
                    .get(header::WWW_AUTHENTICATE)
                    .is_some_and(|v| v == "Basic realm=\"oauth\""),
                "Basic failure lost challenge"
            );
        } else {
            ensure!(
                !response.headers().contains_key(header::WWW_AUTHENTICATE),
                "non-authentication error unexpectedly challenged Basic credentials"
            );
        }
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), MAX_REQUEST_BYTES).await?)?;
        if let Some(error) = error {
            ensure!(
                body["error"] == error && body.as_object().is_some_and(|v| v.len() == 2),
                "OAuth error shape changed or returned extra credential fields"
            );
            ensure!(
                body["error_description"]
                    == if error == "invalid_client" {
                        "Client authentication failed"
                    } else if error == "invalid_request" {
                        "Invalid OAuth request"
                    } else {
                        "Invalid authorization grant"
                    },
                "OAuth error disclosed request-specific data"
            );
        }
        Ok(body)
    }

    #[derive(PartialEq, Eq)]
    struct TokenState {
        id: i64,
        rotated: Option<SystemTime>,
        revoked: Option<SystemTime>,
        family: Option<String>,
        refresh_hash: String,
    }

    async fn token_state(client: &Client, user: i32, client_pk: i64) -> Result<Vec<TokenState>> {
        let mut query = client.query_client();
        let mut stream = query.query("SELECT id, rotated_at, revoked_at, refresh_family_id, refresh_token_hash FROM idp_oidctoken VIEW oidc_token_user_client_idx WHERE user_id = $user AND client_id = $client")
            .param("$user", user).param("$client", client_pk).await?;
        let mut states = Vec::new();
        while let Some(rows) = stream.next_result_set().await? {
            for mut row in rows {
                states.push(TokenState {
                    id: row.remove_field_by_name("id")?.try_into()?,
                    rotated: row.remove_field_by_name("rotated_at")?.try_into()?,
                    revoked: row.remove_field_by_name("revoked_at")?.try_into()?,
                    family: row.remove_field_by_name("refresh_family_id")?.try_into()?,
                    refresh_hash: row.remove_field_by_name("refresh_token_hash")?.try_into()?,
                });
            }
        }
        stream.close().await?;
        states.sort_by_key(|state| state.id);
        Ok(states)
    }

    // Runs inside the existing required HTTP/YDB scenario and reuses its router,
    // database client and ephemeral keyset; each failure gets its own code/family.
    async fn basic_failures_preserve_codes_and_refresh(
        config: Arc<OidcTokenHttpConfig>,
    ) -> Result<()> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use sha2::{Digest, Sha256};

        let client = &config.client;
        let app = router(config.clone());
        let identity = uuid::Uuid::from_u128(rand::random());
        let user = -i32::try_from(rand::random::<u32>() & 0x3fff_ffff)? - 1;
        let client_pk = -i64::try_from(rand::random::<u64>() & 0x3fff_ffff_ffff_ffff)? - 1;
        let client_id = format!("basic-{}", identity.simple());
        let subject = format!("basic-subject-{identity}");
        let secret = "synthetic-basic:secret+value";
        let secret_hash =
            tokio::task::spawn_blocking(move || id_compat::password::hash_new(secret)).await??;
        let encoded_secret: String =
            url::form_urlencoded::byte_serialize(secret.as_bytes()).collect();
        let authorization = format!(
            "Basic {}",
            STANDARD.encode(format!("{client_id}:{encoded_secret}"))
        );
        let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier));
        let failures = [
            (
                "invalid-base64",
                "Basic %%%".to_owned(),
                "",
                StatusCode::UNAUTHORIZED,
                "invalid_client",
            ),
            (
                "missing-colon",
                format!("Basic {}", STANDARD.encode(&client_id)),
                "",
                StatusCode::UNAUTHORIZED,
                "invalid_client",
            ),
            (
                "invalid-form-utf8",
                format!("Basic {}", STANDARD.encode(format!("{client_id}:%FF"))),
                "",
                StatusCode::UNAUTHORIZED,
                "invalid_client",
            ),
            (
                "mixed-secret",
                authorization.clone(),
                "&client_secret=synthetic-body-secret",
                StatusCode::BAD_REQUEST,
                "invalid_request",
            ),
            (
                "wrong-secret",
                format!(
                    "Basic {}",
                    STANDARD.encode(format!("{client_id}:synthetic-wrong-secret"))
                ),
                "",
                StatusCode::UNAUTHORIZED,
                "invalid_client",
            ),
        ];
        // Establish ownership before enabling cleanup; INSERT fails on an ID collision.
        client.query_client().exec("INSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, '!', true, $name, '', '', $email, false, false, CurrentUtcDatetime())")
            .param("$id", user).param("$name", client_id.clone()).param("$email", format!("{client_id}@example.invalid")).await?;
        let result: Result<()> = async {
            client.query_client().exec("INSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, $name, '', $email, true, 'active', false, CurrentUtcDatetime())")
                .param("$id", identity).param("$name", client_id.clone()).param("$email", format!("{client_id}@example.invalid")).await?;
            client.query_client().exec("INSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($user, $identity, $subject, CurrentUtcDatetime())")
                .param("$user", user).param("$identity", identity).param("$subject", subject).await?;
            client.query_client().exec("INSERT INTO idp_oidcclient (id, client_id, name, logo_url, description, client_secret_hash, redirect_uris, allowed_scopes, grant_types, response_types, is_public, is_first_party, created_at, updated_at) VALUES ($id, $client, 'Basic HTTP fixture', '', '', $hash, Unwrap(CAST('[\"https://rp.example.invalid/callback\"]' AS Json)), Unwrap(CAST('[\"openid\",\"offline_access\"]' AS Json)), Unwrap(CAST('[\"authorization_code\",\"refresh_token\"]' AS Json)), Unwrap(CAST('[\"code\"]' AS Json)), false, false, CurrentUtcDatetime(), CurrentUtcDatetime())")
                .param("$id", client_pk).param("$client", client_id.clone()).param("$hash", secret_hash).await?;
            for (name, invalid_auth, extra, status, error) in &failures {
                let code = format!("{client_id}-{name}");
                client.query_client().exec("INSERT INTO idp_oidcauthorizationcode (code, client_id, user_id, redirect_uri, scope, nonce, code_challenge, code_challenge_method, created_at, expires_at) VALUES ($code, $client, $user, 'https://rp.example.invalid/callback', 'openid offline_access', '', $challenge, 'S256', CurrentUtcDatetime(), CAST($expires AS Datetime))")
                    .param("$code", code.clone()).param("$client", client_pk).param("$user", user)
                    .param("$challenge", challenge.clone()).param("$expires", SystemTime::now() + Duration::from_secs(300)).await?;
                let form = url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("grant_type", "authorization_code").append_pair("code", &code)
                    .append_pair("redirect_uri", "https://rp.example.invalid/callback")
                    .append_pair("code_verifier", verifier).finish();
                let before = token_state(client, user, client_pk).await?;
                token_request(&app, invalid_auth, &format!("{form}{extra}"), *status, Some(error)).await.context(*name)?;
                let mut row = client.query_client().query_row("SELECT used_at FROM idp_oidcauthorizationcode WHERE code = $code")
                    .param("$code", code.clone()).await?;
                let used: Option<SystemTime> = row.remove_field_by_name("used_at")?.try_into()?;
                ensure!(used.is_none() && before == token_state(client, user, client_pk).await?,
                    "{name}: authentication failure consumed code or mutated a token family");
                let issued = token_request(&app, &authorization, &form, StatusCode::OK, None).await.context(*name)?;
                let refresh = issued["refresh_token"].as_str().context("missing refresh after valid Basic exchange")?;
                token_request(&app, &authorization, &form, StatusCode::BAD_REQUEST, Some("invalid_grant")).await?;
                let refresh_form = url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("grant_type", "refresh_token").append_pair("refresh_token", refresh).finish();
                let before = token_state(client, user, client_pk).await?;
                token_request(&app, invalid_auth, &format!("{refresh_form}{extra}"), *status, Some(error)).await.context(*name)?;
                ensure!(before == token_state(client, user, client_pk).await?,
                    "{name}: authentication failure rotated or revoked a token family");
                let rotated = token_request(&app, &authorization, &refresh_form, StatusCode::OK, None).await.context(*name)?;
                ensure!(rotated["refresh_token"].as_str().is_some_and(|next| !next.is_empty() && next != refresh),
                    "refresh did not rotate after rejected Basic credentials");
                token_request(&app, &authorization, &refresh_form, StatusCode::BAD_REQUEST, Some("invalid_grant")).await?;
            }
            Ok(())
        }.await;
        for state in token_state(client, user, client_pk).await? {
            client
                .query_client()
                .exec("DELETE FROM idp_oidctoken WHERE id = $id")
                .param("$id", state.id)
                .await?;
        }
        for (name, ..) in &failures {
            client
                .query_client()
                .exec("DELETE FROM idp_oidcauthorizationcode WHERE code = $code")
                .param("$code", format!("{client_id}-{name}"))
                .await?;
        }
        client
            .query_client()
            .exec("DELETE FROM idp_oidcclient WHERE id = $id AND client_id = $client")
            .param("$id", client_pk)
            .param("$client", client_id)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM accounts_accountidentity WHERE user_id = $id")
            .param("$id", user)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM usid_user WHERE user_id = $id")
            .param("$id", identity)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM auth_user WHERE id = $id")
            .param("$id", user)
            .await?;
        result
    }
}
