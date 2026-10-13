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
        .route("/oauth/observability-access", get(userinfo))
        .route("/oauth/jwks", axum::routing::get(jwks))
        .route("/.well-known/jwks.json", axum::routing::get(jwks))
        .route("/.well-known/openid-configuration", get(discovery))
        .with_state(config)
}

async fn discovery(State(config): State<Arc<OidcTokenHttpConfig>>) -> Response {
    json_response(StatusCode::OK, config.discovery.clone())
}

async fn userinfo(State(config): State<Arc<OidcTokenHttpConfig>>, request: Request) -> Response {
    let observability = request.uri().path() == "/oauth/observability-access";
    let avatar_uri = (request
        .headers()
        .get("x-forwarded-host")
        .and_then(|h| h.to_str().ok())
        == Some("grafana.updspace.com"))
    .then(|| {
        request
            .headers()
            .get("x-forwarded-uri")
            .and_then(|h| h.to_str().ok())
    })
    .flatten();
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
        Ok(Some(claims)) => userinfo_response(observability, claims, avatar_uri),
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

fn userinfo_response(observability: bool, claims: Value, avatar_uri: Option<&str>) -> Response {
    // Native monitoring clients must satisfy the same policy as the edge session.
    if (observability || claims["client_id"] == "observability") && !observability_allowed(&claims)
    {
        return json_response(StatusCode::FORBIDDEN, json!({"error":"access_denied"}));
    }
    if !observability {
        return json_response(StatusCode::OK, claims);
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Some(picture) = avatar_uri.and_then(|uri| observability_avatar(&claims, uri)) {
        response
            .headers_mut()
            .insert("x-observability-avatar", picture);
    }
    response
}

fn observability_avatar(claims: &Value, uri: &str) -> Option<HeaderValue> {
    use sha2::Digest;
    let email = claims["email"].as_str()?.trim().to_lowercase();
    if email.is_empty() {
        return None;
    }
    // Grafana 13 uses a SHA-256 email key; it is not an authorization proof.
    let hash = sha2::Sha256::digest(email.as_bytes());
    if uri.split('?').next()? != format!("/avatar/{}", hex::encode(hash)) {
        return None;
    }
    let picture = claims["picture"].as_str()?;
    let url = url::Url::parse(picture).ok()?;
    if url.scheme() != "https"
        || url.host_str() != Some("storage.updspace.com")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.fragment().is_some()
        || !url
            .path()
            .starts_with("/updspace-id-media-ab88348a/avatars/")
    {
        return None;
    }
    HeaderValue::from_str(picture).ok()
}

// Policy uses fresh UserInfo database reads, never browser or cached token flags.
fn observability_allowed(claims: &Value) -> bool {
    claims["client_id"] == "observability"
        && claims["master_flags"]["is_staff"] == true
        && claims["master_flags"]["system_admin"] == true
        && claims["master_flags"]["status"] == "active"
        && claims["master_flags"]["banned"] == false
        && claims["master_flags"]["suspended"] == false
}

#[cfg(test)]
mod observability_tests {
    use super::*;

    #[test]
    fn avatar_is_current_owner_only_and_requires_live_authorization() {
        let picture = "https://storage.updspace.com/updspace-id-media-ab88348a/avatars/fixture.png?X-Amz-Signature=fixture";
        let mut claims = json!({"client_id":"observability", "email":"Fixture@Example.Invalid",
            "picture":picture, "master_flags":{"is_staff":true,"system_admin":true,
            "status":"active","banned":false,"suspended":false}});
        use sha2::Digest;
        let hash = sha2::Sha256::digest(b"fixture@example.invalid");
        let uri = format!("/avatar/{}?s=80", hex::encode(hash));
        let response = userinfo_response(true, claims.clone(), Some(&uri));
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response.headers()["x-observability-avatar"], picture);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        for path in ["/", "/avatar/another-user", "/avatar/", "/api/user"] {
            assert!(observability_avatar(&claims, path).is_none());
        }
        for bad in [
            "",
            "http://storage.updspace.com/updspace-id-media-ab88348a/avatars/a.png",
            "https://evil.invalid/avatars/a.png",
            "https://user@storage.updspace.com/updspace-id-media-ab88348a/avatars/a.png",
            "https://storage.updspace.com/updspace-id-media-ab88348a/exports/a.png",
            "javascript:alert(1)",
        ] {
            claims["picture"] = json!(bad);
            assert!(observability_avatar(&claims, &uri).is_none());
        }
        claims["picture"] = json!(picture);
        for flag in ["is_staff", "system_admin"] {
            let mut denied = claims.clone();
            denied["master_flags"][flag] = json!(false);
            let response = userinfo_response(true, denied, Some(&uri));
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert!(!response.headers().contains_key("x-observability-avatar"));
        }
        assert!(
            !userinfo_response(false, claims.clone(), Some(&uri))
                .headers()
                .contains_key("x-observability-avatar")
        );
        claims["email"] = Value::Null;
        assert!(observability_avatar(&claims, &uri).is_none());
    }

    #[test]
    fn requires_exact_client_and_both_live_privileges() {
        let base = json!({"client_id":"observability", "master_flags":{
            "is_staff":true,"system_admin":true,"status":"active","banned":false,"suspended":false}});
        assert!(observability_allowed(&base));
        assert_eq!(
            userinfo_response(true, base.clone(), None).status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            userinfo_response(false, base.clone(), None).status(),
            StatusCode::OK
        );
        assert_eq!(
            userinfo_response(false, json!({"client_id":"portal"}), None).status(),
            StatusCode::OK
        );
        for (staff, admin) in [(false, false), (true, false), (false, true)] {
            let mut claims = base.clone();
            claims["master_flags"]["is_staff"] = json!(staff);
            claims["master_flags"]["system_admin"] = json!(admin);
            assert!(!observability_allowed(&claims));
            if claims["client_id"] == "observability" {
                assert_eq!(
                    userinfo_response(false, claims.clone(), None).status(),
                    StatusCode::FORBIDDEN
                );
            }
            assert_eq!(
                userinfo_response(true, claims, None).status(),
                StatusCode::FORBIDDEN
            );
        }
        for (key, value) in [
            ("status", json!("suspended")),
            ("banned", json!(true)),
            ("suspended", json!(true)),
            ("is_staff", json!("true")),
        ] {
            let mut claims = base.clone();
            claims["master_flags"][key] = value;
            assert!(!observability_allowed(&claims));
            if claims["client_id"] == "observability" {
                assert_eq!(
                    userinfo_response(false, claims.clone(), None).status(),
                    StatusCode::FORBIDDEN
                );
            }
            assert_eq!(
                userinfo_response(true, claims, None).status(),
                StatusCode::FORBIDDEN
            );
        }
        for client in [json!("portal"), Value::Null, json!(["observability"])] {
            let mut claims = base.clone();
            claims["client_id"] = client;
            assert!(!observability_allowed(&claims));
            if claims["client_id"] == "observability" {
                assert_eq!(
                    userinfo_response(false, claims.clone(), None).status(),
                    StatusCode::FORBIDDEN
                );
            }
            assert_eq!(
                userinfo_response(true, claims, None).status(),
                StatusCode::FORBIDDEN
            );
        }
        assert!(!observability_allowed(&json!({})));
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
mod tests {
    use super::*;
    use anyhow::{Context, ensure};
    use axum::body::Body;
    use base64::engine::general_purpose::STANDARD;
    use std::{
        io::Write,
        process::{Command, Stdio},
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
        let response = router(config)
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
        Ok(())
    }
}
