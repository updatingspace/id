#![recursion_limit = "256"]
#![cfg(debug_assertions)]
//! Real YDB and loopback provider transport; not acceptance against the real providers.
use anyhow::{Context, Result, ensure};
use axum::{
    Form, Json, Router,
    body::{Body, to_bytes},
    extract::State,
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    routing::{get, post},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use cookie::SameSite;
use hmac::{Hmac, Mac};
use id_compat::{account_jwt::AccountJwtCodec, cache::CacheValue, session::SessionCodec};
use id_runtime::{
    cache_store::CacheStore,
    form_token_http::{self, FormTokenConfig},
    login_http::{LoginHttpConfig, LoginHttpOptions},
    media_url::MediaUrl,
    provider_login::{self, ProviderLoginConfig},
};
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

const ORIGIN: &str = "https://id.example.invalid";
const SECRET: &[u8] = b"synthetic-github-login-session-secret-at-least-32";
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Kind {
    #[default]
    Github,
    Discord,
    Steam,
}
impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Discord => "discord",
            Self::Steam => "steam",
        }
    }
    fn other(self) -> Self {
        match self {
            Self::Github => Self::Discord,
            Self::Discord | Self::Steam => Self::Github,
        }
    }
    fn config(self, login: Arc<LoginHttpConfig>) -> Result<ProviderLoginConfig> {
        if self == Self::Steam {
            return ProviderLoginConfig::steam(
                login,
                format!("{ORIGIN}/api/v1/auth/oauth/callback/steam"),
                vec!["/account".into()],
            );
        }
        let constructor = match self {
            Self::Github => ProviderLoginConfig::github,
            Self::Discord => ProviderLoginConfig::discord,
            Self::Steam => unreachable!(),
        };
        constructor(
            login,
            "synthetic-client".into(),
            "synthetic-secret".into(),
            format!("{ORIGIN}/api/v1/auth/oauth/callback/{}", self.name()),
            vec!["/account".into()],
        )
    }
}

#[derive(Default)]
struct Provider {
    kind: Kind,
    user_id_override: Option<Value>,
    omit_identify: bool,
    // Each code has the browser's original PKCE challenge and a provider subject.
    codes: BTreeMap<String, (String, u64)>,
    tokens: BTreeMap<String, u64>,
    exchanges: u32,
    email: String,
    steam_assertions: BTreeMap<String, BTreeMap<String, String>>,
    steam_endpoint: String,
    verification_reply: Option<String>,
    discovery_reply: Option<String>,
    verification_redirect: bool,
    redirected_requests: u32,
}

async fn provider_token(
    State(state): State<Arc<Mutex<Provider>>>,
    headers: HeaderMap,
    Form(form): Form<BTreeMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let invalid = || {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid_grant"})),
        )
    };
    let Ok(mut provider) = state.lock() else {
        return invalid();
    };
    provider.exchanges += 1;
    let Some(code) = form.get("code") else {
        return invalid();
    };
    let Some((challenge, subject)) = provider.codes.remove(code) else {
        return invalid();
    };
    let Some(verifier) = form.get("code_verifier") else {
        return invalid();
    };
    let valid_credentials = match provider.kind {
        Kind::Steam => false,
        Kind::Github => {
            form.get("client_id").map(String::as_str) == Some("synthetic-client")
                && form.get("client_secret").map(String::as_str) == Some("synthetic-secret")
        }
        Kind::Discord => {
            headers
                .get(header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                == Some(
                    format!(
                        "Basic {}",
                        STANDARD.encode("synthetic-client:synthetic-secret")
                    )
                    .as_str(),
                )
                && form.get("grant_type").map(String::as_str) == Some("authorization_code")
                && !form.contains_key("client_secret")
        }
    };
    if !valid_credentials
        || form.get("redirect_uri")
            != Some(&format!(
                "{ORIGIN}/api/v1/auth/oauth/callback/{}",
                provider.kind.name()
            ))
        || !(43..=128).contains(&verifier.len())
        || URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) != challenge
    {
        return invalid();
    }
    let token = format!("synthetic-bearer-{code}");
    provider.tokens.insert(token.clone(), subject);
    let mut body = json!({"access_token":token,"token_type":"bearer"});
    if provider.kind == Kind::Discord {
        body["scope"] = json!(if provider.omit_identify {
            "email"
        } else {
            "identify"
        });
    }
    (StatusCode::OK, Json(body))
}

async fn provider_user(
    State(state): State<Arc<Mutex<Provider>>>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let subject = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .and_then(|token| {
            let provider = state.lock().ok()?;
            if provider.kind == Kind::Github
                && headers
                    .get("x-github-api-version")
                    .and_then(|h| h.to_str().ok())
                    != Some("2022-11-28")
            {
                return None;
            }
            let subject = *provider.tokens.get(token)?;
            let id = provider
                .user_id_override
                .clone()
                .unwrap_or_else(|| match provider.kind {
                    Kind::Github => json!(subject),
                    Kind::Discord | Kind::Steam => json!(subject.to_string()),
                });
            Some((id, provider.email.clone()))
        });
    match subject {
        Some((subject, email)) => (StatusCode::OK, Json(json!({"id":subject,"email":email}))),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"message":"invalid token"})),
        ),
    }
}

const OPENID_NS: &str = "http://specs.openid.net/auth/2.0";
const STEAM_CALLBACK: &str = "/api/v1/auth/oauth/callback/steam";

async fn steam_check(
    State(state): State<Arc<Mutex<Provider>>>,
    Form(form): Form<BTreeMap<String, String>>,
) -> (StatusCode, HeaderMap, String) {
    let Ok(mut provider) = state.lock() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            HeaderMap::new(),
            String::new(),
        );
    };
    provider.exchanges += 1;
    let expected = form
        .get("openid.sig")
        .and_then(|sig| provider.steam_assertions.get(sig));
    // The local OP signs the complete assertion. A verifier must forward every
    // assertion value unchanged except mode, and must never send the RP's state.
    let valid = expected.is_some_and(|expected| expected == &form);
    let mut headers = HeaderMap::new();
    if provider.verification_redirect {
        headers.insert(
            header::LOCATION,
            HeaderValue::from_static("/openid/redirect"),
        );
    }
    (
        if provider.verification_redirect {
            StatusCode::FOUND
        } else {
            StatusCode::OK
        },
        headers,
        provider.verification_reply.clone().unwrap_or_else(|| {
            format!(
                "ns:{OPENID_NS}\nis_valid:{}\n",
                if valid { "true" } else { "false" }
            )
        }),
    )
}

async fn steam_redirect(State(state): State<Arc<Mutex<Provider>>>) -> (StatusCode, String) {
    let Ok(mut provider) = state.lock() else {
        return (StatusCode::SERVICE_UNAVAILABLE, String::new());
    };
    provider.redirected_requests += 1;
    (StatusCode::OK, format!("ns:{OPENID_NS}\nis_valid:true\n"))
}

async fn steam_discovery(State(state): State<Arc<Mutex<Provider>>>) -> (StatusCode, String) {
    let Ok(provider) = state.lock() else {
        return (StatusCode::SERVICE_UNAVAILABLE, String::new());
    };
    (StatusCode::OK,provider.discovery_reply.clone().unwrap_or_else(||format!(
        "<?xml version=\"1.0\"?><xrds:XRDS xmlns:xrds=\"xri://$xrds\" xmlns=\"xri://$xrd*($v*2.0)\"><XRD><Service priority=\"0\"><Type>http://specs.openid.net/auth/2.0/signon</Type><URI>{}</URI></Service></XRD></xrds:XRDS>",provider.steam_endpoint)))
}

fn steam_assertion(
    query: &BTreeMap<String, String>,
    provider: &Arc<Mutex<Provider>>,
    subject: u64,
) -> Result<String> {
    let mut provider = provider
        .lock()
        .map_err(|_| anyhow::anyhow!("provider mutex"))?;
    let return_to = query.get("openid.return_to").context("OpenID return_to")?;
    let url = Url::parse(return_to)?;
    ensure!(url.origin().ascii_serialization() == ORIGIN && url.path() == STEAM_CALLBACK);
    ensure!(
        query.get("openid.realm").map(String::as_str) == Some(&format!("{ORIGIN}/"))
            && query.get("openid.ns").map(String::as_str) == Some(OPENID_NS)
            && query.get("openid.mode").map(String::as_str) == Some("checkid_setup")
            && query.get("openid.claimed_id").map(String::as_str)
                == Some("http://specs.openid.net/auth/2.0/identifier_select")
            && query.get("openid.identity") == query.get("openid.claimed_id")
            && query.len() == 6,
        "Steam authorization accidentally uses OAuth parameters"
    );
    let state = url
        .query_pairs()
        .find(|(key, _)| key == "state")
        .context("Steam state")?
        .1
        .into_owned();
    let sig = STANDARD.encode(rand::random::<[u8; 20]>());
    let mut form: BTreeMap<String, String> = [
        ("openid.ns", OPENID_NS.to_owned()),
        ("openid.mode", "id_res".into()),
        ("openid.op_endpoint", provider.steam_endpoint.clone()),
        (
            "openid.claimed_id",
            format!("https://steamcommunity.com/openid/id/{subject}"),
        ),
        (
            "openid.identity",
            format!("https://steamcommunity.com/openid/id/{subject}"),
        ),
        ("openid.return_to", return_to.clone()),
        ("openid.assoc_handle", "synthetic-steam-association".into()),
        (
            "openid.response_nonce",
            format!(
                "{}{}",
                chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
                Uuid::new_v4().simple()
            ),
        ),
        (
            "openid.signed",
            "op_endpoint,claimed_id,identity,return_to,response_nonce,assoc_handle".into(),
        ),
        ("openid.sig", sig.clone()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect();
    let mut expected = form.clone();
    expected.insert("openid.mode".into(), "check_authentication".into());
    provider.steam_assertions.insert(sig, expected);
    form.insert("state".into(), state);
    Ok(callback_query(&form))
}
fn callback_query(form: &BTreeMap<String, String>) -> String {
    format!(
        "{STEAM_CALLBACK}?{}",
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form)
            .finish()
    )
}
fn callback_fields(path: &str) -> Result<BTreeMap<String, String>> {
    Ok(Url::parse(&format!("{ORIGIN}{path}"))?
        .query_pairs()
        .into_owned()
        .collect())
}
fn sign_steam(form: &mut BTreeMap<String, String>, provider: &Arc<Mutex<Provider>>) -> Result<()> {
    let sig = STANDARD.encode(rand::random::<[u8; 20]>());
    form.insert("openid.sig".into(), sig.clone());
    let mut expected = form.clone();
    expected.remove("state");
    expected.insert("openid.mode".into(), "check_authentication".into());
    provider
        .lock()
        .map_err(|_| anyhow::anyhow!("provider mutex"))?
        .steam_assertions
        .insert(sig, expected);
    Ok(())
}

#[derive(Clone, Default)]
struct Browser {
    cookies: BTreeMap<String, String>,
}
struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}
impl Browser {
    async fn call(&mut self, app: &Router, method: &str, path: &str, body: Value) -> Result<Reply> {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header("x-forwarded-for", "192.0.2.49")
            .header(header::USER_AGENT, "Synthetic provider browser");
        let cookie = self
            .cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        if !cookie.is_empty() {
            req = req.header(header::COOKIE, cookie);
        }
        if method == "POST" {
            req = req
                .header(header::ORIGIN, ORIGIN)
                .header(header::CONTENT_TYPE, "application/json");
            if let Some(csrf) = self.cookies.get("csrftoken") {
                req = req.header("x-csrftoken", csrf);
            }
        }
        let response = app
            .clone()
            .oneshot(req.body(Body::from(body.to_string()))?)
            .await?;
        let status = response.status();
        let headers = response.headers().clone();
        for value in headers.get_all(header::SET_COOKIE) {
            let raw = value.to_str()?;
            let pair = raw.split(';').next().context("cookie pair")?;
            let (key, value) = pair.split_once('=').context("cookie value")?;
            if value.is_empty() || raw.contains("Max-Age=0") {
                self.cookies.remove(key);
            } else {
                self.cookies.insert(key.into(), value.into());
            }
        }
        let bytes = to_bytes(response.into_body(), 1_000_000).await?;
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)?
        };
        Ok(Reply {
            status,
            headers,
            body,
        })
    }

    async fn start(
        &mut self,
        app: &Router,
        provider: &Arc<Mutex<Provider>>,
        subject: u64,
    ) -> Result<String> {
        let name = provider
            .lock()
            .map_err(|_| anyhow::anyhow!("provider mutex"))?
            .kind
            .name();
        let start_path = format!("/api/v1/auth/oauth/login/{name}");
        let callback_path = format!("/api/v1/auth/oauth/callback/{name}");
        let token = self
            .call(
                app,
                "GET",
                "/api/v1/auth/form_token?purpose=login",
                Value::Null,
            )
            .await?;
        ensure!(
            token.status == StatusCode::OK,
            "{name} form-token failed: {} {}",
            token.status,
            token.body
        );
        let r = self
            .call(
                app,
                "POST",
                &start_path,
                json!({"form_token":token.body["form_token"],"next":"/account"}),
            )
            .await?;
        ensure!(
            r.status == StatusCode::OK,
            "start failed: {} {}",
            r.status,
            r.body
        );
        let flow_cookie = r
            .headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|header| header.to_str().ok())
            .find(|cookie| cookie.starts_with(&format!("__Host-id_{name}_flow=")))
            .context("protected flow cookie")?;
        ensure!(
            flow_cookie.contains("Secure")
                && flow_cookie.contains("HttpOnly")
                && flow_cookie.contains("SameSite=Lax")
                && flow_cookie.contains("Path=/")
                && !flow_cookie.contains("Domain="),
            "flow cookie lost browser isolation"
        );
        let url = Url::parse(r.body["authorize_url"].as_str().context("authorize URL")?)?;
        let query: BTreeMap<String, String> = url.query_pairs().into_owned().collect();
        if name == "steam" {
            ensure!(
                url.as_str().starts_with(
                    &provider
                        .lock()
                        .map_err(|_| anyhow::anyhow!("provider mutex"))?
                        .steam_endpoint
                )
            );
            return steam_assertion(&query, provider, subject);
        }
        ensure!(
            query.get("redirect_uri") == Some(&format!("{ORIGIN}{callback_path}"))
                && query.get("code_challenge_method").map(String::as_str) == Some("S256")
        );
        ensure!(
            query.get("scope").map(String::as_str)
                == Some(if name == "github" {
                    "read:user"
                } else {
                    "identify"
                })
        );
        if name == "discord" {
            ensure!(query.get("response_type").map(String::as_str) == Some("code"));
        }
        let code = Uuid::new_v4().simple().to_string();
        provider
            .lock()
            .map_err(|_| anyhow::anyhow!("provider mutex"))?
            .codes
            .insert(
                code.clone(),
                (
                    query
                        .get("code_challenge")
                        .context("PKCE challenge")?
                        .clone(),
                    subject,
                ),
            );
        Ok(format!(
            "{callback_path}?code={code}&state={}",
            query.get("state").context("state")?
        ))
    }
}

fn redirected(reply: &Reply, target: &str) -> Result<()> {
    ensure!(
        reply.status == StatusCode::SEE_OTHER
            && reply
                .headers
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok())
                == Some(target),
        "expected redirect {target}, got: {} {:?}",
        reply.status,
        reply.headers.get(header::LOCATION)
    );
    ensure!(
        !reply.headers.contains_key("x-session-token"),
        "callback leaked session header"
    );
    Ok(())
}

async fn ids(client: &ydb::Client, sql: String, id: i32) -> Result<Vec<String>> {
    let mut query = client.query_client();
    let mut rows = query.query(sql).param("$id", id).await?;
    let mut result = Vec::new();
    while let Some(set) = rows.next_result_set().await? {
        for mut row in set {
            result.push(row.remove_field_by_name("value")?.try_into()?);
        }
    }
    rows.close().await?;
    Ok(result)
}

fn totp_code(unix_seconds: u64) -> Result<String> {
    let mut mac = Hmac::<Sha1>::new_from_slice(b"12345678901234567890")?;
    mac.update(&(unix_seconds / 30).to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 0x0f);
    let value = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]) % 1_000_000;
    Ok(format!("{value:06}"))
}

async fn serve_provider(
    provider: Arc<Mutex<Provider>>,
) -> Result<(String, tokio::task::JoinHandle<std::io::Result<()>>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}/", listener.local_addr()?);
    provider
        .lock()
        .map_err(|_| anyhow::anyhow!("provider mutex"))?
        .steam_endpoint = format!("{origin}openid/login");
    let app = Router::new()
        .route("/openid/login", post(steam_check))
        .route("/openid/redirect", get(steam_redirect).post(steam_redirect))
        .route("/openid/id/{subject}", get(steam_discovery))
        .route("/token", post(provider_token))
        .route("/user", get(provider_user))
        .with_state(provider);
    Ok((
        origin,
        tokio::spawn(async move { axum::serve(listener, app).await }),
    ))
}

// Malformed assertions are signed by the fixture OP where indicated: rejection
// must come from the RP's contract, not only the fake signature verifier.
async fn steam_negative_assertions(
    app: &Router,
    provider: &Arc<Mutex<Provider>>,
    subject: u64,
    cache: &CacheStore,
) -> Result<()> {
    for (field, value) in [
        ("openid.ns", "http://specs.openid.net/auth/1.1".to_owned()),
        ("openid.mode", "check_authentication".into()),
        (
            "openid.op_endpoint",
            "http://169.254.169.254/latest/meta-data/".into(),
        ),
        (
            "openid.return_to",
            format!("{ORIGIN}{STEAM_CALLBACK}?state=other"),
        ),
        (
            "openid.claimed_id",
            format!("https://attacker.invalid/openid/id/{subject}"),
        ),
        (
            "openid.identity",
            format!("https://steamcommunity.com/openid/id/{}", subject + 1),
        ),
        (
            "openid.signed",
            "op_endpoint,claimed_id,return_to,response_nonce,assoc_handle".into(),
        ),
        (
            "openid.signed",
            "op_endpoint,claimed_id,identity,return_to,response_nonce,assoc_handle,identity".into(),
        ),
        ("openid.assoc_handle", "".into()),
        ("openid.response_nonce", "not-a-timestamp".into()),
        (
            "openid.response_nonce",
            format!(
                "{}expired",
                (chrono::Utc::now() - chrono::Duration::minutes(6)).format("%Y-%m-%dT%H:%M:%SZ")
            ),
        ),
        (
            "openid.response_nonce",
            format!(
                "{}future",
                (chrono::Utc::now() + chrono::Duration::minutes(2)).format("%Y-%m-%dT%H:%M:%SZ")
            ),
        ),
    ] {
        let mut browser = Browser::default();
        let path = browser.start(app, provider, subject).await?;
        let mut fields = callback_fields(&path)?;
        fields.insert(field.into(), value);
        sign_steam(&mut fields, provider)?;
        let exchanges = provider
            .lock()
            .map_err(|_| anyhow::anyhow!("provider mutex"))?
            .exchanges;
        redirected(
            &browser
                .call(app, "GET", &callback_query(&fields), Value::Null)
                .await?,
            "/login?provider_error=PROVIDER_UNAVAILABLE",
        )?;
        ensure!(!browser.cookies.contains_key("sessionid"));
        ensure!(
            provider
                .lock()
                .map_err(|_| anyhow::anyhow!("provider mutex"))?
                .exchanges
                == exchanges,
            "malformed {field} reached direct verification"
        );
    }
    for suffix in [
        "0".into(),
        format!("0{subject}"),
        "18446744073709551616".into(),
        format!("{subject}?other=true"),
        format!("{subject}/"),
    ] {
        let mut browser = Browser::default();
        let path = browser.start(app, provider, subject).await?;
        let mut fields = callback_fields(&path)?;
        for key in ["openid.claimed_id", "openid.identity"] {
            fields.insert(
                key.into(),
                format!("https://steamcommunity.com/openid/id/{suffix}"),
            );
        }
        sign_steam(&mut fields, provider)?;
        redirected(
            &browser
                .call(app, "GET", &callback_query(&fields), Value::Null)
                .await?,
            "/login?provider_error=PROVIDER_UNAVAILABLE",
        )?;
        ensure!(!browser.cookies.contains_key("sessionid"));
    }
    for duplicate in [
        "openid.ns",
        "openid.mode",
        "openid.return_to",
        "openid.sig",
        "openid.response_nonce",
    ] {
        let mut browser = Browser::default();
        let path = browser.start(app, provider, subject).await?;
        redirected(
            &browser
                .call(
                    app,
                    "GET",
                    &format!("{path}&{duplicate}=duplicate"),
                    Value::Null,
                )
                .await?,
            "/login?provider_error=INVALID_STATE",
        )?;
        ensure!(!browser.cookies.contains_key("sessionid"));
    }
    for response in [
        format!("ns:{OPENID_NS}\nis_valid:false\n"),
        format!("ns:{OPENID_NS}\nerror:is_valid:true\n"),
        format!("ns:{OPENID_NS}\nis_valid:truejunk\n"),
        format!("ns:{OPENID_NS}\nis_valid:false\nis_valid:true\n"),
        "ns:other\nis_valid:true\n".into(),
        "is_valid:true\n".into(),
        "x".repeat(17_000),
    ] {
        provider
            .lock()
            .map_err(|_| anyhow::anyhow!("provider mutex"))?
            .verification_reply = Some(response);
        let mut browser = Browser::default();
        let path = browser.start(app, provider, subject).await?;
        redirected(
            &browser.call(app, "GET", &path, Value::Null).await?,
            "/login?provider_error=PROVIDER_UNAVAILABLE",
        )?;
        ensure!(!browser.cookies.contains_key("sessionid"));
    }
    provider
        .lock()
        .map_err(|_| anyhow::anyhow!("provider mutex"))?
        .verification_reply = None;
    for response in [
        "<html>not discovery</html>".to_owned(),
        "<xrds:XRDS xmlns:xrds=\"xri://$xrds\" xmlns=\"xri://$xrd*($v*2.0)\"><XRD><Service><Type>http://specs.openid.net/auth/2.0/signon</Type><URI>https://attacker.invalid/</URI></Service></XRD></xrds:XRDS>".into(),
    ] {
        provider.lock().map_err(|_|anyhow::anyhow!("provider mutex"))?.discovery_reply=Some(response);
        let mut browser=Browser::default();
        let path=browser.start(app,provider,subject).await?;
        redirected(&browser.call(app,"GET",&path,Value::Null).await?,"/login?provider_error=PROVIDER_UNAVAILABLE")?;
        ensure!(!browser.cookies.contains_key("sessionid"));
    }
    provider
        .lock()
        .map_err(|_| anyhow::anyhow!("provider mutex"))?
        .discovery_reply = None;
    provider
        .lock()
        .map_err(|_| anyhow::anyhow!("provider mutex"))?
        .verification_redirect = true;
    let mut redirected_op = Browser::default();
    let path = redirected_op.start(app, provider, subject).await?;
    redirected(
        &redirected_op.call(app, "GET", &path, Value::Null).await?,
        "/login?provider_error=PROVIDER_UNAVAILABLE",
    )?;
    {
        let mut provider = provider
            .lock()
            .map_err(|_| anyhow::anyhow!("provider mutex"))?;
        ensure!(
            provider.redirected_requests == 0,
            "OpenID verification followed a redirect"
        );
        provider.verification_redirect = false;
    }
    // Two separately valid state-bound assertions reuse one provider nonce. The
    // mock OP validates both: YDB must supply the independent replay barrier.
    let mut first = Browser::default();
    let path = first.start(app, provider, subject).await?;
    let nonce = callback_fields(&path)?
        .get("openid.response_nonce")
        .context("nonce")?
        .clone();
    redirected(
        &first.call(app, "GET", &path, Value::Null).await?,
        "/account",
    )?;
    let mut second = Browser::default();
    let path = second.start(app, provider, subject).await?;
    let mut fields = callback_fields(&path)?;
    fields.insert("openid.response_nonce".into(), nonce.clone());
    sign_steam(&mut fields, provider)?;
    redirected(
        &second
            .call(app, "GET", &callback_query(&fields), Value::Null)
            .await?,
        "/login?provider_error=INVALID_STATE",
    )?;
    ensure!(!second.cookies.contains_key("sessionid"));
    ensure!(
        cache
            .get(
                &format!("steam-nonce:{:x}", Sha256::digest(nonce.as_bytes())),
                SystemTime::now()
            )
            .await?
            .is_some()
    );
    // Independent browser states race for the same nonce; exactly one may issue.
    let mut left = Browser::default();
    let left_path = left.start(app, provider, subject).await?;
    let nonce = callback_fields(&left_path)?
        .get("openid.response_nonce")
        .context("race nonce")?
        .clone();
    let mut right = Browser::default();
    let right_path = right.start(app, provider, subject).await?;
    let mut right_fields = callback_fields(&right_path)?;
    right_fields.insert("openid.response_nonce".into(), nonce);
    sign_steam(&mut right_fields, provider)?;
    let right_path = callback_query(&right_fields);
    let (left_reply, right_reply) = tokio::join!(
        left.call(app, "GET", &left_path, Value::Null),
        right.call(app, "GET", &right_path, Value::Null)
    );
    ensure!(
        [left_reply?, right_reply?]
            .iter()
            .filter(|reply| reply
                .headers
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok())
                == Some("/account"))
            .count()
            == 1,
        "shared nonce issued more or fewer than one session"
    );
    // Historical HTTP claimed IDs map to the same numeric binding. Discovery
    // and direct verification still use the pinned HTTPS endpoint in production.
    let mut legacy = Browser::default();
    let path = legacy.start(app, provider, subject).await?;
    let mut fields = callback_fields(&path)?;
    for field in ["openid.claimed_id", "openid.identity"] {
        fields.insert(
            field.into(),
            format!("http://steamcommunity.com/openid/id/{subject}"),
        );
    }
    sign_steam(&mut fields, provider)?;
    redirected(
        &legacy
            .call(app, "GET", &callback_query(&fields), Value::Null)
            .await?,
        "/account",
    )?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires migrated local YDB on localhost:2136 and /local"]
async fn github_browser_login_binds_state_identity_and_mfa() -> Result<()> {
    browser_login_binds_state_identity_and_mfa(Kind::Github).await
}

#[tokio::test]
#[ignore = "requires migrated local YDB on localhost:2136 and /local"]
async fn discord_browser_login_binds_state_identity_and_mfa() -> Result<()> {
    browser_login_binds_state_identity_and_mfa(Kind::Discord).await
}

#[tokio::test]
#[ignore = "requires migrated local YDB on localhost:2136 and /local"]
async fn steam_openid_browser_login_binds_assertion_identity_and_mfa() -> Result<()> {
    browser_login_binds_state_identity_and_mfa(Kind::Steam).await
}

async fn browser_login_binds_state_identity_and_mfa(kind: Kind) -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "refuse non-local YDB"
    );
    let name = kind.name();
    let other_name = kind.other().name();
    let start_path = format!("/api/v1/auth/oauth/login/{name}");
    let callback_path = format!("/api/v1/auth/oauth/callback/{name}");
    let pending_path = format!("{start_path}/pending");
    let complete_path = format!("{start_path}/complete");
    let cancel_path = format!("{start_path}/cancel");
    let mfa_redirect = format!("/login?provider_mfa={name}");
    let flow_cookie = format!("__Host-id_{name}_flow");
    let mfa_cookie = format!("__Host-id_{name}_mfa");
    let other_start = format!("/api/v1/auth/oauth/login/{other_name}");
    let other_complete = format!("{other_start}/complete");
    let other_pending = format!("{other_start}/pending");
    let other_callback = format!("/api/v1/auth/oauth/callback/{other_name}");
    let other_flow_cookie = format!("__Host-id_{other_name}_flow");
    let other_mfa_cookie = format!("__Host-id_{other_name}_mfa");
    let client = Arc::new(id_runtime::connect_ydb().await?);
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let account = (match kind {
        Kind::Github => 1_000_000_000,
        Kind::Discord => 1_100_000_000,
        Kind::Steam => 1_200_000_000,
    }) + i32::try_from(stamp % 100_000_000)?;
    let identity = Uuid::new_v4();
    let other_identity = Uuid::new_v4();
    let subject = u64::try_from(stamp % 9_000_000_000 + 1)?
        + if kind == Kind::Steam {
            76_561_198_000_000_000
        } else {
            0
        };
    let table = format!("id_{name}_test_{}", identity.simple());
    let cache = CacheStore::new(client.clone(), &table, "", 1)?;
    let codec = Arc::new(SessionCodec::new(SECRET, &[])?);
    let jwt = Arc::new(AccountJwtCodec::new(SECRET)?);
    let email = format!("{name}-{}@example.invalid", identity.simple());
    let provider = Arc::new(Mutex::new(Provider {
        kind,
        email: email.clone(),
        ..Provider::default()
    }));
    let other_provider = Arc::new(Mutex::new(Provider {
        kind: kind.other(),
        email: email.clone(),
        ..Provider::default()
    }));
    let (provider_origin, server) = serve_provider(provider.clone()).await?;
    let (other_origin, other_server) = serve_provider(other_provider.clone()).await?;
    let options = LoginHttpOptions {
        session_cookie_name: "sessionid".into(),
        csrf_cookie_name: "csrftoken".into(),
        session_cookie_secure: true,
        csrf_cookie_secure: true,
        session_same_site: SameSite::Lax,
        csrf_same_site: SameSite::Lax,
        session_cookie_domain: None,
        csrf_cookie_domain: None,
        session_cookie_age: 3600,
        login_ip_limit: 1000,
        trusted_origins: vec![ORIGIN.into()],
        device_fingerprint_salt: "synthetic-device-salt".into(),
    };
    let login = Arc::new(LoginHttpConfig::new(
        client.clone(),
        cache.clone(),
        codec.clone(),
        AccountJwtCodec::new(SECRET)?,
        MediaUrl::new("https://id.example.invalid/media/")?,
        options,
    )?);
    let config = kind
        .config(login.clone())?
        .with_loopback_provider(&provider_origin)?;
    let other_config = kind
        .other()
        .config(login.clone())?
        .with_loopback_provider(&other_origin)?;
    for endpoint in [
        "https://github.com/",
        "http://evil.invalid/",
        "http://127.0.0.1.evil.invalid/",
    ] {
        ensure!(
            kind.config(login.clone())?
                .with_loopback_provider(endpoint)
                .is_err(),
            "non-loopback test provider was accepted"
        );
    }
    let app = provider_login::router(Arc::new(config))
        .merge(provider_login::router(Arc::new(other_config)))
        .merge(form_token_http::router(Arc::new(FormTokenConfig::new(
            cache.clone(),
            "csrftoken".into(),
            true,
            SameSite::Lax,
            None,
        )?)));
    client.query_client().exec(format!("CREATE TABLE `{table}` (cache_key Utf8 NOT NULL,value String,expires_at Uint64,PRIMARY KEY(cache_key))")).await?;
    // Claim a new account ID without overwriting another test's account.
    client.query_client().exec("INSERT INTO auth_user (id,password,is_active,username,first_name,last_name,email,is_staff,is_superuser,date_joined) VALUES ($id,'!synthetic-unusable-password',true,$name,'','',$email,false,false,CurrentUtcDatetime())")
        .param("$id",account).param("$name",table.clone()).param("$email",email.clone()).await?;
    let result: Result<()> = async {
        client.query_client().exec("INSERT INTO account_emailaddress (id,user_id,email,verified,primary) VALUES ($id,$id,$email,true,true)").param("$id",account).param("$email",email.clone()).await?;
        client.query_client().exec("INSERT INTO accounts_accountemaillookup (user_id,email_key) VALUES ($id,$email)")
            .param("$id",account).param("$email",email.clone()).await?;
        client.query_client().exec("INSERT INTO usid_user (user_id,username,display_name,email,email_verified,status,system_admin,created_at) VALUES ($id,$name,'',$email,true,'active',false,CurrentUtcDatetime())")
            .param("$id",identity).param("$name",table.clone()).param("$email",email.clone()).await?;
        client.query_client().exec("INSERT INTO accounts_accountidentity (user_id,identity_id,public_subject,created_at) VALUES ($id,$identity,$subject,CurrentUtcDatetime())")
            .param("$id",account).param("$identity",identity).param("$subject",table.clone()).await?;
        client.query_client().exec("INSERT INTO socialaccount_socialaccount (id,user_id,provider,uid,last_login,date_joined,extra_data) VALUES ($id,$id,$provider,$subject,CurrentUtcDatetime(),CurrentUtcDatetime(),Unwrap(CAST('{}' AS Json)))")
            .param("$id",account).param("$subject",subject.to_string()).param("$provider", name).await?;

        client.query_client().exec("INSERT INTO socialaccount_socialaccount (id,user_id,provider,uid,last_login,date_joined,extra_data) VALUES ($row,$user,$provider,$subject,CurrentUtcDatetime(),CurrentUtcDatetime(),Unwrap(CAST('{}' AS Json)))")
            .param("$row",account + 200_000_000).param("$user",account)
            .param("$provider",other_name).param("$subject",subject.to_string()).await?;

        // Swapping the callback and cookie cannot move a state to another provider,
        // even when its record is copied into that provider's cache namespace.
        let mut state_owner = Browser::default();
        let owner_callback = state_owner.start(&app,&provider,subject).await?;
        let state = Url::parse(&format!("{ORIGIN}{owner_callback}"))?.query_pairs()
            .find(|(key,_)|key=="state").context("swapped state")?.1.into_owned();
        let now = SystemTime::now();
        let CacheValue::String(flow) = cache.get(&format!("{name}-state:{state}"),now).await?.context("state record")?
            else { anyhow::bail!("state record format"); };
        let mut flow: Value = serde_json::from_str(&flow)?;
        ensure!(flow["provider"] == name);
        flow["callback"] = json!(format!("{ORIGIN}{other_callback}"));
        ensure!(cache.add(&format!("{other_name}-state:{state}"),&CacheValue::String(flow.to_string()),Some(now + Duration::from_secs(300)),now).await?);
        let mut swapped = state_owner.clone();
        swapped.cookies.insert(other_flow_cookie.clone(),state_owner.cookies.get(&flow_cookie).context("source flow cookie")?.clone());
        let calls = other_provider.lock().map_err(|_| anyhow::anyhow!("provider mutex"))?.exchanges;
        redirected(&swapped.call(&app,"GET",&owner_callback.replacen(&callback_path,&other_callback,1),Value::Null).await?,"/login?provider_error=INVALID_STATE")?;
        ensure!(other_provider.lock().map_err(|_| anyhow::anyhow!("provider mutex"))?.exchanges == calls,"cross-provider state reached token exchange");
        ensure!(!swapped.cookies.contains_key("sessionid"));
        redirected(&state_owner.call(&app,"GET",&owner_callback,Value::Null).await?,"/account")?;

        if kind == Kind::Steam {
            steam_negative_assertions(&app,&provider,subject,&cache).await?;
        }
        if kind == Kind::Discord {
            for bad_id in [json!(subject),json!("0"),json!(format!("0{subject}")),json!(format!("+{subject}")),json!("18446744073709551616"),Value::Null] {
                provider.lock().map_err(|_| anyhow::anyhow!("provider mutex"))?.user_id_override=Some(bad_id);
                let mut malformed = Browser::default();
                let path = malformed.start(&app,&provider,subject).await?;
                redirected(&malformed.call(&app,"GET",&path,Value::Null).await?,"/login?provider_error=PROVIDER_UNAVAILABLE")?;
                ensure!(!malformed.cookies.contains_key("sessionid"));
            }
            provider.lock().map_err(|_| anyhow::anyhow!("provider mutex"))?.user_id_override=None;
            provider.lock().map_err(|_| anyhow::anyhow!("provider mutex"))?.omit_identify=true;
            let mut missing_scope = Browser::default();
            let path = missing_scope.start(&app,&provider,subject).await?;
            redirected(&missing_scope.call(&app,"GET",&path,Value::Null).await?,"/login?provider_error=PROVIDER_UNAVAILABLE")?;
            ensure!(!missing_scope.cookies.contains_key("sessionid"));
            provider.lock().map_err(|_| anyhow::anyhow!("provider mutex"))?.omit_identify=false;
        }

        let mut browser = Browser::default();
        let no_csrf = browser.call(&app,"POST",&start_path,json!({})).await?;
        ensure!(no_csrf.status == StatusCode::FORBIDDEN && no_csrf.body["code"] == "CSRF_FAILED");
        let form = browser.call(&app,"GET","/api/v1/auth/form_token?purpose=login",Value::Null).await?;
        let bad_next = browser.call(&app,"POST",&start_path,json!({"form_token":form.body["form_token"],"next":"https://attacker.invalid/"})).await?;
        ensure!(bad_next.status == StatusCode::BAD_REQUEST && bad_next.body["code"] == "INVALID_REDIRECT");
        let callback = browser.start(&app,&provider,subject).await?;
        let calls = provider.lock().map_err(|_| anyhow::anyhow!("provider mutex"))?.exchanges;
        let denied = Browser::default().call(&app,"GET",&callback,Value::Null).await?;
        redirected(&denied,"/login?provider_error=INVALID_STATE")?;
        ensure!(provider.lock().map_err(|_| anyhow::anyhow!("provider mutex"))?.exchanges == calls,
            "cookie mismatch reached provider");
        let mut duplicate = browser.clone();
        let denied = duplicate.call(&app,"GET",&format!("{callback}&state=duplicate"),Value::Null).await?;
        redirected(&denied,"/login?provider_error=INVALID_STATE")?;
        duplicate = browser.clone();
        let reply = browser.call(&app,"GET",&callback,Value::Null).await?;
        redirected(&reply,"/account")?;
        let token = browser.cookies.get("sessionid").context("no session cookie")?;
        let principal = id_runtime::session_store::restore_django_principal(&client,codec.clone(),token,
            id_runtime::session_store::LEGACY_BACKENDS,SystemTime::now()).await?.context("session cannot restore")?;
        ensure!(principal.account_id.get() == i64::from(account) && principal.identity_id.get() == identity);
        let replay = duplicate.call(&app,"GET",&callback,Value::Null).await?;
        redirected(&replay,"/login?provider_error=INVALID_STATE")?;

        let mut expired = Browser::default();
        let path = expired.start(&app,&provider,subject).await?;
        let state = Url::parse(&format!("{ORIGIN}{path}"))?.query_pairs()
            .find(|(key,_)|key=="state").context("expired state")?.1.into_owned();
        client.query_client().exec(format!("UPDATE `{table}` SET expires_at=CAST(0 AS Uint64) WHERE cache_key=$key"))
            .param("$key",cache.key(&format!("{name}-state:{state}"))).await?;
        redirected(&expired.call(&app,"GET",&path,Value::Null).await?,"/login?provider_error=INVALID_STATE")?;

        let mut race = Browser::default();
        let path = race.start(&app,&provider,subject).await?;
        let mut other = race.clone();
        let (first,second) = tokio::join!(race.call(&app,"GET",&path,Value::Null),other.call(&app,"GET",&path,Value::Null));
        let first = first?;
        let second = second?;
        let winners = [first,second].iter().filter(|r|r.headers.get(header::LOCATION)
            .and_then(|v|v.to_str().ok())==Some("/account")).count();
        ensure!(winners==1,"concurrent callback issued more or fewer than one session");

        let mut denied = Browser::default();
        let path = denied.start(&app,&provider,subject).await?;
        let denied_path = if kind == Kind::Steam {
            let fields = callback_fields(&path)?;
            let form = BTreeMap::from([("state".into(),fields.get("state").context("cancel state")?.clone()),("openid.ns".into(),OPENID_NS.into()),("openid.mode".into(),"cancel".into())]);
            callback_query(&form)
        } else {format!("{path}&error=access_denied&error_description=private-provider-message")};
        redirected(&denied.call(&app,"GET",&denied_path,Value::Null).await?,"/login?provider_error=PROVIDER_DENIED")?;
        let mut unavailable = Browser::default();
        let path = unavailable.start(&app,&provider,subject).await?;
        let parsed = Url::parse(&format!("{ORIGIN}{path}"))?;
        let state = parsed.query_pairs().find(|(key,_)|key=="state").context("callback state")?.1.into_owned();
        let unavailable_path = if kind == Kind::Steam {
            let mut fields=callback_fields(&path)?;
            fields.insert("openid.sig".into(),STANDARD.encode([0u8;20]));
            callback_query(&fields)
        } else {format!("{callback_path}?state={state}&code=invalid-code")};
        redirected(&unavailable.call(&app,"GET",&unavailable_path,Value::Null).await?,"/login?provider_error=PROVIDER_UNAVAILABLE")?;

        // A subject linked only to another provider must not authenticate Steam.
        if kind == Kind::Steam {
            client.query_client().exec("UPDATE socialaccount_socialaccount SET uid=$subject WHERE id=$id")
                .param("$id",account+200_000_000).param("$subject",(subject+1).to_string()).await?;
        }
        // A provider email matching the local email is not an identity proof.
        let mut unknown = Browser::default();
        let path = unknown.start(&app,&provider,subject+1).await?;
        let reply = unknown.call(&app,"GET",&path,Value::Null).await?;
        redirected(&reply,"/login?provider_error=ACCOUNT_NOT_LINKED")?;
        ensure!(!unknown.cookies.contains_key("sessionid"));
        if kind == Kind::Steam {
            client.query_client().exec("UPDATE socialaccount_socialaccount SET uid=$subject WHERE id=$id")
                .param("$id",account+200_000_000).param("$subject",subject.to_string()).await?;
        }

        client.query_client().exec("INSERT INTO usid_external_identity (id,user_id,provider,subject,created_at) VALUES ($id,$identity,$provider,$subject,CurrentUtcDatetime())")
            .param("$id",i64::from(account)).param("$identity",other_identity).param("$subject",subject.to_string()).param("$provider", name).await?;
        let mut conflict = Browser::default();
        let path = conflict.start(&app,&provider,subject).await?;
        let reply = conflict.call(&app,"GET",&path,Value::Null).await?;
        redirected(&reply,"/login?provider_error=IDENTITY_CONFLICT")?;
        client.query_client().exec("DELETE FROM usid_external_identity WHERE id=$id").param("$id",i64::from(account)).await?;

        // The UUID binding alone is a supported linked account, and both tables must agree when present.
        client.query_client().exec("INSERT INTO usid_external_identity (id,user_id,provider,subject,created_at) VALUES ($id,$identity,$provider,$subject,CurrentUtcDatetime())")
            .param("$id",i64::from(account)).param("$identity",identity).param("$subject",subject.to_string()).param("$provider", name).await?;
        client.query_client().exec("DELETE FROM socialaccount_socialaccount WHERE id=$id").param("$id",account).await?;
        let mut external = Browser::default();
        let path = external.start(&app,&provider,subject).await?;
        redirected(&external.call(&app,"GET",&path,Value::Null).await?,"/account")?;
        client.query_client().exec("INSERT INTO socialaccount_socialaccount (id,user_id,provider,uid,last_login,date_joined,extra_data) VALUES ($id,$id,$provider,$subject,CurrentUtcDatetime(),CurrentUtcDatetime(),Unwrap(CAST('{}' AS Json)))")
            .param("$id",account).param("$subject",subject.to_string()).param("$provider", name).await?;
        client.query_client().exec("DELETE FROM usid_external_identity WHERE id=$id").param("$id",i64::from(account)).await?;

        client.query_client().exec("INSERT INTO mfa_authenticator (id,user_id,type,data,created_at) VALUES ($id,$user,'recovery_codes',Unwrap(CAST($data AS Json)),CurrentUtcDatetime())")
            .param("$id",i64::from(account)).param("$user",account)
            .param("$data",json!({"migrated_codes":["87654321","13579246","24681357","42424242"]}).to_string()).await?;
        // Both named tests exercise this transition, covering GitHub→Discord and
        // Discord→GitHub. A copied old browser cannot finish the canceled flow.
        let mut switching = Browser::default();
        let path = switching.start(&app,&provider,subject).await?;
        redirected(&switching.call(&app,"GET",&path,Value::Null).await?,&mfa_redirect)?;
        let mut old_provider = switching.clone();
        let path = switching.start(&app,&other_provider,subject).await?;
        let old_pending = old_provider.call(&app,"GET",&pending_path,Value::Null).await?;
        ensure!(old_pending.status == StatusCode::UNAUTHORIZED && old_pending.body["code"] == "PROVIDER_FLOW_EXPIRED");
        let old_complete = old_provider.call(&app,"POST",&complete_path,json!({"recovery_code":"42424242"})).await?;
        ensure!(old_complete.status == StatusCode::UNAUTHORIZED && !old_provider.cookies.contains_key("sessionid"));
        redirected(&switching.call(&app,"GET",&path,Value::Null).await?,&format!("/login?provider_mfa={other_name}"))?;
        ensure!(switching.call(&app,"GET",&other_pending,Value::Null).await?.body["active"] == true);
        let success = switching.call(&app,"POST",&other_complete,json!({"recovery_code":"42424242"})).await?;
        ensure!(success.status == StatusCode::OK && switching.cookies.contains_key("sessionid"),"provider switch failed: {} {}",success.status,success.body);
        let principal = id_runtime::session_store::restore_django_principal(&client,codec.clone(),switching.cookies.get("sessionid").context("switched session")?,
            id_runtime::session_store::LEGACY_BACKENDS,SystemTime::now()).await?.context("switched session restore")?;
        ensure!(principal.account_id.get() == i64::from(account) && principal.identity_id.get() == identity);

        if kind == Kind::Steam {
            // Reverse direction: GitHub → Steam cancels a copied GitHub MFA flow.
            let mut reverse=Browser::default();
            let path=reverse.start(&app,&other_provider,subject).await?;
            redirected(&reverse.call(&app,"GET",&path,Value::Null).await?,&format!("/login?provider_mfa={other_name}"))?;
            let mut old=reverse.clone();
            let path=reverse.start(&app,&provider,subject).await?;
            ensure!(old.call(&app,"GET",&other_pending,Value::Null).await?.status==StatusCode::UNAUTHORIZED);
            ensure!(old.call(&app,"POST",&other_complete,json!({"recovery_code":"24681357"})).await?.status==StatusCode::UNAUTHORIZED);
            redirected(&reverse.call(&app,"GET",&path,Value::Null).await?,&mfa_redirect)?;
            ensure!(reverse.call(&app,"POST",&cancel_path,json!({})).await?.status==StatusCode::OK);
            for status in ["suspended","deleted"] {
                let mut stale=Browser::default();
                let path=stale.start(&app,&provider,subject).await?;
                redirected(&stale.call(&app,"GET",&path,Value::Null).await?,&mfa_redirect)?;
                client.query_client().exec("UPDATE usid_user SET status=$status WHERE user_id=$id").param("$id",identity).param("$status",status).await?;
                let denied=stale.call(&app,"POST",&complete_path,json!({"recovery_code":"24681357"})).await?;
                ensure!(denied.status==StatusCode::UNAUTHORIZED && !stale.cookies.contains_key("sessionid"));
                client.query_client().exec("UPDATE usid_user SET status='active' WHERE user_id=$id").param("$id",identity).await?;
            }
        }

        let mut mfa = Browser::default();
        let path = mfa.start(&app,&provider,subject).await?;
        let reply = mfa.call(&app,"GET",&path,Value::Null).await?;
        redirected(&reply,&mfa_redirect)?;
        ensure!(!mfa.cookies.contains_key("sessionid"));
        let pending = mfa.call(&app,"GET",&pending_path,Value::Null).await?;
        ensure!(pending.status == StatusCode::OK && pending.body["active"] == true && pending.body["next"] == "/account"
            && pending.body["methods"].as_array().is_some_and(|m|m.contains(&json!("recovery_codes"))));
        // Cross-provider cookies and a copied proof are not authorization for
        // the other endpoint, even when both providers bind to the same account.
        let token = mfa.cookies.get(&mfa_cookie).context("primary MFA cookie")?.clone();
        let mut swapped = mfa.clone();
        swapped.cookies.insert(other_flow_cookie.clone(),mfa.cookies.get(&flow_cookie).context("primary flow cookie")?.clone());
        swapped.cookies.insert(other_mfa_cookie.clone(),token.clone());
        ensure!(swapped.call(&app,"GET",&other_pending,Value::Null).await?.status == StatusCode::UNAUTHORIZED);
        let now = SystemTime::now();
        let source_key = format!("{name}-mfa:{token}");
        let copy_key = format!("{other_name}-mfa:{token}");
        let original = cache.get(&source_key,now).await?.context("primary pending proof")?;
        let CacheValue::String(encoded) = &original else { anyhow::bail!("pending proof format"); };
        let mut value: Value = serde_json::from_str(encoded)?;
        ensure!(value["proof"]["provider"] == name);
        ensure!(cache.add(&copy_key,&original,Some(now + Duration::from_secs(300)),now).await?);
        for route in [&other_pending,&other_complete] {
            let mut attempt = swapped.clone();
            let response = attempt.call(&app,if route==&other_pending {"GET"} else {"POST"},route,json!({"recovery_code":"87654321"})).await?;
            ensure!(response.status == StatusCode::UNAUTHORIZED && response.body["code"] == "PROVIDER_FLOW_EXPIRED"
                && !attempt.cookies.contains_key("sessionid"),"cross-provider proof accepted");
        }
        // Corrupting the provider tag in the original namespace is rejected too.
        value["proof"]["provider"] = json!(other_name);
        cache.delete(&source_key).await?;
        ensure!(cache.add(&source_key,&CacheValue::String(value.to_string()),Some(now + Duration::from_secs(300)),now).await?);
        let mut bad_tag = mfa.clone();
        ensure!(bad_tag.call(&app,"POST",&complete_path,json!({"recovery_code":"87654321"})).await?.status == StatusCode::UNAUTHORIZED);
        cache.delete(&source_key).await?;
        ensure!(cache.add(&source_key,&original,Some(now + Duration::from_secs(300)),now).await?);
        cache.delete(&copy_key).await?;
        ensure!(mfa.call(&app,"GET",&pending_path,Value::Null).await?.body["active"] == true);

        let wrong = mfa.call(&app,"POST",&complete_path,json!({"recovery_code":"bad-code"})).await?;
        ensure!(wrong.status == StatusCode::UNAUTHORIZED && wrong.body["code"] == "INVALID_MFA"
            && !mfa.cookies.contains_key("sessionid"));
        let mut mfa_replay = mfa.clone();
        let good = mfa.call(&app,"POST",&complete_path,json!({"recovery_code":"87654321"})).await?;
        ensure!(good.status == StatusCode::OK && good.body["next"] == "/account", "MFA completion: {} {}",good.status,good.body);
        ensure!(!mfa.cookies.contains_key(&flow_cookie) && !mfa.cookies.contains_key(&mfa_cookie));
        let refresh = good.body["refresh_token"].as_str().context("refresh token")?;
        ensure!(matches!(id_runtime::account_jwt_refresh::rotate(&client,codec.clone(),jwt.clone(),refresh,SystemTime::now()).await?,
            id_runtime::account_jwt_refresh::RefreshOutcome::Rotated(_)), "provider session refresh failed");
        let replay = mfa_replay.call(&app,"POST",&complete_path,json!({"recovery_code":"87654321"})).await?;
        ensure!(replay.status == StatusCode::UNAUTHORIZED && !mfa_replay.cookies.contains_key("sessionid"));

        // Cancel a real pending attempt, then replay the copied browser state.
        let mut canceled = Browser::default();
        let path = canceled.start(&app,&provider,subject).await?;
        redirected(&canceled.call(&app,"GET",&path,Value::Null).await?,&mfa_redirect)?;
        let mut old = canceled.clone();
        ensure!(canceled.call(&app,"POST",&cancel_path,json!({})).await?.status == StatusCode::OK);
        ensure!(old.call(&app,"POST",&complete_path,json!({"recovery_code":"13579246"})).await?.status == StatusCode::UNAUTHORIZED);

        // Begin replaces the pending flow even if an old browser copy retains both cookies.
        let mut replaced = Browser::default();
        let path = replaced.start(&app,&provider,subject).await?;
        redirected(&replaced.call(&app,"GET",&path,Value::Null).await?,&mfa_redirect)?;
        let mut old = replaced.clone();
        let fresh_path = replaced.start(&app,&provider,subject).await?;
        let stale = old.call(&app,"POST",&complete_path,json!({"recovery_code":"13579246"})).await?;
        ensure!(stale.status == StatusCode::UNAUTHORIZED && stale.body["code"] == "PROVIDER_FLOW_EXPIRED");
        redirected(&replaced.call(&app,"GET",&fresh_path,Value::Null).await?,&mfa_redirect)?;
        // The canceled attempts did not burn the recovery code; concurrent completes issue once.
        let mut race = replaced.clone();
        let (left,right) = tokio::join!(
            replaced.call(&app,"POST",&complete_path,json!({"recovery_code":"13579246"})),
            race.call(&app,"POST",&complete_path,json!({"recovery_code":"13579246"})));
        let responses = [left?,right?];
        ensure!(responses.iter().filter(|response| response.status == StatusCode::OK).count() == 1,
            "concurrent MFA completion did not issue exactly once");
        ensure!(responses.iter().filter(|response| response.body.pointer("/meta/session_token").is_some()).count() == 1);

        // Account state is rechecked after a genuine provider callback and before code consumption.
        for deleting in [false,true] {
            let mut changed = Browser::default();
            let path = changed.start(&app,&provider,subject).await?;
            redirected(&changed.call(&app,"GET",&path,Value::Null).await?,&mfa_redirect)?;
            if deleting {
                client.query_client().exec("INSERT INTO accounts_accountdeletionrequest (id,user_id,status,requested_at,reason) VALUES ($id,$user,'pending',CurrentUtcDatetime(),'synthetic provider test')")
                    .param("$id",i64::from(account)).param("$user",account).await?;
            } else {
                client.query_client().exec("UPDATE auth_user SET is_active=false WHERE id=$id").param("$id",account).await?;
            }
            let denied = changed.call(&app,"POST",&complete_path,json!({"recovery_code":"24681357"})).await?;
            ensure!(denied.status == StatusCode::UNAUTHORIZED && denied.body["code"] == "PROVIDER_FLOW_EXPIRED"
                && !changed.cookies.contains_key("sessionid"));
            if deleting {
                client.query_client().exec("DELETE FROM accounts_accountdeletionrequest WHERE id=$id")
                    .param("$id",i64::from(account)).await?;
            } else {
                client.query_client().exec("UPDATE auth_user SET is_active=true WHERE id=$id").param("$id",account).await?;
            }
        }
        let mut unused = client.query_client().query_row("SELECT CAST(data AS Utf8) AS data FROM mfa_authenticator WHERE id=$id")
            .param("$id",i64::from(account)).await?;
        let unused: String = unused.remove_field_by_name("data")?.try_into()?;
        let unused: Value = serde_json::from_str(&unused)?;
        ensure!(unused["migrated_codes"] == json!(["24681357"]), "failed attempts consumed recovery codes");

        // Real TOTP verification and replay budget use the shared issuer, including fresh auth metadata.
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let secret = match id_runtime::mfa_secret::key_from_env()? {
            Some(key) => key.seal(i64::from(account), id_compat::mfa_seal::SecretKind::Totp, secret)?,
            None => secret.into(),
        };
        client.query_client().exec("UPDATE mfa_authenticator SET type='totp',data=Unwrap(CAST($data AS Json)) WHERE id=$id")
            .param("$id",i64::from(account)).param("$data",json!({"secret":secret}).to_string()).await?;
        let mut totp = Browser::default();
        let path = totp.start(&app,&provider,subject).await?;
        redirected(&totp.call(&app,"GET",&path,Value::Null).await?,&mfa_redirect)?;
        let pending = totp.call(&app,"GET",&pending_path,Value::Null).await?;
        ensure!(pending.body["methods"] == json!(["totp"]) && pending.body["restart_required"] == false);
        let code = totp_code(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
        let good = totp.call(&app,"POST",&complete_path,json!({"mfa_code":code})).await?;
        ensure!(good.status == StatusCode::OK, "TOTP completion: {} {}",good.status,good.body);
        let mut data = client.query_client().query_row("SELECT session_data FROM django_session WHERE session_key=$key")
            .param("$key",totp.cookies.get("sessionid").context("TOTP session cookie")?.clone()).await?;
        let data: String = data.remove_field_by_name("session_data")?.try_into()?;
        let decoded = codec.decode(&data)?;
        ensure!(decoded.data["id_mfa_verified_user_id"] == account.to_string());
        let methods = decoded.data["account_authentication_methods"].as_array().context("session methods")?;
        ensure!(methods.iter().any(|method|method["method"] == "socialaccount" && method["provider"] == name));
        ensure!(methods.iter().any(|method|method["method"] == "mfa" && method["type"] == "totp"));
        let mut reuse = Browser::default();
        let path = reuse.start(&app,&provider,subject).await?;
        redirected(&reuse.call(&app,"GET",&path,Value::Null).await?,&mfa_redirect)?;
        let rejected = reuse.call(&app,"POST",&complete_path,json!({"mfa_code":code})).await?;
        ensure!(rejected.status == StatusCode::UNAUTHORIZED && rejected.body["code"] == "INVALID_MFA");

        // Passkey-only accounts cannot complete this first slice with an arbitrary MFA code.
        client.query_client().exec("UPDATE mfa_authenticator SET type='webauthn',data=Unwrap(CAST('{}' AS Json)) WHERE id=$id")
            .param("$id",i64::from(account)).await?;
        let mut passkey = Browser::default();
        let path = passkey.start(&app,&provider,subject).await?;
        redirected(&passkey.call(&app,"GET",&path,Value::Null).await?,&mfa_redirect)?;
        let pending = passkey.call(&app,"GET",&pending_path,Value::Null).await?;
        ensure!(pending.body["methods"] == json!([]) && pending.body["restart_required"] == true);
        let denied = passkey.call(&app,"POST",&complete_path,json!({"mfa_code":"000000"})).await?;
        ensure!(denied.status == StatusCode::UNAUTHORIZED && !passkey.cookies.contains_key("sessionid"));
        let pending_cookie = passkey.cookies.get(&mfa_cookie).context("MFA cookie")?;
        client.query_client().exec(format!("UPDATE `{table}` SET expires_at=CAST(0 AS Uint64) WHERE cache_key=$key"))
            .param("$key",cache.key(&format!("{name}-mfa:{pending_cookie}"))).await?;
        let expired = passkey.call(&app,"GET",&pending_path,Value::Null).await?;
        ensure!(expired.status == StatusCode::UNAUTHORIZED && expired.body["restart_required"] == true && expired.body.get("next").is_none());

        // Wrong codes retain pending until the shared account attempt budget blocks them.
        let mut limited = Browser::default();
        let path = limited.start(&app,&provider,subject).await?;
        redirected(&limited.call(&app,"GET",&path,Value::Null).await?,&mfa_redirect)?;
        let mut blocked = false;
        for _ in 0..6 {
            let response = limited.call(&app,"POST",&complete_path,json!({"mfa_code":"000000"})).await?;
            if response.status == StatusCode::TOO_MANY_REQUESTS {
                ensure!(response.body["code"] == "LOGIN_RATE_LIMITED" && response.headers.contains_key(header::RETRY_AFTER));
                blocked = true;
                break;
            }
            ensure!(response.status == StatusCode::UNAUTHORIZED && response.body["code"] == "INVALID_MFA");
        }
        ensure!(blocked, "MFA attempt budget was not enforced");

        let mut unlinked = Browser::default();
        let path = unlinked.start(&app,&provider,subject).await?;
        redirected(&unlinked.call(&app,"GET",&path,Value::Null).await?,&mfa_redirect)?;
        client.query_client().exec("DELETE FROM socialaccount_socialaccount WHERE id=$id").param("$id",account).await?;
        let denied = unlinked.call(&app,"POST",&complete_path,json!({"recovery_code":"13579246"})).await?;
        ensure!(denied.status == StatusCode::UNAUTHORIZED && !unlinked.cookies.contains_key("sessionid"));
        Ok(())
    }.await;
    server.abort();
    other_server.abort();
    // Discover every fixture-owned credential, including one whose HTTP reply was lost.
    for token in ids(
        &client,
        "SELECT session_key AS value FROM usersessions_usersession WHERE user_id=$id".into(),
        account,
    )
    .await?
    {
        client
            .query_client()
            .exec("DELETE FROM django_session WHERE session_key=$key")
            .param("$key", token)
            .await?;
    }
    for row in ids(
        &client,
        "SELECT CAST(id AS Utf8) AS value FROM token_blacklist_outstandingtoken WHERE user_id=$id"
            .into(),
        account,
    )
    .await?
    {
        client
            .query_client()
            .exec("DELETE FROM token_blacklist_blacklistedtoken WHERE token_id=$id")
            .param("$id", row.parse::<i64>()?)
            .await?;
    }
    for row in ids(
        &client,
        "SELECT CAST(id AS Utf8) AS value FROM accounts_loginevent WHERE user_id=$id".into(),
        account,
    )
    .await?
    {
        client
            .query_client()
            .exec("DELETE FROM accounts_newdevicemailoutbox WHERE event_id=$id")
            .param("$id", row.parse::<i64>()?)
            .await?;
    }
    for table in [
        "usersessions_usersession",
        "core_usersessionmeta",
        "core_usersessiontoken",
        "token_blacklist_outstandingtoken",
        "accounts_loginevent",
        "accounts_userdevice",
        "mfa_authenticator",
        "socialaccount_socialaccount",
        "account_emailaddress",
        "accounts_accountemaillookup",
        "accounts_accountdeletionrequest",
        "accounts_accountidentity",
    ] {
        client
            .query_client()
            .exec(format!("DELETE FROM `{table}` WHERE user_id=$id"))
            .param("$id", account)
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM usid_external_identity WHERE id=$id AND (user_id=$owner OR user_id=$identity)")
        .param("$id", i64::from(account))
        .param("$owner", other_identity)
        .param("$identity", identity)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM usid_user WHERE user_id=$id")
        .param("$id", identity)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM auth_user WHERE id=$id")
        .param("$id", account)
        .await?;
    client
        .query_client()
        .exec(format!("DROP TABLE `{table}`"))
        .await?;
    result
}
