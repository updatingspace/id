#![recursion_limit = "256"]
#![cfg(debug_assertions)]
//! Real YDB and loopback provider transport; not acceptance against GitHub itself.
use anyhow::{Context, Result, ensure};
use axum::{
    Form, Json, Router,
    body::{Body, to_bytes},
    extract::State,
    http::{HeaderMap, Request, StatusCode, header},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cookie::SameSite;
use hmac::{Hmac, Mac};
use id_compat::{account_jwt::AccountJwtCodec, session::SessionCodec};
use id_runtime::{
    cache_store::CacheStore,
    form_token_http::{self, FormTokenConfig},
    github_login::{self, CALLBACK_PATH, COMPLETE_PATH, GithubLoginConfig, START_PATH},
    login_http::{LoginHttpConfig, LoginHttpOptions},
    media_url::MediaUrl,
};
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

const ORIGIN: &str = "https://id.example.invalid";
const SECRET: &[u8] = b"synthetic-github-login-session-secret-at-least-32";
const PENDING: &str = "/api/v1/auth/oauth/login/github/pending";
const CANCEL: &str = "/api/v1/auth/oauth/login/github/cancel";

#[derive(Default)]
struct Provider {
    // Each code has the browser's original PKCE challenge and a provider subject.
    codes: BTreeMap<String, (String, u64)>,
    tokens: BTreeMap<String, u64>,
    exchanges: u32,
    email: String,
}

async fn provider_token(
    State(state): State<Arc<Mutex<Provider>>>,
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
    if form.get("client_id").map(String::as_str) != Some("synthetic-client")
        || form.get("client_secret").map(String::as_str) != Some("synthetic-secret")
        || form.get("redirect_uri") != Some(&format!("{ORIGIN}{CALLBACK_PATH}"))
        || URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) != challenge
    {
        return invalid();
    }
    let token = format!("synthetic-bearer-{code}");
    provider.tokens.insert(token.clone(), subject);
    (
        StatusCode::OK,
        Json(json!({"access_token":token,"token_type":"bearer"})),
    )
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
            Some((*provider.tokens.get(token)?, provider.email.clone()))
        });
    match subject {
        Some((subject, email)) => (StatusCode::OK, Json(json!({"id":subject,"email":email}))),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"message":"invalid token"})),
        ),
    }
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
            .header(header::USER_AGENT, "Synthetic GitHub browser");
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
        let token = self
            .call(
                app,
                "GET",
                "/api/v1/auth/form_token?purpose=login",
                Value::Null,
            )
            .await?;
        ensure!(token.status == StatusCode::OK);
        let r = self
            .call(
                app,
                "POST",
                START_PATH,
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
            .find(|cookie| cookie.starts_with("__Host-id_github_flow="))
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
        ensure!(
            query.get("redirect_uri") == Some(&format!("{ORIGIN}{CALLBACK_PATH}"))
                && query.get("code_challenge_method").map(String::as_str) == Some("S256")
        );
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
            "{CALLBACK_PATH}?code={code}&state={}",
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
        "unexpected redirect: {} {:?}",
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

#[tokio::test]
#[ignore = "requires migrated local YDB on localhost:2136 and /local"]
async fn github_browser_login_binds_state_identity_and_mfa() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "refuse non-local YDB"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let account = 1_000_000_000 + i32::try_from(stamp % 100_000_000)?;
    let identity = Uuid::new_v4();
    let other_identity = Uuid::new_v4();
    let subject = u64::try_from(stamp % 9_000_000_000 + 1)?;
    let table = format!("id_github_test_{}", identity.simple());
    let cache = CacheStore::new(client.clone(), &table, "", 1)?;
    let codec = Arc::new(SessionCodec::new(SECRET, &[])?);
    let jwt = Arc::new(AccountJwtCodec::new(SECRET)?);
    let email = format!("github-{}@example.invalid", identity.simple());
    let provider = Arc::new(Mutex::new(Provider {
        email: email.clone(),
        ..Provider::default()
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let provider_origin = format!("http://{}/", listener.local_addr()?);
    let server_app = Router::new()
        .route("/token", post(provider_token))
        .route("/user", get(provider_user))
        .with_state(provider.clone());
    let server = tokio::spawn(async move { axum::serve(listener, server_app).await });
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
    let config = GithubLoginConfig::new(
        login.clone(),
        "synthetic-client".into(),
        "synthetic-secret".into(),
        format!("{ORIGIN}{CALLBACK_PATH}"),
        vec!["/account".into()],
    )?
    .with_loopback_provider(&provider_origin)?;
    for endpoint in [
        "https://github.com/",
        "http://evil.invalid/",
        "http://127.0.0.1.evil.invalid/",
    ] {
        ensure!(
            GithubLoginConfig::new(
                login.clone(),
                "synthetic-client".into(),
                "synthetic-secret".into(),
                format!("{ORIGIN}{CALLBACK_PATH}"),
                vec!["/account".into()]
            )?
            .with_loopback_provider(endpoint)
            .is_err(),
            "non-loopback test provider was accepted"
        );
    }
    let app = github_login::router(Arc::new(config)).merge(form_token_http::router(Arc::new(
        FormTokenConfig::new(cache.clone(), "csrftoken".into(), true, SameSite::Lax, None)?,
    )));
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
        client.query_client().exec("INSERT INTO socialaccount_socialaccount (id,user_id,provider,uid,last_login,date_joined,extra_data) VALUES ($id,$id,'github',$subject,CurrentUtcDatetime(),CurrentUtcDatetime(),Unwrap(CAST('{}' AS Json)))")
            .param("$id",account).param("$subject",subject.to_string()).await?;

        let mut browser = Browser::default();
        let no_csrf = browser.call(&app,"POST",START_PATH,json!({})).await?;
        ensure!(no_csrf.status == StatusCode::FORBIDDEN && no_csrf.body["code"] == "CSRF_FAILED");
        let form = browser.call(&app,"GET","/api/v1/auth/form_token?purpose=login",Value::Null).await?;
        let bad_next = browser.call(&app,"POST",START_PATH,json!({"form_token":form.body["form_token"],"next":"https://attacker.invalid/"})).await?;
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
            .param("$key",cache.key(&format!("github-state:{state}"))).await?;
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
        redirected(&denied.call(&app,"GET",&format!("{path}&error=access_denied&error_description=private-provider-message"),Value::Null).await?,
            "/login?provider_error=PROVIDER_DENIED")?;
        let mut unavailable = Browser::default();
        let path = unavailable.start(&app,&provider,subject).await?;
        let parsed = Url::parse(&format!("{ORIGIN}{path}"))?;
        let state = parsed.query_pairs().find(|(key,_)|key=="state").context("callback state")?.1.into_owned();
        redirected(&unavailable.call(&app,"GET",&format!("{CALLBACK_PATH}?state={state}&code=invalid-code"),Value::Null).await?,
            "/login?provider_error=PROVIDER_UNAVAILABLE")?;

        // A provider email matching the local email is not an identity proof.
        let mut unknown = Browser::default();
        let path = unknown.start(&app,&provider,subject+1).await?;
        let reply = unknown.call(&app,"GET",&path,Value::Null).await?;
        redirected(&reply,"/login?provider_error=ACCOUNT_NOT_LINKED")?;
        ensure!(!unknown.cookies.contains_key("sessionid"));
        client.query_client().exec("INSERT INTO usid_external_identity (id,user_id,provider,subject,created_at) VALUES ($id,$identity,'github',$subject,CurrentUtcDatetime())")
            .param("$id",i64::from(account)).param("$identity",other_identity).param("$subject",subject.to_string()).await?;
        let mut conflict = Browser::default();
        let path = conflict.start(&app,&provider,subject).await?;
        let reply = conflict.call(&app,"GET",&path,Value::Null).await?;
        redirected(&reply,"/login?provider_error=IDENTITY_CONFLICT")?;
        client.query_client().exec("DELETE FROM usid_external_identity WHERE id=$id").param("$id",i64::from(account)).await?;

        // The UUID binding alone is a supported linked account, and both tables must agree when present.
        client.query_client().exec("INSERT INTO usid_external_identity (id,user_id,provider,subject,created_at) VALUES ($id,$identity,'github',$subject,CurrentUtcDatetime())")
            .param("$id",i64::from(account)).param("$identity",identity).param("$subject",subject.to_string()).await?;
        client.query_client().exec("DELETE FROM socialaccount_socialaccount WHERE id=$id").param("$id",account).await?;
        let mut external = Browser::default();
        let path = external.start(&app,&provider,subject).await?;
        redirected(&external.call(&app,"GET",&path,Value::Null).await?,"/account")?;
        client.query_client().exec("INSERT INTO socialaccount_socialaccount (id,user_id,provider,uid,last_login,date_joined,extra_data) VALUES ($id,$id,'github',$subject,CurrentUtcDatetime(),CurrentUtcDatetime(),Unwrap(CAST('{}' AS Json)))")
            .param("$id",account).param("$subject",subject.to_string()).await?;
        client.query_client().exec("DELETE FROM usid_external_identity WHERE id=$id").param("$id",i64::from(account)).await?;

        client.query_client().exec("INSERT INTO mfa_authenticator (id,user_id,type,data,created_at) VALUES ($id,$user,'recovery_codes',Unwrap(CAST($data AS Json)),CurrentUtcDatetime())")
            .param("$id",i64::from(account)).param("$user",account)
            .param("$data",json!({"migrated_codes":["87654321","13579246","24681357"]}).to_string()).await?;
        let mut mfa = Browser::default();
        let path = mfa.start(&app,&provider,subject).await?;
        let reply = mfa.call(&app,"GET",&path,Value::Null).await?;
        redirected(&reply,"/login?provider_mfa=github")?;
        ensure!(!mfa.cookies.contains_key("sessionid"));
        let pending = mfa.call(&app,"GET",PENDING,Value::Null).await?;
        ensure!(pending.status == StatusCode::OK && pending.body["active"] == true && pending.body["next"] == "/account"
            && pending.body["methods"].as_array().is_some_and(|m|m.contains(&json!("recovery_codes"))));
        let wrong = mfa.call(&app,"POST",COMPLETE_PATH,json!({"recovery_code":"bad-code"})).await?;
        ensure!(wrong.status == StatusCode::UNAUTHORIZED && wrong.body["code"] == "INVALID_MFA"
            && !mfa.cookies.contains_key("sessionid"));
        let mut mfa_replay = mfa.clone();
        let good = mfa.call(&app,"POST",COMPLETE_PATH,json!({"recovery_code":"87654321"})).await?;
        ensure!(good.status == StatusCode::OK && good.body["next"] == "/account", "MFA completion: {} {}",good.status,good.body);
        ensure!(!mfa.cookies.contains_key("__Host-id_github_flow") && !mfa.cookies.contains_key("__Host-id_github_mfa"));
        let refresh = good.body["refresh_token"].as_str().context("refresh token")?;
        ensure!(matches!(id_runtime::account_jwt_refresh::rotate(&client,codec.clone(),jwt.clone(),refresh,SystemTime::now()).await?,
            id_runtime::account_jwt_refresh::RefreshOutcome::Rotated(_)), "provider session refresh failed");
        let replay = mfa_replay.call(&app,"POST",COMPLETE_PATH,json!({"recovery_code":"87654321"})).await?;
        ensure!(replay.status == StatusCode::UNAUTHORIZED && !mfa_replay.cookies.contains_key("sessionid"));

        // Cancel a real pending attempt, then replay the copied browser state.
        let mut canceled = Browser::default();
        let path = canceled.start(&app,&provider,subject).await?;
        redirected(&canceled.call(&app,"GET",&path,Value::Null).await?,"/login?provider_mfa=github")?;
        let mut old = canceled.clone();
        ensure!(canceled.call(&app,"POST",CANCEL,json!({})).await?.status == StatusCode::OK);
        ensure!(old.call(&app,"POST",COMPLETE_PATH,json!({"recovery_code":"13579246"})).await?.status == StatusCode::UNAUTHORIZED);

        // Begin replaces the pending flow even if an old browser copy retains both cookies.
        let mut replaced = Browser::default();
        let path = replaced.start(&app,&provider,subject).await?;
        redirected(&replaced.call(&app,"GET",&path,Value::Null).await?,"/login?provider_mfa=github")?;
        let mut old = replaced.clone();
        let fresh_path = replaced.start(&app,&provider,subject).await?;
        let stale = old.call(&app,"POST",COMPLETE_PATH,json!({"recovery_code":"13579246"})).await?;
        ensure!(stale.status == StatusCode::UNAUTHORIZED && stale.body["code"] == "PROVIDER_FLOW_EXPIRED");
        redirected(&replaced.call(&app,"GET",&fresh_path,Value::Null).await?,"/login?provider_mfa=github")?;
        // The canceled attempts did not burn the recovery code; concurrent completes issue once.
        let mut race = replaced.clone();
        let (left,right) = tokio::join!(
            replaced.call(&app,"POST",COMPLETE_PATH,json!({"recovery_code":"13579246"})),
            race.call(&app,"POST",COMPLETE_PATH,json!({"recovery_code":"13579246"})));
        let responses = [left?,right?];
        ensure!(responses.iter().filter(|response| response.status == StatusCode::OK).count() == 1,
            "concurrent MFA completion did not issue exactly once");
        ensure!(responses.iter().filter(|response| response.body.pointer("/meta/session_token").is_some()).count() == 1);

        // Account state is rechecked after a genuine provider callback and before code consumption.
        for deleting in [false,true] {
            let mut changed = Browser::default();
            let path = changed.start(&app,&provider,subject).await?;
            redirected(&changed.call(&app,"GET",&path,Value::Null).await?,"/login?provider_mfa=github")?;
            if deleting {
                client.query_client().exec("INSERT INTO accounts_accountdeletionrequest (id,user_id,status,requested_at,reason) VALUES ($id,$user,'pending',CurrentUtcDatetime(),'synthetic provider test')")
                    .param("$id",i64::from(account)).param("$user",account).await?;
            } else {
                client.query_client().exec("UPDATE auth_user SET is_active=false WHERE id=$id").param("$id",account).await?;
            }
            let denied = changed.call(&app,"POST",COMPLETE_PATH,json!({"recovery_code":"24681357"})).await?;
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
        redirected(&totp.call(&app,"GET",&path,Value::Null).await?,"/login?provider_mfa=github")?;
        let pending = totp.call(&app,"GET",PENDING,Value::Null).await?;
        ensure!(pending.body["methods"] == json!(["totp"]) && pending.body["restart_required"] == false);
        let code = totp_code(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
        let good = totp.call(&app,"POST",COMPLETE_PATH,json!({"mfa_code":code})).await?;
        ensure!(good.status == StatusCode::OK, "TOTP completion: {} {}",good.status,good.body);
        let mut data = client.query_client().query_row("SELECT session_data FROM django_session WHERE session_key=$key")
            .param("$key",totp.cookies.get("sessionid").context("TOTP session cookie")?.clone()).await?;
        let data: String = data.remove_field_by_name("session_data")?.try_into()?;
        let decoded = codec.decode(&data)?;
        ensure!(decoded.data["id_mfa_verified_user_id"] == account.to_string());
        let methods = decoded.data["account_authentication_methods"].as_array().context("session methods")?;
        ensure!(methods.iter().any(|method|method["method"] == "socialaccount" && method["provider"] == "github"));
        ensure!(methods.iter().any(|method|method["method"] == "mfa" && method["type"] == "totp"));
        let mut reuse = Browser::default();
        let path = reuse.start(&app,&provider,subject).await?;
        redirected(&reuse.call(&app,"GET",&path,Value::Null).await?,"/login?provider_mfa=github")?;
        let rejected = reuse.call(&app,"POST",COMPLETE_PATH,json!({"mfa_code":code})).await?;
        ensure!(rejected.status == StatusCode::UNAUTHORIZED && rejected.body["code"] == "INVALID_MFA");

        // Passkey-only accounts cannot complete this first slice with an arbitrary MFA code.
        client.query_client().exec("UPDATE mfa_authenticator SET type='webauthn',data=Unwrap(CAST('{}' AS Json)) WHERE id=$id")
            .param("$id",i64::from(account)).await?;
        let mut passkey = Browser::default();
        let path = passkey.start(&app,&provider,subject).await?;
        redirected(&passkey.call(&app,"GET",&path,Value::Null).await?,"/login?provider_mfa=github")?;
        let pending = passkey.call(&app,"GET",PENDING,Value::Null).await?;
        ensure!(pending.body["methods"] == json!([]) && pending.body["restart_required"] == true);
        let denied = passkey.call(&app,"POST",COMPLETE_PATH,json!({"mfa_code":"000000"})).await?;
        ensure!(denied.status == StatusCode::UNAUTHORIZED && !passkey.cookies.contains_key("sessionid"));
        let pending_cookie = passkey.cookies.get("__Host-id_github_mfa").context("MFA cookie")?;
        client.query_client().exec(format!("UPDATE `{table}` SET expires_at=CAST(0 AS Uint64) WHERE cache_key=$key"))
            .param("$key",cache.key(&format!("github-mfa:{pending_cookie}"))).await?;
        let expired = passkey.call(&app,"GET",PENDING,Value::Null).await?;
        ensure!(expired.status == StatusCode::UNAUTHORIZED && expired.body["restart_required"] == true && expired.body.get("next").is_none());

        // Wrong codes retain pending until the shared account attempt budget blocks them.
        let mut limited = Browser::default();
        let path = limited.start(&app,&provider,subject).await?;
        redirected(&limited.call(&app,"GET",&path,Value::Null).await?,"/login?provider_mfa=github")?;
        let mut blocked = false;
        for _ in 0..6 {
            let response = limited.call(&app,"POST",COMPLETE_PATH,json!({"mfa_code":"000000"})).await?;
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
        redirected(&unlinked.call(&app,"GET",&path,Value::Null).await?,"/login?provider_mfa=github")?;
        client.query_client().exec("DELETE FROM socialaccount_socialaccount WHERE id=$id").param("$id",account).await?;
        let denied = unlinked.call(&app,"POST",COMPLETE_PATH,json!({"recovery_code":"13579246"})).await?;
        ensure!(denied.status == StatusCode::UNAUTHORIZED && !unlinked.cookies.contains_key("sessionid"));
        Ok(())
    }.await;
    server.abort();
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
