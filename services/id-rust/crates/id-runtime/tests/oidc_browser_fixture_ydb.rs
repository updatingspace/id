#![recursion_limit = "256"]
//! Holds a synthetic local-YDB account while an external browser exercises real API/UI servers.

use anyhow::{Context, Result, bail, ensure};
use id_compat::session::SessionCodec;
use serde_json::json;
use std::{
    env, fs,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use url::Url;
use uuid::Uuid;
use ydb::Client;

struct Fixture {
    user_id: i32,
    email_pk: i32,
    client_pk: i64,
    identity_id: Uuid,
    client_id: String,
    session: String,
    subject: String,
    email: String,
    redirect_uri: String,
}

fn local_only() -> Result<()> {
    ensure!(
        matches!(
            env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && env::var("YDB_DATABASE")? == "/local"
            && env::var("DJANGO_DEBUG")? == "true",
        "browser fixture is restricted to local debug YDB"
    );
    Ok(())
}

async fn seed(client: &Client, fixture: &Fixture, codec: &SessionCodec) -> Result<()> {
    let password = "pbkdf2_sha256$1000000$synthetic$synthetic";
    let now = SystemTime::now();
    let payload = json!({"_auth_user_id":fixture.user_id.to_string(),
        "_auth_user_backend":"django.contrib.auth.backends.ModelBackend",
        "_auth_user_hash":codec.auth_hash(password)?});
    let signed = codec.encode(
        payload.as_object().context("session payload")?,
        i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?,
        true,
    )?;
    client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $password, true, $name, 'Browser', 'Fixture', $email, false, false, CurrentUtcDatetime())")
        .param("$id", fixture.user_id).param("$password", password)
        .param("$name", format!("rust-browser-{}", fixture.client_id))
        .param("$email", fixture.email.clone()).await?;
    client.query_client().exec("UPSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, $data, CAST($expires AS Datetime))")
        .param("$key", fixture.session.clone()).param("$data", signed)
        .param("$expires", now + Duration::from_secs(3600)).await?;
    client.query_client().exec("UPSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, $name, 'Browser Fixture', $email, true, 'active', false, CurrentUtcDatetime())")
        .param("$id", fixture.identity_id).param("$name", format!("rust-browser-{}", fixture.client_id))
        .param("$email", fixture.email.clone()).await?;
    client.query_client().exec("UPSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($user_id, $identity_id, $subject, CurrentUtcDatetime())")
        .param("$user_id", fixture.user_id).param("$identity_id", fixture.identity_id)
        .param("$subject", fixture.subject.clone()).await?;
    client.query_client().exec("UPSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($id, $user_id, $email, true, true)")
        .param("$id", fixture.email_pk).param("$user_id", fixture.user_id).param("$email", fixture.email.clone()).await?;
    client.query_client().exec("UPSERT INTO idp_oidcclient (id, client_id, name, logo_url, description, client_secret_hash, redirect_uris, allowed_scopes, grant_types, response_types, is_public, is_first_party, created_at, updated_at) VALUES ($id, $client_id, 'Browser fixture client', '', '', '', Unwrap(CAST($redirects AS Json)), Unwrap(CAST('[\"openid\",\"email\"]' AS Json)), Unwrap(CAST('[\"authorization_code\"]' AS Json)), Unwrap(CAST('[\"code\"]' AS Json)), true, false, CurrentUtcDatetime(), CurrentUtcDatetime())")
        .param("$id", fixture.client_pk).param("$client_id", fixture.client_id.clone())
        .param("$redirects", serde_json::to_string(&[&fixture.redirect_uri])?).await?;
    Ok(())
}

async fn collect_i64(client: &Client, sql: &str, user_id: i32, client_pk: i64) -> Result<Vec<i64>> {
    let mut query = client.query_client();
    let mut rows = query
        .query(sql)
        .param("$user_id", user_id)
        .param("$client_id", client_pk)
        .await?;
    let mut result = Vec::new();
    while let Some(set) = rows.next_result_set().await? {
        for mut row in set {
            result.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    rows.close().await?;
    Ok(result)
}

async fn collect_strings(
    client: &Client,
    sql: &str,
    user_id: i32,
    client_pk: i64,
    column: &str,
) -> Result<Vec<String>> {
    let mut query = client.query_client();
    let mut rows = query
        .query(sql)
        .param("$user_id", user_id)
        .param("$client_id", client_pk)
        .await?;
    let mut result = Vec::new();
    while let Some(set) = rows.next_result_set().await? {
        for mut row in set {
            result.push(row.remove_field_by_name(column)?.try_into()?);
        }
    }
    rows.close().await?;
    Ok(result)
}

async fn cleanup(client: &Client, fixture: &Fixture) -> Result<()> {
    for id in collect_i64(client,
        "SELECT id FROM idp_oidctoken VIEW oidc_token_user_client_idx WHERE user_id = $user_id AND client_id = $client_id",
        fixture.user_id, fixture.client_pk).await? {
        client.query_client().exec("DELETE FROM idp_oidctoken WHERE id = $id").param("$id", id).await?;
    }
    for code in collect_strings(client,
        "SELECT code FROM idp_oidcauthorizationcode VIEW oidc_code_user_idx WHERE user_id = $user_id AND client_id = $client_id",
        fixture.user_id, fixture.client_pk, "code").await? {
        client.query_client().exec("DELETE FROM idp_oidcauthorizationcode WHERE code = $code").param("$code", code).await?;
    }
    for id in collect_strings(client,
        "SELECT request_id FROM idp_oidcauthorizationrequest VIEW oidc_req_user_idx WHERE user_id = $user_id AND client_id = $client_id",
        fixture.user_id, fixture.client_pk, "request_id").await? {
        client.query_client().exec("DELETE FROM idp_oidcauthorizationrequest WHERE request_id = $id").param("$id", id).await?;
    }
    for id in collect_i64(client,
        "SELECT id FROM idp_oidcconsent VIEW oidc_consent_user_idx WHERE user_id = $user_id AND client_id = $client_id",
        fixture.user_id, fixture.client_pk).await? {
        client.query_client().exec("DELETE FROM idp_oidcconsent WHERE id = $id").param("$id", id).await?;
    }
    client
        .query_client()
        .exec("DELETE FROM idp_oidcclient WHERE id = $id")
        .param("$id", fixture.client_pk)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM account_emailaddress WHERE id = $id")
        .param("$id", fixture.email_pk)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountidentity WHERE user_id = $id")
        .param("$id", fixture.user_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM usid_user WHERE user_id = $id")
        .param("$id", fixture.identity_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM django_session WHERE session_key = $key")
        .param("$key", fixture.session.clone())
        .await?;
    client
        .query_client()
        .exec("DELETE FROM auth_user WHERE id = $id")
        .param("$id", fixture.user_id)
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires migrated local YDB and an external browser driver"]
async fn hold_fixture_for_live_browser() -> Result<()> {
    local_only()?;
    let output = env::var("ID_OIDC_BROWSER_FIXTURE_OUTPUT")?;
    let done = env::var("ID_OIDC_BROWSER_DONE")?;
    let redirect_uri = env::var("ID_OIDC_BROWSER_REDIRECT_URI")?;
    let uri = Url::parse(&redirect_uri)?;
    ensure!(
        uri.scheme() == "http"
            && matches!(uri.host_str(), Some("localhost" | "127.0.0.1"))
            && uri.path() == "/callback"
            && uri.query().is_none()
            && uri.fragment().is_none(),
        "fixture redirect must be a local HTTP /callback URL"
    );
    ensure!(
        !Path::new(&output).exists() && !Path::new(&done).exists(),
        "fixture paths must be new"
    );
    let random = rand::random::<u64>();
    let user_id = -i32::try_from(random % 1_000_000_000 + 1)?;
    let fixture = Fixture {
        user_id,
        email_pk: user_id - 1,
        client_pk: -i64::try_from(random % 1_000_000_000 + 10_000_000_000)?,
        identity_id: Uuid::from_u128(rand::random::<u128>()),
        client_id: format!("rust-browser-{random:016x}"),
        session: format!("{:032x}", rand::random::<u128>()),
        subject: format!("rust-browser-sub-{random:016x}"),
        email: format!("rust-browser-{random:016x}@example.invalid"),
        redirect_uri,
    };
    let codec = SessionCodec::new(env::var("DJANGO_SECRET_KEY")?.as_bytes(), &[])?;
    let client = id_runtime::connect_ydb().await?;
    if let Err(error) = seed(&client, &fixture, &codec).await {
        let _ = cleanup(&client, &fixture).await;
        return Err(error);
    }
    let wait: Result<()> = async {
        let staged = format!("{output}.staged");
        fs::write(
            &staged,
            serde_json::to_vec(&json!({"synthetic":true,"format_version":1,
            "client_id":fixture.client_id,"session_token":fixture.session,
            "redirect_uri":fixture.redirect_uri,"subject":fixture.subject,"email":fixture.email}))?,
        )?;
        fs::rename(staged, &output)?;
        for _ in 0..480 {
            if Path::new(&done).exists() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        bail!("browser fixture completion signal timed out")
    }
    .await;
    let clean = cleanup(&client, &fixture).await;
    clean?;
    wait
}
