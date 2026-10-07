#![recursion_limit = "256"]
//! Synthetic account held in local YDB while a browser drives MFA enrollment.

use anyhow::{Context, Result, bail, ensure};
use id_compat::session::SessionCodec;
use serde_json::json;
use std::{
    env, fs,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use ydb::Client;

struct Fixture {
    account_id: i32,
    email_pk: i32,
    identity_id: Uuid,
    session: String,
    email: String,
}

async fn ids(client: &Client, sql: &str, account_id: i32) -> Result<Vec<i64>> {
    let mut query = client.query_client();
    let mut stream = query.query(sql).param("$user_id", account_id).await?;
    let mut found = Vec::new();
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            found.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    stream.close().await?;
    Ok(found)
}

async fn cleanup(client: &Client, fixture: &Fixture) -> Result<()> {
    if env::var("ID_PASSKEY_BROWSER_MODE").as_deref() == Ok("true") {
        let mut query = client.query_client();
        let mut stream = query
            .query("SELECT digest FROM id_passkey_credential WHERE account_id = $user_id")
            .param("$user_id", fixture.account_id)
            .await?;
        let mut digests: Vec<String> = Vec::new();
        while let Some(rows) = stream.next_result_set().await? {
            for mut row in rows {
                digests.push(row.remove_field_by_name("digest")?.try_into()?);
            }
        }
        stream.close().await?;
        for digest in digests {
            client
                .query_client()
                .exec("DELETE FROM id_passkey_credential WHERE digest = $digest")
                .param("$digest", digest)
                .await?;
        }
    }
    for id in ids(client, "SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $user_id", fixture.account_id).await? {
        client.query_client().exec("DELETE FROM mfa_authenticator WHERE id = $id")
            .param("$id", id).await?;
    }
    for id in ids(
        client,
        "SELECT id FROM accounts_accountevent VIEW acct_event_user_idx WHERE user_id = $user_id",
        fixture.account_id,
    )
    .await?
    {
        client
            .query_client()
            .exec("DELETE FROM accounts_accountevent WHERE id = $id")
            .param("$id", id)
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM account_emailaddress WHERE id = $id")
        .param("$id", fixture.email_pk)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountidentity WHERE user_id = $id")
        .param("$id", fixture.account_id)
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
        .param("$id", fixture.account_id)
        .await?;
    Ok(())
}

async fn seed(client: &Client, fixture: &Fixture, codec: &SessionCodec) -> Result<()> {
    let password = "pbkdf2_sha256$1000000$synthetic$synthetic";
    let now = SystemTime::now();
    let epoch = now.duration_since(UNIX_EPOCH)?.as_secs();
    let data = json!({"_auth_user_id":fixture.account_id.to_string(),
        "_auth_user_backend":"django.contrib.auth.backends.ModelBackend",
        "_auth_user_hash":codec.auth_hash(password)?,
        "account_authentication_methods":[{"method":"password","at":epoch as f64}]});
    let signed = codec.encode(
        data.as_object().context("session payload")?,
        i64::try_from(epoch)?,
        true,
    )?;
    let name = format!("rust-totp-browser-{}", fixture.session);
    client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $password, true, $name, '', '', $email, false, false, CurrentUtcDatetime())")
        .param("$id", fixture.account_id).param("$password", password)
        .param("$name", name.clone()).param("$email", fixture.email.clone()).await?;
    client.query_client().exec("UPSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, $data, CAST($expires AS Datetime))")
        .param("$key", fixture.session.clone()).param("$data", signed)
        .param("$expires", now + Duration::from_secs(3600)).await?;
    client.query_client().exec("UPSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, $name, $name, $email, true, 'active', false, CurrentUtcDatetime())")
        .param("$id", fixture.identity_id).param("$name", name)
        .param("$email", fixture.email.clone()).await?;
    client.query_client().exec("UPSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($user_id, $identity_id, $subject, CurrentUtcDatetime())")
        .param("$user_id", fixture.account_id).param("$identity_id", fixture.identity_id)
        .param("$subject", format!("totp-browser-sub-{}", fixture.session)).await?;
    client.query_client().exec("UPSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($id, $user_id, $email, true, true)")
        .param("$id", fixture.email_pk).param("$user_id", fixture.account_id)
        .param("$email", fixture.email.clone()).await?;
    Ok(())
}

async fn verify(client: &Client, fixture: &Fixture, codec: &SessionCodec) -> Result<()> {
    if env::var("ID_PASSKEY_BROWSER_MODE").as_deref() == Ok("true") {
        let mut query = client.query_client();
        let mut stream = query.query("SELECT type FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $user_id")
            .param("$user_id", fixture.account_id).await?;
        let mut kinds: Vec<String> = Vec::new();
        while let Some(rows) = stream.next_result_set().await? {
            for mut row in rows {
                kinds.push(row.remove_field_by_name("type")?.try_into()?);
            }
        }
        stream.close().await?;
        kinds.sort();
        ensure!(
            kinds == ["recovery_codes", "webauthn"],
            "browser registration did not persist passkey and recovery codes: {kinds:?}"
        );
        let mut row = client
            .query_client()
            .query_row("SELECT session_data FROM django_session WHERE session_key = $key")
            .param("$key", fixture.session.clone())
            .await?;
        let signed: String = row.remove_field_by_name("session_data")?.try_into()?;
        let data = codec.decode(&signed)?.data;
        ensure!(
            data.get("id_rust_passkey_pending").is_none()
                && data.get("id_mfa_verified_user_id")
                    == Some(&json!(fixture.account_id.to_string())),
            "browser registration left challenge or no MFA proof"
        );
        return Ok(());
    }
    let mut query = client.query_client();
    let mut stream = query.query("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $user_id")
        .param("$user_id", fixture.account_id).await?;
    let mut remaining = 0;
    while let Some(rows) = stream.next_result_set().await? {
        for _ in rows {
            remaining += 1;
        }
    }
    stream.close().await?;
    ensure!(remaining == 0, "browser disable left MFA credentials");
    let mut query = client.query_client();
    let mut stream = query.query("SELECT action FROM accounts_accountevent VIEW acct_event_user_idx WHERE user_id = $user_id")
        .param("$user_id", fixture.account_id).await?;
    let mut actions: Vec<String> = Vec::new();
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            actions.push(row.remove_field_by_name("action")?.try_into()?);
        }
    }
    stream.close().await?;
    actions.sort();
    ensure!(
        actions
            == [
                "mfa_recovery_regenerated",
                "mfa_totp_disabled",
                "mfa_totp_enabled"
            ],
        "browser MFA audit events missing"
    );
    let mut row = client
        .query_client()
        .query_row("SELECT session_data FROM django_session WHERE session_key = $key")
        .param("$key", fixture.session.clone())
        .await?;
    let signed: String = row.remove_field_by_name("session_data")?.try_into()?;
    let data = codec.decode(&signed)?.data;
    ensure!(
        !data.contains_key("id_mfa_verified_user_id")
            && !data.contains_key("id_rust_totp_pending")
            && data["account_authentication_methods"]
                .as_array()
                .is_some_and(|methods| methods.iter().all(|method| method["method"] != "mfa")),
        "browser disable left MFA proof in session"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires migrated local YDB and external Chromium driver"]
async fn hold_account_for_real_totp_browser() -> Result<()> {
    ensure!(
        matches!(
            env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && env::var("YDB_DATABASE")? == "/local"
            && env::var("DJANGO_DEBUG")? == "true",
        "TOTP browser fixture requires local debug YDB"
    );
    let output = env::var("ID_TOTP_BROWSER_FIXTURE_OUTPUT")?;
    let done = env::var("ID_TOTP_BROWSER_DONE")?;
    ensure!(
        !Path::new(&output).exists() && !Path::new(&done).exists(),
        "fixture paths must be new"
    );
    let random = rand::random::<u64>();
    let account_id = -i32::try_from(random % 1_000_000_000 + 1)?;
    let fixture = Fixture {
        account_id,
        email_pk: account_id - 1,
        identity_id: Uuid::from_u128(rand::random()),
        session: format!("{:032x}", rand::random::<u128>()),
        email: format!("totp-browser-{random:016x}@example.invalid"),
    };
    let codec = SessionCodec::new(env::var("DJANGO_SECRET_KEY")?.as_bytes(), &[])?;
    let client = id_runtime::connect_ydb().await?;
    if let Err(error) = seed(&client, &fixture, &codec).await {
        let _ = cleanup(&client, &fixture).await;
        return Err(error);
    }
    let result: Result<()> = async {
        let staged = format!("{output}.staged");
        fs::write(
            &staged,
            serde_json::to_vec(&json!({"synthetic":true,"format_version":1,
            "session_token":fixture.session,"email":fixture.email}))?,
        )?;
        fs::rename(staged, &output)?;
        for _ in 0..480 {
            if Path::new(&done).exists() {
                return verify(&client, &fixture, &codec).await;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        bail!("TOTP browser fixture completion timed out")
    }
    .await;
    cleanup(&client, &fixture).await?;
    result
}
