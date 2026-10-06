#![recursion_limit = "256"]
//! Disposable account while Chromium exercises the real recovery UI and API.

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
    meta_id: i64,
    identity_id: Uuid,
    session: String,
    email: String,
    old_hash: String,
    new_password: &'static str,
}

async fn seed(client: &Client, fixture: &Fixture, codec: &SessionCodec) -> Result<()> {
    let now = SystemTime::now();
    let epoch = now.duration_since(UNIX_EPOCH)?.as_secs();
    let data = json!({
        "_auth_user_id":fixture.account_id.to_string(),
        "_auth_user_backend":"django.contrib.auth.backends.ModelBackend",
        "_auth_user_hash":codec.auth_hash(&fixture.old_hash)?,
        "account_authentication_methods":[{"method":"password","at":epoch as f64}],
    });
    let signed = codec.encode(
        data.as_object().context("session payload")?,
        i64::try_from(epoch)?,
        true,
    )?;
    let name = format!("rust-reset-browser-{}", fixture.account_id);
    client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $password, true, $name, '', '', $email, false, false, CurrentUtcDatetime())")
        .param("$id", fixture.account_id).param("$password", fixture.old_hash.clone())
        .param("$name", name.clone()).param("$email", fixture.email.clone()).await?;
    client
        .query_client()
        .exec("UPSERT INTO accounts_accountemaillookup (user_id, email_key) VALUES ($id, $email)")
        .param("$id", fixture.account_id)
        .param("$email", fixture.email.clone())
        .await?;
    client.query_client().exec("UPSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($id, $id, $email, true, true)")
        .param("$id", fixture.account_id).param("$email", fixture.email.clone()).await?;
    client.query_client().exec("UPSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, $name, $name, $email, true, 'active', false, CurrentUtcDatetime())")
        .param("$id", fixture.identity_id).param("$name", name.clone())
        .param("$email", fixture.email.clone()).await?;
    client.query_client().exec("UPSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($id, $identity, $subject, CurrentUtcDatetime())")
        .param("$id", fixture.account_id).param("$identity", fixture.identity_id)
        .param("$subject", format!("reset-browser-sub-{}", fixture.account_id)).await?;
    client.query_client().exec("UPSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, $data, CAST($expires AS Datetime))")
        .param("$key", fixture.session.clone()).param("$data", signed)
        .param("$expires", now + Duration::from_secs(3600)).await?;
    client.query_client().exec("INSERT INTO core_usersessionmeta (id, user_id, session_key, user_agent, revoked_reason, first_seen) VALUES ($id, $user, $key, '', '', CAST($now AS Datetime))")
        .param("$id", fixture.meta_id).param("$user", fixture.account_id)
        .param("$key", fixture.session.clone()).param("$now", now).await?;
    Ok(())
}

async fn cleanup(client: &Client, fixture: &Fixture) -> Result<()> {
    for table in ["id_password_reset", "id_password_mail"] {
        let mut query = client.query_client();
        let mut stream = query
            .query(format!("SELECT id FROM `{table}` WHERE user_id = $id"))
            .param("$id", fixture.account_id)
            .await?;
        let mut ids = Vec::<String>::new();
        while let Some(rows) = stream.next_result_set().await? {
            for mut row in rows {
                ids.push(row.remove_field_by_name("id")?.try_into()?);
            }
        }
        stream.close().await?;
        for id in ids {
            client
                .query_client()
                .exec(format!("DELETE FROM `{table}` WHERE id = $id"))
                .param("$id", id)
                .await?;
        }
    }
    client
        .query_client()
        .exec("DELETE FROM django_session WHERE session_key = $key")
        .param("$key", fixture.session.clone())
        .await?;
    client
        .query_client()
        .exec("DELETE FROM core_usersessionmeta WHERE id = $id")
        .param("$id", fixture.meta_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM account_emailaddress WHERE id = $id")
        .param("$id", fixture.account_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountemaillookup WHERE user_id = $id")
        .param("$id", fixture.account_id)
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
        .exec("DELETE FROM auth_user WHERE id = $id")
        .param("$id", fixture.account_id)
        .await?;
    Ok(())
}

async fn reset_id(client: &Client, account_id: i32) -> Result<Option<Uuid>> {
    let mut query = client.query_client();
    let mut stream = query
        .query("SELECT id FROM id_password_reset WHERE user_id = $id")
        .param("$id", account_id)
        .await?;
    let mut ids = Vec::new();
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            let id: String = row.remove_field_by_name("id")?.try_into()?;
            ids.push(Uuid::parse_str(&id)?);
        }
    }
    stream.close().await?;
    ensure!(ids.len() <= 1, "browser created multiple reset intents");
    Ok(ids.pop())
}

async fn verify(client: &Client, fixture: &Fixture, id: Uuid) -> Result<()> {
    let mut row = client
        .query_client()
        .query_row("SELECT password FROM auth_user WHERE id = $id")
        .param("$id", fixture.account_id)
        .await?;
    let hash: String = row.remove_field_by_name("password")?.try_into()?;
    ensure!(id_compat::password::verify(fixture.new_password, &hash)?);
    ensure!(!id_compat::password::verify(
        "Initial synthetic reset password 123!",
        &hash
    )?);
    let session = client
        .query_client()
        .query_row("SELECT session_key FROM django_session WHERE session_key = $key")
        .param("$key", fixture.session.clone())
        .optional()
        .await?;
    ensure!(
        session.is_none(),
        "old browser session survived password reset"
    );
    let mut row = client
        .query_client()
        .query_row("SELECT consumed_at, recipient FROM id_password_reset WHERE id = $id")
        .param("$id", id.to_string())
        .await?;
    let consumed: Option<SystemTime> = row.remove_field_by_name("consumed_at")?.try_into()?;
    let recipient: String = row.remove_field_by_name("recipient")?.try_into()?;
    ensure!(
        consumed.is_some() && recipient.is_empty(),
        "reset intent was not consumed and scrubbed"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires migrated local YDB and an external Chromium driver"]
async fn hold_account_for_real_recovery_browser() -> Result<()> {
    ensure!(
        matches!(
            env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && env::var("YDB_DATABASE")? == "/local"
            && env::var("DJANGO_DEBUG")? == "true",
        "browser recovery fixture requires local debug YDB"
    );
    let output = env::var("ID_RESET_BROWSER_FIXTURE_OUTPUT")?;
    let key_output = env::var("ID_RESET_BROWSER_KEY_OUTPUT")?;
    let done = env::var("ID_RESET_BROWSER_DONE")?;
    ensure!(
        !Path::new(&output).exists()
            && !Path::new(&key_output).exists()
            && !Path::new(&done).exists()
    );
    let random = rand::random::<u64>();
    let account_id = -i32::try_from(random % 1_000_000_000 + 1)?;
    let fixture = Fixture {
        account_id,
        meta_id: i64::from(account_id).abs() + 10_000_000_000,
        identity_id: Uuid::from_u128(rand::random()),
        session: format!("{:032x}", rand::random::<u128>()),
        email: format!("reset-browser-{random:016x}@example.invalid"),
        old_hash: id_compat::password::hash_new("Initial synthetic reset password 123!")?,
        new_password: "Garden meadow river 7426!",
    };
    let client = id_runtime::connect_ydb().await?;
    let codec = SessionCodec::new(env::var("DJANGO_SECRET_KEY")?.as_bytes(), &[])?;
    if let Err(error) = seed(&client, &fixture, &codec).await {
        let _ = cleanup(&client, &fixture).await;
        return Err(error);
    }
    let result: Result<()> = async {
        fs::write(
            &output,
            serde_json::to_vec(&json!({
                "synthetic":true, "format_version":1, "email":fixture.email,
                "session_token":fixture.session, "new_password":fixture.new_password,
            }))?,
        )?;
        let id = loop {
            if let Some(id) = reset_id(&client, fixture.account_id).await? {
                break id;
            }
            if Path::new(&done).exists() {
                bail!("browser finished before requesting recovery");
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        };
        let key = id_runtime::password_reset::ResetKey::from_env()?.issue(id)?;
        fs::write(&key_output, key)?;
        for _ in 0..480 {
            if Path::new(&done).exists() {
                return verify(&client, &fixture, id).await;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        bail!("recovery browser fixture completion timed out")
    }
    .await;
    let cleanup_result = cleanup(&client, &fixture).await;
    result.and(cleanup_result)
}
