//! Hold a synthetic account in a disposable local YDB for the real Topcoat deletion journey.

use anyhow::{Context, Result, bail, ensure};
use id_compat::session::SessionCodec;
use serde_json::json;
use std::{
    env, fs,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires explicitly disposable local YDB and Chromium driver"]
async fn hold_account_for_deletion_browser() -> Result<()> {
    ensure!(
        matches!(
            env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2137" | "grpc://127.0.0.1:2137"
        ) && env::var("YDB_DATABASE")? == "/local"
            && env::var("ID_DISPOSABLE_YDB")?.as_str() == "true"
            && env::var("DJANGO_DEBUG")?.as_str() == "true",
        "deletion browser fixture requires explicitly disposable local YDB on 2137"
    );
    let output = env::var("ID_DELETION_BROWSER_FIXTURE_OUTPUT")?;
    let result_path = env::var("ID_DELETION_BROWSER_RESULT")?;
    let done = env::var("ID_DELETION_BROWSER_DONE")?;
    ensure!(
        [&output, &result_path, &done]
            .iter()
            .all(|value| !Path::new(value).exists()),
        "fixture paths must be new"
    );
    let client = id_runtime::connect_ydb().await?;
    ensure!(
        id_runtime::legacy_cutover_reset::is_sealed(&client).await?,
        "legacy cutover must be sealed before the deletion rehearsal"
    );
    let stamp = rand::random::<u64>();
    let account_id = 100_000_000 + i32::try_from(stamp % 800_000_000)?;
    let identity = Uuid::new_v4();
    let session = format!("{:032x}", rand::random::<u128>());
    let email = format!("deletion-browser-{stamp:016x}@example.invalid");
    let password = "synthetic-deletion-browser-password";
    let hash =
        tokio::task::spawn_blocking(move || id_compat::password::hash_new(password)).await??;
    let codec = SessionCodec::new(env::var("DJANGO_SECRET_KEY")?.as_bytes(), &[])?;
    let now = SystemTime::now();
    let payload = json!({
        "_auth_user_id": account_id.to_string(),
        "_auth_user_backend": "accounts.backends.EmailBackend",
        "_auth_user_hash": codec.auth_hash(&hash)?,
    });
    let encoded = codec.encode(
        payload.as_object().context("synthetic session payload")?,
        i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?,
        true,
    )?;
    client.query_client().exec("INSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $hash, true, $name, '', '', $email, false, false, CurrentUtcDatetime())")
        .param("$id", account_id).param("$hash", hash)
        .param("$name", format!("deletion-browser-{stamp}"))
        .param("$email", email.clone()).await?;
    client.query_client().exec("INSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, $name, '', $email, true, 'active', false, CurrentUtcDatetime())")
        .param("$id", identity).param("$name", format!("deletion-browser-{stamp}"))
        .param("$email", email.clone()).await?;
    client.query_client().exec("INSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($owner, $identity, $subject, CurrentUtcDatetime())")
        .param("$owner", account_id).param("$identity", identity)
        .param("$subject", format!("deletion-browser-subject-{stamp}")).await?;
    client.query_client().exec("INSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($id, $owner, $email, true, true)")
        .param("$id", account_id + 1_000_000_000).param("$owner", account_id)
        .param("$email", email.clone()).await?;
    client.query_client().exec("INSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, $data, CAST($expiry AS Datetime))")
        .param("$key", session.clone()).param("$data", encoded)
        .param("$expiry", now + Duration::from_secs(3600)).await?;
    client.query_client().exec("INSERT INTO core_usersessionmeta (id, user_id, session_key, user_agent, first_seen, revoked_reason) VALUES ($id, $owner, $key, 'deletion-browser', CurrentUtcDatetime(), '')")
        .param("$id", i64::from(account_id) + 1_000_000_000).param("$owner", account_id)
        .param("$key", session.clone()).await?;
    let staged = format!("{output}.staged");
    fs::write(
        &staged,
        serde_json::to_vec(&json!({
            "session_token": session, "email": email, "password": password,
        }))?,
    )?;
    fs::rename(staged, &output)?;
    for _ in 0..480 {
        if Path::new(&done).exists() {
            let id: i64 = fs::read_to_string(&result_path)?.trim().parse()?;
            let mut row = client
                .query_client()
                .query_row(
                    "SELECT user_id, status FROM accounts_accountdeletionrequest WHERE id = $id",
                )
                .param("$id", id)
                .await?;
            let owner: i32 = row.remove_field_by_name("user_id")?.try_into()?;
            let status: String = row.remove_field_by_name("status")?.try_into()?;
            ensure!(
                owner == account_id && status == "pending",
                "browser did not create the owner's deletion request"
            );
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    bail!("deletion browser fixture completion timed out")
}
