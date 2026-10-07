#![recursion_limit = "256"]
//! Synthetic operator and target held in local YDB for a real browser journey.

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
#[ignore = "requires migrated local YDB and external Chromium driver"]
async fn hold_operator_for_real_browser() -> Result<()> {
    ensure!(
        matches!(
            env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && env::var("YDB_DATABASE")? == "/local"
            && env::var("DJANGO_DEBUG")? == "true",
        "operator browser fixture requires local debug YDB"
    );
    let output = env::var("ID_ADMIN_BROWSER_FIXTURE_OUTPUT")?;
    let done = env::var("ID_ADMIN_BROWSER_DONE")?;
    ensure!(
        !Path::new(&output).exists() && !Path::new(&done).exists(),
        "fixture paths must be new"
    );
    let stamp = rand::random::<u64>();
    let operator_id = 1_000_000_000 + i32::try_from(stamp % 300_000_000)?;
    let target_id = operator_id + 400_000_000;
    let email_id = target_id - 1_000_000_000;
    let deletion_id = i64::try_from(stamp % 1_000_000_000_000 + 1)?;
    let operator_identity = Uuid::from_u128(rand::random());
    let target_identity = Uuid::from_u128(rand::random());
    let token = format!("admin-browser-{:032x}", rand::random::<u128>());
    let target_email = format!("admin-browser-target-{stamp:016x}@example.invalid");
    let subject = format!("admin-browser-subject-{stamp:016x}");
    let password_plain = "synthetic-operator-password";
    let password =
        tokio::task::spawn_blocking(move || id_compat::password::hash_new(password_plain))
            .await??;
    let codec = SessionCodec::new(env::var("DJANGO_SECRET_KEY")?.as_bytes(), &[])?;
    let now = SystemTime::now();
    let epoch = now.duration_since(UNIX_EPOCH)?.as_secs();
    let payload = json!({
        "_auth_user_id": operator_id.to_string(),
        "_auth_user_backend": "django.contrib.auth.backends.ModelBackend",
        "_auth_user_hash": codec.auth_hash(&password)?,
        "id_mfa_verified_user_id": operator_id.to_string(),
    });
    let encoded = codec.encode(
        payload.as_object().context("operator session payload")?,
        i64::try_from(epoch)?,
        true,
    )?;
    let client = id_runtime::connect_ydb().await?;
    let result: Result<()> = async {
        client.query_client().exec("INSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $password, true, $name, '', '', $email, true, true, CurrentUtcDatetime())")
            .param("$id", operator_id).param("$password", password.clone())
            .param("$name", format!("admin-browser-operator-{stamp}"))
            .param("$email", format!("admin-browser-operator-{stamp}@example.invalid")).await?;
        client.query_client().exec("INSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, $name, $name, $email, true, 'active', true, CurrentUtcDatetime())")
            .param("$id", operator_identity).param("$name", format!("admin-browser-operator-{stamp}"))
            .param("$email", format!("admin-browser-operator-{stamp}@example.invalid")).await?;
        client.query_client().exec("INSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($user, $identity, $subject, CurrentUtcDatetime())")
            .param("$user", operator_id).param("$identity", operator_identity)
            .param("$subject", format!("admin-browser-operator-subject-{stamp}")).await?;
        client.query_client().exec("INSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $user, 'totp', Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime())")
            .param("$id", i64::from(operator_id)).param("$user", operator_id).await?;
        client.query_client().exec("INSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, $data, CAST($expires AS Datetime))")
            .param("$key", token.clone()).param("$data", encoded)
            .param("$expires", now + Duration::from_secs(3600)).await?;
        client.query_client().exec("INSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $password, true, $name, '', '', $email, false, false, CurrentUtcDatetime())")
            .param("$id", target_id).param("$password", password.clone())
            .param("$name", format!("admin-browser-target-{stamp}"))
            .param("$email", target_email.clone()).await?;
        client.query_client().exec("INSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, $name, $name, $email, true, 'active', false, CurrentUtcDatetime())")
            .param("$id", target_identity).param("$name", format!("admin-browser-target-{stamp}"))
            .param("$email", target_email.clone()).await?;
        client.query_client().exec("INSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($user, $identity, $subject, CurrentUtcDatetime())")
            .param("$user", target_id).param("$identity", target_identity).param("$subject", subject.clone()).await?;
        client.query_client().exec("INSERT INTO accounts_accountemaillookup (user_id, email_key) VALUES ($id, $email)")
            .param("$id", target_id).param("$email", target_email.clone()).await?;
        client.query_client().exec("INSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($id, $user, $email, true, true)")
            .param("$id", email_id).param("$user", target_id).param("$email", target_email.clone()).await?;
        client.query_client().exec("INSERT INTO accounts_accountdeletionrequest (id, user_id, status, requested_at, reason) VALUES ($id, $user, 'pending', CurrentUtcDatetime(), 'synthetic fixture')")
            .param("$id", deletion_id).param("$user", target_id + 1).await?;
        let staged = format!("{output}.staged");
        fs::write(&staged, serde_json::to_vec(&json!({
            "synthetic": true, "format_version": 1, "session_token": token,
            "target_id": target_id, "target_email": target_email,
            "deletion_id": deletion_id, "operator_password": password_plain,
        }))?)?;
        fs::rename(staged, &output)?;
        for _ in 0..480 {
            if Path::new(&done).exists() {
                let mut row = client.query_client().query_row("SELECT is_active FROM auth_user WHERE id = $id")
                    .param("$id", target_id).await?;
                let active: bool = row.remove_field_by_name("is_active")?.try_into()?;
                ensure!(!active, "browser did not suspend target in YDB");
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        bail!("operator browser fixture completion timed out")
    }.await;
    let mut audit_query = client.query_client();
    let mut audit = audit_query
        .query("SELECT id FROM usid_audit_log WHERE actor_user_id = $actor AND target_id = $target")
        .param("$actor", operator_identity)
        .param("$target", target_identity.to_string())
        .await?;
    let mut audit_ids: Vec<i64> = Vec::new();
    while let Some(rows) = audit.next_result_set().await? {
        for mut row in rows {
            audit_ids.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    audit.close().await?;
    for id in audit_ids {
        client
            .query_client()
            .exec("DELETE FROM usid_audit_log WHERE id = $id")
            .param("$id", id)
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM accounts_accountdeletionrequest WHERE id = $id")
        .param("$id", deletion_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM account_emailaddress WHERE id = $id")
        .param("$id", email_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountemaillookup WHERE user_id = $id")
        .param("$id", target_id)
        .await?;
    for id in [operator_id, target_id] {
        client
            .query_client()
            .exec("DELETE FROM accounts_accountidentity WHERE user_id = $id")
            .param("$id", id)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM auth_user WHERE id = $id")
            .param("$id", id)
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM mfa_authenticator WHERE id = $id")
        .param("$id", i64::from(operator_id))
        .await?;
    client
        .query_client()
        .exec("DELETE FROM django_session WHERE session_key = $key")
        .param("$key", token)
        .await?;
    for identity in [operator_identity, target_identity] {
        client
            .query_client()
            .exec("DELETE FROM usid_user WHERE user_id = $id")
            .param("$id", identity)
            .await?;
    }
    result
}
