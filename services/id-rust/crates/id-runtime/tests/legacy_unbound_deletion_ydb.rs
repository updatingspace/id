#![recursion_limit = "256"]
//! A pre-master-identity deletion must be resumable without inventing an identity.

use anyhow::{Result, ensure};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires explicitly disposable local YDB on port 2137 with frozen legacy schema"]
async fn deletes_inactive_unbound_account_without_cutover_seal() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2137" | "grpc://127.0.0.1:2137"
        ) && std::env::var("YDB_DATABASE")? == "/local"
            && std::env::var("ID_DISPOSABLE_YDB").as_deref() == Ok("true"),
        "test requires explicitly disposable local YDB on port 2137"
    );
    let client = id_runtime::connect_ydb().await?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let account_id = i32::try_from(stamp % 1_000_000_000 + 1)?;
    let operation_id = i64::from(account_id);
    let other_identity = Uuid::new_v4();
    client.query_client().exec("INSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, 'other-owner', '', 'other@example.invalid', true, 'active', false, CurrentUtcDatetime())")
        .param("$id", other_identity).await?;
    client.query_client().exec("INSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, 'unusable-password', false, $name, '', '', $email, false, false, CurrentUtcDatetime())")
        .param("$id", account_id).param("$name", format!("deleted-{stamp}"))
        .param("$email", format!("deleted-{stamp}@deleted.local")).await?;
    client.query_client().exec("INSERT INTO accounts_accountidentity (user_id, public_subject, created_at) VALUES ($id, $subject, CurrentUtcDatetime())")
        .param("$id", account_id).param("$subject", format!("legacy-{stamp}")).await?;
    client.query_client().exec("INSERT INTO accounts_accountdeletionrequest (id, user_id, status, requested_at, reason) VALUES ($id, $owner, 'pending', CurrentUtcDatetime(), '')")
        .param("$id", operation_id).param("$owner", account_id).await?;
    client.query_client().exec("INSERT INTO accounts_userprofile (id, user_id, avatar_source, gravatar_enabled, phone_number, phone_verified, created_at, updated_at) VALUES ($id, $owner, 'none', false, '', false, CurrentUtcDatetime(), CurrentUtcDatetime())")
        .param("$id", operation_id).param("$owner", account_id).await?;
    let active_id = account_id + 1;
    let active_operation = operation_id + 1;
    client.query_client().exec("INSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, 'hash', true, $name, '', '', $email, false, false, CurrentUtcDatetime())")
        .param("$id", active_id).param("$name", format!("active-{stamp}"))
        .param("$email", format!("active-{stamp}@example.invalid")).await?;
    client.query_client().exec("INSERT INTO accounts_accountidentity (user_id, public_subject, created_at) VALUES ($id, $subject, CurrentUtcDatetime())")
        .param("$id", active_id).param("$subject", format!("active-{stamp}")).await?;
    client.query_client().exec("INSERT INTO accounts_accountdeletionrequest (id, user_id, status, requested_at, reason) VALUES ($id, $owner, 'pending', CurrentUtcDatetime(), '')")
        .param("$id", active_operation).param("$owner", active_id).await?;
    ensure!(
        id_runtime::account_deletion_cleanup::erase_credentials(&client, active_operation)
            .await
            .is_err(),
        "active legacy account entered deletion cleanup"
    );
    client
        .query_client()
        .exec("DELETE FROM accounts_accountdeletionrequest WHERE id = $id")
        .param("$id", active_operation)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountidentity WHERE user_id = $id")
        .param("$id", active_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM auth_user WHERE id = $id")
        .param("$id", active_id)
        .await?;

    let credentials = id_runtime::account_deletion_cleanup::drain_pending(&client, 10).await?;
    ensure!(
        credentials.attempted == 1 && credentials.completed == 1 && credentials.deferred == 0,
        "legacy credential stage failed: {credentials:?}"
    );
    let avatars =
        id_runtime::account_deletion_cleanup::drain_pending_avatars(&client, None, 10).await?;
    ensure!(
        avatars.completed == 1 && avatars.deferred == 0,
        "legacy avatar stage failed: {avatars:?}"
    );
    let profiles =
        id_runtime::account_deletion_cleanup::drain_pending_profiles(&client, 10).await?;
    ensure!(
        profiles.completed == 1 && profiles.deferred == 0,
        "legacy profile stage failed: {profiles:?}"
    );
    client.query_client().exec("INSERT INTO usid_audit_log (id, action, target_type, target_id, meta_json, created_at) VALUES ($id, 'unrelated', '', '', Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime())")
        .param("$id", operation_id).await?;
    let blocked = id_runtime::account_deletion_cleanup::drain_pending_globals(&client, 10).await?;
    ensure!(
        blocked.attempted == 1 && blocked.deferred == 1 && blocked.completed == 0,
        "unbound deletion ignored unknown global records: {blocked:?}"
    );
    client
        .query_client()
        .exec("DELETE FROM usid_audit_log WHERE id = $id")
        .param("$id", operation_id)
        .await?;
    let globals = id_runtime::account_deletion_cleanup::drain_pending_globals(&client, 10).await?;
    ensure!(
        globals.completed == 1 && globals.deferred == 0,
        "legacy global stage failed: {globals:?}"
    );
    let finalized = id_runtime::account_deletion_finalize::drain_pending(&client, 10).await?;
    ensure!(
        finalized.completed == 1 && finalized.deferred == 0,
        "legacy finalization failed: {finalized:?}"
    );
    let mut receipt = client.query_client().query_row("SELECT status, user_id, executed_at FROM accounts_accountdeletionrequest WHERE id = $id")
        .param("$id", operation_id).await?;
    let status: String = receipt.remove_field_by_name("status")?.try_into()?;
    let owner: i32 = receipt.remove_field_by_name("user_id")?.try_into()?;
    let executed: Option<SystemTime> = receipt.remove_field_by_name("executed_at")?.try_into()?;
    ensure!(
        status == "succeeded" && owner == 0 && executed.is_some(),
        "deletion receipt was not anonymized"
    );
    ensure!(
        client
            .query_client()
            .query_row("SELECT id FROM auth_user WHERE id = $id")
            .param("$id", account_id)
            .optional()
            .await?
            .is_none(),
        "legacy account survived"
    );
    ensure!(
        client
            .query_client()
            .query_row("SELECT user_id FROM usid_user WHERE user_id = $id")
            .param("$id", other_identity)
            .optional()
            .await?
            .is_some(),
        "unrelated identity was removed"
    );
    client
        .query_client()
        .exec("DELETE FROM usid_user WHERE user_id = $id")
        .param("$id", other_identity)
        .await?;
    Ok(())
}
