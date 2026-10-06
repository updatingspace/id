//! Explicit legacy-state reset on a dedicated disposable local YDB only.

use anyhow::{Result, ensure};
use hmac::{Hmac, Mac};
use id_compat::session::SessionCodec;
use sha2::Sha256;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires disposable local YDB with frozen legacy schema"]
async fn resets_only_selected_legacy_state() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2137" | "grpc://127.0.0.1:2137"
        ) && std::env::var("YDB_DATABASE")? == "/local"
            && std::env::var("ID_DISPOSABLE_YDB").as_deref() == Ok("true"),
        "cutover reset test requires explicitly disposable local YDB on port 2137"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let account_id = -i32::try_from(stamp % 1_000_000_000 + 1)?;
    let row_id = i64::from(account_id);
    let identity = Uuid::from_u128((stamp << 32) | u128::from(std::process::id()));
    let session_key = format!("cutover-{}", -account_id);
    client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, 'hash', true, 'cutover-test', '', '', 'cutover@example.invalid', false, false, CurrentUtcDatetime())")
        .param("$id", account_id).await?;
    client.query_client().exec("UPSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, 'cutover-test', '', 'cutover@example.invalid', true, 'active', false, CurrentUtcDatetime())")
        .param("$id", identity).await?;
    client.query_client().exec("UPSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, 'synthetic', CurrentUtcDatetime())")
        .param("$key", session_key.clone()).await?;
    client.query_client().exec("UPSERT INTO usersessions_usersession (id, user_id, created_at, ip, last_seen_at, session_key, user_agent, data) VALUES ($id, $user_id, CurrentUtcDatetime(), '', CurrentUtcDatetime(), $key, '', Unwrap(CAST('{}' AS Json)))")
        .param("$id", row_id).param("$user_id", account_id).param("$key", session_key.clone()).await?;
    client.query_client().exec("UPSERT INTO core_usersessionmeta (id, user_id, session_key, user_agent, first_seen, revoked_reason) VALUES ($id, $user_id, $key, '', CurrentUtcDatetime(), '')")
        .param("$id", row_id).param("$user_id", account_id).param("$key", session_key.clone()).await?;
    client.query_client().exec("UPSERT INTO core_usersessiontoken (id, user_id, session_key, refresh_jti, created_at) VALUES ($id, $user_id, $key, 'synthetic', CurrentUtcDatetime())")
        .param("$id", row_id).param("$user_id", account_id).param("$key", session_key).await?;
    client.query_client().exec("UPSERT INTO usid_application (id, tenant_slug, payload_json, status, created_at) VALUES ($id, 'synthetic', Unwrap(CAST('{}' AS Json)), 'pending', CurrentUtcDatetime())")
        .param("$id", row_id).await?;
    client.query_client().exec("UPSERT INTO usid_audit_log (id, action, target_type, target_id, meta_json, created_at) VALUES ($id, 'synthetic', '', '', Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime())")
        .param("$id", row_id).await?;
    client.query_client().exec("UPSERT INTO usid_outbox (id, tenant_id, event_type, payload_json, created_at, attempts, last_error) VALUES ($id, $tenant, 'synthetic', Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime(), 0, '')")
        .param("$id", row_id).param("$tenant", identity).await?;

    let dry_run = id_runtime::legacy_cutover_reset::reset(&client, 1, false).await?;
    ensure!(
        dry_run.dry_run && !dry_run.complete && dry_run.tables.len() == 7,
        "dry-run misstated cutover state: {dry_run:?}"
    );
    ensure!(
        dry_run
            .tables
            .iter()
            .all(|table| table.before == 1 && table.remaining == 1 && table.delete_attempts == 0),
        "dry-run changed legacy data: {dry_run:?}"
    );
    let applied = id_runtime::legacy_cutover_reset::reset(&client, 1, true).await?;
    ensure!(
        !applied.dry_run
            && applied.complete
            && applied.tables.iter().all(|table| table.before == 1
                && table.delete_attempts == 1
                && table.removed == 1
                && table.remaining == 0),
        "cutover reset did not clear selected tables: {applied:?}"
    );
    let repeated = id_runtime::legacy_cutover_reset::reset(&client, 1, true).await?;
    ensure!(
        repeated.complete && repeated.tables.iter().all(|table| table.removed == 0),
        "cutover reset was not idempotent: {repeated:?}"
    );
    let before_seal = id_runtime::account_deletion_finalize::drain_pending(&client, 10).await?;
    ensure!(
        before_seal.attempted == 0 && before_seal.deferred == 0,
        "automatic finalization ran before cutover seal: {before_seal:?}"
    );
    ensure!(
        id_runtime::legacy_cutover_reset::seal(&client).await?,
        "completed reset did not create a cutover seal"
    );
    ensure!(
        !id_runtime::legacy_cutover_reset::seal(&client).await?,
        "cutover seal was not idempotent"
    );
    ensure!(
        id_runtime::legacy_cutover_reset::reset(&client, 1, true)
            .await
            .is_err(),
        "sealed cutover allowed a later reset"
    );
    ensure!(
        client
            .query_client()
            .query_row("SELECT id FROM auth_user WHERE id = $id")
            .param("$id", account_id)
            .optional()
            .await?
            .is_some(),
        "cutover reset deleted a critical account"
    );
    ensure!(
        client
            .query_client()
            .query_row("SELECT user_id FROM usid_user WHERE user_id = $id")
            .param("$id", identity)
            .optional()
            .await?
            .is_some(),
        "cutover reset deleted a critical master identity"
    );
    let operation_key = b"synthetic-deletion-operation-key-min-32-characters";
    let retry_token = "a".repeat(32);
    let retry_key = "finalize-once";
    let mut mac = Hmac::<Sha256>::new_from_slice(operation_key)?;
    mac.update(b"account-deletion-v1\0");
    mac.update(retry_token.as_bytes());
    mac.update(b"\0");
    mac.update(retry_key.as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    let operation_id = ((u64::from_be_bytes(bytes) & ((1u64 << 62) - 1)) | (1u64 << 62)) as i64;
    client
        .query_client()
        .exec("UPDATE auth_user SET is_active = false WHERE id = $id")
        .param("$id", account_id)
        .await?;
    client
        .query_client()
        .exec("UPDATE usid_user SET status = 'suspended' WHERE user_id = $id")
        .param("$id", identity)
        .await?;
    client.query_client().exec("INSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($user_id, $identity_id, $subject, CurrentUtcDatetime())")
        .param("$user_id", account_id).param("$identity_id", identity)
        .param("$subject", format!("cutover-sub-{stamp}")).await?;
    client.query_client().exec("INSERT INTO accounts_accountdeletionrequest (id, user_id, status, requested_at, reason) VALUES ($id, $user_id, 'running', CurrentUtcDatetime(), 'private test reason')")
        .param("$id", operation_id).param("$user_id", account_id).await?;
    let blocked = id_runtime::account_deletion_finalize::finalize(&client, operation_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("finalizer lost operation"))?;
    ensure!(
        !blocked.finalized && !blocked.cleanup_completed,
        "finalizer ignored missing stage markers: {blocked:?}"
    );
    id_runtime::account_deletion_cleanup::ensure_progress_schema(&client).await?;
    client.query_client().exec("UPSERT INTO id_deletion_progress (operation_id, avatar_done, updated_at) VALUES ($id, true, CurrentUtcDatetime())")
        .param("$id", operation_id).await?;
    client.query_client().exec("UPSERT INTO id_deletion_profile_progress (operation_id, profile_done, updated_at) VALUES ($id, true, CurrentUtcDatetime())")
        .param("$id", operation_id).await?;
    client.query_client().exec("UPSERT INTO id_deletion_global_progress (operation_id, uuid_done, updated_at) VALUES ($id, true, CurrentUtcDatetime())")
        .param("$id", operation_id).await?;
    client.query_client().exec("UPSERT INTO core_usersessionmeta (id, user_id, session_key, user_agent, first_seen, revoked_reason) VALUES ($id, $user_id, $key, '', CurrentUtcDatetime(), 'account_deleted')")
        .param("$id", row_id).param("$user_id", account_id)
        .param("$key", format!("cutover-final-{stamp}")).await?;
    client.query_client().exec("UPSERT INTO usid_audit_log (id, action, target_type, target_id, meta_json, created_at) VALUES ($id, 'late-write', '', '', Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime())")
        .param("$id", row_id).await?;
    client.query_client().exec("UPSERT INTO usid_outbox (id, tenant_id, event_type, payload_json, created_at, attempts, last_error) VALUES ($id, $tenant, 'unrelated', Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime(), 0, '')")
        .param("$id", row_id).param("$tenant", Uuid::nil()).await?;
    client.query_client().exec("INSERT INTO accounts_userdevice (id, user_id, device_id, user_agent, first_seen, last_seen, last_ip) VALUES ($id, $user_id, 'late-device', '', CurrentUtcDatetime(), CurrentUtcDatetime(), '')")
        .param("$id", row_id).param("$user_id", account_id).await?;
    let blocked_child = id_runtime::account_deletion_finalize::finalize(&client, operation_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("finalizer lost operation"))?;
    ensure!(
        !blocked_child.finalized && !blocked_child.cleanup_completed,
        "finalizer ignored remaining owner data: {blocked_child:?}"
    );
    client
        .query_client()
        .exec("DELETE FROM accounts_userdevice WHERE id = $id")
        .param("$id", row_id)
        .await?;
    let recovered = id_runtime::account_deletion_finalize::drain_pending(&client, 10).await?;
    ensure!(
        recovered.attempted == 1 && recovered.completed == 1 && recovered.deferred == 0,
        "unrelated audit event blocked ready deletion: {recovered:?}"
    );
    ensure!(
        client
            .query_client()
            .query_row("SELECT id FROM usid_audit_log WHERE id = $id")
            .param("$id", row_id)
            .optional()
            .await?
            .is_some(),
        "finalization erased another identity's audit event"
    );
    ensure!(
        client
            .query_client()
            .query_row("SELECT id FROM usid_outbox WHERE id = $id")
            .param("$id", row_id)
            .optional()
            .await?
            .is_some(),
        "finalization erased another identity's outbox event"
    );
    let finalized = id_runtime::account_deletion::read_status(&client, operation_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("finalizer lost operation"))?;
    ensure!(
        finalized.status == "succeeded" && finalized.cleanup_completed,
        "finalizer did not erase identity: {finalized:?}"
    );
    let repeated = id_runtime::account_deletion_finalize::finalize(&client, operation_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("finalized receipt missing"))?;
    ensure!(
        repeated.already_finalized && repeated.cleanup_completed && !repeated.finalized,
        "finalizer was not idempotent: {repeated:?}"
    );
    let deletion = id_runtime::account_deletion::AccountDeletion::new(
        client.clone(),
        Arc::new(SessionCodec::new(
            b"synthetic-local-secret-min-32-characters",
            &[],
        )?),
        id_runtime::cache_store::CacheStore::new(client.clone(), "id_shared_cache", "", 1)?,
        None,
        operation_key,
        2,
    )?;
    let retry = deletion
        .request(
            &retry_token,
            retry_key,
            "irrelevant",
            None,
            None,
            SystemTime::now(),
        )
        .await?;
    ensure!(
        matches!(&retry, id_runtime::account_deletion::DeletionResult::Accepted {
        id, status, existing: true } if *id == operation_id && status == "succeeded"),
        "idempotent retry lost completed receipt: {retry:?}"
    );
    let status = id_runtime::account_deletion::read_status(&client, operation_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("operator status missing"))?;
    ensure!(
        status.status == "succeeded" && status.cleanup_completed,
        "operator status did not reflect cleanup"
    );
    let audit = id_runtime::account_deletion_audit::audit(&client, operation_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("completed deletion audit missing"))?;
    ensure!(
        audit.full_cleanup_proven
            && audit.account_rows == 0
            && audit.identity_rows == 0
            && audit.session_metadata_rows == 0,
        "completed deletion audit did not recognize receipt: {audit:?}"
    );
    let mut receipt = client.query_client().query_row("SELECT user_id, reason, executed_at FROM accounts_accountdeletionrequest WHERE id = $id")
        .param("$id", operation_id).await?;
    let owner: i32 = receipt.remove_field_by_name("user_id")?.try_into()?;
    let reason: String = receipt.remove_field_by_name("reason")?.try_into()?;
    let executed_at: Option<SystemTime> =
        receipt.remove_field_by_name("executed_at")?.try_into()?;
    ensure!(
        owner == 0 && reason.is_empty() && executed_at.is_some(),
        "finalized receipt retained personal fields"
    );
    ensure!(
        client
            .query_client()
            .query_row("SELECT id FROM auth_user WHERE id = $id")
            .param("$id", account_id)
            .optional()
            .await?
            .is_none(),
        "finalization retained auth account"
    );
    ensure!(
        client
            .query_client()
            .query_row("SELECT user_id FROM usid_user WHERE user_id = $id")
            .param("$id", identity)
            .optional()
            .await?
            .is_none(),
        "finalization retained master identity"
    );
    ensure!(
        client
            .query_client()
            .query_row("SELECT id FROM core_usersessionmeta WHERE user_id = $id LIMIT 1")
            .param("$id", account_id)
            .optional()
            .await?
            .is_none(),
        "finalization retained session metadata"
    );
    client
        .query_client()
        .exec("DELETE FROM accounts_accountdeletionrequest WHERE id = $id")
        .param("$id", operation_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM usid_audit_log WHERE id = $id")
        .param("$id", row_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM usid_outbox WHERE id = $id")
        .param("$id", row_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM auth_user WHERE id = $id")
        .param("$id", account_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM usid_user WHERE user_id = $id")
        .param("$id", identity)
        .await?;
    Ok(())
}
