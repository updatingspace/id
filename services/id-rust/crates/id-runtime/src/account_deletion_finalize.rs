//! Final erasure after all owner-scoped cleanup. Master identities additionally
//! require an explicitly sealed legacy cutover.
//! The operation receipt retains only an opaque operation ID and timestamps.

use crate::{
    account_deletion_cleanup::{CredentialDrain, ensure_progress_schema},
    legacy_cutover_reset,
    tx_retry::retry_known_abort,
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::time::Duration;
use uuid::Uuid;
use ydb::{Client, Transaction, TxMode, closure};

// No Rust writer creates applications after the legacy cutover. A late row
// means an old, unscoped writer is still active, so finalization must stop.
const LEGACY_UNOWNED_TABLE: &str = "usid_application";
// An unbound legacy account has no UUID with which to prove ownership of
// audit/outbox rows. Keep the old whole-table guard for that exceptional path.
const UNBOUND_GLOBAL_TABLES: &[&str] = &["usid_audit_log", "usid_outbox"];
const EMPTY_ACCOUNT_TABLES: &[(&str, &str)] = &[
    ("mfa_authenticator", "user_id"),
    ("id_passkey_credential", "account_id"),
    ("core_usersessiontoken", "user_id"),
    ("idp_oidcauthorizationcode", "user_id"),
    ("idp_oidcauthorizationrequest", "user_id"),
    ("idp_oidctoken", "user_id"),
    ("id_password_reset", "user_id"),
    ("id_email_verification", "user_id"),
    ("id_email_change", "user_id"),
    ("id_email_claim", "user_id"),
    ("token_blacklist_outstandingtoken", "user_id"),
    ("accounts_userprofile", "user_id"),
    ("accounts_userpreferences", "user_id"),
    ("accounts_userconsent", "user_id"),
    ("accounts_userdevice", "user_id"),
    ("accounts_loginevent", "user_id"),
    ("accounts_accountevent", "user_id"),
    ("accounts_dataexportrequest", "user_id"),
    ("account_emailaddress", "user_id"),
    ("accounts_accountemaillookup", "user_id"),
    ("idp_oidcconsent", "user_id"),
    ("socialaccount_socialaccount", "user_id"),
    ("id_password_mail", "user_id"),
    ("id_security_mail", "user_id"),
    ("django_admin_log", "user_id"),
    ("auth_user_groups", "user_id"),
    ("auth_user_user_permissions", "user_id"),
    ("usersessions_usersession", "user_id"),
];
const EMPTY_IDENTITY_TABLES: &[&str] = &[
    "usid_session",
    "usid_external_identity",
    "usid_tenant_membership",
    "usid_migration_map",
    "usid_activation_token",
    "usid_magic_link_token",
    "usid_oauth_state",
];

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct FinalizeResult {
    pub id: String,
    pub finalized: bool,
    pub already_finalized: bool,
    pub cleanup_completed: bool,
}

pub async fn finalize(client: &Client, id: i64) -> Result<Option<FinalizeResult>> {
    ensure!(id > 0, "invalid deletion operation ID");
    let cutover_sealed = legacy_cutover_reset::is_sealed(client).await?;
    ensure_progress_schema(client).await?;
    crate::passkey_index::ensure_schema(client).await?;
    crate::password_reset::ensure_schema(client).await?;
    crate::email_verify::ensure_schema(client).await?;
    crate::password_mail::ensure_schema(client).await?;
    crate::security_mail::ensure_schema(client).await?;
    retry_known_abort(|| async {
        client.query_client().retry_tx(closure!([id, cutover_sealed], async |tx: &mut Transaction| {
            let Some(mut operation) = tx.query_row("SELECT user_id, status, executed_at FROM accounts_accountdeletionrequest WHERE id = $id")
                .param("$id", *id).optional().await? else { return Ok(None); };
            let account_id: i32 = operation.remove_field_by_name("user_id")?.try_into()?;
            let status: String = operation.remove_field_by_name("status")?.try_into()?;
            let executed_at: Option<std::time::SystemTime> = operation.remove_field_by_name("executed_at")?.try_into()?;
            if status == "succeeded" && account_id == 0 && executed_at.is_some() {
                return Ok(Some(FinalizeResult { id: id.to_string(), finalized: false,
                    already_finalized: true, cleanup_completed: true }));
            }
            if status != "running" || account_id == 0 { return Ok(Some(incomplete(*id))); }
            let Some(mut avatar) = tx.query_row("SELECT avatar_done FROM id_deletion_progress WHERE operation_id = $id")
                .param("$id", *id).optional().await? else { return Ok(Some(incomplete(*id))); };
            let avatar_done: bool = avatar.remove_field_by_name("avatar_done")?.try_into()?;
            let Some(mut profile) = tx.query_row("SELECT profile_done FROM id_deletion_profile_progress WHERE operation_id = $id")
                .param("$id", *id).optional().await? else { return Ok(Some(incomplete(*id))); };
            let profile_done: bool = profile.remove_field_by_name("profile_done")?.try_into()?;
            let Some(mut global) = tx.query_row("SELECT uuid_done FROM id_deletion_global_progress WHERE operation_id = $id")
                .param("$id", *id).optional().await? else { return Ok(Some(incomplete(*id))); };
            let uuid_done: bool = global.remove_field_by_name("uuid_done")?.try_into()?;
            if !avatar_done || !profile_done || !uuid_done { return Ok(Some(incomplete(*id))); }
            let Some(mut account) = tx.query_row("SELECT is_active FROM auth_user WHERE id = $id")
                .param("$id", account_id).optional().await? else { return Ok(Some(incomplete(*id))); };
            let active: bool = account.remove_field_by_name("is_active")?.try_into()?;
            if active { return Ok(Some(incomplete(*id))); }
            let Some(mut binding) = tx.query_row("SELECT identity_id FROM accounts_accountidentity WHERE user_id = $id")
                .param("$id", account_id).optional().await? else { return Ok(Some(incomplete(*id))); };
            let identity_id: Option<Uuid> = binding.remove_field_by_name("identity_id")?.try_into()?;
            if tx.query_row(format!("SELECT id FROM `{LEGACY_UNOWNED_TABLE}` LIMIT 1"))
                .optional().await?.is_some() { return Ok(Some(incomplete(*id))); }
            if let Some(identity_id) = identity_id {
                if !*cutover_sealed { return Ok(Some(incomplete(*id))); }
                let Some(mut identity) = tx.query_row("SELECT status FROM usid_user WHERE user_id = $id")
                    .param("$id", identity_id).optional().await? else { return Ok(Some(incomplete(*id))); };
                let identity_status: String = identity.remove_field_by_name("status")?.try_into()?;
                if identity_status != "suspended" { return Ok(Some(incomplete(*id))); }
                // Before the seal, audit/outbox are emptied. The only Rust
                // writer after it is magic-link consumption, which reads the
                // active identity in the same serializable transaction as its
                // writes. It cannot append a row for this suspended identity.
                // uuid_done proves a clean addressable pass; unrelated users'
                // later audit/outbox events must not block this deletion.
            } else {
                for table in UNBOUND_GLOBAL_TABLES {
                    if tx.query_row(format!("SELECT id FROM `{table}` LIMIT 1"))
                        .optional().await?.is_some() { return Ok(Some(incomplete(*id))); }
                }
            }
            for (table, column) in EMPTY_ACCOUNT_TABLES {
                if tx.query_row(format!("SELECT `{column}` FROM `{table}` WHERE `{column}` = $id LIMIT 1"))
                    .param("$id", account_id).optional().await?.is_some() { return Ok(Some(incomplete(*id))); }
            }
            if let Some(identity_id) = identity_id {
                for table in EMPTY_IDENTITY_TABLES {
                    if tx.query_row(format!("SELECT user_id FROM `{table}` WHERE user_id = $id LIMIT 1"))
                        .param("$id", identity_id).optional().await?.is_some() { return Ok(Some(incomplete(*id))); }
                }
            }
            tx.exec("DELETE FROM core_usersessionmeta WHERE user_id = $id")
                .param("$id", account_id).await?;
            tx.exec("DELETE FROM accounts_accountidentity WHERE user_id = $id")
                .param("$id", account_id).await?;
            tx.exec("DELETE FROM auth_user WHERE id = $id")
                .param("$id", account_id).await?;
            if let Some(identity_id) = identity_id {
                tx.exec("DELETE FROM usid_user WHERE user_id = $id")
                    .param("$id", identity_id).await?;
            }
            tx.exec("UPDATE accounts_accountdeletionrequest SET user_id = 0, reason = '', status = 'succeeded', executed_at = CurrentUtcDatetime() WHERE id = $id")
                .param("$id", *id).await?;
            for table in ["id_deletion_progress", "id_deletion_profile_progress", "id_deletion_global_progress"] {
                tx.exec(format!("DELETE FROM `{table}` WHERE operation_id = $id"))
                    .param("$id", *id).await?;
            }
            Ok(Some(FinalizeResult { id: id.to_string(), finalized: true,
                already_finalized: false, cleanup_completed: true }))
        })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
            .timeout(Duration::from_secs(45)).await
    }).await.context("finalize account deletion")
}

fn incomplete(id: i64) -> FinalizeResult {
    FinalizeResult {
        id: id.to_string(),
        finalized: false,
        already_finalized: false,
        cleanup_completed: false,
    }
}

/// Timer recovery selects only operations whose UUID cleanup has completed.
/// Master identities remain disabled until an explicit cutover seal.
pub async fn drain_pending(client: &Client, limit: u64) -> Result<CredentialDrain> {
    ensure!(
        (1..=10).contains(&limit),
        "finalization batch size must be 1..=10"
    );
    ensure_progress_schema(client).await?;
    let mut query_client = client.query_client();
    let mut query = query_client.query(format!(
        "SELECT operation_id FROM id_deletion_global_progress VIEW id_deletion_global_due_idx WHERE uuid_done = true LIMIT {limit}"
    )).timeout(Duration::from_secs(15)).await?;
    let mut ids = Vec::new();
    while let Some(rows) = query.next_result_set().await? {
        for mut row in rows {
            ids.push(row.remove_field_by_name("operation_id")?.try_into()?);
        }
    }
    query.close().await?;
    let mut report = CredentialDrain::default();
    for id in ids {
        report.attempted += 1;
        match finalize(client, id).await {
            Ok(Some(result)) if result.finalized || result.already_finalized => {
                report.completed += 1;
            }
            Ok(_) => report.deferred += 1,
            Err(_) => {
                tracing::warn!("account deletion finalization deferred");
                report.deferred += 1;
            }
        }
    }
    Ok(report)
}
