//! First resumable deletion step: erase the primary login credentials after the
//! acceptance transaction has disabled the account. This deliberately never
//! reports `succeeded`: personal records and media need separate cleanup.

use crate::{media_delete::S3MediaDelete, tx_retry::retry_known_abort};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::time::Duration;
use ydb::{Client, Transaction, TxMode, closure};

const ACCOUNT_CREDENTIAL_TABLES: &[&str] = &[
    "mfa_authenticator",
    "id_passkey_credential",
    "idp_oidcauthorizationcode",
    "idp_oidcauthorizationrequest",
    "idp_oidctoken",
    "id_password_reset",
    "id_email_verification",
    "id_email_change",
    "id_email_claim",
    "core_usersessiontoken",
    "token_blacklist_outstandingtoken",
];

const IDENTITY_CREDENTIAL_TABLES: &[&str] = &[
    "usid_activation_token",
    "usid_magic_link_token",
    "usid_oauth_state",
    "usid_session",
    "usid_external_identity",
];

const PROFILE_HISTORY_TABLES: &[&str] = &[
    "accounts_userprofile",
    "accounts_userpreferences",
    "accounts_userconsent",
    "accounts_userdevice",
    "accounts_loginevent",
    "accounts_accountevent",
    "accounts_dataexportrequest",
    "account_emailaddress",
    "accounts_accountemaillookup",
    "idp_oidcconsent",
    "socialaccount_socialaccount",
    "id_password_mail",
    "id_security_mail",
    "django_admin_log",
    "auth_user_groups",
    "auth_user_user_permissions",
    "usersessions_usersession",
];

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct CredentialCleanup {
    pub id: String,
    pub status: String,
    pub credential_stage_completed: bool,
    pub cleanup_completed: bool,
}

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct CredentialDrain {
    pub attempted: usize,
    pub completed: usize,
    pub deferred: usize,
}

const PROGRESS_TABLE: &str = "id_deletion_progress";
const PROFILE_PROGRESS_TABLE: &str = "id_deletion_profile_progress";
const GLOBAL_PROGRESS_TABLE: &str = "id_deletion_global_progress";

pub async fn ensure_progress_schema(client: &Client) -> Result<()> {
    client.query_client().exec(format!(
        "CREATE TABLE IF NOT EXISTS `{PROGRESS_TABLE}` (operation_id Int64 NOT NULL, avatar_done Bool NOT NULL, updated_at Datetime NOT NULL, INDEX `id_deletion_avatar_due_idx` GLOBAL ON (avatar_done), PRIMARY KEY (operation_id))"
    )).timeout(Duration::from_secs(15)).await?;
    client.query_client().exec(format!(
        "CREATE TABLE IF NOT EXISTS `{PROFILE_PROGRESS_TABLE}` (operation_id Int64 NOT NULL, profile_done Bool NOT NULL, updated_at Datetime NOT NULL, INDEX `id_deletion_profile_due_idx` GLOBAL ON (profile_done), PRIMARY KEY (operation_id))"
    )).timeout(Duration::from_secs(15)).await?;
    client.query_client().exec(format!(
        "CREATE TABLE IF NOT EXISTS `{GLOBAL_PROGRESS_TABLE}` (operation_id Int64 NOT NULL, uuid_done Bool NOT NULL, updated_at Datetime NOT NULL, INDEX `id_deletion_global_due_idx` GLOBAL ON (uuid_done), PRIMARY KEY (operation_id))"
    )).timeout(Duration::from_secs(15)).await?;
    Ok(())
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct AvatarCleanup {
    pub id: String,
    pub avatar_removed: bool,
    pub cleanup_completed: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ProfileCleanup {
    pub id: String,
    pub profile_history_removed: bool,
    pub cleanup_completed: bool,
}

/// Removes owner-scoped profile/history after media deletion. The account,
/// immutable binding and operation record remain for the final identity/audit
/// reconciliation, so this stage cannot report full completion.
pub async fn erase_profile_history(client: &Client, id: i64) -> Result<Option<ProfileCleanup>> {
    ensure!(id > 0, "invalid deletion operation ID");
    ensure_progress_schema(client).await?;
    crate::password_mail::ensure_schema(client).await?;
    crate::security_mail::ensure_schema(client).await?;
    crate::data_export_operation::ensure_schema(client).await?;
    retry_known_abort(|| async {
        client.query_client().retry_tx(closure!([id], async |tx: &mut Transaction| {
            let Some(mut operation) = tx.query_row("SELECT user_id, status FROM accounts_accountdeletionrequest WHERE id = $id")
                .param("$id", *id).optional().await? else { return Ok(None); };
            let account_id: i32 = operation.remove_field_by_name("user_id")?.try_into()?;
            let status: String = operation.remove_field_by_name("status")?.try_into()?;
            if status != "running" { return Ok(Some(ProfileCleanup {
                id: id.to_string(), profile_history_removed: false, cleanup_completed: false,
            })); }
            let Some(mut avatar) = tx.query_row(format!("SELECT avatar_done FROM `{PROGRESS_TABLE}` WHERE operation_id = $id"))
                .param("$id", *id).optional().await? else { return Ok(Some(ProfileCleanup {
                    id: id.to_string(), profile_history_removed: false, cleanup_completed: false,
                })); };
            let avatar_done: bool = avatar.remove_field_by_name("avatar_done")?.try_into()?;
            if !avatar_done { return Ok(Some(ProfileCleanup {
                id: id.to_string(), profile_history_removed: false, cleanup_completed: false,
            })); }
            let Some(mut account) = tx.query_row("SELECT is_active FROM auth_user WHERE id = $id")
                .param("$id", account_id).optional().await? else { return Ok(Some(ProfileCleanup {
                    id: id.to_string(), profile_history_removed: false, cleanup_completed: false,
                })); };
            let active: bool = account.remove_field_by_name("is_active")?.try_into()?;
            if active { return Ok(Some(ProfileCleanup {
                id: id.to_string(), profile_history_removed: false, cleanup_completed: false,
            })); }
            if tx.query_row("SELECT id FROM id_data_export_operation VIEW id_data_export_owner_idx WHERE user_id = $id LIMIT 1")
                .param("$id", account_id).optional().await?.is_some() {
                return Ok(Some(ProfileCleanup {
                    id: id.to_string(), profile_history_removed: false, cleanup_completed: false,
                }));
            }
            let mut profiles = tx.query("SELECT CAST(avatar AS Utf8) AS avatar_key FROM accounts_userprofile VIEW acct_profile_user_idx WHERE user_id = $id LIMIT 2")
                .param("$id", account_id).await?;
            let mut avatar_keys = Vec::new();
            while let Some(rows) = profiles.next_result_set().await? {
                for mut row in rows {
                    avatar_keys.push(row.remove_field_by_name("avatar_key")?.try_into()?);
                }
            }
            profiles.close().await?;
            if avatar_keys.len() > 1 || avatar_keys.into_iter().any(|key: Option<String>| key.is_some_and(|key| !key.is_empty())) {
                return Ok(Some(ProfileCleanup { id: id.to_string(), profile_history_removed: false, cleanup_completed: false }));
            }
            // Process at most 100 dependent rows per transaction. A full
            // page commits as incomplete so the next job pass continues.
            let login_events = related_i64(tx,
                "SELECT id FROM accounts_loginevent VIEW acct_login_user_idx WHERE user_id = $user_id LIMIT 100",
                account_id).await?;
            if !login_events.is_empty() {
                let batch_full = login_events.len() == 100;
                for event_id in login_events {
                    tx.exec("DELETE FROM accounts_newdevicemailoutbox WHERE event_id = $id")
                        .param("$id", event_id).await?;
                    tx.exec("DELETE FROM accounts_loginevent WHERE id = $id")
                        .param("$id", event_id).await?;
                }
                if batch_full { return Ok(Some(ProfileCleanup { id: id.to_string(), profile_history_removed: false, cleanup_completed: false })); }
            }
            let emails = related_i32(tx,
                "SELECT id FROM account_emailaddress VIEW account_emailaddress_user_id_2c513194 WHERE user_id = $user_id LIMIT 100",
                account_id).await?;
            if !emails.is_empty() {
                let batch_full = emails.len() == 100;
                for email_id in emails {
                    tx.exec("DELETE FROM account_emailconfirmation WHERE email_address_id = $id")
                        .param("$id", email_id).await?;
                    tx.exec("DELETE FROM account_emailaddress WHERE id = $id")
                        .param("$id", email_id).await?;
                }
                if batch_full { return Ok(Some(ProfileCleanup { id: id.to_string(), profile_history_removed: false, cleanup_completed: false })); }
            }
            let socials = related_i32(tx,
                "SELECT id FROM socialaccount_socialaccount VIEW socialaccount_socialaccount_user_id_8146e70c WHERE user_id = $user_id LIMIT 100",
                account_id).await?;
            if !socials.is_empty() {
                let batch_full = socials.len() == 100;
                for social_id in socials {
                    tx.exec("DELETE FROM socialaccount_socialtoken WHERE account_id = $id")
                        .param("$id", social_id).await?;
                    tx.exec("DELETE FROM socialaccount_socialaccount WHERE id = $id")
                        .param("$id", social_id).await?;
                }
                if batch_full { return Ok(Some(ProfileCleanup { id: id.to_string(), profile_history_removed: false, cleanup_completed: false })); }
            }
            let session_keys = related_strings(tx,
                "SELECT session_key FROM core_usersessionmeta VIEW core_usersessionmeta_user_id_9dceac03 WHERE user_id = $user_id LIMIT 100",
                account_id).await?;
            if !session_keys.is_empty() {
                let batch_full = session_keys.len() == 100;
                for session_key in session_keys {
                    tx.exec("DELETE FROM django_session WHERE session_key = $key")
                        .param("$key", session_key.clone()).await?;
                    tx.exec("DELETE FROM core_usersessionmeta WHERE session_key = $key AND user_id = $owner")
                        .param("$key", session_key).param("$owner", account_id).await?;
                }
                if batch_full { return Ok(Some(ProfileCleanup { id: id.to_string(), profile_history_removed: false, cleanup_completed: false })); }
            }
            let allauth_keys = related_strings(tx,
                "SELECT session_key FROM usersessions_usersession VIEW usersessions_usersession_user_id_af5e0a6d WHERE user_id = $user_id LIMIT 100",
                account_id).await?;
            if !allauth_keys.is_empty() {
                let batch_full = allauth_keys.len() == 100;
                for session_key in allauth_keys {
                    tx.exec("DELETE FROM django_session WHERE session_key = $key")
                        .param("$key", session_key.clone()).await?;
                    tx.exec("DELETE FROM usersessions_usersession WHERE session_key = $key AND user_id = $owner")
                        .param("$key", session_key).param("$owner", account_id).await?;
                }
                if batch_full { return Ok(Some(ProfileCleanup { id: id.to_string(), profile_history_removed: false, cleanup_completed: false })); }
            }
            for table in PROFILE_HISTORY_TABLES {
                tx.exec(format!("DELETE FROM `{table}` WHERE user_id = $id"))
                    .param("$id", account_id).await?;
            }
            let Some(mut binding) = tx.query_row("SELECT identity_id FROM accounts_accountidentity WHERE user_id = $id")
                .param("$id", account_id).optional().await? else { return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("deletion binding missing"))); };
            let identity_id: Option<uuid::Uuid> = binding.remove_field_by_name("identity_id")?.try_into()?;
            if let Some(identity_id) = identity_id {
                let Some(mut identity) = tx.query_row("SELECT status FROM usid_user WHERE user_id = $id")
                    .param("$id", identity_id).optional().await? else { return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("deletion identity missing"))); };
                let identity_status: String = identity.remove_field_by_name("status")?.try_into()?;
                if identity_status != "suspended" {
                    return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("deletion identity is not suspended")));
                }
            }
            if let Some(identity_id) = identity_id {
                for table in ["usid_tenant_membership", "usid_migration_map"] {
                    tx.exec(format!("DELETE FROM `{table}` WHERE user_id = $id"))
                        .param("$id", identity_id).await?;
                }
            }
            tx.exec(format!("UPSERT INTO `{PROFILE_PROGRESS_TABLE}` (operation_id, profile_done, updated_at) VALUES ($id, true, CurrentUtcDatetime())"))
                .param("$id", *id).await?;
            if tx.query_row(format!("SELECT operation_id FROM `{GLOBAL_PROGRESS_TABLE}` WHERE operation_id = $id"))
                .param("$id", *id).optional().await?.is_none() {
                tx.exec(format!("INSERT INTO `{GLOBAL_PROGRESS_TABLE}` (operation_id, uuid_done, updated_at) VALUES ($id, false, CurrentUtcDatetime())"))
                    .param("$id", *id).await?;
            }
            Ok(Some(ProfileCleanup {
                id: id.to_string(), profile_history_removed: true, cleanup_completed: false,
            }))
        })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
            .timeout(Duration::from_secs(30)).await
    }).await.context("erase account profile and history")
}

/// Deletes the external object first. YDB retains its key until a second,
/// serializable check confirms that the same profile still owns that key.
pub async fn erase_avatar(
    client: &Client,
    media: Option<&S3MediaDelete>,
    id: i64,
) -> Result<Option<AvatarCleanup>> {
    ensure!(id > 0, "invalid deletion operation ID");
    ensure_progress_schema(client).await?;
    let Some(mut operation) = client
        .query_client()
        .query_row("SELECT user_id, status FROM accounts_accountdeletionrequest WHERE id = $id")
        .param("$id", id)
        .optional()
        .await?
    else {
        return Ok(None);
    };
    let account_id: i32 = operation.remove_field_by_name("user_id")?.try_into()?;
    let status: String = operation.remove_field_by_name("status")?.try_into()?;
    ensure!(
        status == "running",
        "avatar cleanup requires running deletion"
    );
    crate::data_export_operation::ensure_schema(client).await?;
    if crate::data_export_operation::has_unsealed_delayed(client, account_id).await? {
        // The snapshot may still need the current avatar bytes. A later
        // worker pass resumes this stage after the export is sealed.
        return Ok(None);
    }
    let mut query_client = client.query_client();
    let mut profiles = query_client.query("SELECT id, CAST(avatar AS Utf8) AS avatar_key FROM accounts_userprofile VIEW acct_profile_user_idx WHERE user_id = $id LIMIT 2")
        .param("$id", account_id).await?;
    let mut found = Vec::new();
    while let Some(rows) = profiles.next_result_set().await? {
        for mut row in rows {
            let profile_id: i64 = row.remove_field_by_name("id")?.try_into()?;
            let key: Option<String> = row.remove_field_by_name("avatar_key")?.try_into()?;
            found.push((profile_id, key));
        }
    }
    profiles.close().await?;
    ensure!(found.len() <= 1, "multiple profiles for deletion account");
    let expected = found
        .first()
        .and_then(|(_, key)| key.clone())
        .filter(|key| !key.is_empty());
    if let Some(key) = expected.as_deref() {
        let media = media.context("S3 media deletion is not configured")?;
        media.delete_avatar(account_id, key).await?;
    }
    let expected = expected.clone();
    let cleared = retry_known_abort(|| {
        let expected = expected.clone();
        async move {
            client.query_client().retry_tx(closure!([expected], async |tx: &mut Transaction| {
                let Some(mut operation) = tx.query_row("SELECT user_id, status FROM accounts_accountdeletionrequest WHERE id = $id")
                    .param("$id", id).optional().await? else { return Ok(false); };
                let owner: i32 = operation.remove_field_by_name("user_id")?.try_into()?;
                let status: String = operation.remove_field_by_name("status")?.try_into()?;
                if owner != account_id || status != "running" { return Ok(false); }
                let Some(mut account) = tx.query_row("SELECT is_active FROM auth_user WHERE id = $id")
                    .param("$id", account_id).optional().await? else { return Ok(false); };
                let active: bool = account.remove_field_by_name("is_active")?.try_into()?;
                if active { return Ok(false); }
                let mut profiles = tx.query("SELECT id, CAST(avatar AS Utf8) AS avatar_key FROM accounts_userprofile VIEW acct_profile_user_idx WHERE user_id = $id LIMIT 2")
                    .param("$id", account_id).await?;
                let mut current = Vec::new();
                while let Some(rows) = profiles.next_result_set().await? {
                    for mut row in rows {
                        let profile_id: i64 = row.remove_field_by_name("id")?.try_into()?;
                        let key: Option<String> = row.remove_field_by_name("avatar_key")?.try_into()?;
                        current.push((profile_id, key.filter(|key| !key.is_empty())));
                    }
                }
                profiles.close().await?;
                if current.len() > 1 || current.first().and_then(|(_, key)| key.clone()) != *expected {
                    return Ok(false);
                }
                if let Some((profile_id, Some(_))) = current.first() {
                    tx.exec("UPDATE accounts_userprofile SET avatar = NULL, avatar_source = 'none', updated_at = CurrentUtcDatetime() WHERE id = $id")
                        .param("$id", *profile_id).await?;
                }
                tx.exec(format!("UPSERT INTO `{PROGRESS_TABLE}` (operation_id, avatar_done, updated_at) VALUES ($id, true, CurrentUtcDatetime())"))
                    .param("$id", id).await?;
                if tx.query_row(format!("SELECT operation_id FROM `{PROFILE_PROGRESS_TABLE}` WHERE operation_id = $id"))
                    .param("$id", id).optional().await?.is_none() {
                    tx.exec(format!("INSERT INTO `{PROFILE_PROGRESS_TABLE}` (operation_id, profile_done, updated_at) VALUES ($id, false, CurrentUtcDatetime())"))
                        .param("$id", id).await?;
                }
                Ok(true)
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
                .timeout(Duration::from_secs(15)).await
        }
    }).await.context("confirm avatar deletion")?;
    Ok(Some(AvatarCleanup {
        id: id.to_string(),
        avatar_removed: cleared,
        cleanup_completed: false,
    }))
}

/// Timer recovery only selects `pending` operations. A committed credential
/// stage becomes `running`, so subsequent timer invocations do not redo it.
pub async fn drain_pending(client: &Client, limit: u64) -> Result<CredentialDrain> {
    ensure!(
        (1..=10).contains(&limit),
        "deletion batch size must be 1..=10"
    );
    let mut query_client = client.query_client();
    let mut query = query_client.query(format!(
        "SELECT id FROM accounts_accountdeletionrequest VIEW acct_delete_status_idx WHERE status = 'pending' ORDER BY requested_at LIMIT {limit}"
    )).timeout(Duration::from_secs(15)).await?;
    let mut ids = Vec::new();
    while let Some(rows) = query.next_result_set().await? {
        for mut row in rows {
            ids.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    query.close().await?;
    let mut report = CredentialDrain::default();
    for id in ids {
        report.attempted += 1;
        match erase_credentials(client, id).await {
            Ok(Some(result)) if result.credential_stage_completed => report.completed += 1,
            Ok(_) => report.deferred += 1,
            Err(_) => {
                tracing::warn!("account deletion credential stage deferred");
                report.deferred += 1;
            }
        }
    }
    Ok(report)
}

pub async fn drain_pending_avatars(
    client: &Client,
    media: Option<&S3MediaDelete>,
    limit: u64,
) -> Result<CredentialDrain> {
    ensure!(
        (1..=10).contains(&limit),
        "avatar deletion batch size must be 1..=10"
    );
    ensure_progress_schema(client).await?;
    let mut query_client = client.query_client();
    let mut query = query_client.query(format!(
        "SELECT operation_id FROM `{PROGRESS_TABLE}` VIEW id_deletion_avatar_due_idx WHERE avatar_done = false LIMIT {limit}"
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
        match erase_avatar(client, media, id).await {
            Ok(Some(result)) if result.avatar_removed => report.completed += 1,
            Ok(_) => report.deferred += 1,
            Err(_) => {
                tracing::warn!("account deletion avatar stage deferred");
                report.deferred += 1;
            }
        }
    }
    Ok(report)
}

pub async fn drain_pending_profiles(client: &Client, limit: u64) -> Result<CredentialDrain> {
    drain_pending_profiles_with_exports(client, None, limit).await
}

pub async fn drain_pending_profiles_with_exports(
    client: &Client,
    storage: Option<&crate::data_export_s3::S3Export>,
    limit: u64,
) -> Result<CredentialDrain> {
    ensure!(
        (1..=10).contains(&limit),
        "profile deletion batch size must be 1..=10"
    );
    ensure_progress_schema(client).await?;
    let mut query_client = client.query_client();
    let mut query = query_client.query(format!(
        "SELECT operation_id FROM `{PROFILE_PROGRESS_TABLE}` VIEW id_deletion_profile_due_idx WHERE profile_done = false LIMIT {limit}"
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
        if let Some(storage) = storage {
            let owner = client
                .query_client()
                .query_row(
                    "SELECT user_id, status FROM accounts_accountdeletionrequest WHERE id = $id",
                )
                .param("$id", id)
                .optional()
                .await?;
            if let Some(mut owner) = owner {
                let account_id: i32 = owner.remove_field_by_name("user_id")?.try_into()?;
                let status: String = owner.remove_field_by_name("status")?.try_into()?;
                if status == "running" {
                    match crate::data_export_job::clean_owner(client, storage, account_id, 100)
                        .await
                    {
                        Ok(true) => {}
                        Ok(false) => {
                            report.deferred += 1;
                            continue;
                        }
                        Err(error) => {
                            tracing::warn!(operation_id = id, error = %error, "account export cleanup deferred");
                            report.deferred += 1;
                            continue;
                        }
                    }
                }
            }
        }
        match erase_profile_history(client, id).await {
            Ok(Some(result)) if result.profile_history_removed => report.completed += 1,
            Ok(_) => report.deferred += 1,
            Err(_) => {
                tracing::warn!("account deletion profile stage deferred");
                report.deferred += 1;
            }
        }
    }
    Ok(report)
}

/// Repeatedly removes exact UUID references. A clean rescan only marks the
/// UUID pass as done; applications and final identity erasure remain separate.
pub async fn drain_pending_globals(client: &Client, limit: u64) -> Result<CredentialDrain> {
    ensure!(
        (1..=10).contains(&limit),
        "global deletion batch size must be 1..=10"
    );
    ensure_progress_schema(client).await?;
    let mut query_client = client.query_client();
    let mut query = query_client.query(format!(
        "SELECT operation_id FROM `{GLOBAL_PROGRESS_TABLE}` VIEW id_deletion_global_due_idx WHERE uuid_done = false LIMIT {limit}"
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
        match legacy_unbound(client, id).await {
            Ok(true) => {
                match mark_uuid_pass_done(client, id, true).await {
                    Ok(true) => report.completed += 1,
                    Ok(false) | Err(_) => report.deferred += 1,
                }
                continue;
            }
            Ok(false) => {}
            Err(_) => {
                report.deferred += 1;
                continue;
            }
        }
        match crate::account_deletion_audit::erase_global_uuid_references(client, id).await {
            Ok(Some(result))
                if result.audit_candidates == 0
                    && result.outbox_candidates == 0
                    && !result.audit_scan_truncated
                    && !result.outbox_scan_truncated =>
            {
                if mark_uuid_pass_done(client, id, false).await? {
                    report.completed += 1;
                } else {
                    report.deferred += 1;
                }
            }
            Ok(Some(result)) if result.audit_removed > 0 || result.outbox_removed > 0 => {
                report.completed += 1;
            }
            Ok(_) => report.deferred += 1,
            Err(_) => {
                tracing::warn!("account deletion global UUID pass deferred");
                report.deferred += 1;
            }
        }
    }
    Ok(report)
}

/// Complete one operation's global-reference pass without scanning other
/// deletion requests. A clean repeat scan is required before marking it done.
pub async fn complete_global_pass(client: &Client, id: i64) -> Result<bool> {
    ensure!(id > 0, "invalid deletion operation ID");
    ensure_progress_schema(client).await?;
    if legacy_unbound(client, id).await? {
        return mark_uuid_pass_done(client, id, true).await;
    }
    let Some(result) =
        crate::account_deletion_audit::erase_global_uuid_references(client, id).await?
    else {
        return Ok(false);
    };
    if result.audit_candidates != 0
        || result.outbox_candidates != 0
        || result.audit_scan_truncated
        || result.outbox_scan_truncated
    {
        return Ok(false);
    }
    mark_uuid_pass_done(client, id, false).await
}

async fn legacy_unbound(client: &Client, id: i64) -> Result<bool> {
    let mut operation = client
        .query_client()
        .query_row("SELECT user_id FROM accounts_accountdeletionrequest WHERE id = $id")
        .param("$id", id)
        .await?;
    let account_id: i32 = operation.remove_field_by_name("user_id")?.try_into()?;
    let mut binding = client
        .query_client()
        .query_row("SELECT identity_id FROM accounts_accountidentity WHERE user_id = $id")
        .param("$id", account_id)
        .await?;
    let identity_id: Option<uuid::Uuid> =
        binding.remove_field_by_name("identity_id")?.try_into()?;
    Ok(identity_id.is_none())
}

async fn mark_uuid_pass_done(client: &Client, id: i64, expected_unbound: bool) -> Result<bool> {
    retry_known_abort(|| async {
        client.query_client().retry_tx(closure!([id, expected_unbound], async |tx: &mut Transaction| {
            let Some(mut operation) = tx.query_row("SELECT user_id, status FROM accounts_accountdeletionrequest WHERE id = $id")
                .param("$id", *id).optional().await? else { return Ok(false); };
            let account_id: i32 = operation.remove_field_by_name("user_id")?.try_into()?;
            let status: String = operation.remove_field_by_name("status")?.try_into()?;
            if status != "running" { return Ok(false); }
            let Some(mut account) = tx.query_row("SELECT is_active FROM auth_user WHERE id = $id")
                .param("$id", account_id).optional().await? else { return Ok(false); };
            let active: bool = account.remove_field_by_name("is_active")?.try_into()?;
            if active { return Ok(false); }
            let Some(mut binding) = tx.query_row("SELECT identity_id FROM accounts_accountidentity WHERE user_id = $id")
                .param("$id", account_id).optional().await? else { return Ok(false); };
            let identity_id: Option<uuid::Uuid> = binding.remove_field_by_name("identity_id")?.try_into()?;
            if identity_id.is_none() != *expected_unbound { return Ok(false); }
            if let Some(identity_id) = identity_id {
                let Some(mut identity) = tx.query_row("SELECT status FROM usid_user WHERE user_id = $id")
                    .param("$id", identity_id).optional().await? else { return Ok(false); };
                let identity_status: String = identity.remove_field_by_name("status")?.try_into()?;
                if identity_status != "suspended" { return Ok(false); }
            } else {
                for table in ["usid_application", "usid_audit_log", "usid_outbox"] {
                    if tx.query_row(format!("SELECT id FROM `{table}` LIMIT 1"))
                        .optional().await?.is_some() { return Ok(false); }
                }
            }
            let Some(mut profile) = tx.query_row(format!("SELECT profile_done FROM `{PROFILE_PROGRESS_TABLE}` WHERE operation_id = $id"))
                .param("$id", *id).optional().await? else { return Ok(false); };
            let profile_done: bool = profile.remove_field_by_name("profile_done")?.try_into()?;
            if !profile_done { return Ok(false); }
            let Some(mut progress) = tx.query_row(format!("SELECT uuid_done FROM `{GLOBAL_PROGRESS_TABLE}` WHERE operation_id = $id"))
                .param("$id", *id).optional().await? else { return Ok(false); };
            let already_done: bool = progress.remove_field_by_name("uuid_done")?.try_into()?;
            if already_done { return Ok(true); }
            tx.exec(format!("UPDATE `{GLOBAL_PROGRESS_TABLE}` SET uuid_done = true, updated_at = CurrentUtcDatetime() WHERE operation_id = $id"))
                .param("$id", *id).await?;
            Ok(true)
        })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
            .timeout(Duration::from_secs(15)).await
    }).await.context("mark global UUID pass done")
}

async fn related_i64(
    tx: &mut Transaction,
    statement: &str,
    user_id: i32,
) -> ydb::YdbResultWithCustomerErr<Vec<i64>> {
    let mut query = tx.query(statement).param("$user_id", user_id).await?;
    let mut ids = Vec::new();
    while let Some(rows) = query.next_result_set().await? {
        for mut row in rows {
            ids.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    query.close().await?;
    if ids.len() > 1000 {
        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
            "too many related credentials for one deletion transaction",
        )));
    }
    Ok(ids)
}

async fn related_i32(
    tx: &mut Transaction,
    statement: &str,
    user_id: i32,
) -> ydb::YdbResultWithCustomerErr<Vec<i32>> {
    let mut query = tx.query(statement).param("$user_id", user_id).await?;
    let mut ids = Vec::new();
    while let Some(rows) = query.next_result_set().await? {
        for mut row in rows {
            ids.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    query.close().await?;
    if ids.len() > 1000 {
        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
            "too many related credentials for one deletion transaction",
        )));
    }
    Ok(ids)
}

async fn related_strings(
    tx: &mut Transaction,
    statement: &str,
    user_id: i32,
) -> ydb::YdbResultWithCustomerErr<Vec<String>> {
    let mut query = tx.query(statement).param("$user_id", user_id).await?;
    let mut values = Vec::new();
    while let Some(rows) = query.next_result_set().await? {
        for mut row in rows {
            values.push(row.remove_field_by_name("session_key")?.try_into()?);
        }
    }
    query.close().await?;
    if values.len() > 1000 {
        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
            "too many sessions for one deletion transaction",
        )));
    }
    Ok(values)
}

/// Safe to repeat after a crash or an ambiguous commit. Two workers may race;
/// the serializable transaction keeps their state transition consistent.
pub async fn erase_credentials(client: &Client, id: i64) -> Result<Option<CredentialCleanup>> {
    ensure!(id > 0, "invalid deletion operation ID");
    crate::passkey_index::ensure_schema(client).await?;
    crate::password_reset::ensure_schema(client).await?;
    crate::email_verify::ensure_schema(client).await?;
    ensure_progress_schema(client).await?;
    retry_known_abort(|| async {
        client.query_client().retry_tx(closure!([id], async |tx: &mut Transaction| {
            let Some(mut operation) = tx.query_row("SELECT user_id, status, executed_at FROM accounts_accountdeletionrequest WHERE id = $id")
                .param("$id", *id).optional().await? else { return Ok(None); };
            let account_id: i32 = operation.remove_field_by_name("user_id")?.try_into()?;
            let status: String = operation.remove_field_by_name("status")?.try_into()?;
            let executed_at: Option<std::time::SystemTime> = operation.remove_field_by_name("executed_at")?.try_into()?;
            if status == "succeeded" || status == "executed" || status == "canceled" {
                let cleanup_completed = status == "succeeded" && executed_at.is_some();
                return Ok(Some(CredentialCleanup {
                    id: id.to_string(), status, credential_stage_completed: false,
                    cleanup_completed,
                }));
            }
            if status != "pending" && status != "running" {
                return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("unknown account deletion status")));
            }
            let Some(mut account) = tx.query_row("SELECT is_active FROM auth_user WHERE id = $id")
                .param("$id", account_id).optional().await? else {
                return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("deletion account missing before credential cleanup")));
            };
            let active: bool = account.remove_field_by_name("is_active")?.try_into()?;
            if active {
                return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("deletion account is still active")));
            }
            let Some(mut binding) = tx.query_row("SELECT identity_id FROM accounts_accountidentity WHERE user_id = $id")
                .param("$id", account_id).optional().await? else {
                return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("deletion identity binding missing")));
            };
            let identity_id: Option<uuid::Uuid> = binding.remove_field_by_name("identity_id")?.try_into()?;
            if let Some(identity_id) = identity_id {
                let Some(mut identity) = tx.query_row("SELECT status FROM usid_user WHERE user_id = $id")
                    .param("$id", identity_id).optional().await? else {
                    return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("deletion identity missing")));
                };
                let identity_status: String = identity.remove_field_by_name("status")?.try_into()?;
                if identity_status != "suspended" {
                    return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("deletion identity is not suspended")));
                }
            }
            let outstanding = related_i64(tx,
                "SELECT id FROM token_blacklist_outstandingtoken VIEW token_blacklist_outstandingtoken_user_id_83bc629a WHERE user_id = $user_id LIMIT 1001",
                account_id).await?;
            for token_id in outstanding {
                tx.exec("DELETE FROM token_blacklist_blacklistedtoken WHERE token_id = $id")
                    .param("$id", token_id).await?;
            }
            let social_accounts = related_i32(tx,
                "SELECT id FROM socialaccount_socialaccount VIEW socialaccount_socialaccount_user_id_8146e70c WHERE user_id = $user_id LIMIT 1001",
                account_id).await?;
            for social_account_id in social_accounts {
                tx.exec("DELETE FROM socialaccount_socialtoken WHERE account_id = $id")
                    .param("$id", social_account_id).await?;
            }
            let email_addresses = related_i32(tx,
                "SELECT id FROM account_emailaddress VIEW account_emailaddress_user_id_2c513194 WHERE user_id = $user_id LIMIT 1001",
                account_id).await?;
            for email_id in email_addresses {
                tx.exec("DELETE FROM account_emailconfirmation WHERE email_address_id = $id")
                    .param("$id", email_id).await?;
            }
            for table in ACCOUNT_CREDENTIAL_TABLES {
                let column = if *table == "id_passkey_credential" { "account_id" } else { "user_id" };
                tx.exec(format!("DELETE FROM `{table}` WHERE `{column}` = $id"))
                    .param("$id", account_id).await?;
            }
            if let Some(identity_id) = identity_id {
                for table in IDENTITY_CREDENTIAL_TABLES {
                    tx.exec(format!("DELETE FROM `{table}` WHERE user_id = $id"))
                        .param("$id", identity_id).await?;
                }
            }
            tx.exec("UPDATE accounts_accountdeletionrequest SET status = 'running' WHERE id = $id")
                .param("$id", *id).await?;
            if tx.query_row(format!("SELECT operation_id FROM `{PROGRESS_TABLE}` WHERE operation_id = $id"))
                .param("$id", *id).optional().await?.is_none() {
                tx.exec(format!("INSERT INTO `{PROGRESS_TABLE}` (operation_id, avatar_done, updated_at) VALUES ($id, false, CurrentUtcDatetime())"))
                    .param("$id", *id).await?;
            }
            Ok(Some(CredentialCleanup {
                id: id.to_string(), status: "running".into(),
                credential_stage_completed: true, cleanup_completed: false,
            }))
        })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
            .timeout(Duration::from_secs(30)).await
    }).await.context("erase account deletion credentials")
}
