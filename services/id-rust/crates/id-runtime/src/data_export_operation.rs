//! Durable owner-scoped export requests. Object upload is a separate stage;
//! a claim can be completed only after the private archive was acknowledged.

use crate::{
    cache_store::CacheStore,
    data_export_escrow::{self, ExportEscrowKey},
    data_export_mail,
    session_issuer::{MfaVerdict, check_and_consume_mfa},
    session_store::{LEGACY_BACKENDS, restore_django_session_tx},
    tx_retry::retry_known_abort,
};
use anyhow::{Context, Result, ensure};
use hmac::{Hmac, KeyInit, Mac};
use id_compat::{mfa_seal::MfaSealKey, session::SessionCodec};
use serde::Serialize;
use sha2::Sha256;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use ydb::{Client, IndexStatus, IndexType, Transaction, TxMode, Value, closure};

const TABLE: &str = "id_data_export_operation";
const DUE_INDEX: &str = "id_data_export_due_idx";
const EXPIRY_INDEX: &str = "id_data_export_expiry_idx";
const OWNER_INDEX: &str = "id_data_export_owner_idx";
const LEASE: Duration = Duration::from_secs(15 * 60);
const RETENTION: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_DELAYED_SNAPSHOT_ATTEMPTS: i32 = 10;

#[derive(Debug, Clone, Serialize)]
pub struct ExportOperation {
    pub id: String,
    pub status: String,
    pub manifest: Option<serde_json::Value>,
    pub expires_at: Option<SystemTime>,
}

/// Operator-facing lifecycle only. Never expose owner, recipient, manifest,
/// private object key or a download capability through this view.
#[derive(Debug, Serialize)]
pub struct OperatorExportStatus {
    pub id: String,
    pub status: String,
    pub escrow_state: Option<String>,
    pub archive_sealed: bool,
    pub release_at: Option<u64>,
    pub expires_at: Option<u64>,
}

pub async fn read_operator_status(
    client: &Client,
    id: &str,
) -> Result<Option<OperatorExportStatus>> {
    ensure!(
        id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid export operation ID"
    );
    let id = id.to_owned();
    client
        .query_client()
        .retry_tx(closure!([id], async |tx: &mut Transaction| {
            let Some(mut operation) = tx
                .query_row(format!(
                    "SELECT status, object_key, expires_at FROM `{TABLE}` WHERE id = $id"
                ))
                .param("$id", id.clone())
                .optional()
                .await?
            else {
                return Ok(None);
            };
            let status: String = operation.remove_field_by_name("status")?.try_into()?;
            let object_key: String = operation.remove_field_by_name("object_key")?.try_into()?;
            let operation_expiry: Option<SystemTime> =
                operation.remove_field_by_name("expires_at")?.try_into()?;
            let escrow = tx
                .query_row("SELECT state, release_at, expires_at, object_key, delivery_state FROM id_data_export_escrow WHERE id = $id")
                .param("$id", id.clone())
                .optional()
                .await?;
            let (escrow_state, release_at, escrow_expiry, escrow_sealed, delivery_sent) =
                if let Some(mut escrow) = escrow {
                    let state: String = escrow.remove_field_by_name("state")?.try_into()?;
                    let release: SystemTime =
                        escrow.remove_field_by_name("release_at")?.try_into()?;
                    let expiry: SystemTime =
                        escrow.remove_field_by_name("expires_at")?.try_into()?;
                    let key: String = escrow.remove_field_by_name("object_key")?.try_into()?;
                    let delivery: String =
                        escrow.remove_field_by_name("delivery_state")?.try_into()?;
                    (Some(state), Some(release), Some(expiry), !key.is_empty(), delivery == "sent")
                } else {
                    (None, None, None, false, false)
                };
            let status = if status == "cooldown" && delivery_sent {
                "ready".to_owned()
            } else {
                status
            };
            let seconds = |value: SystemTime| value.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            Ok(Some(OperatorExportStatus {
                id: id.clone(),
                status,
                escrow_state,
                archive_sealed: !object_key.is_empty() || escrow_sealed,
                release_at: release_at.map(seconds),
                expires_at: escrow_expiry.or(operation_expiry).map(seconds),
            }))
        }))
        .isolation(TxMode::SnapshotReadOnly)
        .timeout(Duration::from_secs(5))
        .await
        .context("read operator export lifecycle")
}

#[derive(Debug)]
pub struct ExportClaim {
    pub id: String,
    pub account_id: i32,
    pub token: String,
    pub escrow: bool,
}

#[derive(Debug)]
pub struct StoredExport {
    pub id: String,
    pub account_id: i32,
    pub object_key: String,
    pub status: String,
    pub lease_until: Option<SystemTime>,
}

#[derive(Debug)]
pub enum AuthenticatedExportResult {
    Accepted(ExportOperation),
    Unauthorized,
    Stale,
    MfaRequired,
    WrongMfa,
    EmailUnverified,
}

pub(crate) struct AuthenticatedExportRequest<'a> {
    pub token: &'a str,
    pub account_id: i32,
    pub password_hash: &'a str,
    pub mfa_code: Option<&'a str>,
    pub key: &'a str,
    pub secret: &'a [u8],
    pub escrow_key: Option<&'a ExportEscrowKey>,
    pub now: SystemTime,
}

/// Additive, repeatable schema step. An existing table is checked for drift.
pub async fn ensure_schema(client: &Client) -> Result<()> {
    client.query_client().exec(format!(
        "CREATE TABLE IF NOT EXISTS `{TABLE}` (id Utf8 NOT NULL, user_id Int32 NOT NULL, status Utf8 NOT NULL, attempts Int32 NOT NULL, next_attempt_at Datetime NOT NULL, lease_until Datetime, claim_token Utf8 NOT NULL, object_key Utf8 NOT NULL, manifest Utf8 NOT NULL, created_at Datetime NOT NULL, completed_at Datetime, expires_at Datetime, INDEX `{DUE_INDEX}` GLOBAL ON (status, next_attempt_at), INDEX `{EXPIRY_INDEX}` GLOBAL ON (status, expires_at), INDEX `{OWNER_INDEX}` GLOBAL ON (user_id, created_at), PRIMARY KEY (id))"
    )).timeout(Duration::from_secs(15)).await?;
    for (name, columns) in [
        (EXPIRY_INDEX, "status, expires_at"),
        (OWNER_INDEX, "user_id, created_at"),
    ] {
        let current = client
            .table_client()
            .describe_table(format!("{}/{TABLE}", client.database()))
            .await?;
        if !current.indexes.iter().any(|index| index.name == name) {
            client
                .query_client()
                .exec(format!(
                    "ALTER TABLE `{TABLE}` ADD INDEX `{name}` GLOBAL ON ({columns})"
                ))
                .timeout(Duration::from_secs(30))
                .await?;
        }
    }
    let table = client
        .table_client()
        .describe_table(format!("{}/{TABLE}", client.database()))
        .await?;
    ensure!(
        table.primary_key == ["id"],
        "export operation primary key drift"
    );
    let expected = [
        "id",
        "user_id",
        "status",
        "attempts",
        "next_attempt_at",
        "lease_until",
        "claim_token",
        "object_key",
        "manifest",
        "created_at",
        "completed_at",
        "expires_at",
    ];
    let actual: std::collections::BTreeSet<_> =
        table.columns.iter().map(|c| c.name.as_str()).collect();
    ensure!(
        actual == expected.into_iter().collect(),
        "export operation columns drift"
    );
    for (name, kind, nullable) in [
        ("id", "text", false),
        ("user_id", "int32", false),
        ("status", "text", false),
        ("attempts", "int32", false),
        ("next_attempt_at", "datetime", false),
        ("lease_until", "datetime", true),
        ("claim_token", "text", false),
        ("object_key", "text", false),
        ("manifest", "text", false),
        ("created_at", "datetime", false),
        ("completed_at", "datetime", true),
        ("expires_at", "datetime", true),
    ] {
        let column = table
            .columns
            .iter()
            .find(|c| c.name == name)
            .context("export operation column missing")?;
        let value = column
            .type_value
            .as_ref()
            .map_err(|_| anyhow::anyhow!("unsupported export operation column type: {name}"))?;
        ensure!(
            value.is_optional() == nullable,
            "export operation nullability drift: {name}"
        );
        if !nullable {
            ensure!(
                matches!(
                    (kind, value),
                    ("text", Value::Text(_))
                        | ("int32", Value::Int32(_))
                        | ("datetime", Value::DateTime(_))
                ),
                "export operation type drift: {name}"
            );
        }
    }
    for (name, columns) in [
        (DUE_INDEX, &["status", "next_attempt_at"][..]),
        (EXPIRY_INDEX, &["status", "expires_at"][..]),
        (OWNER_INDEX, &["user_id", "created_at"][..]),
    ] {
        let mut ready = false;
        for _ in 0..100 {
            let table = client
                .table_client()
                .describe_table(format!("{}/{TABLE}", client.database()))
                .await?;
            let index = table
                .indexes
                .iter()
                .find(|index| index.name == name)
                .context("export operation index missing")?;
            ensure!(
                index.index_columns == columns && index.index_type == IndexType::Global,
                "export operation index drift: {name}"
            );
            if index.status == IndexStatus::Ready {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        ensure!(ready, "export operation index not ready: {name}");
    }
    Ok(())
}

fn operation_id(account_id: i32, key: &str, secret: &[u8]) -> Result<String> {
    operation_id_for_mode(account_id, key, secret, false)
}

fn operation_id_for_mode(
    account_id: i32,
    key: &str,
    secret: &[u8],
    delayed: bool,
) -> Result<String> {
    ensure!(
        account_id > 0 && secret.len() >= 32,
        "invalid export operation identity"
    );
    ensure!(
        !key.is_empty()
            && key.len() <= 128
            && key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')),
        "invalid export idempotency key"
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)?;
    mac.update(if delayed {
        b"id-data-export-v2\0"
    } else {
        b"id-data-export-v1\0"
    });
    mac.update(&account_id.to_be_bytes());
    mac.update(b"\0");
    mac.update(key.as_bytes());
    Ok(hex::encode(&mac.finalize().into_bytes()[..16]))
}

/// Repeating a request with the same owner and key returns the same operation.
pub async fn request(
    client: &Client,
    account_id: i32,
    key: &str,
    secret: &[u8],
    now: SystemTime,
) -> Result<ExportOperation> {
    let id = operation_id(account_id, key, secret)?;
    let request_id = id.clone();
    retry_known_abort(|| {
        let id = request_id.clone();
        async move {
            client
                .query_client()
                .retry_tx(closure!([id], async |tx: &mut Transaction| {
                    if let Some(row) = read_tx(tx, id, account_id).await? {
                        return Ok(row);
                    }
                    insert_new_tx(tx, id, account_id, now, false).await
                }))
                .with_mode(TxMode::SerializableReadWrite)
                .idempotent(false)
                .timeout(Duration::from_secs(10))
                .await
        }
    })
    .await
    .context("create export operation")
}

/// Read the exact hash only for a live session that has already completed MFA.
/// Password verification itself happens off the async executor in the caller.
pub(crate) async fn password_hash_for_session(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: &str,
    now: SystemTime,
) -> Result<Option<(i32, String)>> {
    let token = token.to_owned();
    let backends = LEGACY_BACKENDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    client.query_client().retry_tx(closure!([token, codec, backends], async |tx: &mut Transaction| {
        let Some(session) = restore_django_session_tx(tx, codec.as_ref(), token, backends, now).await? else { return Ok(None); };
        let account_id = i32::try_from(session.principal.account_id.get())
            .map_err(ydb::YdbOrCustomerError::from_err)?;
        let has_mfa = tx.query_row("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $id LIMIT 1")
            .param("$id", account_id).optional().await?.is_some();
        if has_mfa && !session.mfa_verified { return Ok(None); }
        let Some(mut user) = tx.query_row("SELECT password FROM auth_user WHERE id = $id")
            .param("$id", account_id).optional().await? else { return Ok(None); };
        let hash: String = user.remove_field_by_name("password")?.try_into()?;
        Ok(Some((account_id, hash)))
    })).isolation(TxMode::SnapshotReadOnly).timeout(Duration::from_secs(10)).await
        .context("read export reauthentication hash")
}

/// Repeat session, password-hash and MFA checks in the operation transaction.
/// A recovery code is consumed only if the operation insert commits. Replaying
/// an already committed idempotency key returns its receipt before MFA use.
pub(crate) async fn request_authenticated(
    client: &Client,
    codec: Arc<SessionCodec>,
    cache: CacheStore,
    seal_key: Option<Arc<MfaSealKey>>,
    request: AuthenticatedExportRequest<'_>,
) -> Result<AuthenticatedExportResult> {
    let escrow_key = request.escrow_key.cloned();
    let id = operation_id_for_mode(
        request.account_id,
        request.key,
        request.secret,
        escrow_key.is_some(),
    )?;
    let token = request.token.to_owned();
    let account_id = request.account_id;
    let password_hash = request.password_hash.to_owned();
    let now = request.now;
    let code = request.mfa_code.map(|value| value.trim().replace(' ', ""));
    let backends = LEGACY_BACKENDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    retry_known_abort(|| {
        let id = id.clone();
        let token = token.clone();
        let password_hash = password_hash.clone();
        let code = code.clone();
        let codec = codec.clone();
        let cache = cache.clone();
        let seal_key = seal_key.clone();
        let escrow_key = escrow_key.clone();
        let backends = backends.clone();
        async move {
            client.query_client().retry_tx(closure!([id, token, password_hash, code, codec, cache, seal_key, escrow_key, backends], async |tx: &mut Transaction| {
                let Some(session) = restore_django_session_tx(tx, codec.as_ref(), token, backends, now).await? else { return Ok(AuthenticatedExportResult::Unauthorized); };
                if session.principal.account_id.get() != i64::from(account_id) {
                    return Ok(AuthenticatedExportResult::Unauthorized);
                }
                let has_mfa = tx.query_row("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $id LIMIT 1")
                    .param("$id", account_id).optional().await?.is_some();
                if has_mfa && !session.mfa_verified { return Ok(AuthenticatedExportResult::Unauthorized); }
                let Some(mut user) = tx.query_row("SELECT password FROM auth_user WHERE id = $id")
                    .param("$id", account_id).optional().await? else { return Ok(AuthenticatedExportResult::Unauthorized); };
                let actual_hash: String = user.remove_field_by_name("password")?.try_into()?;
                if actual_hash != *password_hash { return Ok(AuthenticatedExportResult::Stale); }
                if let Some(existing) = read_tx(tx, id, account_id).await? {
                    if escrow_key.is_some() && (!data_export_escrow::owner_exists_tx(tx, id, account_id).await?
                        || !data_export_mail::intents_exist_tx(tx, id).await?) {
                        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("delayed export escrow missing")));
                    }
                    return Ok(AuthenticatedExportResult::Accepted(existing));
                }
                let sealed_recipient = if let Some(key) = escrow_key.as_ref() {
                    let Some(address) = verified_delivery_email_tx(tx, account_id).await? else {
                        return Ok(AuthenticatedExportResult::EmailUnverified);
                    };
                    Some(key.seal_recipient(id, &address).map_err(|_| ydb::YdbOrCustomerError::from_err(std::io::Error::other("invalid export delivery address")))?)
                } else { None };
                let verdict = check_and_consume_mfa(tx, account_id, code.as_deref(), Some(cache), seal_key.as_deref(), now).await?;
                match verdict {
                    MfaVerdict::Reject if code.is_none() => return Ok(AuthenticatedExportResult::MfaRequired),
                    MfaVerdict::Reject | MfaVerdict::Webauthn => return Ok(AuthenticatedExportResult::WrongMfa),
                    MfaVerdict::NoMfa | MfaVerdict::Totp | MfaVerdict::Recovery => {},
                }
                let operation = insert_new_tx(tx, id, account_id, now, escrow_key.is_some()).await?;
                if let Some(recipient) = sealed_recipient {
                    data_export_escrow::insert_request_tx(tx, id, account_id, &recipient, now).await?;
                    data_export_mail::insert_request_tx(tx, id, now).await?;
                }
                Ok(AuthenticatedExportResult::Accepted(operation))
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(15)).await
        }
    }).await.context("create reauthenticated export operation")
}

async fn verified_delivery_email_tx(
    tx: &mut Transaction,
    account_id: i32,
) -> ydb::YdbResultWithCustomerErr<Option<String>> {
    let mut rows = tx.query("SELECT email, verified FROM account_emailaddress VIEW account_emailaddress_user_id_2c513194 WHERE user_id = $id AND primary = true LIMIT 2")
        .param("$id", account_id).await?;
    let mut result = Vec::new();
    while let Some(set) = rows.next_result_set().await? {
        for mut row in set {
            let email: String = row.remove_field_by_name("email")?.try_into()?;
            let verified: bool = row.remove_field_by_name("verified")?.try_into()?;
            result.push((email, verified));
        }
    }
    rows.close().await?;
    if result.len() > 1 {
        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
            "ambiguous primary export email",
        )));
    }
    Ok(result
        .pop()
        .filter(|(email, verified)| *verified && !email.is_empty())
        .map(|(email, _)| email))
}

async fn insert_new_tx(
    tx: &mut Transaction,
    id: &str,
    account_id: i32,
    now: SystemTime,
    delayed: bool,
) -> ydb::YdbResultWithCustomerErr<ExportOperation> {
    let Some(mut user) = tx
        .query_row("SELECT is_active FROM auth_user WHERE id = $id")
        .param("$id", account_id)
        .optional()
        .await?
    else {
        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
            "export owner missing",
        )));
    };
    let active: bool = user.remove_field_by_name("is_active")?.try_into()?;
    if !active {
        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
            "export owner inactive",
        )));
    }
    let Some(mut binding) = tx
        .query_row("SELECT identity_id FROM accounts_accountidentity WHERE user_id = $id")
        .param("$id", account_id)
        .optional()
        .await?
    else {
        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
            "export identity missing",
        )));
    };
    let identity: Option<Uuid> = binding.remove_field_by_name("identity_id")?.try_into()?;
    let Some(identity) = identity else {
        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
            "export identity missing",
        )));
    };
    let Some(mut master) = tx
        .query_row("SELECT status FROM usid_user WHERE user_id = $id")
        .param("$id", identity)
        .optional()
        .await?
    else {
        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
            "export master identity missing",
        )));
    };
    let status: String = master.remove_field_by_name("status")?.try_into()?;
    if status != "active" {
        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
            "export master identity inactive",
        )));
    }
    let deleting = tx.query_row("SELECT id FROM accounts_accountdeletionrequest VIEW accounts_accountdeletionrequest_user_id_6a166c52 WHERE user_id = $id AND status IN ('pending', 'running') LIMIT 1")
        .param("$id", account_id).optional().await?.is_some();
    if deleting {
        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
            "export owner deleting",
        )));
    }
    let status = if delayed {
        "pending_delayed"
    } else {
        "pending"
    };
    tx.exec(format!("INSERT INTO `{TABLE}` (id, user_id, status, attempts, next_attempt_at, claim_token, object_key, manifest, created_at) VALUES ($id, $user, $status, 0, CAST($now AS Datetime), '', '', '', CAST($now AS Datetime))"))
        .param("$id", id.to_owned()).param("$user", account_id).param("$status", status.to_owned()).param("$now", now).await?;
    Ok(ExportOperation {
        id: id.to_owned(),
        status: status.to_owned(),
        manifest: None,
        expires_at: None,
    })
}

async fn read_tx(
    tx: &mut Transaction,
    id: &str,
    owner: i32,
) -> ydb::YdbResultWithCustomerErr<Option<ExportOperation>> {
    let Some(mut row) = tx
        .query_row(format!(
            "SELECT user_id, status, manifest, expires_at FROM `{TABLE}` WHERE id = $id"
        ))
        .param("$id", id.to_owned())
        .optional()
        .await?
    else {
        return Ok(None);
    };
    let user_id: i32 = row.remove_field_by_name("user_id")?.try_into()?;
    let status: String = row.remove_field_by_name("status")?.try_into()?;
    // A scrubbed receipt retains only the HMAC-derived ID. The caller already
    // proved the owner and key by deriving this exact ID in request().
    if user_id != owner && !(user_id == 0 && status == "failed") {
        return Ok(None);
    }
    let manifest: String = row.remove_field_by_name("manifest")?.try_into()?;
    let expires_at: Option<SystemTime> = row.remove_field_by_name("expires_at")?.try_into()?;
    let manifest = if manifest.is_empty() {
        None
    } else {
        Some(serde_json::from_str(&manifest).map_err(ydb::YdbOrCustomerError::from_err)?)
    };
    Ok(Some(ExportOperation {
        id: id.to_owned(),
        status,
        manifest,
        expires_at,
    }))
}

pub async fn read_owned(
    client: &Client,
    account_id: i32,
    id: &str,
) -> Result<Option<ExportOperation>> {
    ensure!(
        account_id > 0 && id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid export operation ID"
    );
    let Some(mut row) = client
        .query_client()
        .query_row(format!(
            "SELECT user_id, status, manifest, expires_at FROM `{TABLE}` WHERE id = $id"
        ))
        .param("$id", id.to_owned())
        .optional()
        .await?
    else {
        return Ok(None);
    };
    let owner: i32 = row.remove_field_by_name("user_id")?.try_into()?;
    if owner != account_id {
        return Ok(None);
    }
    let status: String = row.remove_field_by_name("status")?.try_into()?;
    let raw: String = row.remove_field_by_name("manifest")?.try_into()?;
    let manifest = if raw.is_empty() {
        None
    } else {
        Some(serde_json::from_str(&raw)?)
    };
    let expires_at: Option<SystemTime> = row.remove_field_by_name("expires_at")?.try_into()?;
    Ok(Some(ExportOperation {
        id: id.to_owned(),
        status,
        manifest,
        expires_at,
    }))
}

/// Return a private key only while the owner remains active and the archive
/// has not expired. The public handler must also authenticate a live session.
pub async fn download_key(
    client: &Client,
    account_id: i32,
    id: &str,
    now: SystemTime,
) -> Result<Option<String>> {
    ensure!(
        account_id > 0 && id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid export operation ID"
    );
    let id = id.to_owned();
    client.query_client().retry_tx(closure!([id], async |tx: &mut Transaction| {
        let Some(mut row) = tx.query_row(format!("SELECT user_id, status, object_key, expires_at FROM `{TABLE}` WHERE id = $id"))
            .param("$id", id.clone()).optional().await? else { return Ok(None); };
        let owner: i32 = row.remove_field_by_name("user_id")?.try_into()?;
        let status: String = row.remove_field_by_name("status")?.try_into()?;
        let key: String = row.remove_field_by_name("object_key")?.try_into()?;
        let expires: Option<SystemTime> = row.remove_field_by_name("expires_at")?.try_into()?;
        if owner != account_id || status != "succeeded" || key.is_empty() || !expires.is_some_and(|when| when > now) { return Ok(None); }
        let Some(mut account) = tx.query_row("SELECT is_active FROM auth_user WHERE id = $id")
            .param("$id", account_id).optional().await? else { return Ok(None); };
        let active: bool = account.remove_field_by_name("is_active")?.try_into()?;
        if !active { return Ok(None); }
        let deleting = tx.query_row("SELECT id FROM accounts_accountdeletionrequest VIEW accounts_accountdeletionrequest_user_id_6a166c52 WHERE user_id = $id AND status IN ('pending', 'running') LIMIT 1")
            .param("$id", account_id).optional().await?.is_some();
        if deleting { return Ok(None); }
        Ok(Some(key))
    })).isolation(TxMode::SerializableReadWrite).timeout(Duration::from_secs(5)).await
        .context("read private export key")
}

pub async fn due_ids(client: &Client, now: SystemTime, limit: u64) -> Result<Vec<String>> {
    ensure!((1..=100).contains(&limit), "invalid export batch size");
    let mut ids = Vec::new();
    for status in ["pending", "running", "pending_delayed", "running_delayed"] {
        let mut query_client = client.query_client();
        let mut query = query_client.query(format!("SELECT id FROM `{TABLE}` VIEW `{DUE_INDEX}` WHERE status = $status AND next_attempt_at <= CAST($now AS Datetime) ORDER BY next_attempt_at LIMIT $limit"))
            .param("$status", status.to_owned()).param("$now", now).param("$limit", limit).await?;
        while let Some(set) = query.next_result_set().await? {
            for mut row in set {
                ids.push(row.remove_field_by_name("id")?.try_into()?);
            }
        }
        query.close().await?;
    }
    ids.truncate(limit as usize);
    Ok(ids)
}

pub async fn expired(client: &Client, now: SystemTime, limit: u64) -> Result<Vec<StoredExport>> {
    ensure!(
        (1..=100).contains(&limit),
        "invalid export expiry batch size"
    );
    let mut query_client = client.query_client();
    let mut query = query_client.query(format!("SELECT id, user_id, object_key FROM `{TABLE}` VIEW `{EXPIRY_INDEX}` WHERE status = 'succeeded' AND expires_at <= CAST($now AS Datetime) ORDER BY expires_at LIMIT $limit"))
        .param("$now", now).param("$limit", limit).await?;
    let mut rows = Vec::new();
    while let Some(set) = query.next_result_set().await? {
        for mut row in set {
            rows.push(StoredExport {
                id: row.remove_field_by_name("id")?.try_into()?,
                account_id: row.remove_field_by_name("user_id")?.try_into()?,
                object_key: row.remove_field_by_name("object_key")?.try_into()?,
                status: "succeeded".into(),
                lease_until: None,
            });
        }
    }
    query.close().await?;
    Ok(rows)
}

pub async fn for_owner(client: &Client, account_id: i32, limit: u64) -> Result<Vec<StoredExport>> {
    ensure!(
        account_id > 0 && (1..=100).contains(&limit),
        "invalid export owner cleanup batch"
    );
    let mut query_client = client.query_client();
    let mut query = query_client.query(format!("SELECT id, object_key, status, lease_until FROM `{TABLE}` VIEW `{OWNER_INDEX}` WHERE user_id = $owner ORDER BY created_at LIMIT $limit"))
        .param("$owner", account_id).param("$limit", limit).await?;
    let mut rows = Vec::new();
    while let Some(set) = query.next_result_set().await? {
        for mut row in set {
            rows.push(StoredExport {
                id: row.remove_field_by_name("id")?.try_into()?,
                account_id,
                object_key: row.remove_field_by_name("object_key")?.try_into()?,
                status: row.remove_field_by_name("status")?.try_into()?,
                lease_until: row.remove_field_by_name("lease_until")?.try_into()?,
            });
        }
    }
    query.close().await?;
    Ok(rows)
}

/// Avatar cleanup must wait for any previously accepted export that still
/// needs the profile's media. Account access is already revoked by deletion.
pub async fn has_unsealed_delayed(client: &Client, account_id: i32) -> Result<bool> {
    ensure!(account_id > 0, "invalid export owner");
    let mut query_client = client.query_client();
    let mut query = query_client.query(format!(
        "SELECT id FROM `{TABLE}` VIEW `{OWNER_INDEX}` WHERE user_id = $owner AND status IN ('pending_delayed', 'running_delayed') LIMIT 1"
    )).param("$owner", account_id).await?;
    let mut found = false;
    while let Some(rows) = query.next_result_set().await? {
        found |= rows.into_iter().next().is_some();
    }
    query.close().await?;
    Ok(found)
}

/// Preserve only the opaque idempotency receipt after confirmed object removal.
pub async fn scrub(client: &Client, stored: &StoredExport) -> Result<bool> {
    ensure!(
        stored.account_id > 0
            && stored.id.len() == 32
            && stored.id.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid export scrub target"
    );
    let id = stored.id.clone();
    let object_key = stored.object_key.clone();
    let owner = stored.account_id;
    retry_known_abort(|| {
        let id = id.clone(); let object_key = object_key.clone();
        async move {
            client.query_client().retry_tx(closure!([id, object_key], async |tx: &mut Transaction| {
                let Some(mut row) = tx.query_row(format!("SELECT user_id, object_key FROM `{TABLE}` WHERE id = $id"))
                    .param("$id", id.clone()).optional().await? else { return Ok(false); };
                let current_owner: i32 = row.remove_field_by_name("user_id")?.try_into()?;
                let current_key: String = row.remove_field_by_name("object_key")?.try_into()?;
                if current_owner != owner || current_key != *object_key { return Ok(false); }
                tx.exec(format!("UPDATE `{TABLE}` SET user_id = 0, status = 'failed', claim_token = '', lease_until = NULL, object_key = '', manifest = '', completed_at = NULL, expires_at = NULL WHERE id = $id"))
                    .param("$id", id.clone()).await?;
                Ok(true)
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(10)).await
        }
    }).await.context("scrub private export operation")
}

/// Detach a sealed delayed export from the account before personal records are
/// erased. The escrow keeps the private archive and encrypted delivery address;
/// the owner-scoped operation retains only its opaque receipt.
pub async fn detach_sealed(client: &Client, stored: &StoredExport) -> Result<bool> {
    ensure!(
        stored.account_id > 0 && stored.status == "cooldown" && !stored.object_key.is_empty(),
        "invalid delayed export detachment"
    );
    let id = stored.id.clone();
    let owner = stored.account_id;
    let object_key = stored.object_key.clone();
    retry_known_abort(|| {
        let id = id.clone();
        let object_key = object_key.clone();
        async move {
            client.query_client().retry_tx(closure!([id, object_key], async |tx: &mut Transaction| {
                let Some(mut operation) = tx.query_row(format!("SELECT user_id, status, object_key FROM `{TABLE}` WHERE id = $id"))
                    .param("$id", id.clone()).optional().await? else { return Ok(false); };
                let operation_owner: i32 = operation.remove_field_by_name("user_id")?.try_into()?;
                let status: String = operation.remove_field_by_name("status")?.try_into()?;
                let current_key: String = operation.remove_field_by_name("object_key")?.try_into()?;
                if operation_owner != owner || status != "cooldown" || current_key != *object_key { return Ok(false); }
                let Some(mut escrow) = tx.query_row("SELECT user_id, state, object_key FROM id_data_export_escrow WHERE id = $id")
                    .param("$id", id.clone()).optional().await? else { return Ok(false); };
                let escrow_owner: i32 = escrow.remove_field_by_name("user_id")?.try_into()?;
                let escrow_state: String = escrow.remove_field_by_name("state")?.try_into()?;
                let escrow_key: String = escrow.remove_field_by_name("object_key")?.try_into()?;
                if escrow_owner != owner || escrow_state != "sealed" || escrow_key != *object_key { return Ok(false); }
                tx.exec("UPDATE id_data_export_escrow SET user_id = 0 WHERE id = $id")
                    .param("$id", id.clone()).await?;
                tx.exec(format!("UPDATE `{TABLE}` SET user_id = 0, object_key = '', manifest = '', claim_token = '', lease_until = NULL WHERE id = $id"))
                    .param("$id", id.clone()).await?;
                Ok(true)
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(10)).await
        }
    }).await.context("detach sealed delayed export")
}

/// The token fences a stale worker after lease expiry.
pub async fn claim(client: &Client, id: &str, now: SystemTime) -> Result<Option<ExportClaim>> {
    ensure!(
        id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid export operation ID"
    );
    let id = id.to_owned();
    let token = Uuid::new_v4().to_string();
    let until = now.checked_add(LEASE).context("export lease overflow")?;
    retry_known_abort(|| {
        let id = id.clone(); let token = token.clone();
        async move {
            client.query_client().retry_tx(closure!([id, token], async |tx: &mut Transaction| {
                let Some(mut row) = tx.query_row(format!("SELECT user_id, status, next_attempt_at, attempts, object_key FROM `{TABLE}` WHERE id = $id"))
                    .param("$id", id.clone()).optional().await? else { return Ok(None); };
                let user_id: i32 = row.remove_field_by_name("user_id")?.try_into()?;
                let status: String = row.remove_field_by_name("status")?.try_into()?;
                let next: SystemTime = row.remove_field_by_name("next_attempt_at")?.try_into()?;
                let attempts: i32 = row.remove_field_by_name("attempts")?.try_into()?;
                let object_key: String = row.remove_field_by_name("object_key")?.try_into()?;
                if !matches!(status.as_str(), "pending" | "running" | "pending_delayed" | "running_delayed") || next > now { return Ok(None); }
                let escrow = matches!(status.as_str(), "pending_delayed" | "running_delayed");
                let active = match tx.query_row("SELECT is_active FROM auth_user WHERE id = $id")
                    .param("$id", user_id).optional().await? {
                    Some(mut account) => account.remove_field_by_name("is_active")?.try_into()?,
                    None => false,
                };
                let deleting = tx.query_row("SELECT id FROM accounts_accountdeletionrequest VIEW accounts_accountdeletionrequest_user_id_6a166c52 WHERE user_id = $id AND status IN ('pending', 'running') LIMIT 1")
                    .param("$id", user_id).optional().await?.is_some();
                if escrow && !data_export_escrow::owner_exists_tx(tx, id, user_id).await? {
                    return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("delayed export escrow missing")));
                }
                if (!active && !deleting) || (!escrow && (!active || deleting)) {
                    tx.exec(format!("UPDATE `{TABLE}` SET status = 'failed', claim_token = '', lease_until = NULL WHERE id = $id"))
                        .param("$id", id.clone()).await?;
                    return Ok(None);
                }
                if escrow && attempts >= MAX_DELAYED_SNAPSHOT_ATTEMPTS {
                    if !object_key.is_empty() || !data_export_escrow::fail_snapshot_tx(tx, id, user_id).await? {
                        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("delayed export failure state inconsistent")));
                    }
                    tx.exec(format!("UPDATE `{TABLE}` SET status = 'failed', claim_token = '', lease_until = NULL, completed_at = CAST($now AS Datetime) WHERE id = $id"))
                        .param("$id", id.clone()).param("$now", now).await?;
                    return Ok(None);
                }
                let running = if escrow { "running_delayed" } else { "running" };
                tx.exec(format!("UPDATE `{TABLE}` SET status = $status, attempts = attempts + 1, claim_token = $token, lease_until = CAST($until AS Datetime), next_attempt_at = CAST($until AS Datetime) WHERE id = $id"))
                    .param("$id", id.clone()).param("$status", running.to_owned()).param("$token", token.clone()).param("$until", until).await?;
                Ok(Some(ExportClaim { id: id.clone(), account_id: user_id, token: token.clone(), escrow }))
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(10)).await
        }
    }).await.context("claim export operation")
}

pub async fn complete(
    client: &Client,
    claim: &ExportClaim,
    object_key: &str,
    manifest: &serde_json::Value,
    now: SystemTime,
) -> Result<bool> {
    let expected_key = if claim.escrow {
        format!("exports/escrow/{}/{}.ndjson", claim.id, claim.token)
    } else {
        format!(
            "exports/user_{}/{}/{}.ndjson",
            claim.account_id, claim.id, claim.token
        )
    };
    ensure!(
        object_key == expected_key,
        "export object key does not belong to claim"
    );
    let serialized = serde_json::to_string(manifest)?;
    ensure!(serialized.len() <= 64 * 1024, "export manifest too large");
    let expires = now
        .checked_add(RETENTION)
        .context("export expiry overflow")?;
    let id = claim.id.clone();
    let token = claim.token.clone();
    let owner = claim.account_id;
    let escrow = claim.escrow;
    let object_key = object_key.to_owned();
    retry_known_abort(|| {
        let id = id.clone(); let token = token.clone(); let serialized = serialized.clone(); let object_key = object_key.clone();
        async move {
            client.query_client().retry_tx(closure!([id, token, serialized, object_key], async |tx: &mut Transaction| {
                let Some(mut row) = tx.query_row(format!("SELECT user_id, status, claim_token FROM `{TABLE}` WHERE id = $id"))
                    .param("$id", id.clone()).optional().await? else { return Ok(false); };
                let user_id: i32 = row.remove_field_by_name("user_id")?.try_into()?;
                let status: String = row.remove_field_by_name("status")?.try_into()?;
                let current: String = row.remove_field_by_name("claim_token")?.try_into()?;
                let expected_status = if escrow { "running_delayed" } else { "running" };
                if user_id != owner || status != expected_status || current != *token { return Ok(false); }
                let Some(mut account) = tx.query_row("SELECT is_active FROM auth_user WHERE id = $id")
                    .param("$id", owner).optional().await? else { return Ok(false); };
                let active: bool = account.remove_field_by_name("is_active")?.try_into()?;
                let deleting = tx.query_row("SELECT id FROM accounts_accountdeletionrequest VIEW accounts_accountdeletionrequest_user_id_6a166c52 WHERE user_id = $id AND status IN ('pending', 'running') LIMIT 1")
                    .param("$id", owner).optional().await?.is_some();
                if (!active && !deleting) || (!escrow && (!active || deleting)) { return Ok(false); }
                let expires = if escrow {
                    data_export_escrow::seal_snapshot_tx(tx, id, owner, object_key, serialized, now).await?
                } else { expires };
                let completed_status = if escrow { "cooldown" } else { "succeeded" };
                tx.exec(format!("UPDATE `{TABLE}` SET status = $status, claim_token = '', lease_until = NULL, object_key = $key, manifest = $manifest, completed_at = CAST($now AS Datetime), expires_at = CAST($expires AS Datetime) WHERE id = $id"))
                    .param("$status", completed_status.to_owned())
                    .param("$id", id.clone()).param("$key", object_key.clone()).param("$manifest", serialized.clone())
                    .param("$now", now).param("$expires", expires).await?;
                Ok(true)
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(10)).await
        }
    }).await.context("complete export operation")
}
