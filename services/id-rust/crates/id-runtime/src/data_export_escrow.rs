//! Short-lived delivery state for an account export that must outlive account
//! deletion. The escrow is separate from the owner-scoped export operation.
//! Its mail address is encrypted and its download capability is never stored.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use anyhow::{Context, Result, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, Mac};
use lettre::message::Mailbox;
use sha2::Sha256;
use std::time::{Duration, SystemTime};
use subtle::ConstantTimeEq;
use ydb::{Client, IndexStatus, IndexType, Transaction, Value};

const TABLE: &str = "id_data_export_escrow";
const RELEASE_INDEX: &str = "id_export_escrow_release_idx";
const EXPIRY_INDEX: &str = "id_export_escrow_expiry_idx";
const OWNER_INDEX: &str = "id_export_escrow_owner_idx";
const ENVELOPE_PREFIX: &str = "id-export-email-v1:";
const NONCE_BYTES: usize = 12;
pub const COOLDOWN: Duration = Duration::from_secs(24 * 60 * 60);
pub const DELIVERY_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug)]
pub struct ExpiredEscrow {
    pub id: String,
    pub object_key: String,
}

#[derive(Clone)]
pub struct ExportEscrowKey([u8; 32]);

impl ExportEscrowKey {
    pub fn from_base64(encoded: &str) -> Result<Self> {
        let raw = STANDARD
            .decode(encoded)
            .context("invalid export escrow key")?;
        let bytes: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("export escrow key must be 32 bytes"))?;
        Ok(Self(bytes))
    }

    pub fn seal_recipient(&self, id: &str, address: &str) -> Result<String> {
        validate_id(id)?;
        ensure!(
            address.len() <= 254 && address.parse::<Mailbox>().is_ok(),
            "invalid export delivery address"
        );
        let nonce: [u8; NONCE_BYTES] = rand::random();
        let email_key = self.subkey(b"recipient-encryption")?;
        let cipher = Aes256Gcm::new_from_slice(&email_key)?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: address.as_bytes(),
                    aad: &recipient_aad(id),
                },
            )
            .map_err(|_| anyhow::anyhow!("export address encryption failed"))?;
        let mut packed = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
        packed.extend_from_slice(&nonce);
        packed.extend_from_slice(&ciphertext);
        Ok(format!(
            "{ENVELOPE_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(packed)
        ))
    }

    pub fn unseal_recipient(&self, id: &str, envelope: &str) -> Result<String> {
        validate_id(id)?;
        let packed = envelope
            .strip_prefix(ENVELOPE_PREFIX)
            .context("unsupported export address envelope")?;
        let packed = URL_SAFE_NO_PAD
            .decode(packed)
            .context("invalid export address envelope")?;
        ensure!(
            (NONCE_BYTES + 16..=NONCE_BYTES + 254 + 16).contains(&packed.len()),
            "invalid export address envelope length"
        );
        let (nonce, ciphertext) = packed.split_at(NONCE_BYTES);
        let email_key = self.subkey(b"recipient-encryption")?;
        let cipher = Aes256Gcm::new_from_slice(&email_key)?;
        let plain = cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &recipient_aad(id),
                },
            )
            .map_err(|_| anyhow::anyhow!("export address authentication failed"))?;
        let address = String::from_utf8(plain)?;
        ensure!(
            address.len() <= 254 && address.parse::<Mailbox>().is_ok(),
            "invalid decrypted export address"
        );
        Ok(address)
    }

    /// Reconstructible after an ambiguous SMTP acknowledgement: retries send
    /// the same capability, never mint a second one. Authorization still needs
    /// a due, sealed, unconsumed escrow record.
    pub fn capability(&self, id: &str) -> Result<String> {
        validate_id(id)?;
        let capability_key = self.subkey(b"download-capability")?;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&capability_key)?;
        mac.update(b"updspace-id:export-download:v1\0");
        mac.update(id.as_bytes());
        Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }

    pub fn verifies_capability(&self, id: &str, supplied: &str) -> Result<bool> {
        validate_id(id)?;
        if supplied.len() > 64 {
            return Ok(false);
        }
        let Ok(decoded) = URL_SAFE_NO_PAD.decode(supplied) else {
            return Ok(false);
        };
        let expected = URL_SAFE_NO_PAD.decode(self.capability(id)?)?;
        Ok(decoded.len() == expected.len() && bool::from(decoded.ct_eq(&expected)))
    }

    /// Sent with the immediate notice, before any archive is available. This
    /// purpose-separated token can revoke the export but cannot download it.
    pub fn cancel_capability(&self, id: &str) -> Result<String> {
        validate_id(id)?;
        let capability_key = self.subkey(b"cancel-capability")?;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&capability_key)?;
        mac.update(b"updspace-id:export-cancel:v1\0");
        mac.update(id.as_bytes());
        Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }

    pub fn verifies_cancel_capability(&self, id: &str, supplied: &str) -> Result<bool> {
        validate_id(id)?;
        if supplied.len() > 64 {
            return Ok(false);
        }
        let Ok(decoded) = URL_SAFE_NO_PAD.decode(supplied) else {
            return Ok(false);
        };
        let expected = URL_SAFE_NO_PAD.decode(self.cancel_capability(id)?)?;
        Ok(decoded.len() == expected.len() && bool::from(decoded.ct_eq(&expected)))
    }

    fn subkey(&self, purpose: &[u8]) -> Result<[u8; 32]> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.0)?;
        mac.update(b"updspace-id:export-escrow-key:v1\0");
        mac.update(purpose);
        Ok(mac.finalize().into_bytes().into())
    }
}

fn validate_id(id: &str) -> Result<()> {
    ensure!(
        id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid export escrow ID"
    );
    Ok(())
}

fn recipient_aad(id: &str) -> Vec<u8> {
    let mut aad = b"updspace-id:export-recipient:v1\0".to_vec();
    aad.extend_from_slice(id.as_bytes());
    aad
}

/// Additive storage. A live deployment must run this before accepting delayed
/// requests; a mismatched table is a hard error instead of a silent fallback.
pub async fn ensure_schema(client: &Client) -> Result<()> {
    client.query_client().exec(format!(
        "CREATE TABLE IF NOT EXISTS `{TABLE}` (id Utf8 NOT NULL, user_id Int32 NOT NULL, encrypted_email Utf8 NOT NULL, state Utf8 NOT NULL, release_at Datetime NOT NULL, expires_at Datetime NOT NULL, object_key Utf8 NOT NULL, manifest Utf8 NOT NULL, notice_state Utf8 NOT NULL, delivery_state Utf8 NOT NULL, created_at Datetime NOT NULL, sealed_at Datetime, consumed_at Datetime, INDEX `{RELEASE_INDEX}` GLOBAL ON (state, release_at), INDEX `{EXPIRY_INDEX}` GLOBAL ON (state, expires_at), INDEX `{OWNER_INDEX}` GLOBAL ON (user_id, created_at), PRIMARY KEY (id))"
    )).timeout(Duration::from_secs(15)).await?;
    let description = client
        .table_client()
        .describe_table(format!("{}/{TABLE}", client.database()))
        .await?;
    ensure!(
        description.primary_key == ["id"],
        "export escrow primary key drift"
    );
    let expected = [
        "id",
        "user_id",
        "encrypted_email",
        "state",
        "release_at",
        "expires_at",
        "object_key",
        "manifest",
        "notice_state",
        "delivery_state",
        "created_at",
        "sealed_at",
        "consumed_at",
    ];
    let actual: std::collections::BTreeSet<_> = description
        .columns
        .iter()
        .map(|column| column.name.as_str())
        .collect();
    ensure!(
        actual == expected.into_iter().collect(),
        "export escrow column drift"
    );
    for (name, kind, nullable) in [
        ("id", "text", false),
        ("user_id", "int32", false),
        ("encrypted_email", "text", false),
        ("state", "text", false),
        ("release_at", "datetime", false),
        ("expires_at", "datetime", false),
        ("object_key", "text", false),
        ("manifest", "text", false),
        ("notice_state", "text", false),
        ("delivery_state", "text", false),
        ("created_at", "datetime", false),
        ("sealed_at", "datetime", true),
        ("consumed_at", "datetime", true),
    ] {
        let column = description
            .columns
            .iter()
            .find(|column| column.name == name)
            .context("export escrow column missing")?;
        let value = column
            .type_value
            .as_ref()
            .map_err(|_| anyhow::anyhow!("unsupported export escrow column: {name}"))?;
        ensure!(
            value.is_optional() == nullable,
            "export escrow nullability drift: {name}"
        );
        if !nullable {
            ensure!(
                matches!(
                    (kind, value),
                    ("text", Value::Text(_))
                        | ("int32", Value::Int32(_))
                        | ("datetime", Value::DateTime(_))
                ),
                "export escrow type drift: {name}"
            );
        }
    }
    for (name, columns) in [
        (RELEASE_INDEX, &["state", "release_at"][..]),
        (EXPIRY_INDEX, &["state", "expires_at"][..]),
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
                .context("export escrow index missing")?;
            ensure!(
                index.index_columns == columns && index.index_type == IndexType::Global,
                "export escrow index drift: {name}"
            );
            if index.status == IndexStatus::Ready {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        ensure!(ready, "export escrow index not ready: {name}");
    }
    Ok(())
}

/// Insert in the same serializable transaction as the authenticated export
/// request. The verified email is sealed before the transaction and cannot be
/// changed by a later account email update.
pub async fn insert_request_tx(
    tx: &mut Transaction,
    id: &str,
    owner: i32,
    sealed_recipient: &str,
    now: SystemTime,
) -> ydb::YdbResultWithCustomerErr<()> {
    if validate_id(id).is_err() || owner <= 0 || !sealed_recipient.starts_with(ENVELOPE_PREFIX) {
        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
            "invalid export escrow request",
        )));
    }
    let release = now + COOLDOWN;
    let expiry = release + DELIVERY_WINDOW;
    tx.exec(format!("INSERT INTO `{TABLE}` (id, user_id, encrypted_email, state, release_at, expires_at, object_key, manifest, notice_state, delivery_state, created_at) VALUES ($id, $owner, $email, 'accepted', CAST($release AS Datetime), CAST($expiry AS Datetime), '', '', 'pending', 'pending', CAST($now AS Datetime))"))
        .param("$id", id.to_owned())
        .param("$owner", owner)
        .param("$email", sealed_recipient.to_owned())
        .param("$release", release)
        .param("$expiry", expiry)
        .param("$now", now)
        .await?;
    Ok(())
}

pub async fn owner_exists_tx(
    tx: &mut Transaction,
    id: &str,
    owner: i32,
) -> ydb::YdbResultWithCustomerErr<bool> {
    let Some(mut row) = tx
        .query_row(format!("SELECT user_id FROM `{TABLE}` WHERE id = $id"))
        .param("$id", id.to_owned())
        .optional()
        .await?
    else {
        return Ok(false);
    };
    let stored_owner: i32 = row.remove_field_by_name("user_id")?.try_into()?;
    Ok(stored_owner == owner)
}

pub async fn release_at(client: &Client, id: &str, owner: i32) -> Result<Option<SystemTime>> {
    validate_id(id)?;
    ensure!(owner > 0, "invalid export owner");
    let Some(mut row) = client
        .query_client()
        .query_row(format!(
            "SELECT user_id, release_at FROM `{TABLE}` WHERE id = $id"
        ))
        .param("$id", id.to_owned())
        .optional()
        .await?
    else {
        return Ok(None);
    };
    let stored_owner: i32 = row.remove_field_by_name("user_id")?.try_into()?;
    if stored_owner != owner {
        return Ok(None);
    }
    Ok(Some(row.remove_field_by_name("release_at")?.try_into()?))
}

pub async fn delivery_sent(client: &Client, id: &str, owner: i32) -> Result<Option<bool>> {
    validate_id(id)?;
    ensure!(owner > 0, "invalid export owner");
    let Some(mut row) = client
        .query_client()
        .query_row(format!(
            "SELECT user_id, delivery_state FROM `{TABLE}` WHERE id = $id"
        ))
        .param("$id", id.to_owned())
        .optional()
        .await?
    else {
        return Ok(None);
    };
    let stored_owner: i32 = row.remove_field_by_name("user_id")?.try_into()?;
    if stored_owner != owner {
        return Ok(None);
    }
    let state: String = row.remove_field_by_name("delivery_state")?.try_into()?;
    Ok(Some(state == "sent"))
}

/// Bearer capability from an email, independent of the deleted account row.
/// It can be reused within the short delivery window so a lost HTTP response
/// does not irreversibly consume the only way to retrieve the archive.
pub async fn downloadable_key(
    client: &Client,
    key: &ExportEscrowKey,
    id: &str,
    supplied: &str,
    now: SystemTime,
) -> Result<Option<String>> {
    if !valid_capability_request(id, supplied) || !key.verifies_capability(id, supplied)? {
        return Ok(None);
    }
    let Some(mut row) = client
        .query_client()
        .query_row(format!(
            "SELECT state, release_at, expires_at, object_key FROM `{TABLE}` WHERE id = $id"
        ))
        .param("$id", id.to_owned())
        .optional()
        .await?
    else {
        return Ok(None);
    };
    let state: String = row.remove_field_by_name("state")?.try_into()?;
    let release: SystemTime = row.remove_field_by_name("release_at")?.try_into()?;
    let expiry: SystemTime = row.remove_field_by_name("expires_at")?.try_into()?;
    let object_key: String = row.remove_field_by_name("object_key")?.try_into()?;
    if !matches!(state.as_str(), "sealed" | "released")
        || now < release
        || now >= expiry
        || !object_key.starts_with(&format!("exports/escrow/{id}/"))
        || !object_key.ends_with(".ndjson")
    {
        return Ok(None);
    }
    Ok(Some(object_key))
}

fn valid_capability_request(id: &str, token: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()) && token.len() == 43
}

/// Called in the same serializable transaction that completes the upload.
/// The archive stays private until a later release job confirms delivery.
pub async fn seal_snapshot_tx(
    tx: &mut Transaction,
    id: &str,
    owner: i32,
    object_key: &str,
    manifest: &str,
    now: SystemTime,
) -> ydb::YdbResultWithCustomerErr<SystemTime> {
    let Some(mut row) = tx
        .query_row(format!(
            "SELECT user_id, state, object_key, expires_at FROM `{TABLE}` WHERE id = $id"
        ))
        .param("$id", id.to_owned())
        .optional()
        .await?
    else {
        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
            "export escrow missing",
        )));
    };
    let stored_owner: i32 = row.remove_field_by_name("user_id")?.try_into()?;
    let state: String = row.remove_field_by_name("state")?.try_into()?;
    let stored_key: String = row.remove_field_by_name("object_key")?.try_into()?;
    let expires_at: SystemTime = row.remove_field_by_name("expires_at")?.try_into()?;
    if stored_owner != owner || state != "accepted" || !stored_key.is_empty() || expires_at <= now {
        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
            "export escrow not sealable",
        )));
    }
    tx.exec(format!("UPDATE `{TABLE}` SET state = 'sealed', object_key = $key, manifest = $manifest, sealed_at = CAST($now AS Datetime) WHERE id = $id"))
        .param("$id", id.to_owned()).param("$key", object_key.to_owned())
        .param("$manifest", manifest.to_owned()).param("$now", now).await?;
    Ok(expires_at)
}

pub async fn expired(client: &Client, now: SystemTime, limit: u64) -> Result<Vec<ExpiredEscrow>> {
    ensure!(
        (1..=100).contains(&limit),
        "invalid escrow expiry batch size"
    );
    let mut found = Vec::new();
    for state in ["sealed", "released", "failed", "cancelled"] {
        let mut query_client = client.query_client();
        let mut query = query_client.query(format!("SELECT id, object_key FROM `{TABLE}` VIEW `{EXPIRY_INDEX}` WHERE state = $state AND expires_at <= CAST($now AS Datetime) ORDER BY expires_at LIMIT $limit"))
            .param("$state", state.to_owned()).param("$now", now).param("$limit", limit).await?;
        while let Some(set) = query.next_result_set().await? {
            for mut row in set {
                found.push(ExpiredEscrow {
                    id: row.remove_field_by_name("id")?.try_into()?,
                    object_key: row.remove_field_by_name("object_key")?.try_into()?,
                });
            }
        }
        query.close().await?;
    }
    found.truncate(limit as usize);
    Ok(found)
}

/// Must be called only after S3 confirmed deletion. One transaction removes
/// the delivery address and any remaining owner-scoped operation metadata.
pub async fn forget_expired(
    client: &Client,
    expired: &ExpiredEscrow,
    now: SystemTime,
) -> Result<bool> {
    validate_id(&expired.id)?;
    ensure!(
        expired.object_key.is_empty()
            || (expired
                .object_key
                .starts_with(&format!("exports/escrow/{}/", expired.id))
                && expired.object_key.len() <= 512),
        "invalid expired escrow key"
    );
    let id = expired.id.clone();
    let key = expired.object_key.clone();
    let changed = client.query_client().retry_tx(ydb::closure!([id, key], async |tx: &mut Transaction| {
        let Some(mut row) = tx.query_row(format!("SELECT state, object_key, expires_at FROM `{TABLE}` WHERE id = $id"))
            .param("$id", id.clone()).optional().await? else { return Ok(false); };
        let state: String = row.remove_field_by_name("state")?.try_into()?;
        let current_key: String = row.remove_field_by_name("object_key")?.try_into()?;
        let expires_at: SystemTime = row.remove_field_by_name("expires_at")?.try_into()?;
        if !matches!(state.as_str(), "sealed" | "released" | "failed" | "cancelled") || current_key != *key || expires_at > now {
            return Ok(false);
        }
        if state == "failed" && !key.is_empty() { return Ok(false); }
        if matches!(state.as_str(), "sealed" | "released") && key.is_empty() { return Ok(false); }
        let operation = tx.query_row("SELECT user_id, object_key FROM id_data_export_operation WHERE id = $id")
            .param("$id", id.clone()).optional().await?;
        if let Some(mut operation) = operation {
            let owner: i32 = operation.remove_field_by_name("user_id")?.try_into()?;
            let operation_key: String = operation.remove_field_by_name("object_key")?.try_into()?;
            if owner != 0 && operation_key != *key { return Ok(false); }
            tx.exec("UPDATE id_data_export_operation SET user_id = 0, status = 'expired', object_key = '', manifest = '', claim_token = '', lease_until = NULL WHERE id = $id")
                .param("$id", id.clone()).await?;
        }
        tx.exec(format!("UPDATE `{TABLE}` SET user_id = 0, state = 'expired', encrypted_email = '', object_key = '', manifest = '', notice_state = '', delivery_state = '' WHERE id = $id"))
            .param("$id", id.clone()).await?;
        Ok(true)
    })).with_mode(ydb::TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(10)).await?;
    Ok(changed)
}

/// Operator cancellation immediately revokes every download and mail path.
/// The object key is returned for deletion outside the transaction; repeating
/// this call after an uncertain S3 result returns the same key.
pub async fn cancel(client: &Client, id: &str) -> Result<Option<String>> {
    cancel_scoped(client, id, None).await
}

/// An authenticated owner may revoke an unexpected request without waiting
/// for an operator. After revocation, owner-scoped reads intentionally return
/// no operation: the receipt contains no personal data or archive link.
pub async fn cancel_owned(client: &Client, id: &str, owner: i32) -> Result<Option<String>> {
    ensure!(owner > 0, "invalid export owner");
    cancel_scoped(client, id, Some(owner)).await
}

/// A notice recipient can cancel even after account deletion revoked the
/// session. The token never grants access to the archive.
pub async fn cancel_with_capability(
    client: &Client,
    key: &ExportEscrowKey,
    id: &str,
    supplied: &str,
) -> Result<Option<String>> {
    if !valid_capability_request(id, supplied) || !key.verifies_cancel_capability(id, supplied)? {
        return Ok(None);
    }
    cancel_scoped(client, id, None).await
}

async fn cancel_scoped(
    client: &Client,
    id: &str,
    expected_owner: Option<i32>,
) -> Result<Option<String>> {
    validate_id(id)?;
    let id = id.to_owned();
    client.query_client().retry_tx(ydb::closure!([id, expected_owner], async |tx: &mut Transaction| {
        let expected_owner = *expected_owner;
        let Some(mut row) = tx.query_row(format!("SELECT user_id, state, object_key FROM `{TABLE}` WHERE id = $id"))
            .param("$id", id.clone()).optional().await? else { return Ok(None); };
        let owner: i32 = row.remove_field_by_name("user_id")?.try_into()?;
        let state: String = row.remove_field_by_name("state")?.try_into()?;
        let object_key: String = row.remove_field_by_name("object_key")?.try_into()?;
        if state == "expired" || expected_owner.is_some_and(|expected| owner != expected) {
            return Ok(None);
        }
        if let Some(expected) = expected_owner {
            let Some(mut operation) = tx.query_row("SELECT user_id FROM id_data_export_operation WHERE id = $id")
                .param("$id", id.clone()).optional().await? else { return Ok(None); };
            let operation_owner: i32 = operation.remove_field_by_name("user_id")?.try_into()?;
            if operation_owner != expected { return Ok(None); }
        }
        if state != "cancelled" {
            if !matches!(state.as_str(), "accepted" | "sealed" | "released" | "failed") {
                return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("unknown export escrow state")));
            }
            tx.exec(format!("UPDATE `{TABLE}` SET user_id = 0, state = 'cancelled', encrypted_email = '', notice_state = 'cancelled', delivery_state = 'cancelled' WHERE id = $id"))
                .param("$id", id.clone()).await?;
            tx.exec("UPDATE id_data_export_operation SET user_id = 0, status = 'cancelled', claim_token = '', lease_until = NULL, object_key = '', manifest = '' WHERE id = $id")
                .param("$id", id.clone()).await?;
            for kind in ["notice", "delivery"] {
                tx.exec("UPDATE id_data_export_mail SET state = 'cancelled', claim_token = '', lease_until = NULL WHERE id = $id")
                    .param("$id", format!("{id}:{kind}")).await?;
            }
        }
        Ok(Some(object_key))
    })).with_mode(ydb::TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(10)).await
        .context("cancel export escrow")
}

/// Clear the last object reference only after private S3 deletion succeeded.
pub async fn forget_cancelled(client: &Client, id: &str, deleted_key: &str) -> Result<bool> {
    validate_id(id)?;
    ensure!(
        deleted_key.is_empty()
            || (deleted_key.starts_with("exports/escrow/") && deleted_key.len() <= 512),
        "invalid cancelled escrow key"
    );
    let id = id.to_owned();
    let key = deleted_key.to_owned();
    client.query_client().retry_tx(ydb::closure!([id, key], async |tx: &mut Transaction| {
        let Some(mut row) = tx.query_row(format!("SELECT state, object_key FROM `{TABLE}` WHERE id = $id"))
            .param("$id", id.clone()).optional().await? else { return Ok(false); };
        let state: String = row.remove_field_by_name("state")?.try_into()?;
        let current_key: String = row.remove_field_by_name("object_key")?.try_into()?;
        if state != "cancelled" || current_key != *key { return Ok(false); }
        tx.exec(format!("UPDATE `{TABLE}` SET state = 'expired', object_key = '', manifest = '' WHERE id = $id"))
            .param("$id", id.clone()).await?;
        Ok(true)
    })).with_mode(ydb::TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(10)).await
        .context("forget cancelled export object")
}

/// A repeated snapshot failure ends the accepted request without creating a
/// downloadable archive. Keep the encrypted address until the failure notice
/// has been attempted, but detach it from the account being deleted.
pub async fn fail_snapshot_tx(
    tx: &mut Transaction,
    id: &str,
    owner: i32,
) -> ydb::YdbResultWithCustomerErr<bool> {
    let Some(mut row) = tx
        .query_row(format!(
            "SELECT user_id, state, object_key FROM `{TABLE}` WHERE id = $id"
        ))
        .param("$id", id.to_owned())
        .optional()
        .await?
    else {
        return Ok(false);
    };
    let current_owner: i32 = row.remove_field_by_name("user_id")?.try_into()?;
    let state: String = row.remove_field_by_name("state")?.try_into()?;
    let key: String = row.remove_field_by_name("object_key")?.try_into()?;
    if current_owner != owner || state != "accepted" || !key.is_empty() {
        return Ok(false);
    }
    tx.exec(format!(
        "UPDATE `{TABLE}` SET user_id = 0, state = 'failed' WHERE id = $id"
    ))
    .param("$id", id.to_owned())
    .await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipient_is_bound_to_operation_and_capability_is_stable() -> Result<()> {
        let key = ExportEscrowKey::from_base64(&STANDARD.encode([0x47; 32]))?;
        let id = "0123456789abcdef0123456789abcdef";
        let other = "fedcba9876543210fedcba9876543210";
        let envelope = key.seal_recipient(id, "person@example.invalid")?;
        assert!(!envelope.contains("person@example.invalid"));
        assert_eq!(
            key.unseal_recipient(id, &envelope)?,
            "person@example.invalid"
        );
        assert!(key.unseal_recipient(other, &envelope).is_err());
        let token = key.capability(id)?;
        assert!(key.verifies_capability(id, &token)?);
        assert!(!key.verifies_capability(other, &token)?);
        assert!(!key.verifies_capability(id, "wrong")?);
        assert_eq!(token, key.capability(id)?);
        let cancel = key.cancel_capability(id)?;
        assert!(key.verifies_cancel_capability(id, &cancel)?);
        assert!(!key.verifies_cancel_capability(other, &cancel)?);
        assert!(!key.verifies_cancel_capability(id, &token)?);
        assert!(!key.verifies_capability(id, &cancel)?);
        assert_eq!(cancel, key.cancel_capability(id)?);
        Ok(())
    }

    #[test]
    fn malformed_key_address_and_envelope_fail_closed() -> Result<()> {
        assert!(ExportEscrowKey::from_base64("short").is_err());
        let key = ExportEscrowKey::from_base64(&STANDARD.encode([0x47; 32]))?;
        let id = "0123456789abcdef0123456789abcdef";
        assert!(
            key.seal_recipient(id, "bad\nBcc:someone@example.invalid")
                .is_err()
        );
        assert!(key.seal_recipient("bad", "person@example.invalid").is_err());
        let mut envelope = key.seal_recipient(id, "person@example.invalid")?;
        envelope.push('x');
        assert!(key.unseal_recipient(id, &envelope).is_err());
        Ok(())
    }
}
