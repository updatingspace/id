//! Recover due exports from YDB and upload one private archive per claim.

use crate::{data_export_operation, data_export_s3::S3Export};
use anyhow::{Result, ensure};
use std::{sync::Arc, time::SystemTime};
use ydb::Client;

#[derive(Default, Debug)]
pub struct ExportDrain {
    pub attempted: usize,
    pub completed: usize,
    pub deferred: usize,
}

pub async fn drain_due(client: Arc<Client>, storage: &S3Export, limit: u64) -> Result<ExportDrain> {
    ensure!((1..=10).contains(&limit), "invalid export job batch size");
    let mut result = ExportDrain::default();
    for id in data_export_operation::due_ids(&client, SystemTime::now(), limit).await? {
        let one = drain_one(client.clone(), storage, &id).await?;
        result.attempted += one.attempted;
        result.completed += one.completed;
        result.deferred += one.deferred;
    }
    Ok(result)
}

/// Process a known operation without letting older due rows starve it.
pub async fn drain_one(client: Arc<Client>, storage: &S3Export, id: &str) -> Result<ExportDrain> {
    let mut result = ExportDrain::default();
    let Some(claim) = data_export_operation::claim(&client, id, SystemTime::now()).await? else {
        return Ok(result);
    };
    result.attempted = 1;
    match storage.upload_export(client.clone(), &claim).await {
        Ok((key, manifest)) => {
            let manifest = serde_json::to_value(manifest)?;
            match data_export_operation::complete(
                &client,
                &claim,
                &key,
                &manifest,
                SystemTime::now(),
            )
            .await
            {
                Ok(true) => result.completed += 1,
                Ok(false) => {
                    // A replacement worker owns a different object key.
                    // Never publish this stale attempt's object.
                    if let Err(error) = storage.delete_object(&key).await {
                        tracing::warn!(operation_id = %id, error = %error, "stale export object cleanup failed");
                    }
                    result.deferred += 1;
                }
                Err(error) => {
                    // Commit may have succeeded. Do not delete the object
                    // or replay a second completion after an unknown result.
                    tracing::warn!(operation_id = %id, error = %error, "export completion uncertain");
                    result.deferred += 1;
                }
            }
        }
        Err(error) => {
            tracing::warn!(operation_id = %id, error = %error, "export upload deferred");
            result.deferred += 1;
        }
    }
    Ok(result)
}

pub async fn clean_expired(
    client: &Client,
    storage: &S3Export,
    limit: u64,
    now: SystemTime,
) -> Result<ExportDrain> {
    let mut result = ExportDrain::default();
    for stored in data_export_operation::expired(client, now, limit).await? {
        result.attempted += 1;
        if stored.object_key.is_empty() {
            result.deferred += 1;
            continue;
        }
        match storage.delete_object(&stored.object_key).await {
            Ok(()) => match data_export_operation::scrub(client, &stored).await {
                Ok(true) => result.completed += 1,
                Ok(false) | Err(_) => result.deferred += 1,
            },
            Err(error) => {
                tracing::warn!(operation_id = %stored.id, error = %error, "expired export deletion deferred");
                result.deferred += 1;
            }
        }
    }
    Ok(result)
}

/// Escrow objects live outside account prefixes, so their expiry requires a
/// separate sweep. Keep this opt-in until delayed delivery is complete.
pub async fn clean_expired_escrow(
    client: &Client,
    storage: &S3Export,
    limit: u64,
    now: SystemTime,
) -> Result<ExportDrain> {
    let mut result = ExportDrain::default();
    for stored in crate::data_export_escrow::expired(client, now, limit).await? {
        result.attempted += 1;
        let deleted = if stored.object_key.is_empty() {
            Ok(())
        } else {
            storage.delete_object(&stored.object_key).await
        };
        match deleted {
            Ok(()) => match crate::data_export_escrow::forget_expired(client, &stored, now).await {
                Ok(true) => result.completed += 1,
                Ok(false) | Err(_) => result.deferred += 1,
            },
            Err(error) => {
                tracing::warn!(operation_id = %stored.id, error = %error, "expired escrow deletion deferred");
                result.deferred += 1;
            }
        }
    }
    Ok(result)
}

/// Delete an account's archives before its profile deletion can finish. A
/// running upload is fenced by scrub; its worker must remove the stale object.
pub async fn clean_owner(
    client: &Client,
    storage: &S3Export,
    account_id: i32,
    limit: u64,
) -> Result<bool> {
    ensure!(account_id > 0, "invalid export owner");
    ensure!(
        (1..=100).contains(&limit),
        "invalid owner cleanup batch size"
    );
    let mut deferred = false;
    for stored in data_export_operation::for_owner(client, account_id, limit).await? {
        if matches!(
            stored.status.as_str(),
            "pending_delayed" | "running_delayed"
        ) {
            // A pending deletion cannot erase the source records until the
            // requested snapshot is safely sealed in private storage.
            deferred = true;
            continue;
        }
        if stored.status == "cooldown" {
            match data_export_operation::detach_sealed(client, &stored).await {
                Ok(true) => {}
                Ok(false) | Err(_) => deferred = true,
            }
            continue;
        }
        if stored.status == "running"
            && stored
                .lease_until
                .is_none_or(|until| until > SystemTime::now())
        {
            deferred = true;
            continue;
        }
        if !stored.object_key.is_empty()
            && let Err(error) = storage.delete_object(&stored.object_key).await
        {
            tracing::warn!(operation_id = %stored.id, error = %error, "account export deletion deferred");
            deferred = true;
            continue;
        }
        match data_export_operation::scrub(client, &stored).await {
            Ok(true) => {}
            Ok(false) | Err(_) => deferred = true,
        }
    }
    if deferred {
        return Ok(false);
    }
    let page = storage.list_owner_objects(account_id).await?;
    for key in &page.keys {
        storage.delete_object(key).await?;
    }
    // A following pass confirms the prefix is empty after the deletions.
    // An index read also prevents proceeding after a concurrent scrub race.
    Ok(page.keys.is_empty()
        && !page.truncated
        && data_export_operation::for_owner(client, account_id, 1)
            .await?
            .is_empty())
}
