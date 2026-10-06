#![recursion_limit = "256"]
//! Resumable credential-index backfill across page boundaries on real YDB.

use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::test]
#[ignore = "requires migrated disposable local YDB"]
async fn backfill_is_repeatable_and_duplicate_blocks_ready_marker() -> Result<()> {
    ensure!(
        std::env::var("YDB_DATABASE")? == "/local",
        "test requires local YDB"
    );
    let client = id_runtime::connect_ydb().await?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let first = i64::try_from(stamp)?;
    let owner = -i32::try_from(stamp % 1_000_000_000 + 1)?;
    let count = 105u64;
    let result: Result<()> = async {
        id_runtime::passkey_index::ensure_schema(&client).await?;
        let empty = id_runtime::passkey_index::backfill(&client).await?;
        ensure!(empty.scanned == 0, "test requires isolated MFA rows");
        for offset in 0..count {
            let raw_id = URL_SAFE_NO_PAD.encode([stamp.to_be_bytes().as_slice(), offset.to_be_bytes().as_slice()].concat());
            client.query_client().exec("INSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $owner, 'webauthn', Unwrap(CAST($data AS Json)), CurrentUtcDatetime())")
                .param("$id", first + i64::try_from(offset)?).param("$owner", owner)
                .param("$data", json!({"credential":{"rawId":raw_id}}).to_string()).await?;
        }
        let first_run = id_runtime::passkey_index::backfill(&client).await?;
        ensure!(first_run.scanned == count && first_run.inserted == count,
            "first pass missed page boundary: {first_run:?}");
        let second_run = id_runtime::passkey_index::backfill(&client).await?;
        ensure!(second_run.scanned == count && second_run.existing == count && second_run.inserted == 0,
            "second pass was not idempotent: {second_run:?}");
        client.query_client().exec("DELETE FROM mfa_authenticator WHERE id = $id")
            .param("$id", first).await?;
        let repaired = id_runtime::passkey_index::backfill(&client).await?;
        ensure!(repaired.scanned == count - 1 && repaired.stale_removed == 1,
            "deleted credential left an index mapping: {repaired:?}");
        let duplicate = URL_SAFE_NO_PAD.encode([stamp.to_be_bytes().as_slice(), 1u64.to_be_bytes().as_slice()].concat());
        client.query_client().exec("INSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $owner, 'webauthn', Unwrap(CAST($data AS Json)), CurrentUtcDatetime())")
            .param("$id", first + i64::try_from(count)?).param("$owner", owner)
            .param("$data", json!({"credential":{"rawId":duplicate}}).to_string()).await?;
        ensure!(id_runtime::passkey_index::backfill(&client).await.is_err(),
            "duplicate credential ID did not block backfill");
        let marker = client.query_client().query_row("SELECT digest FROM id_passkey_credential WHERE digest = 'ready'")
            .optional().await?;
        ensure!(marker.is_none(), "failed backfill left ready marker");
        Ok(())
    }.await;
    for offset in 0..=count {
        client
            .query_client()
            .exec("DELETE FROM mfa_authenticator WHERE id = $id")
            .param("$id", first + i64::try_from(offset)?)
            .await?;
    }
    let _ = id_runtime::passkey_index::backfill(&client).await?;
    result
}
