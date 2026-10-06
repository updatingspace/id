#![recursion_limit = "256"]
//! Read-only passkey audit across more than one YDB page.

use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::test]
#[ignore = "requires migrated disposable local YDB"]
async fn counts_legacy_credentials_across_pages_without_exposing_them() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "test requires local YDB"
    );
    let client = id_runtime::connect_ydb().await?;
    let fixture: Value = serde_json::from_str(include_str!("fixtures/legacy_passkey.json"))?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let first = i64::try_from(stamp)?;
    let owner = -i32::try_from(stamp % 1_000_000_000 + 1)?;
    let valid = json!({"name":"synthetic", "credential":fixture["registration"]}).to_string();
    let malformed = json!({"name":"synthetic"}).to_string();
    let incompatible = json!({"credential":{"rawId":"bad"}}).to_string();
    let outcome: Result<()> = async {
        for offset in 0..102 {
            let data = match offset {
                0 | 101 => valid.clone(),
                1 => incompatible.clone(),
                _ => malformed.clone(),
            };
            client.query_client().exec("UPSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $user_id, 'webauthn', Unwrap(CAST($data AS Json)), CurrentUtcDatetime())")
                .param("$id", first + offset).param("$user_id", owner).param("$data", data).await?;
        }
        client.query_client().exec("UPSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $user_id, 'totp', Unwrap(CAST($data AS Json)), CurrentUtcDatetime())")
            .param("$id", first + 102).param("$user_id", owner)
            .param("$data", json!({"secret":"synthetic"}).to_string()).await?;
        let report = id_runtime::passkey_audit::audit(&client,
            fixture["rp_id"].as_str().ok_or_else(|| anyhow::anyhow!("RP ID"))?,
            fixture["origin"].as_str().ok_or_else(|| anyhow::anyhow!("origin"))?).await?;
        ensure!(report.scanned == 102 && report.convertible == 2 && report.malformed == 99
            && report.incompatible == 1 && report.duplicate_credential_ids == 1 && !report.ready(),
            "audit lost a page or misclassified records: {report:?}");
        let output = serde_json::to_string(&report)?;
        ensure!(!output.contains("synthetic") && !output.contains("RUST-LEGACY"),
            "audit output disclosed credential data");
        Ok(())
    }.await;
    for offset in 0..103 {
        client
            .query_client()
            .exec("DELETE FROM mfa_authenticator WHERE id = $id")
            .param("$id", first + offset)
            .await?;
    }
    outcome
}
