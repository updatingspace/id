//! Rust ledger writes only after identity and email postconditions hold.

use anyhow::{Result, ensure};
use id_runtime::migration_ledger;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires Rust-bootstrapped local YDB"]
async fn blocks_unbound_account_then_records_versions_once() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "test must use local YDB"
    );
    let client = id_runtime::connect_ydb().await?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let id = -i32::try_from(stamp % 1_000_000_000 + 100)?;
    client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, '!', true, $name, '', '', $email, false, false, CurrentUtcDatetime())")
        .param("$id", id)
        .param("$name", format!("rust-ledger-{stamp}"))
        .param("$email", format!("rust-ledger-{stamp}@example.invalid"))
        .await?;
    let blocked = migration_ledger::reconcile(&client, true).await;
    let identity_id = Uuid::new_v4();
    let outcome: Result<()> = async {
        ensure!(blocked.is_err(), "unbound account was accepted by ledger");
        client.query_client().exec("UPSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($identity, $name, $name, $email, true, 'active', false, CurrentUtcDatetime())")
            .param("$identity", identity_id)
            .param("$name", format!("rust-ledger-{stamp}"))
            .param("$email", format!("rust-ledger-{stamp}@example.invalid"))
            .await?;
        client.query_client().exec("UPSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($id, $identity, $subject, CurrentUtcDatetime())")
            .param("$id", id).param("$identity", identity_id)
            .param("$subject", identity_id.to_string()).await?;
        client.query_client().exec("UPSERT INTO accounts_accountemaillookup (user_id, email_key) VALUES ($id, $key)")
            .param("$id", id).param("$key", format!("rust-ledger-{stamp}@example.invalid"))
            .await?;
        let first = migration_ledger::reconcile(&client, true).await?;
        ensure!(first.verified_versions == 4 && first.bound_accounts >= 1,
            "ledger rejected proven binding: {first:?}");
        let repeated = migration_ledger::reconcile(&client, true).await?;
        ensure!(repeated.verified_versions == 4 && repeated.recorded_versions == 0,
            "repeated ledger write changed versions: {repeated:?}");
        let checked = migration_ledger::reconcile(&client, false).await?;
        ensure!(checked.verified_versions == 4 && checked.recorded_versions == 0);
        Ok(())
    }.await;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountemaillookup WHERE user_id = $id")
        .param("$id", id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountidentity WHERE user_id = $id")
        .param("$id", id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM usid_user WHERE user_id = $identity")
        .param("$identity", identity_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM auth_user WHERE id = $id")
        .param("$id", id)
        .await?;
    outcome
}
