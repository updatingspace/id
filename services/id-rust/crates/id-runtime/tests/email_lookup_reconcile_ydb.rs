//! Rust-only repair of the derived account-email lookup on disposable YDB.

use anyhow::{Result, ensure};
use id_runtime::{email_lookup_reconcile::reconcile, login_email_audit::audit_auth_user};
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::test]
#[ignore = "requires the migrated local YDB schema"]
async fn repairs_missing_and_stale_keys_and_removes_orphans() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "test must use local YDB"
    );
    let client = id_runtime::connect_ydb().await?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let base = -i32::try_from(stamp % 1_000_000_000 + 100)?;
    let ids = [base, base - 1, base - 2];
    let orphan = base - 3;
    for (offset, id) in ids.into_iter().enumerate() {
        client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, '!', true, $name, '', '', $email, false, false, CurrentUtcDatetime())")
            .param("$id", id)
            .param("$name", format!("rust-lookup-{stamp}-{offset}"))
            .param("$email", format!(" Rust-lookup-{stamp}-{offset}@Example.invalid "))
            .await?;
    }
    client
        .query_client()
        .exec("UPSERT INTO accounts_accountemaillookup (user_id, email_key) VALUES ($id, 'stale')")
        .param("$id", ids[1])
        .await?;
    client
        .query_client()
        .exec("UPSERT INTO accounts_accountemaillookup (user_id, email_key) VALUES ($id, $key)")
        .param("$id", ids[2])
        .param("$key", format!("rust-lookup-{stamp}-2@example.invalid"))
        .await?;
    client
        .query_client()
        .exec("UPSERT INTO accounts_accountemaillookup (user_id, email_key) VALUES ($id, 'orphan')")
        .param("$id", orphan)
        .await?;
    let outcome: Result<()> = async {
        let dry = reconcile(&client, 1, false).await?;
        ensure!(dry.dry_run && dry.missing_or_stale_before == 2 && dry.orphans_before == 1);
        ensure!(audit_auth_user(&client).await?.lookup_missing_or_stale == 2);
        let report = reconcile(&client, 1, true).await?;
        ensure!(
            report.scanned_accounts == 3
                && report.repaired_lookups == 2
                && report.removed_orphans == 1,
            "repair report: {report:?}"
        );
        ensure!(audit_auth_user(&client).await?.unambiguous());
        let repeated = reconcile(&client, 2, true).await?;
        ensure!(
            repeated.repaired_lookups == 0 && repeated.removed_orphans == 0,
            "second repair changed rows: {repeated:?}"
        );
        for id in [ids[0], ids[1]] {
            client
                .query_client()
                .exec("UPDATE auth_user SET email = 'Duplicate@example.invalid' WHERE id = $id")
                .param("$id", id)
                .await?;
        }
        ensure!(
            reconcile(&client, 1, true).await.is_err(),
            "email collision did not block reconciliation"
        );
        ensure!(
            audit_auth_user(&client).await?.collision_groups == 1,
            "collision fixture was not visible to the audit"
        );
        Ok(())
    }
    .await;
    for id in ids.into_iter().chain([orphan]) {
        client
            .query_client()
            .exec("DELETE FROM accounts_accountemaillookup WHERE user_id = $id")
            .param("$id", id)
            .await?;
    }
    for id in ids {
        client
            .query_client()
            .exec("DELETE FROM auth_user WHERE id = $id")
            .param("$id", id)
            .await?;
    }
    outcome
}
