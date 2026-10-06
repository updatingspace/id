//! Transitional YDB migration ledger with exact legacy checksums.
//! A version is recorded only after schema and data invariants are verified.

use crate::{legacy_schema, login_email_audit, tx_retry::retry_known_abort};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{collections::HashMap, time::Duration};
use ydb::{Client, TableDescription, Transaction, TxMode, Value, closure};

const TABLE: &str = "id_schema_migrations";
const MIGRATIONS: [(&str, &str); 4] = [
    (
        "0001_immutable_identity",
        "014c286f43c4f1c6e72d1f995f9b3afa144473a3842d67e5d99b2f4286fa4321",
    ),
    (
        "0002_account_email_lookup",
        "b68b1a335707bbe6b130b6b08e730c2d0c5e4f13838d37093e20e3f1acc3c102",
    ),
    (
        "0003_membership_source",
        "fc259f9f95e1c0ad348e4361223d88f229a071406de9f7aca5cfae51619a8637",
    ),
    (
        "0004_oidc_refresh_family",
        "f1df1be706071615f95d32ec7725c72f50e55a8d6b533e2e1d56193a20f56520",
    ),
];

#[derive(Debug, Default, Serialize)]
pub struct LedgerReport {
    pub verified_versions: usize,
    pub recorded_versions: usize,
    pub bound_accounts: u64,
    pub email_accounts: u64,
}

async fn count(client: &Client, sql: &str) -> Result<u64> {
    let mut row = client
        .query_client()
        .query_row(sql)
        .timeout(Duration::from_secs(30))
        .await?;
    Ok(row.remove_field_by_name("count")?.try_into()?)
}

async fn verify_identity_bindings(client: &Client) -> Result<u64> {
    let accounts = count(client, "SELECT COUNT(*) AS count FROM auth_user").await?;
    let missing = count(client, "SELECT COUNT(*) AS count FROM auth_user AS a LEFT JOIN accounts_accountidentity AS b ON a.id = b.user_id WHERE b.user_id IS NULL").await?;
    let orphan = count(client, "SELECT COUNT(*) AS count FROM accounts_accountidentity AS b LEFT JOIN auth_user AS a ON a.id = b.user_id WHERE a.id IS NULL").await?;
    let incomplete = count(client, "SELECT COUNT(*) AS count FROM accounts_accountidentity WHERE identity_id IS NULL OR public_subject = '' OR LENGTH(public_subject) > 128").await?;
    let missing_master = count(client, "SELECT COUNT(*) AS count FROM accounts_accountidentity AS b LEFT JOIN usid_user AS i ON b.identity_id = i.user_id WHERE b.identity_id IS NOT NULL AND i.user_id IS NULL").await?;
    let repeated_subject = count(client, "SELECT COUNT(*) AS count FROM (SELECT public_subject FROM accounts_accountidentity GROUP BY public_subject HAVING COUNT(*) > 1)").await?;
    let repeated_identity = count(client, "SELECT COUNT(*) AS count FROM (SELECT identity_id FROM accounts_accountidentity WHERE identity_id IS NOT NULL GROUP BY identity_id HAVING COUNT(*) > 1)").await?;
    ensure!(
        missing == 0
            && orphan == 0
            && incomplete == 0
            && missing_master == 0
            && repeated_subject == 0
            && repeated_identity == 0,
        "identity binding audit failed: missing={missing}, orphan={orphan}, incomplete={incomplete}, missing_master={missing_master}, repeated_subject={repeated_subject}, repeated_identity={repeated_identity}"
    );
    Ok(accounts)
}

fn validate_table(description: &TableDescription) -> Result<()> {
    ensure!(
        description.primary_key == ["name"],
        "migration ledger primary key drift"
    );
    ensure!(
        description.columns.len() == 3,
        "migration ledger columns drift"
    );
    for (name, kind) in [
        ("name", "text"),
        ("checksum", "text"),
        ("applied_at", "datetime"),
    ] {
        let column = description
            .columns
            .iter()
            .find(|column| column.name == name)
            .with_context(|| format!("migration ledger column {name} missing"))?;
        let value = column
            .type_value
            .as_ref()
            .map_err(|_| anyhow::anyhow!("migration ledger column {name} type unsupported"))?;
        ensure!(
            matches!(
                (kind, value),
                ("text", Value::Text(_)) | ("datetime", Value::DateTime(_))
            ),
            "migration ledger column {name} type drift"
        );
    }
    Ok(())
}

async fn read(client: &Client) -> Result<HashMap<String, String>> {
    let mut pager = client.query_client();
    let mut stream = pager
        .query(format!("SELECT name, checksum FROM `{TABLE}`"))
        .await?;
    let mut rows = HashMap::new();
    while let Some(result) = stream.next_result_set().await? {
        for mut row in result {
            let name: String = row.remove_field_by_name("name")?.try_into()?;
            let checksum: String = row.remove_field_by_name("checksum")?.try_into()?;
            ensure!(
                rows.insert(name, checksum).is_none(),
                "duplicate migration ledger row"
            );
        }
    }
    stream.close().await?;
    Ok(rows)
}

fn validate_rows(rows: &HashMap<String, String>) -> Result<()> {
    for (name, checksum) in rows {
        ensure!(
            MIGRATIONS
                .iter()
                .any(|(expected_name, expected_checksum)| name == expected_name
                    && checksum == expected_checksum),
            "unknown or modified migration ledger version: {name}"
        );
    }
    Ok(())
}

async fn write_once(client: &Client, name: &str, checksum: &str) -> Result<bool> {
    let name = name.to_owned();
    let checksum = checksum.to_owned();
    retry_known_abort(|| {
        let name = name.clone();
        let checksum = checksum.clone();
        async move {
            client.query_client().retry_tx(closure!([name, checksum], async |tx: &mut Transaction| {
                if let Some(mut row) = tx.query_row(format!("SELECT checksum FROM `{TABLE}` WHERE name = $name"))
                    .param("$name", name.clone()).optional().await? {
                    let actual: String = row.remove_field_by_name("checksum")?.try_into()?;
                    if actual != *checksum {
                        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
                            "migration ledger checksum changed",
                        )));
                    }
                    return Ok(false);
                }
                tx.exec(format!("INSERT INTO `{TABLE}` (name, checksum, applied_at) VALUES ($name, $checksum, CurrentUtcDatetime())"))
                    .param("$name", name.clone()).param("$checksum", checksum.clone()).await?;
                Ok(true)
            })).isolation(TxMode::SerializableReadWrite).timeout(Duration::from_secs(10)).await
        }
    }).await.context("record verified YDB migration")
}

/// Checks the frozen schema and identity/email postconditions before recording
/// any legacy version. Call while old writers are stopped or dual-writing.
pub async fn reconcile(client: &Client, apply: bool) -> Result<LedgerReport> {
    legacy_schema::reconcile(client, false).await?;
    if apply {
        client.query_client().exec(format!(
            "CREATE TABLE IF NOT EXISTS `{TABLE}` (name Utf8 NOT NULL, checksum Utf8 NOT NULL, applied_at Datetime NOT NULL, PRIMARY KEY (name))"
        )).timeout(Duration::from_secs(15)).await?;
    }
    let description = client
        .table_client()
        .describe_table(format!("{}/{TABLE}", client.database()))
        .await
        .context("migration ledger missing; run with --apply after data verification")?;
    validate_table(&description)?;
    let rows = read(client).await?;
    validate_rows(&rows)?;
    let mut report = LedgerReport {
        verified_versions: rows.len(),
        ..LedgerReport::default()
    };
    report.bound_accounts = verify_identity_bindings(client).await?;
    let email = login_email_audit::audit_auth_user(client).await?;
    ensure!(
        email.unambiguous(),
        "email lookup audit failed for migration ledger"
    );
    report.email_accounts = email.accounts;
    if !apply {
        ensure!(
            rows.len() == MIGRATIONS.len(),
            "migration ledger incomplete"
        );
        return Ok(report);
    }
    for (name, checksum) in MIGRATIONS {
        if write_once(client, name, checksum).await? {
            report.recorded_versions += 1;
        }
    }
    let rows = read(client).await?;
    validate_rows(&rows)?;
    ensure!(
        rows.len() == MIGRATIONS.len(),
        "migration ledger incomplete after write"
    );
    report.verified_versions = rows.len();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_changed_or_unknown_ledger_versions() {
        let mut rows = HashMap::new();
        rows.insert(MIGRATIONS[0].0.to_owned(), "changed".to_owned());
        assert!(validate_rows(&rows).is_err());
        rows.clear();
        rows.insert("unknown".to_owned(), "checksum".to_owned());
        assert!(validate_rows(&rows).is_err());
    }
}
