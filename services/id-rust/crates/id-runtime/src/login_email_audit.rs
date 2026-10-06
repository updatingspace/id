//! Read-only inventory before replacing the legacy case-insensitive email scan.
//! No address or account identifier leaves this module in the report.

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::time::Duration;
use ydb::Client;

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct LoginEmailAudit {
    pub accounts: u64,
    pub noncanonical: u64,
    pub empty: u64,
    pub normalization_mismatch: u64,
    pub collision_groups: u64,
    pub lookup_missing_or_stale: u64,
    pub lookup_orphans: u64,
}

impl LoginEmailAudit {
    pub fn unambiguous(&self) -> bool {
        self.empty == 0
            && self.normalization_mismatch == 0
            && self.collision_groups == 0
            && self.lookup_missing_or_stale == 0
            && self.lookup_orphans == 0
    }
}

/// Each page is a separate snapshot. Stop old writers and repeat immediately
/// before canary; this inventory cannot establish a durable uniqueness rule.
pub async fn audit_auth_user(client: &Client) -> Result<LoginEmailAudit> {
    audit_tables(client, "auth_user", "accounts_accountemaillookup").await
}

async fn audit_tables(client: &Client, table: &str, lookup_table: &str) -> Result<LoginEmailAudit> {
    for name in [table, lookup_table] {
        ensure!(
            !name.is_empty()
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                && name.as_bytes()[0].is_ascii_alphabetic(),
            "invalid email audit table name"
        );
    }
    let collision_sql = format!(
        "SELECT COUNT(*) AS collision_groups FROM (\
         SELECT COUNT(*) AS entries FROM `{table}` \
         GROUP BY Unicode::ToLower(Unicode::Strip(email)) AS email_key \
         HAVING COUNT(*) > 1)"
    );
    let mut row = client
        .query_client()
        .query_row(collision_sql)
        .timeout(Duration::from_secs(60))
        .await
        .context("count normalized account email collisions")?;
    let mut report = LoginEmailAudit {
        collision_groups: row.remove_field_by_name("collision_groups")?.try_into()?,
        ..Default::default()
    };
    let missing_sql = format!(
        "SELECT COUNT(*) AS missing_or_stale FROM `{table}` AS a \
         LEFT JOIN `{lookup_table}` AS l ON a.id = l.user_id \
         WHERE l.user_id IS NULL OR l.email_key IS NULL \
         OR l.email_key != Unicode::ToLower(Unicode::Strip(a.email))"
    );
    let mut row = client
        .query_client()
        .query_row(missing_sql)
        .timeout(Duration::from_secs(60))
        .await
        .context("count missing or stale account email lookup rows")?;
    report.lookup_missing_or_stale = row.remove_field_by_name("missing_or_stale")?.try_into()?;
    let orphan_sql = format!(
        "SELECT COUNT(*) AS orphans FROM `{lookup_table}` AS l \
         LEFT JOIN `{table}` AS a ON l.user_id = a.id WHERE a.id IS NULL"
    );
    let mut row = client
        .query_client()
        .query_row(orphan_sql)
        .timeout(Duration::from_secs(60))
        .await
        .context("count orphan account email lookup rows")?;
    report.lookup_orphans = row.remove_field_by_name("orphans")?.try_into()?;
    let mut after: Option<i32> = None;
    let mut pager = client.query_client();
    loop {
        let sql = if after.is_some() {
            format!(
                "SELECT id, email, Unicode::ToLower(Unicode::Strip(email)) AS email_key \
                 FROM `{table}` WHERE id > $after ORDER BY id LIMIT 100"
            )
        } else {
            format!(
                "SELECT id, email, Unicode::ToLower(Unicode::Strip(email)) AS email_key \
                 FROM `{table}` ORDER BY id LIMIT 100"
            )
        };
        let query = pager.query(sql).timeout(Duration::from_secs(10));
        let mut stream = if let Some(id) = after {
            query.param("$after", id).await?
        } else {
            query.await?
        };
        let mut page = Vec::new();
        while let Some(rows) = stream.next_result_set().await? {
            for mut row in rows {
                let id: i32 = row.remove_field_by_name("id")?.try_into()?;
                let email: Option<String> = row.remove_field_by_name("email")?.try_into()?;
                let ydb_key: Option<String> = row.remove_field_by_name("email_key")?.try_into()?;
                page.push((id, email, ydb_key));
            }
        }
        stream.close().await?;
        if page.is_empty() {
            return Ok(report);
        }
        for (_, email, ydb_key) in &page {
            report.accounts += 1;
            let Some(email) = email else {
                report.empty += 1;
                continue;
            };
            let rust_key = email.trim().to_lowercase();
            if rust_key.is_empty() {
                report.empty += 1;
            }
            if rust_key != *email {
                report.noncanonical += 1;
            }
            if ydb_key.as_deref() != Some(rust_key.as_str()) {
                report.normalization_mismatch += 1;
            }
        }
        after = page.last().map(|row| row.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn audit_gate_requires_unique_and_consistent_keys() {
        assert!(LoginEmailAudit::default().unambiguous());
        assert!(
            !LoginEmailAudit {
                collision_groups: 1,
                ..Default::default()
            }
            .unambiguous()
        );
        assert!(
            !LoginEmailAudit {
                normalization_mismatch: 1,
                ..Default::default()
            }
            .unambiguous()
        );
    }

    #[tokio::test]
    #[ignore = "requires an isolated local /local YDB"]
    async fn counts_collisions_across_pages_without_exposing_addresses() -> Result<()> {
        ensure!(
            matches!(
                std::env::var("YDB_ENDPOINT")?.as_str(),
                "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
            ) && std::env::var("YDB_DATABASE")? == "/local",
            "email audit test requires local /local YDB"
        );
        let client = crate::connect_ydb().await?;
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
        let table = format!("email_audit_{}_{}", std::process::id(), stamp);
        let lookup_table = format!("email_lookup_audit_{}_{}", std::process::id(), stamp);
        client
            .query_client()
            .exec(format!(
                "CREATE TABLE `{table}` (id Int32 NOT NULL, email Utf8, PRIMARY KEY(id))"
            ))
            .await?;
        client
            .query_client()
            .exec(format!(
                "CREATE TABLE `{lookup_table}` (user_id Int32 NOT NULL, email_key Utf8, PRIMARY KEY(user_id))"
            ))
            .await?;
        let checked: Result<()> = async {
            let entries = (1..=103)
                .map(|id| {
                    let email = match id {
                        1 => "alice@example.invalid".to_owned(),
                        2 => "ALICE@example.invalid".to_owned(),
                        3 => " padded@example.invalid ".to_owned(),
                        4 => String::new(),
                        _ => format!("user{id}@example.invalid"),
                    };
                    format!("({id}, '{email}')")
                })
                .collect::<Vec<_>>()
                .join(", ");
            client
                .query_client()
                .exec(format!(
                    "UPSERT INTO `{table}` (id, email) VALUES {entries}"
                ))
                .await?;
            let lookup_entries = (1..=104)
                .filter(|id| *id != 5)
                .map(|id| {
                    let key = match id {
                        1 | 2 => "alice@example.invalid".to_owned(),
                        3 => "padded@example.invalid".to_owned(),
                        4 => String::new(),
                        6 => "stale@example.invalid".to_owned(),
                        _ => format!("user{id}@example.invalid"),
                    };
                    format!("({id}, '{key}')")
                })
                .collect::<Vec<_>>()
                .join(", ");
            client
                .query_client()
                .exec(format!(
                    "UPSERT INTO `{lookup_table}` (user_id, email_key) VALUES {lookup_entries}"
                ))
                .await?;
            let report = audit_tables(&client, &table, &lookup_table).await?;
            assert_eq!(report.accounts, 103);
            assert_eq!(report.noncanonical, 2);
            assert_eq!(report.empty, 1);
            assert_eq!(report.normalization_mismatch, 0);
            assert_eq!(report.collision_groups, 1);
            assert_eq!(report.lookup_missing_or_stale, 2);
            assert_eq!(report.lookup_orphans, 1);
            assert!(!report.unambiguous());
            client
                .query_client()
                .exec(format!("DELETE FROM `{table}` WHERE id IN (2, 4)"))
                .await?;
            client
                .query_client()
                .exec(format!(
                    "DELETE FROM `{lookup_table}` WHERE user_id IN (2, 4, 104)"
                ))
                .await?;
            client
                .query_client()
                .exec(format!("UPSERT INTO `{lookup_table}` (user_id, email_key) VALUES (5, 'user5@example.invalid'), (6, 'user6@example.invalid')"))
                .await?;
            let clean = audit_tables(&client, &table, &lookup_table).await?;
            assert_eq!(clean.accounts, 101);
            assert!(clean.unambiguous());
            Ok(())
        }
        .await;
        let cleanup = client
            .query_client()
            .exec(format!("DROP TABLE `{table}`"))
            .await;
        let lookup_cleanup = client
            .query_client()
            .exec(format!("DROP TABLE `{lookup_table}`"))
            .await;
        checked?;
        cleanup?;
        lookup_cleanup?;
        Ok(())
    }
}
