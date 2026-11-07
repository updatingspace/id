//! Explicit cutover reset for legacy state the owner chose not to migrate.
//! Run only after stopping old writers and before admitting new Rust traffic.
//! One invocation removes a bounded batch from each table and can be repeated.

use anyhow::{Result, bail, ensure};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use ydb::Client;

const SEAL_TABLE: &str = "id_legacy_cutover_seal";

async fn ensure_seal_schema(client: &Client) -> Result<()> {
    client.query_client().exec(format!(
        "CREATE TABLE IF NOT EXISTS `{SEAL_TABLE}` (name Utf8 NOT NULL, sealed_at Datetime NOT NULL, PRIMARY KEY (name))"
    )).timeout(Duration::from_secs(15)).await?;
    Ok(())
}

pub async fn is_sealed(client: &Client) -> Result<bool> {
    ensure_seal_schema(client).await?;
    read_seal_status(client).await
}

/// Read the existing cutover marker without changing the YDB schema.
pub async fn read_seal_status(client: &Client) -> Result<bool> {
    Ok(client
        .query_client()
        .query_row(format!(
            "SELECT name FROM `{SEAL_TABLE}` WHERE name = 'legacy-transient'"
        ))
        .optional()
        .await?
        .is_some())
}

pub async fn seal(client: &Client) -> Result<bool> {
    ensure_seal_schema(client).await?;
    if is_sealed(client).await? {
        return Ok(false);
    }
    ensure!(
        seal_readiness(client).await?,
        "legacy unscoped tables are not empty"
    );
    client.query_client().exec(format!(
        "INSERT INTO `{SEAL_TABLE}` (name, sealed_at) VALUES ('legacy-transient', CurrentUtcDatetime())"
    )).timeout(Duration::from_secs(15)).await?;
    Ok(true)
}

/// Live Rust sessions use the former Django session tables. Sealing after
/// cutover must check only records whose owner cannot be proven; the optional
/// pre-cutover reset still drains sessions separately.
pub async fn seal_readiness(client: &Client) -> Result<bool> {
    for table in ["usid_application", "usid_audit_log", "usid_outbox"] {
        if count(client, table).await? != 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

const AUDIT_PAGE_SIZE: usize = 100;
const MAX_AUDIT_ROWS: u64 = 10_000;

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct LegacyAuditInventory {
    pub total: u64,
    pub scanned: u64,
    pub truncated: bool,
    pub missing_actor: u64,
    pub first_at_epoch: Option<u64>,
    pub last_at_epoch: Option<u64>,
    pub actions: BTreeMap<String, u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine_action_review: Option<BTreeMap<String, u64>>,
}

/// Report only bounded counts and dates. Neither identifiers nor JSON bodies
/// leave this read-only diagnostic; it does not prove the cutover can be sealed.
pub async fn audit_inventory(client: &Client) -> Result<LegacyAuditInventory> {
    audit_inventory_with_review(client, false).await
}

/// Opt-in operator review of short machine event names for otherwise unknown
/// categories. Reject free text so a malformed action cannot echo personal data.
pub async fn audit_inventory_with_review(
    client: &Client,
    review_machine_actions: bool,
) -> Result<LegacyAuditInventory> {
    let mut report = LegacyAuditInventory {
        total: count(client, "usid_audit_log").await?,
        machine_action_review: review_machine_actions.then(BTreeMap::new),
        ..Default::default()
    };
    let mut after: Option<i64> = None;
    let mut pager = client.query_client();
    while report.scanned < MAX_AUDIT_ROWS {
        let filter = if after.is_some() {
            "WHERE id > $after "
        } else {
            ""
        };
        let query = pager.query(format!(
            "SELECT id, action, target_type, actor_user_id, created_at FROM usid_audit_log {filter}ORDER BY id LIMIT {AUDIT_PAGE_SIZE}"
        )).timeout(Duration::from_secs(15));
        let mut stream = if let Some(id) = after {
            query.param("$after", id).await?
        } else {
            query.await?
        };
        let mut page = 0;
        while let Some(rows) = stream.next_result_set().await? {
            for mut row in rows {
                let id: i64 = row.remove_field_by_name("id")?.try_into()?;
                let action: String = row.remove_field_by_name("action")?.try_into()?;
                let target_type: String = row.remove_field_by_name("target_type")?.try_into()?;
                let actor: Option<Uuid> = row.remove_field_by_name("actor_user_id")?.try_into()?;
                let created_at: SystemTime = row.remove_field_by_name("created_at")?.try_into()?;
                let epoch = created_at.duration_since(UNIX_EPOCH)?.as_secs();
                report.first_at_epoch = Some(
                    report
                        .first_at_epoch
                        .map_or(epoch, |value| value.min(epoch)),
                );
                report.last_at_epoch =
                    Some(report.last_at_epoch.map_or(epoch, |value| value.max(epoch)));
                if actor.is_none() {
                    report.missing_actor += 1;
                }
                let label = known_action(&action, &target_type);
                *report.actions.entry(label.to_owned()).or_default() += 1;
                if label == "unclassified"
                    && let Some(review) = report.machine_action_review.as_mut()
                {
                    let category = machine_action_category(&action, &target_type)
                        .unwrap_or_else(|| "opaque".to_owned());
                    let category = if review.len() < 16 || review.contains_key(&category) {
                        category
                    } else {
                        "overflow".to_owned()
                    };
                    *review.entry(category).or_default() += 1;
                }
                report.scanned += 1;
                page += 1;
                after = Some(id);
                if report.scanned == MAX_AUDIT_ROWS {
                    break;
                }
            }
            if report.scanned == MAX_AUDIT_ROWS {
                break;
            }
        }
        stream.close().await?;
        if page < AUDIT_PAGE_SIZE {
            break;
        }
    }
    report.truncated = report.scanned < report.total;
    Ok(report)
}

fn machine_action_category(action: &str, target_type: &str) -> Option<String> {
    let (namespace, verb) = action.split_once('.')?;
    if !matches!(
        namespace,
        "account"
            | "admin"
            | "application"
            | "auth"
            | "external_identity"
            | "magic_link"
            | "oidc_client"
            | "operator"
            | "provider"
            | "session"
            | "system"
            | "tenant"
    ) || verb.is_empty()
        || verb.len() > 32
        || !verb
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        || target_type.is_empty()
        || target_type.len() > 32
        || !target_type
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        return None;
    }
    Some(format!("{action}/{target_type}"))
}

fn known_action(action: &str, target_type: &str) -> &'static str {
    match (action, target_type) {
        ("account.suspended", "user") => "account.suspended",
        ("magic_link.consumed", "user") => "magic_link.consumed",
        ("provider.linked", "provider") => "provider.linked",
        ("oidc_client.created", "oidc_client") => "oidc_client.created",
        ("oidc_client.secret_rotated", "oidc_client") => "oidc_client.secret_rotated",
        ("oidc_client.redirects_updated", "oidc_client") => "oidc_client.redirects_updated",
        // Exact action/target pairs from the retired Django record_audit callers.
        // Classifying them does not prove row provenance or ownership.
        ("magic_link.requested", "user") => "magic_link.requested",
        ("auth.oauth_login", "user") => "auth.oauth_login",
        ("application.approved", "application") => "application.approved",
        ("application.rejected", "application") => "application.rejected",
        ("account.activated", "user") => "account.activated",
        ("external_identity.linked", "external_identity") => "external_identity.linked",
        _ => "unclassified",
    }
}

#[cfg(test)]
mod inventory_tests {
    use super::{known_action, machine_action_category};

    #[test]
    fn only_exact_known_writer_pairs_are_reported() {
        assert_eq!(
            known_action("magic_link.consumed", "user"),
            "magic_link.consumed"
        );
        assert_eq!(known_action("auth.oauth_login", "user"), "auth.oauth_login");
        assert_eq!(
            known_action("application.approved", "application"),
            "application.approved"
        );
        assert_eq!(known_action("magic_link.consumed", "other"), "unclassified");
        assert_eq!(
            known_action("someone@example.invalid", "user"),
            "unclassified"
        );
    }

    #[test]
    fn review_only_returns_short_machine_action_pairs() {
        assert_eq!(
            machine_action_category("operator.bootstrapped", "user").as_deref(),
            Some("operator.bootstrapped/user")
        );
        for (action, target) in [
            ("person@example.invalid", "user"),
            ("operator.john.doe", "user"),
            ("operator.name-with-email", "user"),
            ("operator.created", "user@example.invalid"),
            ("unknown.event", "user"),
        ] {
            assert_eq!(machine_action_category(action, target), None);
        }
    }
}

const TABLES: &[(&str, &str)] = &[
    ("django_session", "session_key"),
    ("usersessions_usersession", "id"),
    ("core_usersessionmeta", "id"),
    ("core_usersessiontoken", "id"),
    ("usid_application", "id"),
    ("usid_audit_log", "id"),
    ("usid_outbox", "id"),
];

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct TableReset {
    pub table: &'static str,
    pub before: u64,
    pub delete_attempts: u64,
    pub removed: u64,
    pub remaining: u64,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ResetReport {
    pub dry_run: bool,
    pub tables: Vec<TableReset>,
    pub complete: bool,
}

pub async fn reset(client: &Client, batch: u64, apply: bool) -> Result<ResetReport> {
    ensure!(
        (1..=1000).contains(&batch),
        "cutover reset batch must be 1..=1000"
    );
    if apply {
        crate::legacy_schema::require_local_ydb_for_pilot()?;
        ensure!(
            std::env::var("ID_DISPOSABLE_YDB").as_deref() == Ok("true"),
            "cutover reset requires explicitly disposable local YDB"
        );
        ensure_seal_schema(client).await?;
        if is_sealed(client).await? {
            bail!("legacy cutover is sealed; reset would erase new sessions");
        }
    }
    let mut tables = Vec::with_capacity(TABLES.len());
    for &(table, key) in TABLES {
        let before = count(client, table).await?;
        let mut delete_attempts = 0;
        if apply && before > 0 {
            if key == "session_key" {
                for value in string_keys(client, table, key, batch).await? {
                    client
                        .query_client()
                        .exec(format!("DELETE FROM `{table}` WHERE `{key}` = $key"))
                        .param("$key", value)
                        .timeout(Duration::from_secs(15))
                        .await?;
                    delete_attempts += 1;
                }
            } else {
                for value in i64_keys(client, table, key, batch).await? {
                    client
                        .query_client()
                        .exec(format!("DELETE FROM `{table}` WHERE `{key}` = $key"))
                        .param("$key", value)
                        .timeout(Duration::from_secs(15))
                        .await?;
                    delete_attempts += 1;
                }
            }
        }
        let remaining = if apply {
            count(client, table).await?
        } else {
            before
        };
        let removed = before.saturating_sub(remaining);
        tables.push(TableReset {
            table,
            before,
            delete_attempts,
            removed,
            remaining,
        });
    }
    let complete = tables.iter().all(|table| table.remaining == 0);
    Ok(ResetReport {
        dry_run: !apply,
        tables,
        complete,
    })
}

async fn count(client: &Client, table: &str) -> Result<u64> {
    let mut row = client
        .query_client()
        .query_row(format!("SELECT COUNT(*) AS n FROM `{table}`"))
        .timeout(Duration::from_secs(15))
        .await?;
    Ok(row.remove_field_by_name("n")?.try_into()?)
}

async fn string_keys(client: &Client, table: &str, key: &str, batch: u64) -> Result<Vec<String>> {
    let mut query_client = client.query_client();
    let mut stream = query_client
        .query(format!(
            "SELECT `{key}` FROM `{table}` ORDER BY `{key}` LIMIT {batch}"
        ))
        .timeout(Duration::from_secs(15))
        .await?;
    let mut keys = Vec::new();
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            keys.push(row.remove_field_by_name(key)?.try_into()?);
        }
    }
    stream.close().await?;
    Ok(keys)
}

async fn i64_keys(client: &Client, table: &str, key: &str, batch: u64) -> Result<Vec<i64>> {
    let mut query_client = client.query_client();
    let mut stream = query_client
        .query(format!(
            "SELECT `{key}` FROM `{table}` ORDER BY `{key}` LIMIT {batch}"
        ))
        .timeout(Duration::from_secs(15))
        .await?;
    let mut keys = Vec::new();
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            keys.push(row.remove_field_by_name(key)?.try_into()?);
        }
    }
    stream.close().await?;
    Ok(keys)
}
