//! Read-only inventory for the last deletion stage. Legacy global JSON has no
//! ownership index, so exact matches are evidence of remaining data, not proof
//! that an unmatched record is safe to retain.

use crate::tx_retry::retry_known_abort;
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::Value;
use std::time::Duration;
use uuid::Uuid;
use ydb::{Client, Transaction, TxMode, closure};

const PAGE_SIZE: usize = 100;
const MAX_GLOBAL_ROWS: u64 = 10_000;

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct GlobalReferences {
    pub scanned: u64,
    pub matched: u64,
    pub malformed_json: u64,
    pub truncated: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct DeletionAudit {
    pub id: String,
    pub status: String,
    pub profile_stage_completed: bool,
    pub account_rows: u64,
    pub identity_binding_rows: u64,
    pub identity_rows: u64,
    pub session_metadata_rows: u64,
    pub audit_log: GlobalReferences,
    pub outbox: GlobalReferences,
    pub applications: GlobalReferences,
    /// Exact JSON matching and a paged read cannot establish completeness.
    pub full_cleanup_proven: bool,
}

pub async fn audit(client: &Client, id: i64) -> Result<Option<DeletionAudit>> {
    ensure!(id > 0, "invalid deletion operation ID");
    let Some(mut operation) = client
        .query_client()
        .query_row("SELECT user_id, status FROM accounts_accountdeletionrequest WHERE id = $id")
        .param("$id", id)
        .optional()
        .await?
    else {
        return Ok(None);
    };
    let account_id: i32 = operation.remove_field_by_name("user_id")?.try_into()?;
    let status: String = operation.remove_field_by_name("status")?.try_into()?;
    if status == "succeeded" && account_id == 0 {
        return Ok(Some(DeletionAudit {
            id: id.to_string(),
            status,
            profile_stage_completed: true,
            account_rows: 0,
            identity_binding_rows: 0,
            identity_rows: 0,
            session_metadata_rows: 0,
            audit_log: GlobalReferences::default(),
            outbox: GlobalReferences::default(),
            applications: GlobalReferences::default(),
            full_cleanup_proven: true,
        }));
    }
    let Some(mut account) = client
        .query_client()
        .query_row("SELECT email FROM auth_user WHERE id = $id")
        .param("$id", account_id)
        .optional()
        .await?
    else {
        anyhow::bail!("deletion account missing before final audit");
    };
    let account_email: String = account.remove_field_by_name("email")?.try_into()?;
    let Some(mut binding) = client
        .query_client()
        .query_row("SELECT identity_id FROM accounts_accountidentity WHERE user_id = $id")
        .param("$id", account_id)
        .optional()
        .await?
    else {
        anyhow::bail!("deletion identity binding missing before final audit");
    };
    let identity_id: Option<Uuid> = binding.remove_field_by_name("identity_id")?.try_into()?;
    let identity_id = identity_id.context("deletion identity ID missing before final audit")?;
    let mut emails = vec![account_email];
    if let Some(mut identity) = client
        .query_client()
        .query_row("SELECT email FROM usid_user WHERE user_id = $id")
        .param("$id", identity_id)
        .optional()
        .await?
    {
        let email: String = identity.remove_field_by_name("email")?.try_into()?;
        emails.push(email);
    }
    emails.retain(|email| !email.is_empty());
    let profile_stage_completed = if let Some(mut row) = client
        .query_client()
        .query_row("SELECT profile_done FROM id_deletion_profile_progress WHERE operation_id = $id")
        .param("$id", id)
        .optional()
        .await?
    {
        row.remove_field_by_name("profile_done")?.try_into()?
    } else {
        false
    };
    let account_rows = count_i32(client, "auth_user", "id", account_id).await?;
    let identity_binding_rows =
        count_i32(client, "accounts_accountidentity", "user_id", account_id).await?;
    let identity_rows = count_uuid(client, "usid_user", "user_id", identity_id).await?;
    let session_metadata_rows =
        count_i32(client, "core_usersessionmeta", "user_id", account_id).await?;
    let audit_log = scan_global(client, Source::Audit, identity_id, &emails, false)
        .await?
        .0;
    let outbox = scan_global(client, Source::Outbox, identity_id, &emails, false)
        .await?
        .0;
    let applications = scan_global(client, Source::Application, identity_id, &emails, false)
        .await?
        .0;
    Ok(Some(DeletionAudit {
        id: id.to_string(),
        status,
        profile_stage_completed,
        account_rows,
        identity_binding_rows,
        identity_rows,
        session_metadata_rows,
        audit_log,
        outbox,
        applications,
        full_cleanup_proven: false,
    }))
}

async fn count_i32(client: &Client, table: &str, column: &str, id: i32) -> Result<u64> {
    let mut row = client
        .query_client()
        .query_row(format!(
            "SELECT COUNT(*) AS n FROM `{table}` WHERE `{column}` = $id"
        ))
        .param("$id", id)
        .await?;
    Ok(row.remove_field_by_name("n")?.try_into()?)
}

async fn count_uuid(client: &Client, table: &str, column: &str, id: Uuid) -> Result<u64> {
    let mut row = client
        .query_client()
        .query_row(format!(
            "SELECT COUNT(*) AS n FROM `{table}` WHERE `{column}` = $id"
        ))
        .param("$id", id)
        .await?;
    Ok(row.remove_field_by_name("n")?.try_into()?)
}

#[derive(Clone, Copy)]
enum Source {
    Audit,
    Outbox,
    Application,
}

impl Source {
    fn table(self) -> &'static str {
        match self {
            Self::Audit => "usid_audit_log",
            Self::Outbox => "usid_outbox",
            Self::Application => "usid_application",
        }
    }

    fn query(self, after: Option<i64>) -> String {
        let (table, body, extra) = match self {
            Self::Audit => ("usid_audit_log", "meta_json", ", actor_user_id, target_id"),
            Self::Outbox => ("usid_outbox", "payload_json", ""),
            Self::Application => ("usid_application", "payload_json", ", reviewed_by_user_id"),
        };
        let filter = if after.is_some() {
            "WHERE id > $after "
        } else {
            ""
        };
        format!(
            "SELECT id, CAST({body} AS Utf8) AS body{extra} FROM `{table}` {filter}ORDER BY id LIMIT {PAGE_SIZE}"
        )
    }

    fn query_one(self) -> String {
        let (body, extra) = match self {
            Self::Audit => ("meta_json", ", actor_user_id, target_id"),
            Self::Outbox => ("payload_json", ""),
            Self::Application => ("payload_json", ", reviewed_by_user_id"),
        };
        format!(
            "SELECT CAST({body} AS Utf8) AS body{extra} FROM `{}` WHERE id = $id",
            self.table()
        )
    }
}

async fn scan_global(
    client: &Client,
    source: Source,
    identity: Uuid,
    emails: &[String],
    collect_matches: bool,
) -> Result<(GlobalReferences, Vec<i64>)> {
    let mut report = GlobalReferences::default();
    let mut matches = Vec::new();
    let mut after: Option<i64> = None;
    let mut pager = client.query_client();
    loop {
        let query = pager
            .query(source.query(after))
            .timeout(Duration::from_secs(15));
        let mut stream = if let Some(after) = after {
            query.param("$after", after).await?
        } else {
            query.await?
        };
        let mut page = 0;
        let mut batch_full = false;
        while let Some(rows) = stream.next_result_set().await? {
            for mut row in rows {
                page += 1;
                let row_id: i64 = row.remove_field_by_name("id")?.try_into()?;
                let body: String = row.remove_field_by_name("body")?.try_into()?;
                let direct = match source {
                    Source::Audit => {
                        let actor: Option<Uuid> =
                            row.remove_field_by_name("actor_user_id")?.try_into()?;
                        let target: String = row.remove_field_by_name("target_id")?.try_into()?;
                        actor == Some(identity) || matches_person(&target, identity, emails)
                    }
                    Source::Application => {
                        let reviewer: Option<Uuid> = row
                            .remove_field_by_name("reviewed_by_user_id")?
                            .try_into()?;
                        reviewer == Some(identity)
                    }
                    Source::Outbox => false,
                };
                let matched = match serde_json::from_str::<Value>(&body) {
                    Ok(json) => direct || json_matches(&json, identity, emails),
                    Err(_) => {
                        report.malformed_json += 1;
                        direct
                    }
                };
                if matched {
                    report.matched += 1;
                    if collect_matches && matches.len() < PAGE_SIZE {
                        matches.push(row_id);
                    }
                }
                report.scanned += 1;
                after = Some(row_id);
                if collect_matches && matches.len() == PAGE_SIZE {
                    batch_full = true;
                    break;
                }
            }
            if batch_full {
                break;
            }
        }
        stream.close().await?;
        if batch_full {
            report.truncated = true;
            break;
        }
        if page < PAGE_SIZE {
            break;
        }
        if !collect_matches && report.scanned >= MAX_GLOBAL_ROWS {
            report.truncated = true;
            break;
        }
    }
    Ok((report, matches))
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct GlobalCleanup {
    pub id: String,
    pub audit_candidates: usize,
    pub outbox_candidates: usize,
    pub audit_removed: usize,
    pub outbox_removed: usize,
    pub applications_removed: usize,
    pub audit_scan_truncated: bool,
    pub outbox_scan_truncated: bool,
    /// Application ownership and other legacy formats still need review.
    pub cleanup_completed: bool,
}

/// Remove only exact UUID references. Email-only matches may belong to a
/// different application after address reuse, so they remain for review.
/// Every selected row is re-read in a serializable transaction before deletion.
pub async fn erase_global_uuid_references(
    client: &Client,
    id: i64,
) -> Result<Option<GlobalCleanup>> {
    ensure!(id > 0, "invalid deletion operation ID");
    let Some(mut operation) = client
        .query_client()
        .query_row("SELECT user_id, status FROM accounts_accountdeletionrequest WHERE id = $id")
        .param("$id", id)
        .optional()
        .await?
    else {
        return Ok(None);
    };
    let account_id: i32 = operation.remove_field_by_name("user_id")?.try_into()?;
    let status: String = operation.remove_field_by_name("status")?.try_into()?;
    ensure!(
        status == "running",
        "global cleanup requires running deletion"
    );
    let Some(mut binding) = client
        .query_client()
        .query_row("SELECT identity_id FROM accounts_accountidentity WHERE user_id = $id")
        .param("$id", account_id)
        .optional()
        .await?
    else {
        anyhow::bail!("deletion identity binding missing before global cleanup");
    };
    let identity: Option<Uuid> = binding.remove_field_by_name("identity_id")?.try_into()?;
    let identity = identity.context("deletion identity ID missing before global cleanup")?;
    let (audit_scan, audit_ids) = scan_global(client, Source::Audit, identity, &[], true).await?;
    let (outbox_scan, outbox_ids) =
        scan_global(client, Source::Outbox, identity, &[], true).await?;
    let mut result = GlobalCleanup {
        id: id.to_string(),
        audit_candidates: audit_ids.len(),
        outbox_candidates: outbox_ids.len(),
        audit_removed: 0,
        outbox_removed: 0,
        applications_removed: 0,
        audit_scan_truncated: audit_scan.truncated,
        outbox_scan_truncated: outbox_scan.truncated,
        cleanup_completed: false,
    };
    for row_id in audit_ids {
        let (removed, application_removed) =
            erase_one(client, id, account_id, identity, Source::Audit, row_id).await?;
        if removed {
            result.audit_removed += 1;
        }
        if application_removed {
            result.applications_removed += 1;
        }
    }
    for row_id in outbox_ids {
        let (removed, application_removed) =
            erase_one(client, id, account_id, identity, Source::Outbox, row_id).await?;
        if removed {
            result.outbox_removed += 1;
        }
        if application_removed {
            result.applications_removed += 1;
        }
    }
    Ok(Some(result))
}

async fn erase_one(
    client: &Client,
    operation_id: i64,
    account_id: i32,
    identity: Uuid,
    source: Source,
    row_id: i64,
) -> Result<(bool, bool)> {
    retry_known_abort(|| async {
        client.query_client().retry_tx(closure!([operation_id, account_id, identity, source, row_id], async |tx: &mut Transaction| {
            let Some(mut operation) = tx.query_row("SELECT user_id, status FROM accounts_accountdeletionrequest WHERE id = $id")
                .param("$id", *operation_id).optional().await? else { return Ok((false, false)); };
            let owner: i32 = operation.remove_field_by_name("user_id")?.try_into()?;
            let status: String = operation.remove_field_by_name("status")?.try_into()?;
            if owner != *account_id || status != "running" { return Ok((false, false)); }
            let Some(mut progress) = tx.query_row("SELECT profile_done FROM id_deletion_profile_progress WHERE operation_id = $id")
                .param("$id", *operation_id).optional().await? else { return Ok((false, false)); };
            let profile_done: bool = progress.remove_field_by_name("profile_done")?.try_into()?;
            if !profile_done { return Ok((false, false)); }
            let Some(mut account) = tx.query_row("SELECT is_active FROM auth_user WHERE id = $id")
                .param("$id", *account_id).optional().await? else { return Ok((false, false)); };
            let active: bool = account.remove_field_by_name("is_active")?.try_into()?;
            if active { return Ok((false, false)); }
            let Some(mut binding) = tx.query_row("SELECT identity_id FROM accounts_accountidentity WHERE user_id = $id")
                .param("$id", *account_id).optional().await? else { return Ok((false, false)); };
            let bound: Option<Uuid> = binding.remove_field_by_name("identity_id")?.try_into()?;
            if bound != Some(*identity) { return Ok((false, false)); }
            let Some(mut master) = tx.query_row("SELECT status FROM usid_user WHERE user_id = $id")
                .param("$id", *identity).optional().await? else { return Ok((false, false)); };
            let master_status: String = master.remove_field_by_name("status")?.try_into()?;
            if master_status != "suspended" { return Ok((false, false)); }
            let Some(mut row) = tx.query_row(source.query_one()).param("$id", *row_id).optional().await? else { return Ok((false, false)); };
            let body: String = row.remove_field_by_name("body")?.try_into()?;
            let direct = match *source {
                Source::Audit => {
                    let actor: Option<Uuid> = row.remove_field_by_name("actor_user_id")?.try_into()?;
                    let target: String = row.remove_field_by_name("target_id")?.try_into()?;
                    actor == Some(*identity) || target == identity.to_string()
                }
                Source::Outbox => false,
                Source::Application => return Ok((false, false)),
            };
            let json = serde_json::from_str::<Value>(&body).ok();
            let nested = json.as_ref().is_some_and(|value| json_matches(value, *identity, &[]));
            if !direct && !nested { return Ok((false, false)); }
            let mut application_removed = false;
            if let Some(application_id) = json.as_ref().and_then(|value| linked_application_id(value, *identity)) {
                let exists = tx.query_row("SELECT id FROM usid_application WHERE id = $id")
                    .param("$id", application_id).optional().await?.is_some();
                if exists {
                    tx.exec("DELETE FROM usid_application WHERE id = $id")
                        .param("$id", application_id).await?;
                    application_removed = true;
                }
            }
            tx.exec(format!("DELETE FROM `{}` WHERE id = $id", source.table()))
                .param("$id", *row_id).await?;
            Ok((true, application_removed))
        })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
            .timeout(Duration::from_secs(15)).await
    }).await.context("erase global identity reference")
}

fn linked_application_id(value: &Value, identity: Uuid) -> Option<i64> {
    (value.get("user_id")?.as_str()? == identity.to_string())
        .then(|| value.get("application_id")?.as_i64())
        .flatten()
}

fn matches_person(value: &str, identity: Uuid, emails: &[String]) -> bool {
    value == identity.to_string()
        || emails
            .iter()
            .any(|email| !email.is_empty() && value.eq_ignore_ascii_case(email))
}

fn json_matches(value: &Value, identity: Uuid, emails: &[String]) -> bool {
    match value {
        Value::String(s) => matches_person(s, identity, emails),
        Value::Array(values) => values
            .iter()
            .any(|value| json_matches(value, identity, emails)),
        Value::Object(values) => values
            .values()
            .any(|value| json_matches(value, identity, emails)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_nested_matches_only() {
        let identity = Uuid::from_u128(0x0f4d10569d2143499dd63b6d5ef7c155);
        let emails = vec!["A@Example.org".to_string()];
        let matching = serde_json::json!({"actor": {"user_id": identity.to_string()}, "other": ["a@example.org"]});
        assert!(json_matches(&matching, identity, &emails));
        assert!(!json_matches(
            &serde_json::json!({"email": "not-a@example.org"}),
            identity,
            &emails
        ));
        assert!(!json_matches(
            &serde_json::json!({"count": 42}),
            identity,
            &emails
        ));
        assert!(!json_matches(
            &serde_json::json!({"target": ""}),
            identity,
            &[String::new()]
        ));
    }

    #[test]
    fn application_link_requires_explicit_subject() {
        let identity = Uuid::from_u128(0x0f4d10569d2143499dd63b6d5ef7c155);
        let linked = serde_json::json!({"user_id": identity.to_string(), "application_id": 42});
        assert_eq!(linked_application_id(&linked, identity), Some(42));
        let reviewer =
            serde_json::json!({"reviewer_user_id": identity.to_string(), "application_id": 42});
        assert_eq!(linked_application_id(&reviewer, identity), None);
        let other = serde_json::json!({"user_id": Uuid::nil().to_string(), "application_id": 42});
        assert_eq!(linked_application_id(&other, identity), None);
    }
}
