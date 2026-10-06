//! Conservative creation of missing master identities and fixed account bindings.
//! Never link an account to an existing master by matching email.

use crate::{ids::PublicSubject, login_email_audit, tx_retry::retry_known_abort};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime},
};
use uuid::Uuid;
use ydb::{Client, Transaction, TxMode, closure};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Existing,
    NewBinding,
    NewMasterForBinding,
    NeedsReview(&'static str),
}

#[derive(Debug, Default, Serialize)]
pub struct IdentityReconcileReport {
    pub dry_run: bool,
    pub scanned: u64,
    pub existing: u64,
    pub new_bindings: u64,
    pub new_masters_for_bindings: u64,
    pub needs_review: u64,
    pub review_reasons: BTreeMap<String, u64>,
}

async fn page_account_ids(client: &Client, after: Option<i32>, batch: u64) -> Result<Vec<i32>> {
    let sql = if after.is_some() {
        format!("SELECT id FROM auth_user WHERE id > $after ORDER BY id LIMIT {batch}")
    } else {
        format!("SELECT id FROM auth_user ORDER BY id LIMIT {batch}")
    };
    let mut pager = client.query_client();
    let query = pager.query(sql).timeout(Duration::from_secs(15));
    let mut stream = if let Some(after) = after {
        query.param("$after", after).await?
    } else {
        query.await?
    };
    let mut ids = Vec::new();
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            ids.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    stream.close().await?;
    Ok(ids)
}

async fn one(client: &Client, id: i32, apply: bool, now: SystemTime) -> Result<Outcome> {
    let new_identity = Uuid::new_v4();
    retry_known_abort(|| async {
        client.query_client().retry_tx(closure!([id, new_identity], async |tx: &mut Transaction| {
            let Some(mut account) = tx.query_row("SELECT username, first_name, last_name, email, is_active, is_staff, is_superuser FROM auth_user WHERE id = $id")
                .param("$id", *id).optional().await? else { return Ok(Outcome::Existing); };
            let username: String = account.remove_field_by_name("username")?.try_into()?;
            let first_name: String = account.remove_field_by_name("first_name")?.try_into()?;
            let last_name: String = account.remove_field_by_name("last_name")?.try_into()?;
            let email: String = account.remove_field_by_name("email")?.try_into()?;
            let active: bool = account.remove_field_by_name("is_active")?.try_into()?;
            let staff: bool = account.remove_field_by_name("is_staff")?.try_into()?;
            let superuser: bool = account.remove_field_by_name("is_superuser")?.try_into()?;
            let email_key = email.trim().to_lowercase();
            if email_key.is_empty() || email_key.len() > 254 {
                return Ok(Outcome::NeedsReview("invalid_account_email"));
            }
            let Some(mut lookup) = tx.query_row("SELECT email_key FROM accounts_accountemaillookup WHERE user_id = $id")
                .param("$id", *id).optional().await? else { return Ok(Outcome::NeedsReview("missing_email_lookup")); };
            let stored_key: String = lookup.remove_field_by_name("email_key")?.try_into()?;
            if stored_key != email_key { return Ok(Outcome::NeedsReview("email_lookup_drift")); }

            let binding = tx.query_row("SELECT identity_id, public_subject FROM accounts_accountidentity WHERE user_id = $id")
                .param("$id", *id).optional().await?;
            let (subject, has_binding) = if let Some(mut binding) = binding {
                let identity_id: Option<Uuid> = binding.remove_field_by_name("identity_id")?.try_into()?;
                let subject: String = binding.remove_field_by_name("public_subject")?.try_into()?;
                if let Some(identity_id) = identity_id {
                    let master = tx.query_row("SELECT user_id FROM usid_user WHERE user_id = $identity")
                        .param("$identity", identity_id).optional().await?;
                    return Ok(if master.is_none() {
                        Outcome::NeedsReview("missing_master")
                    } else if PublicSubject::parse(subject).is_none() {
                        Outcome::NeedsReview("invalid_public_subject")
                    } else { Outcome::Existing });
                }
                (subject, true)
            } else {
                // No binding means historical OIDC subject ownership is unknown.
                if tx.query_row("SELECT id FROM idp_oidctoken WHERE user_id = $id LIMIT 1")
                    .param("$id", *id).optional().await?.is_some() {
                    return Ok(Outcome::NeedsReview("oidc_history_without_binding"));
                }
                (id.to_string(), false)
            };
            if PublicSubject::parse(subject.clone()).is_none() {
                return Ok(Outcome::NeedsReview("invalid_public_subject"));
            }
            let mut owners = tx.query("SELECT user_id FROM accounts_accountidentity WHERE public_subject = $subject LIMIT 2")
                .param("$subject", subject.clone()).await?;
            let mut other_owner = false;
            while let Some(rows) = owners.next_result_set().await? {
                for mut row in rows {
                    let owner: i32 = row.remove_field_by_name("user_id")?.try_into()?;
                    if owner != *id { other_owner = true; }
                }
            }
            owners.close().await?;
            if other_owner { return Ok(Outcome::NeedsReview("duplicate_public_subject")); }
            // A matching email is not proof that an existing master belongs to
            // this account. Never attach to it automatically.
            if tx.query_row("SELECT user_id FROM usid_user WHERE Unicode::ToLower(Unicode::Strip(email)) = $email LIMIT 1")
                .param("$email", email_key.clone()).optional().await?.is_some() {
                return Ok(Outcome::NeedsReview("existing_master_email"));
            }
            if tx.query_row("SELECT user_id FROM usid_user WHERE user_id = $identity")
                .param("$identity", *new_identity).optional().await?.is_some() {
                return Ok(Outcome::NeedsReview("identity_uuid_collision"));
            }
            let mut addresses = tx.query("SELECT email, verified FROM account_emailaddress VIEW account_emailaddress_user_id_2c513194 WHERE user_id = $id AND primary = true LIMIT 2")
                .param("$id", *id).await?;
            let mut primary = Vec::new();
            while let Some(rows) = addresses.next_result_set().await? {
                for mut row in rows {
                    let address: String = row.remove_field_by_name("email")?.try_into()?;
                    let verified: bool = row.remove_field_by_name("verified")?.try_into()?;
                    primary.push((address, verified));
                }
            }
            addresses.close().await?;
            if primary.len() > 1 || primary.iter().any(|(address, verified)|
                *verified && address.trim().to_lowercase() != email_key) {
                return Ok(Outcome::NeedsReview("primary_email_conflict"));
            }
            let verified = primary.first().is_some_and(|(address, verified)|
                *verified && address.trim().to_lowercase() == email_key);
            // Creating an active global principal changes access rights.
            // Unverified or disabled legacy accounts require explicit review.
            if !active { return Ok(Outcome::NeedsReview("inactive_account")); }
            if !verified { return Ok(Outcome::NeedsReview("unverified_primary_email")); }
            let outcome = if has_binding { Outcome::NewMasterForBinding } else { Outcome::NewBinding };
            if !apply { return Ok(outcome); }
            let display_name = format!("{first_name} {last_name}").trim().to_owned();
            let username = if username.trim().is_empty() {
                email_key.split('@').next().unwrap_or("account").to_owned()
            } else { username };
            let username: String = username.chars().take(64).collect();
            let display_name: String = if display_name.is_empty() { username.clone() }
                else { display_name.chars().take(128).collect() };
            tx.exec("INSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($identity, $username, $display, $email, $verified, $status, $admin, CAST($now AS Datetime))")
                .param("$identity", *new_identity).param("$username", username)
                .param("$display", display_name).param("$email", email_key)
                .param("$verified", true).param("$status", "active")
                .param("$admin", staff || superuser).param("$now", now).await?;
            if has_binding {
                tx.exec("UPDATE accounts_accountidentity SET identity_id = $identity WHERE user_id = $id AND identity_id IS NULL")
                    .param("$identity", *new_identity).param("$id", *id).await?;
            } else {
                tx.exec("INSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($id, $identity, $subject, CAST($now AS Datetime))")
                    .param("$id", *id).param("$identity", *new_identity)
                    .param("$subject", subject).param("$now", now).await?;
            }
            Ok(outcome)
        })).with_mode(TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(20)).await
    }).await.context("reconcile one account identity")
}

/// Bounded scan. Safe rows are written independently; conflicted rows remain
/// untouched and counted for operator review. Old identity writers must stop.
pub async fn reconcile(
    client: &Client,
    batch: u64,
    apply: bool,
) -> Result<IdentityReconcileReport> {
    ensure!((1..=1000).contains(&batch), "batch must be 1..1000");
    let email_audit = login_email_audit::audit_auth_user(client).await?;
    ensure!(
        email_audit.unambiguous(),
        "account email lookup must be reconciled first"
    );
    let mut report = IdentityReconcileReport {
        dry_run: !apply,
        ..Default::default()
    };
    let mut after = None;
    loop {
        let ids = page_account_ids(client, after, batch).await?;
        if ids.is_empty() {
            break;
        }
        for id in &ids {
            report.scanned += 1;
            match one(client, *id, apply, SystemTime::now()).await? {
                Outcome::Existing => report.existing += 1,
                Outcome::NewBinding => report.new_bindings += 1,
                Outcome::NewMasterForBinding => report.new_masters_for_bindings += 1,
                Outcome::NeedsReview(reason) => {
                    report.needs_review += 1;
                    *report.review_reasons.entry(reason.to_owned()).or_default() += 1;
                }
            }
        }
        after = ids.last().copied();
    }
    Ok(report)
}
