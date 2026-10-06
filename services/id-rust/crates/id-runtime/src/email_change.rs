//! Transactional, one-use email change requests on the transition YDB schema.
//! A per-user intent invalidates replaced links; a per-address claim serializes
//! concurrent requests from different accounts for the same new address.

use crate::{
    password_mail,
    session_store::{LEGACY_BACKENDS, restore_django_session_tx},
    totp_setup::{recent_auth, session_data},
    tx_retry::retry_known_abort,
};
use anyhow::{Context, Result, ensure};
use id_compat::session::SessionCodec;
use rand::random;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use uuid::Uuid;
use ydb::{Client, Transaction, TxMode, closure};

const INTENT_TABLE: &str = "id_email_change";
const CLAIM_TABLE: &str = "id_email_claim";
const MAIL_TABLE: &str = "id_email_verification";
const LINK_TTL: Duration = Duration::from_secs(24 * 3600);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageResult {
    Unauthorized,
    ReauthRequired,
    InvalidEmail,
    EmailExists,
    NoChange,
    Staged,
    AddressIdCollision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfirmOutcome {
    NotChange,
    Invalid,
    Confirmed,
}

pub async fn ensure_schema(client: &Client) -> Result<()> {
    for (name, ddl) in [
        (
            INTENT_TABLE,
            format!(
                "CREATE TABLE IF NOT EXISTS `{INTENT_TABLE}` (user_id Int32 NOT NULL, intent_id Utf8 NOT NULL, old_email Utf8 NOT NULL, new_email Utf8 NOT NULL, address_id Int32 NOT NULL, expires_at Datetime NOT NULL, PRIMARY KEY (user_id))"
            ),
        ),
        (
            CLAIM_TABLE,
            format!(
                "CREATE TABLE IF NOT EXISTS `{CLAIM_TABLE}` (email_key Utf8 NOT NULL, user_id Int32 NOT NULL, intent_id Utf8 NOT NULL, expires_at Datetime NOT NULL, PRIMARY KEY (email_key))"
            ),
        ),
    ] {
        client
            .query_client()
            .exec(ddl)
            .timeout(Duration::from_secs(15))
            .await?;
        let table = client
            .table_client()
            .describe_table(format!("{}/{name}", client.database()))
            .await?;
        ensure!(
            table.primary_key
                == [if name == INTENT_TABLE {
                    "user_id"
                } else {
                    "email_key"
                }],
            "email change primary key drift: {name}"
        );
        let columns: std::collections::BTreeSet<_> = table
            .columns
            .iter()
            .map(|column| column.name.as_str())
            .collect();
        let expected: std::collections::BTreeSet<_> = if name == INTENT_TABLE {
            [
                "user_id",
                "intent_id",
                "old_email",
                "new_email",
                "address_id",
                "expires_at",
            ]
            .into_iter()
            .collect()
        } else {
            ["email_key", "user_id", "intent_id", "expires_at"]
                .into_iter()
                .collect()
        };
        ensure!(columns == expected, "email change columns drift: {name}");
        if name == INTENT_TABLE {
            let address = table
                .columns
                .iter()
                .find(|column| column.name == "address_id")
                .context("email change address ID column missing")?;
            ensure!(
                matches!(address.type_value.as_ref(), Ok(ydb::Value::Int32(_))),
                "email change address ID type drift"
            );
        }
    }
    Ok(())
}

async fn available(
    tx: &mut Transaction,
    user_id: i32,
    identity_id: Uuid,
    email: &str,
) -> ydb::YdbResultWithCustomerErr<bool> {
    let mut owners = tx.query("SELECT user_id FROM accounts_accountemaillookup VIEW acct_email_key_idx WHERE email_key = $email LIMIT 2")
        .param("$email", email.to_owned()).await?;
    let mut valid = true;
    while let Some(rows) = owners.next_result_set().await? {
        for mut row in rows {
            let owner: i32 = row.remove_field_by_name("user_id")?.try_into()?;
            valid &= owner == user_id;
        }
    }
    owners.close().await?;
    if !valid {
        return Ok(false);
    }
    let mut identities = tx
        .query("SELECT user_id FROM usid_user WHERE Unicode::ToLower(email) = $email LIMIT 2")
        .param("$email", email.to_owned())
        .await?;
    while let Some(rows) = identities.next_result_set().await? {
        for mut row in rows {
            let owner: Uuid = row.remove_field_by_name("user_id")?.try_into()?;
            valid &= owner == identity_id;
        }
    }
    identities.close().await?;
    if !valid {
        return Ok(false);
    }
    // Legacy verified secondary addresses have no email index. This rare
    // mutation scans them rather than silently attaching another owner.
    let mut verified = tx.query("SELECT user_id FROM account_emailaddress WHERE Unicode::ToLower(email) = $email AND verified = true LIMIT 2")
        .param("$email", email.to_owned()).await?;
    while let Some(rows) = verified.next_result_set().await? {
        for mut row in rows {
            let owner: i32 = row.remove_field_by_name("user_id")?.try_into()?;
            valid &= owner == user_id;
        }
    }
    verified.close().await?;
    Ok(valid)
}

/// Stage an address and durable mail intent together. Unknown commit outcomes
/// are returned as errors; no new credential is returned to the caller.
pub async fn stage(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: &str,
    new_email: &str,
    now: SystemTime,
) -> Result<StageResult> {
    let email = new_email.trim().to_lowercase();
    if email.len() > 254 || !password_mail::valid_recipient(&email) {
        return Ok(StageResult::InvalidEmail);
    }
    if token.is_empty() || token.len() > 256 {
        return Ok(StageResult::Unauthorized);
    }
    let intent_id = Uuid::new_v4().to_string();
    let address_id = -i32::try_from(random::<u32>() % (i32::MAX as u32 - 1) + 1)?;
    let expires = now
        .checked_add(LINK_TTL)
        .context("email change expiry overflow")?;
    let token = token.to_owned();
    let backends: Vec<String> = LEGACY_BACKENDS.iter().map(|s| (*s).to_owned()).collect();
    retry_known_abort(|| {
        let (codec, token, backends, email, intent_id) =
            (codec.clone(), token.clone(), backends.clone(), email.clone(), intent_id.clone());
        async {
            client.query_client().retry_tx(closure!([codec, token, backends, email, intent_id], async |tx: &mut Transaction| {
                let Some(session) = restore_django_session_tx(tx, codec.as_ref(), token, backends, now).await? else {
                    return Ok(StageResult::Unauthorized);
                };
                let user_id = i32::try_from(session.principal.account_id.get())
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                let has_mfa = tx.query_row("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $id LIMIT 1")
                    .param("$id", user_id).optional().await?.is_some();
                if has_mfa && !session.mfa_verified { return Ok(StageResult::Unauthorized); }
                let data = session_data(tx, codec.as_ref(), token).await?;
                if !recent_auth(&data, now) { return Ok(StageResult::ReauthRequired); }
                let Some(mut account) = tx.query_row("SELECT email FROM auth_user WHERE id = $id AND is_active = true")
                    .param("$id", user_id).optional().await? else { return Ok(StageResult::Unauthorized); };
                let old_email: String = account.remove_field_by_name("email")?.try_into()?;
                let old_email = old_email.trim().to_lowercase();
                if old_email == *email { return Ok(StageResult::NoChange); }
                let Some(mut binding) = tx.query_row("SELECT identity_id FROM accounts_accountidentity WHERE user_id = $id")
                    .param("$id", user_id).optional().await? else { return Ok(StageResult::Unauthorized); };
                let identity_id: Option<Uuid> = binding.remove_field_by_name("identity_id")?.try_into()?;
                let Some(identity_id) = identity_id else { return Ok(StageResult::Unauthorized); };
                let Some(mut identity) = tx.query_row("SELECT email, status FROM usid_user WHERE user_id = $id")
                    .param("$id", identity_id).optional().await? else { return Ok(StageResult::Unauthorized); };
                let identity_email: String = identity.remove_field_by_name("email")?.try_into()?;
                let status: String = identity.remove_field_by_name("status")?.try_into()?;
                if identity_email.trim().to_lowercase() != old_email || status != "active" {
                    return Ok(StageResult::Unauthorized);
                }
                if !available(tx, user_id, identity_id, email).await? {
                    return Ok(StageResult::EmailExists);
                }
                let Some(mut primary) = tx.query_row("SELECT id, email FROM account_emailaddress VIEW account_emailaddress_user_id_2c513194 WHERE user_id = $id AND primary = true LIMIT 2")
                    .param("$id", user_id).optional().await? else { return Ok(StageResult::Unauthorized); };
                let primary_email: String = primary.remove_field_by_name("email")?.try_into()?;
                let _: i32 = primary.remove_field_by_name("id")?.try_into()?;
                if primary_email.trim().to_lowercase() != old_email { return Ok(StageResult::Unauthorized); }
                if tx.query_row("SELECT id FROM account_emailaddress WHERE id = $id")
                    .param("$id", address_id).optional().await?.is_some() {
                    return Ok(StageResult::AddressIdCollision);
                }
                if let Some(mut claim) = tx.query_row(format!("SELECT user_id, expires_at FROM `{CLAIM_TABLE}` WHERE email_key = $email"))
                    .param("$email", email.clone()).optional().await? {
                    let owner: i32 = claim.remove_field_by_name("user_id")?.try_into()?;
                    let until: SystemTime = claim.remove_field_by_name("expires_at")?.try_into()?;
                    if owner != user_id && until > now { return Ok(StageResult::EmailExists); }
                }
                if let Some(mut previous) = tx.query_row(format!("SELECT intent_id, new_email FROM `{INTENT_TABLE}` WHERE user_id = $id"))
                    .param("$id", user_id).optional().await? {
                    let previous_id: String = previous.remove_field_by_name("intent_id")?.try_into()?;
                    let previous_email: String = previous.remove_field_by_name("new_email")?.try_into()?;
                    tx.exec(format!("UPDATE `{MAIL_TABLE}` SET status = 'cancelled', recipient = Unwrap(CAST('' AS Utf8)), claim_token = Unwrap(CAST('' AS Utf8)), lease_until = NULL WHERE id = $id"))
                        .param("$id", previous_id.clone()).await?;
                    tx.exec(format!("DELETE FROM `{CLAIM_TABLE}` WHERE email_key = $email AND user_id = $user_id AND intent_id = $id"))
                        .param("$email", previous_email).param("$user_id", user_id).param("$id", previous_id).await?;
                }
                let mut pending = tx.query("SELECT id FROM account_emailaddress VIEW account_emailaddress_user_id_2c513194 WHERE user_id = $id AND primary = false LIMIT 101")
                    .param("$id", user_id).await?;
                let mut pending_ids = Vec::<i32>::new();
                while let Some(rows) = pending.next_result_set().await? {
                    for mut row in rows { pending_ids.push(row.remove_field_by_name("id")?.try_into()?); }
                }
                pending.close().await?;
                if pending_ids.len() > 100 {
                    return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("too many secondary addresses")));
                }
                for id in pending_ids {
                    tx.exec("DELETE FROM account_emailconfirmation WHERE email_address_id = $id").param("$id", id).await?;
                    tx.exec("DELETE FROM account_emailaddress WHERE id = $id AND user_id = $user_id AND primary = false")
                        .param("$id", id).param("$user_id", user_id).await?;
                }
                tx.exec("INSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($id, $user_id, $email, false, false)")
                    .param("$id", address_id).param("$user_id", user_id).param("$email", email.clone()).await?;
                tx.exec(format!("UPSERT INTO `{INTENT_TABLE}` (user_id, intent_id, old_email, new_email, address_id, expires_at) VALUES ($user_id, $id, $old, $email, $address_id, CAST($expires AS Datetime))"))
                    .param("$user_id", user_id).param("$id", intent_id.clone()).param("$old", old_email)
                    .param("$email", email.clone()).param("$address_id", address_id).param("$expires", expires).await?;
                tx.exec(format!("UPSERT INTO `{CLAIM_TABLE}` (email_key, user_id, intent_id, expires_at) VALUES ($email, $user_id, $id, CAST($expires AS Datetime))"))
                    .param("$email", email.clone()).param("$user_id", user_id).param("$id", intent_id.clone()).param("$expires", expires).await?;
                tx.exec(format!("INSERT INTO `{MAIL_TABLE}` (id, user_id, recipient, expires_at, status, attempts, next_attempt_at, claim_token, created_at) VALUES ($id, $user_id, $email, CAST($expires AS Datetime), 'pending', 0, CAST($now AS Datetime), '', CAST($now AS Datetime))"))
                    .param("$id", intent_id.clone()).param("$user_id", user_id).param("$email", email.clone()).param("$expires", expires).param("$now", now).await?;
                Ok(StageResult::Staged)
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(20)).await
        }
    }).await.context("stage email change")
}

pub(crate) async fn cancel_tx(
    tx: &mut Transaction,
    user_id: i32,
) -> ydb::YdbResultWithCustomerErr<bool> {
    let Some(mut row) = tx
        .query_row(format!(
            "SELECT intent_id, new_email FROM `{INTENT_TABLE}` WHERE user_id = $id"
        ))
        .param("$id", user_id)
        .optional()
        .await?
    else {
        return Ok(false);
    };
    let intent_id: String = row.remove_field_by_name("intent_id")?.try_into()?;
    let email: String = row.remove_field_by_name("new_email")?.try_into()?;
    tx.exec(format!("UPDATE `{MAIL_TABLE}` SET status = 'cancelled', recipient = Unwrap(CAST('' AS Utf8)), claim_token = Unwrap(CAST('' AS Utf8)), lease_until = NULL WHERE id = $id"))
        .param("$id", intent_id.clone()).await?;
    tx.exec(format!("DELETE FROM `{CLAIM_TABLE}` WHERE email_key = $email AND user_id = $user_id AND intent_id = $id"))
        .param("$email", email).param("$user_id", user_id).param("$id", intent_id).await?;
    tx.exec(format!("DELETE FROM `{INTENT_TABLE}` WHERE user_id = $id"))
        .param("$id", user_id)
        .await?;
    Ok(true)
}

/// Remove expired pending addresses and claims without touching the primary
/// address. The verification timer calls this before deleting expired mail.
pub async fn cleanup_expired(client: &Client, now: SystemTime, limit: u64) -> Result<usize> {
    ensure!(
        (1..=100).contains(&limit),
        "invalid email change cleanup batch size"
    );
    let mut query_client = client.query_client();
    let mut rows = query_client.query(format!(
        "SELECT user_id, intent_id FROM `{INTENT_TABLE}` WHERE expires_at <= CAST($now AS Datetime) LIMIT $limit"
    )).param("$now", now).param("$limit", limit).await?;
    let mut candidates = Vec::<(i32, String)>::new();
    while let Some(set) = rows.next_result_set().await? {
        for mut row in set {
            candidates.push((
                row.remove_field_by_name("user_id")?.try_into()?,
                row.remove_field_by_name("intent_id")?.try_into()?,
            ));
        }
    }
    rows.close().await?;
    let mut cleaned = 0;
    for (user_id, intent_id) in candidates {
        let removed = retry_known_abort(|| {
            let intent_id = intent_id.clone();
            async {
                client.query_client().retry_tx(closure!([intent_id], async |tx: &mut Transaction| {
                    let Some(mut row) = tx.query_row(format!("SELECT intent_id, address_id, expires_at FROM `{INTENT_TABLE}` WHERE user_id = $id"))
                        .param("$id", user_id).optional().await? else { return Ok(false); };
                    let current_id: String = row.remove_field_by_name("intent_id")?.try_into()?;
                    let address_id: i32 = row.remove_field_by_name("address_id")?.try_into()?;
                    let expires: SystemTime = row.remove_field_by_name("expires_at")?.try_into()?;
                    if current_id != *intent_id || expires > now { return Ok(false); }
                    cancel_tx(tx, user_id).await?;
                    tx.exec("DELETE FROM account_emailconfirmation WHERE email_address_id = $id")
                        .param("$id", address_id).await?;
                    tx.exec("DELETE FROM account_emailaddress WHERE id = $id AND user_id = $user_id AND primary = false AND verified = false")
                        .param("$id", address_id).param("$user_id", user_id).await?;
                    Ok(true)
                })).with_mode(TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(15)).await
            }
        }).await?;
        cleaned += usize::from(removed);
    }
    Ok(cleaned)
}

struct ChangeState {
    old_email: String,
    address_id: i32,
    primary_id: i32,
    identity_id: Uuid,
}

async fn state_tx(
    tx: &mut Transaction,
    intent_id: &str,
    user_id: i32,
    recipient: &str,
    now: SystemTime,
) -> ydb::YdbResultWithCustomerErr<Option<ChangeState>> {
    let Some(mut row) = tx.query_row(format!("SELECT intent_id, old_email, new_email, address_id, expires_at FROM `{INTENT_TABLE}` WHERE user_id = $id"))
        .param("$id", user_id).optional().await? else { return Ok(None); };
    let current_id: String = row.remove_field_by_name("intent_id")?.try_into()?;
    let old_email: String = row.remove_field_by_name("old_email")?.try_into()?;
    let new_email: String = row.remove_field_by_name("new_email")?.try_into()?;
    let address_id: i32 = row.remove_field_by_name("address_id")?.try_into()?;
    let expires: SystemTime = row.remove_field_by_name("expires_at")?.try_into()?;
    if current_id != intent_id || new_email != recipient || expires <= now {
        return Ok(None);
    }
    let Some(mut claim) = tx
        .query_row(format!(
            "SELECT user_id, intent_id, expires_at FROM `{CLAIM_TABLE}` WHERE email_key = $email"
        ))
        .param("$email", new_email.clone())
        .optional()
        .await?
    else {
        return Ok(None);
    };
    let claim_user: i32 = claim.remove_field_by_name("user_id")?.try_into()?;
    let claim_id: String = claim.remove_field_by_name("intent_id")?.try_into()?;
    let claim_expires: SystemTime = claim.remove_field_by_name("expires_at")?.try_into()?;
    if claim_user != user_id || claim_id != intent_id || claim_expires <= now {
        return Ok(None);
    }
    let Some(mut account) = tx
        .query_row("SELECT email FROM auth_user WHERE id = $id AND is_active = true")
        .param("$id", user_id)
        .optional()
        .await?
    else {
        return Ok(None);
    };
    let account_email: String = account.remove_field_by_name("email")?.try_into()?;
    if account_email.trim().to_lowercase() != old_email {
        return Ok(None);
    }
    let Some(mut candidate) = tx
        .query_row(
            "SELECT user_id, email, verified, primary FROM account_emailaddress WHERE id = $id",
        )
        .param("$id", address_id)
        .optional()
        .await?
    else {
        return Ok(None);
    };
    let candidate_user: i32 = candidate.remove_field_by_name("user_id")?.try_into()?;
    let candidate_email: String = candidate.remove_field_by_name("email")?.try_into()?;
    let verified: bool = candidate.remove_field_by_name("verified")?.try_into()?;
    let primary: bool = candidate.remove_field_by_name("primary")?.try_into()?;
    if candidate_user != user_id
        || candidate_email.trim().to_lowercase() != new_email
        || verified
        || primary
    {
        return Ok(None);
    }
    let mut primary_rows = tx.query("SELECT id, email FROM account_emailaddress VIEW account_emailaddress_user_id_2c513194 WHERE user_id = $id AND primary = true LIMIT 2")
        .param("$id", user_id).await?;
    let mut primaries = Vec::<(i32, String)>::new();
    while let Some(rows) = primary_rows.next_result_set().await? {
        for mut row in rows {
            primaries.push((
                row.remove_field_by_name("id")?.try_into()?,
                row.remove_field_by_name("email")?.try_into()?,
            ));
        }
    }
    primary_rows.close().await?;
    if primaries.len() != 1 || primaries[0].1.trim().to_lowercase() != old_email {
        return Ok(None);
    }
    let Some(mut binding) = tx
        .query_row("SELECT identity_id FROM accounts_accountidentity WHERE user_id = $id")
        .param("$id", user_id)
        .optional()
        .await?
    else {
        return Ok(None);
    };
    let identity_id: Option<Uuid> = binding.remove_field_by_name("identity_id")?.try_into()?;
    let Some(identity_id) = identity_id else {
        return Ok(None);
    };
    let Some(mut identity) = tx
        .query_row("SELECT email, status FROM usid_user WHERE user_id = $id")
        .param("$id", identity_id)
        .optional()
        .await?
    else {
        return Ok(None);
    };
    let identity_email: String = identity.remove_field_by_name("email")?.try_into()?;
    let identity_status: String = identity.remove_field_by_name("status")?.try_into()?;
    if identity_email.trim().to_lowercase() != old_email || identity_status != "active" {
        return Ok(None);
    }
    let mut deletion = tx.query_row("SELECT COUNT(*) AS count FROM accounts_accountdeletionrequest VIEW accounts_accountdeletionrequest_user_id_6a166c52 WHERE user_id = $id AND status != 'canceled'")
        .param("$id", user_id).await?;
    let count: u64 = deletion.remove_field_by_name("count")?.try_into()?;
    Ok((count == 0).then_some(ChangeState {
        old_email,
        address_id,
        primary_id: primaries[0].0,
        identity_id,
    }))
}

pub(crate) async fn eligible_tx(
    tx: &mut Transaction,
    intent_id: &str,
    user_id: i32,
    recipient: &str,
    now: SystemTime,
) -> ydb::YdbResultWithCustomerErr<bool> {
    Ok(state_tx(tx, intent_id, user_id, recipient, now)
        .await?
        .is_some())
}

pub(crate) async fn confirm_tx(
    tx: &mut Transaction,
    intent_id: &str,
    user_id: i32,
    recipient: &str,
    now: SystemTime,
) -> ydb::YdbResultWithCustomerErr<ConfirmOutcome> {
    let Some(mut intent) = tx
        .query_row(format!(
            "SELECT intent_id FROM `{INTENT_TABLE}` WHERE user_id = $id"
        ))
        .param("$id", user_id)
        .optional()
        .await?
    else {
        return Ok(ConfirmOutcome::NotChange);
    };
    let active_id: String = intent.remove_field_by_name("intent_id")?.try_into()?;
    if active_id != intent_id {
        return Ok(ConfirmOutcome::Invalid);
    }
    let Some(state) = state_tx(tx, intent_id, user_id, recipient, now).await? else {
        return Ok(ConfirmOutcome::Invalid);
    };
    if !available(tx, user_id, state.identity_id, recipient).await? {
        return Ok(ConfirmOutcome::Invalid);
    }
    tx.exec(
        "UPDATE auth_user SET email = $email WHERE id = $id AND email = $old AND is_active = true",
    )
    .param("$email", recipient.to_owned())
    .param("$id", user_id)
    .param("$old", state.old_email.clone())
    .await?;
    tx.exec("UPDATE accounts_accountemaillookup SET email_key = $email WHERE user_id = $id")
        .param("$email", recipient.to_owned())
        .param("$id", user_id)
        .await?;
    tx.exec("UPDATE usid_user SET email = $email, email_verified = true WHERE user_id = $id AND email = $old")
        .param("$email", recipient.to_owned()).param("$id", state.identity_id).param("$old", state.old_email.clone()).await?;
    tx.exec("UPDATE account_emailaddress SET verified = true, primary = true WHERE id = $id AND user_id = $user_id AND verified = false AND primary = false")
        .param("$id", state.address_id).param("$user_id", user_id).await?;
    tx.exec("DELETE FROM account_emailconfirmation WHERE email_address_id = $id")
        .param("$id", state.primary_id)
        .await?;
    tx.exec("DELETE FROM account_emailaddress WHERE id = $id AND user_id = $user_id")
        .param("$id", state.primary_id)
        .param("$user_id", user_id)
        .await?;
    tx.exec("INSERT INTO accounts_accountevent (user_id, action, meta, created_at) VALUES ($id, 'email.changed', Unwrap(CAST('{}' AS Json)), CAST($now AS Datetime))")
        .param("$id", user_id).param("$now", now).await?;
    let old_notice = Uuid::new_v4().to_string();
    let new_notice = Uuid::new_v4().to_string();
    crate::security_mail::enqueue_tx(
        tx,
        &old_notice,
        user_id,
        &state.old_email,
        "email_changed",
        now,
    )
    .await?;
    crate::security_mail::enqueue_tx(tx, &new_notice, user_id, recipient, "email_confirmed", now)
        .await?;
    tx.exec(format!("UPDATE `{MAIL_TABLE}` SET consumed_at = CAST($now AS Datetime), status = 'cancelled', recipient = Unwrap(CAST('' AS Utf8)), claim_token = Unwrap(CAST('' AS Utf8)), lease_until = NULL WHERE id = $id"))
        .param("$now", now).param("$id", intent_id.to_owned()).await?;
    tx.exec(format!("DELETE FROM `{CLAIM_TABLE}` WHERE email_key = $email AND user_id = $user_id AND intent_id = $id"))
        .param("$email", recipient.to_owned()).param("$user_id", user_id).param("$id", intent_id.to_owned()).await?;
    tx.exec(format!("DELETE FROM `{INTENT_TABLE}` WHERE user_id = $id"))
        .param("$id", user_id)
        .await?;
    Ok(ConfirmOutcome::Confirmed)
}
