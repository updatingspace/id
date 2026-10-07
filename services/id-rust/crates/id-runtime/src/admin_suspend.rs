//! Operator account suspension. The password check runs outside the executor;
//! the final transaction rechecks the operator, target and credential hash.

use crate::{
    ids::PublicSubject,
    password_change::revoke_credentials,
    session_store::{LEGACY_BACKENDS, restore_django_session_tx},
    tx_retry::retry_known_abort,
};
use anyhow::{Context, Result};
use id_compat::session::SessionCodec;
use serde::Deserialize;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use ydb::{Client, Transaction, TxMode, closure};

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SuspensionReason {
    SecurityIncident,
    OwnerRequest,
    PolicyReview,
}

impl SuspensionReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::SecurityIncident => "security_incident",
            Self::OwnerRequest => "owner_request",
            Self::PolicyReview => "policy_review",
        }
    }
}

pub(crate) enum Preflight {
    Unauthorized,
    Forbidden,
    Ready {
        actor_id: i32,
        password_hash: String,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SuspendResult {
    Unauthorized,
    Forbidden,
    WrongPassword,
    TargetMissing,
    SelfTarget,
    ProtectedTarget,
    StaleReview,
    AlreadyClosed,
    Suspended,
}

pub(crate) async fn preflight(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: &str,
    now: SystemTime,
) -> Result<Preflight> {
    let token = token.to_owned();
    let backends = LEGACY_BACKENDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    client.query_client().retry_tx(closure!([token, codec, backends], async |tx: &mut Transaction| {
        let Some(session) = restore_django_session_tx(tx, codec.as_ref(), token, backends, now).await? else {
            return Ok(Preflight::Unauthorized);
        };
        let actor_id = i32::try_from(session.principal.account_id.get()).map_err(ydb::YdbOrCustomerError::from_err)?;
        let Some(mut actor) = tx.query_row("SELECT password, is_staff, is_superuser FROM auth_user WHERE id = $id")
            .param("$id", actor_id).optional().await? else { return Ok(Preflight::Unauthorized) };
        let staff: bool = actor.remove_field_by_name("is_staff")?.try_into()?;
        let superuser: bool = actor.remove_field_by_name("is_superuser")?.try_into()?;
        let has_mfa = tx.query_row("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $id LIMIT 1")
            .param("$id", actor_id).optional().await?.is_some();
        if !staff || !superuser || !has_mfa || !session.mfa_verified {
            return Ok(Preflight::Forbidden);
        }
        Ok(Preflight::Ready { actor_id, password_hash: actor.remove_field_by_name("password")?.try_into()? })
    })).isolation(TxMode::SerializableReadWrite).timeout(Duration::from_secs(5)).await
        .context("operator suspension preflight")
}

pub(crate) struct SuspendInput<'a> {
    pub token: &'a str,
    pub actor_id: i32,
    pub password_hash: &'a str,
    pub target_id: i32,
    pub expected_subject: &'a str,
    pub reason: SuspensionReason,
    pub now: SystemTime,
}

/// Call only after verifying the submitted password against the preflight hash.
/// A lost commit response is not retried as success; the caller must re-read.
pub(crate) async fn suspend(
    client: &Client,
    codec: Arc<SessionCodec>,
    input: SuspendInput<'_>,
) -> Result<SuspendResult> {
    let token = input.token.to_owned();
    let old_hash = input.password_hash.to_owned();
    let expected_subject = input.expected_subject.to_owned();
    let backends = LEGACY_BACKENDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    retry_known_abort(|| {
        let token = token.clone();
        let codec = codec.clone();
        let old_hash = old_hash.clone();
        let expected_subject = expected_subject.clone();
        let backends = backends.clone();
        async {
            client.query_client().retry_tx(closure!([token, codec, old_hash, expected_subject, backends], async |tx: &mut Transaction| {
                let Some(session) = restore_django_session_tx(tx, codec.as_ref(), token, backends, input.now).await? else {
                    return Ok(SuspendResult::Unauthorized);
                };
                if session.principal.account_id.get() != i64::from(input.actor_id) {
                    return Ok(SuspendResult::Unauthorized);
                }
                let Some(mut actor) = tx.query_row("SELECT password, is_staff, is_superuser FROM auth_user WHERE id = $id")
                    .param("$id", input.actor_id).optional().await? else { return Ok(SuspendResult::Unauthorized) };
                let current_hash: String = actor.remove_field_by_name("password")?.try_into()?;
                let staff: bool = actor.remove_field_by_name("is_staff")?.try_into()?;
                let superuser: bool = actor.remove_field_by_name("is_superuser")?.try_into()?;
                let has_mfa = tx.query_row("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $id LIMIT 1")
                    .param("$id", input.actor_id).optional().await?.is_some();
                if !staff || !superuser || !has_mfa || !session.mfa_verified {
                    return Ok(SuspendResult::Forbidden);
                }
                if current_hash != *old_hash {
                    return Ok(SuspendResult::WrongPassword);
                }
                if input.target_id == input.actor_id {
                    return Ok(SuspendResult::SelfTarget);
                }
                let Some(mut target) = tx.query_row("SELECT is_active, is_staff, is_superuser FROM auth_user WHERE id = $id")
                    .param("$id", input.target_id).optional().await? else { return Ok(SuspendResult::TargetMissing) };
                let active: bool = target.remove_field_by_name("is_active")?.try_into()?;
                let target_staff: bool = target.remove_field_by_name("is_staff")?.try_into()?;
                let target_superuser: bool = target.remove_field_by_name("is_superuser")?.try_into()?;
                if target_staff || target_superuser { return Ok(SuspendResult::ProtectedTarget) }
                let Some(mut binding) = tx.query_row("SELECT identity_id, public_subject FROM accounts_accountidentity WHERE user_id = $id")
                    .param("$id", input.target_id).optional().await? else { return Ok(SuspendResult::StaleReview) };
                let identity_id: Option<uuid::Uuid> = binding.remove_field_by_name("identity_id")?.try_into()?;
                let subject: String = binding.remove_field_by_name("public_subject")?.try_into()?;
                let Some(identity_id) = identity_id else { return Ok(SuspendResult::StaleReview) };
                if PublicSubject::parse(subject.clone()).is_none() || subject != *expected_subject {
                    return Ok(SuspendResult::StaleReview);
                }
                let mut owners = tx.query("SELECT user_id FROM accounts_accountidentity WHERE identity_id = $id LIMIT 2")
                    .param("$id", identity_id).await?;
                let mut owner_ids: Vec<i32> = Vec::with_capacity(2);
                while let Some(rows) = owners.next_result_set().await? {
                    for mut row in rows { owner_ids.push(row.remove_field_by_name("user_id")?.try_into()?); }
                }
                owners.close().await?;
                if owner_ids.as_slice() != [input.target_id] { return Ok(SuspendResult::StaleReview) }
                let mut subjects = tx.query("SELECT user_id FROM accounts_accountidentity WHERE public_subject = $subject LIMIT 2")
                    .param("$subject", subject).await?;
                let mut subject_owner_ids: Vec<i32> = Vec::with_capacity(2);
                while let Some(rows) = subjects.next_result_set().await? {
                    for mut row in rows { subject_owner_ids.push(row.remove_field_by_name("user_id")?.try_into()?); }
                }
                subjects.close().await?;
                if subject_owner_ids.as_slice() != [input.target_id] { return Ok(SuspendResult::StaleReview) }
                let Some(mut identity) = tx.query_row("SELECT status FROM usid_user WHERE user_id = $id")
                    .param("$id", identity_id).optional().await? else { return Ok(SuspendResult::StaleReview) };
                let identity_status: String = identity.remove_field_by_name("status")?.try_into()?;
                if !active || identity_status != "active" {
                    return Ok(SuspendResult::AlreadyClosed);
                }
                let deletion_pending = tx.query_row("SELECT id FROM accounts_accountdeletionrequest VIEW accounts_accountdeletionrequest_user_id_6a166c52 WHERE user_id = $id AND status != 'canceled' LIMIT 1")
                    .param("$id", input.target_id).optional().await?.is_some();
                if deletion_pending { return Ok(SuspendResult::AlreadyClosed) }
                tx.exec("UPDATE auth_user SET is_active = false WHERE id = $id")
                    .param("$id", input.target_id).await?;
                tx.exec("UPDATE usid_user SET status = 'suspended' WHERE user_id = $id")
                    .param("$id", identity_id).await?;
                revoke_credentials(tx, input.target_id, input.now, "operator_suspended").await?;
                let meta = serde_json::json!({"reason": input.reason.as_str()}).to_string();
                tx.exec("INSERT INTO usid_audit_log (actor_user_id, action, target_type, target_id, tenant_id, meta_json, created_at) VALUES ($actor, 'account.suspended', 'user', $target, NULL, UNWRAP(CAST($meta AS Json)), CAST($now AS Datetime))")
                    .param("$actor", session.principal.identity_id.get())
                    .param("$target", identity_id.to_string()).param("$meta", meta)
                    .param("$now", input.now).await?;
                Ok(SuspendResult::Suspended)
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
                .timeout(Duration::from_secs(30)).await
        }
    }).await.context("operator suspension")
}
