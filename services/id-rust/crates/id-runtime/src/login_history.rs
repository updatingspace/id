//! Owner-scoped login history, read in the same snapshot as session/MFA checks.

use crate::session_store::{LEGACY_BACKENDS, restore_django_session_tx};
use anyhow::{Context, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use id_compat::session::SessionCodec;
use serde::Serialize;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use ydb::{Client, Transaction, TxMode, closure};

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct LoginEvent {
    pub status: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub device_id: Option<String>,
    pub is_new_device: bool,
    pub reason: Option<String>,
    pub created_at: String,
}

pub async fn read(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: &str,
    now: SystemTime,
) -> Result<Option<Vec<LoginEvent>>> {
    let token = token.to_owned();
    let backends: Vec<String> = LEGACY_BACKENDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    client.query_client().retry_tx(closure!([token, codec, backends], async |tx: &mut Transaction| {
        let Some(session) = restore_django_session_tx(tx, codec.as_ref(), token, backends, now).await? else {
            return Ok(None);
        };
        let user_id = i32::try_from(session.principal.account_id.get())
            .map_err(ydb::YdbOrCustomerError::from_err)?;
        let has_mfa = tx.query_row("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $id LIMIT 1")
            .param("$id", user_id).optional().await?.is_some();
        if has_mfa && !session.mfa_verified { return Ok(None); }
        let mut query = tx.query("SELECT status, ip_address, user_agent, device_id, is_new_device, reason, created_at FROM accounts_loginevent VIEW acct_login_user_idx WHERE user_id = $id ORDER BY created_at DESC LIMIT 100")
            .param("$id", user_id).await?;
        let mut events = Vec::new();
        while let Some(rows) = query.next_result_set().await? {
            for mut row in rows {
                let created_at: SystemTime = row.remove_field_by_name("created_at")?.try_into()?;
                events.push(LoginEvent {
                    status: row.remove_field_by_name("status")?.try_into()?,
                    ip_address: row.remove_field_by_name("ip_address")?.try_into()?,
                    user_agent: row.remove_field_by_name("user_agent")?.try_into()?,
                    device_id: row.remove_field_by_name("device_id")?.try_into()?,
                    is_new_device: row.remove_field_by_name("is_new_device")?.try_into()?,
                    reason: row.remove_field_by_name("reason")?.try_into()?,
                    created_at: DateTime::<Utc>::from(created_at).to_rfc3339_opts(SecondsFormat::Millis, true),
                });
            }
        }
        query.close().await?;
        Ok(Some(events))
    })).isolation(TxMode::SerializableReadWrite).timeout(Duration::from_secs(10)).await
        .context("read owner login history")
}
