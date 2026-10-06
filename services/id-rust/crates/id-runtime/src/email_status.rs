//! Owner-scoped email status read from the legacy YDB tables.

use crate::session_store::{LEGACY_BACKENDS, restore_django_session_tx};
use anyhow::{Context, Result, ensure};
use id_compat::session::SessionCodec;
use serde::Serialize;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use ydb::{Client, Transaction, TxMode, closure};

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct EmailStatus {
    pub email: String,
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_email: Option<String>,
}

#[derive(Debug)]
struct Address {
    id: i32,
    email: String,
    verified: bool,
    primary: bool,
}

pub async fn read(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: &str,
    now: SystemTime,
) -> Result<Option<EmailStatus>> {
    let token = token.to_owned();
    let backends: Vec<String> = LEGACY_BACKENDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    let rows = client
        .query_client()
        .retry_tx(closure!([token, codec, backends], async |tx: &mut Transaction| {
            let Some(session) = restore_django_session_tx(
                tx, codec.as_ref(), token, backends, now,
            ).await? else {
                return Ok(None);
            };
            let user_id = i32::try_from(session.principal.account_id.get())
                .map_err(ydb::YdbOrCustomerError::from_err)?;
            let has_mfa = tx.query_row(
                "SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $user_id LIMIT 1"
            ).param("$user_id", user_id).optional().await?.is_some();
            if has_mfa && !session.mfa_verified {
                return Ok(None);
            }
            let mut account = tx.query_row("SELECT email FROM auth_user WHERE id = $user_id")
                .param("$user_id", user_id).optional().await?
                .ok_or_else(|| ydb::YdbOrCustomerError::from_err(std::io::Error::other("authorized account missing")))?;
            let fallback: String = account.remove_field_by_name("email")?.try_into()?;
            let mut stream = tx.query(
                "SELECT id, email, verified, primary FROM account_emailaddress VIEW account_emailaddress_user_id_2c513194 WHERE user_id = $user_id LIMIT 101"
            ).param("$user_id", user_id).await?;
            let mut addresses = Vec::new();
            while let Some(rows) = stream.next_result_set().await? {
                for mut row in rows {
                    addresses.push(Address {
                        id: row.remove_field_by_name("id")?.try_into()?,
                        email: row.remove_field_by_name("email")?.try_into()?,
                        verified: row.remove_field_by_name("verified")?.try_into()?,
                        primary: row.remove_field_by_name("primary")?.try_into()?,
                    });
                }
            }
            stream.close().await?;
            Ok(Some((fallback, addresses)))
        }))
        .isolation(TxMode::SerializableReadWrite)
        .timeout(Duration::from_secs(5))
        .await
        .context("read authorized email status")?;
    rows.map(|(fallback, addresses)| assemble(fallback, addresses))
        .transpose()
}

fn assemble(fallback: String, mut addresses: Vec<Address>) -> Result<EmailStatus> {
    ensure!(addresses.len() <= 100, "too many email addresses");
    addresses.retain(|address| address.primary || !address.verified);
    addresses.sort_by(|a, b| b.primary.cmp(&a.primary).then_with(|| b.id.cmp(&a.id)));
    let primary = addresses.iter().find(|address| address.primary);
    let pending = addresses
        .iter()
        .take(2)
        .find(|address| !address.primary && !address.verified);
    Ok(EmailStatus {
        email: primary.map_or(fallback, |address| address.email.clone()),
        verified: primary.is_some_and(|address| address.verified),
        pending_email: pending.map(|address| address.email.clone()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirrors_primary_and_newest_pending_selection() -> Result<()> {
        let status = assemble(
            "fallback@example.invalid".into(),
            vec![
                Address {
                    id: 1,
                    email: "first@example.invalid".into(),
                    verified: false,
                    primary: false,
                },
                Address {
                    id: 3,
                    email: "new@example.invalid".into(),
                    verified: false,
                    primary: false,
                },
                Address {
                    id: 4,
                    email: "secondary@example.invalid".into(),
                    verified: true,
                    primary: false,
                },
                Address {
                    id: 2,
                    email: "main@example.invalid".into(),
                    verified: true,
                    primary: true,
                },
            ],
        )?;
        assert_eq!(status.email, "main@example.invalid");
        assert!(status.verified);
        assert_eq!(status.pending_email.as_deref(), Some("new@example.invalid"));
        let fallback = assemble("fallback@example.invalid".into(), Vec::new())?;
        assert_eq!(fallback.email, "fallback@example.invalid");
        assert!(!fallback.verified);
        assert!(fallback.pending_email.is_none());
        assert!(
            serde_json::to_value(&fallback)?
                .get("pending_email")
                .is_none()
        );
        Ok(())
    }
}
