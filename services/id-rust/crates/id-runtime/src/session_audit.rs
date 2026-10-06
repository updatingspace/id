//! Read-only inventory of legacy sessions before an MFA-aware Rust canary.
//! Outputs counts only; session keys, account IDs and decoded data stay in memory.

use crate::session_store::restore_django_session_tx;
use anyhow::{Context, Result};
use id_compat::session::SessionCodec;
use serde::Serialize;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use ydb::{Client, Transaction, TxMode, closure};

#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct MfaSessionAudit {
    pub scanned: u64,
    pub expired: u64,
    pub ineligible: u64,
    pub eligible_without_mfa: u64,
    pub eligible_mfa_proven: u64,
    pub eligible_mfa_unproven: u64,
}

impl MfaSessionAudit {
    fn classify(&mut self, classification: Classification) {
        match classification {
            Classification::Expired => self.expired += 1,
            Classification::Ineligible => self.ineligible += 1,
            Classification::NoMfa => self.eligible_without_mfa += 1,
            Classification::MfaProven => self.eligible_mfa_proven += 1,
            Classification::MfaUnproven => self.eligible_mfa_unproven += 1,
        }
    }
}

#[derive(Clone, Copy)]
enum Classification {
    Expired,
    Ineligible,
    NoMfa,
    MfaProven,
    MfaUnproven,
}

/// Every page is a separate snapshot. Run after old writers have drained and
/// repeat immediately before canary; this is an inventory, not a data lock.
pub async fn audit_mfa_sessions(
    client: &Client,
    codec: Arc<SessionCodec>,
    allowed_backends: &[&str],
    now: SystemTime,
) -> Result<MfaSessionAudit> {
    audit_mfa_sessions_with_prefix(client, codec, allowed_backends, now, "").await
}

/// Prefix-scoped form supports isolated synthetic integration checks. The CLI
/// always invokes the full inventory above, never a prefix-scoped gate.
pub async fn audit_mfa_sessions_with_prefix(
    client: &Client,
    codec: Arc<SessionCodec>,
    allowed_backends: &[&str],
    now: SystemTime,
    prefix: &str,
) -> Result<MfaSessionAudit> {
    let mut after = prefix.to_owned();
    let mut counts = MfaSessionAudit::default();
    let backends: Vec<String> = allowed_backends
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    let mut pager = client.query_client();
    loop {
        let mut stream = pager
            .query("SELECT session_key, expire_date FROM django_session WHERE session_key > $after ORDER BY session_key LIMIT 100")
            .param("$after", after.clone())
            .timeout(Duration::from_secs(10))
            .await
            .context("page Django sessions for MFA audit")?;
        let mut page = Vec::new();
        while let Some(rows) = stream.next_result_set().await? {
            for mut row in rows {
                let key: String = row.remove_field_by_name("session_key")?.try_into()?;
                let expiry: SystemTime = row.remove_field_by_name("expire_date")?.try_into()?;
                page.push((key, expiry));
            }
        }
        stream.close().await?;
        if page.is_empty() {
            return Ok(counts);
        }
        for (key, expiry) in &page {
            if !key.starts_with(prefix) {
                return Ok(counts);
            }
            counts.scanned += 1;
            if *expiry <= now {
                counts.classify(Classification::Expired);
                continue;
            }
            let token = key.clone();
            let codec = codec.clone();
            let backends = backends.clone();
            let found = client
                .query_client()
                .retry_tx(closure!([token, codec, backends], async |tx: &mut Transaction| {
                    let Some(restored) = restore_django_session_tx(
                        tx,
                        codec.as_ref(),
                        token.as_str(),
                        backends.as_slice(),
                        now,
                    ).await? else {
                        return Ok(None);
                    };
                    let user_id = i32::try_from(restored.principal.account_id.get())
                        .map_err(ydb::YdbOrCustomerError::from_err)?;
                    let has_mfa = tx.query_row("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $user_id LIMIT 1")
                        .param("$user_id", user_id).optional().await?.is_some();
                    Ok(Some((has_mfa, restored.mfa_verified)))
                }))
                .isolation(TxMode::SerializableReadWrite)
                .timeout(Duration::from_secs(5))
                .await
                .context("classify authenticated session for MFA audit")?;
            counts.classify(match found {
                None => Classification::Ineligible,
                Some((false, _)) => Classification::NoMfa,
                Some((true, true)) => Classification::MfaProven,
                Some((true, false)) => Classification::MfaUnproven,
            });
        }
        after = page
            .last()
            .context("session audit page unexpectedly empty")?
            .0
            .clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_scanned_session_has_one_outcome() {
        let mut audit = MfaSessionAudit::default();
        for classification in [
            Classification::Expired,
            Classification::Ineligible,
            Classification::NoMfa,
            Classification::MfaProven,
            Classification::MfaUnproven,
        ] {
            audit.scanned += 1;
            audit.classify(classification);
        }
        assert_eq!(audit.scanned, 5);
        assert_eq!(
            audit.expired
                + audit.ineligible
                + audit.eligible_without_mfa
                + audit.eligible_mfa_proven
                + audit.eligible_mfa_unproven,
            audit.scanned
        );
    }
}
