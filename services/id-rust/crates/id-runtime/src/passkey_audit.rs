//! Read-only compatibility gate for legacy WebAuthn credentials.
//! Reports counts only; credential IDs, users and registration responses stay local.

use crate::legacy_passkey::import_registration;
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, time::Duration};
use webauthn_rs::prelude::{Url, WebauthnBuilder};
use ydb::Client;

#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct PasskeyAudit {
    pub scanned: u64,
    pub convertible: u64,
    pub malformed: u64,
    pub incompatible: u64,
    pub duplicate_credential_ids: u64,
}

impl PasskeyAudit {
    pub fn ready(&self) -> bool {
        self.malformed == 0 && self.incompatible == 0 && self.duplicate_credential_ids == 0
    }
}

pub async fn audit(client: &Client, rp_id: &str, origin: &str) -> Result<PasskeyAudit> {
    let rp_origin = Url::parse(origin).context("invalid configured WebAuthn origin")?;
    WebauthnBuilder::new(rp_id, &rp_origin)
        .context("invalid configured WebAuthn RP ID")?
        .build()
        .context("invalid configured WebAuthn RP")?;
    let mut result = PasskeyAudit::default();
    let mut seen = HashSet::<[u8; 32]>::new();
    let mut after: Option<i64> = None;
    let mut pager = client.query_client();
    loop {
        let sql = if after.is_some() {
            "SELECT id, type, CAST(data AS Utf8) AS data FROM mfa_authenticator WHERE id > $after ORDER BY id LIMIT 100"
        } else {
            "SELECT id, type, CAST(data AS Utf8) AS data FROM mfa_authenticator ORDER BY id LIMIT 100"
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
                let id: i64 = row.remove_field_by_name("id")?.try_into()?;
                let kind: String = row.remove_field_by_name("type")?.try_into()?;
                let data: String = row.remove_field_by_name("data")?.try_into()?;
                page.push((id, kind, data));
            }
        }
        stream.close().await?;
        if page.is_empty() {
            return Ok(result);
        }
        for (_, kind, data) in &page {
            if kind != "webauthn" {
                continue;
            }
            result.scanned += 1;
            let Ok(record) = serde_json::from_str::<Value>(data) else {
                result.malformed += 1;
                continue;
            };
            let Some(registration) = record.get("credential") else {
                result.malformed += 1;
                continue;
            };
            match import_registration(registration, rp_id, origin) {
                Ok(passkey) => {
                    result.convertible += 1;
                    let digest: [u8; 32] = Sha256::digest(passkey.cred_id().as_ref()).into();
                    if !seen.insert(digest) {
                        result.duplicate_credential_ids += 1;
                    }
                }
                Err(_) => result.incompatible += 1,
            }
        }
        after = page.last().map(|row| row.0);
        if page.len() < 100 {
            return Ok(result);
        }
    }
}

pub async fn audit_from_env(client: &Client) -> Result<PasskeyAudit> {
    let rp_id = std::env::var("ID_WEBAUTHN_RP_ID").context("ID_WEBAUTHN_RP_ID required")?;
    let origin = std::env::var("ID_WEBAUTHN_ORIGIN").context("ID_WEBAUTHN_ORIGIN required")?;
    audit(client, &rp_id, &origin).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_fails_for_any_incompatible_or_duplicate_credential() {
        assert!(PasskeyAudit::default().ready());
        assert!(
            !PasskeyAudit {
                incompatible: 1,
                ..Default::default()
            }
            .ready()
        );
        assert!(
            !PasskeyAudit {
                duplicate_credential_ids: 1,
                ..Default::default()
            }
            .ready()
        );
    }
}
