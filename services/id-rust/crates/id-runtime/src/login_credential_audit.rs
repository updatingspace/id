//! Read-only production inventory for the password-login cutover.
//! Reports only counts; account IDs, hashes, MFA secrets and codes never leave this module.

use anyhow::{Result, ensure};
use serde::Serialize;
use serde_json::Value;
use std::{collections::HashMap, time::Duration};
use ydb::Client;

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct LoginCredentialAudit {
    pub accounts: u64,
    pub argon2: u64,
    pub pbkdf2_sha256: u64,
    pub bcrypt_sha256: u64,
    pub unusable_password: u64,
    pub unsupported_password: u64,
    pub totp: u64,
    pub recovery_codes: u64,
    pub webauthn: u64,
    pub unknown_mfa_type: u64,
    pub malformed_mfa_data: u64,
    pub duplicate_totp_or_recovery: u64,
}

impl LoginCredentialAudit {
    pub fn supported(&self) -> bool {
        self.unsupported_password == 0
            && self.unknown_mfa_type == 0
            && self.malformed_mfa_data == 0
            && self.duplicate_totp_or_recovery == 0
    }

    fn record_password(&mut self, hash: &str) {
        self.accounts += 1;
        if hash.starts_with('!') {
            self.unusable_password += 1;
        } else if hash.starts_with("argon2$") {
            self.argon2 += 1;
        } else if hash.starts_with("pbkdf2_sha256$") {
            self.pbkdf2_sha256 += 1;
        } else if hash.starts_with("bcrypt_sha256$") {
            self.bcrypt_sha256 += 1;
        } else {
            self.unsupported_password += 1;
        }
    }

    fn record_mfa(&mut self, kind: &str, data: &str) {
        let Ok(data) = serde_json::from_str::<Value>(data) else {
            self.malformed_mfa_data += 1;
            return;
        };
        match kind {
            "totp" => {
                self.totp += 1;
                if data
                    .get("secret")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
                {
                    self.malformed_mfa_data += 1;
                }
            }
            "recovery_codes" => {
                self.recovery_codes += 1;
                let migrated = data.get("migrated_codes").is_some_and(Value::is_array);
                let seeded = data
                    .get("seed")
                    .and_then(Value::as_str)
                    .is_some_and(|v| !v.is_empty())
                    && data.get("used_mask").and_then(Value::as_u64).is_some();
                if !migrated && !seeded {
                    self.malformed_mfa_data += 1;
                }
            }
            "webauthn" => self.webauthn += 1,
            _ => self.unknown_mfa_type += 1,
        }
    }
}

/// Pages are separate snapshots. Repeat just before routing login to Rust.
pub async fn audit(client: &Client) -> Result<LoginCredentialAudit> {
    let mut report = LoginCredentialAudit::default();
    let mut pager = client.query_client();
    let mut after: Option<i32> = None;
    loop {
        let sql = if after.is_some() {
            "SELECT id, password FROM auth_user WHERE id > $after ORDER BY id LIMIT 100"
        } else {
            "SELECT id, password FROM auth_user ORDER BY id LIMIT 100"
        };
        let query = pager.query(sql).timeout(Duration::from_secs(10));
        let mut stream = if let Some(id) = after {
            query.param("$after", id).await?
        } else {
            query.await?
        };
        let mut last = None;
        while let Some(rows) = stream.next_result_set().await? {
            for mut row in rows {
                let id: i32 = row.remove_field_by_name("id")?.try_into()?;
                let hash: String = row.remove_field_by_name("password")?.try_into()?;
                report.record_password(&hash);
                last = Some(id);
            }
        }
        stream.close().await?;
        let Some(id) = last else { break };
        ensure!(
            after.is_none_or(|previous| id > previous),
            "password audit did not advance"
        );
        after = Some(id);
    }

    let mut after: Option<i64> = None;
    let mut per_user = HashMap::<i32, (bool, bool)>::new();
    loop {
        let sql = if after.is_some() {
            "SELECT id, user_id, type, CAST(data AS Utf8) AS data FROM mfa_authenticator WHERE id > $after ORDER BY id LIMIT 100"
        } else {
            "SELECT id, user_id, type, CAST(data AS Utf8) AS data FROM mfa_authenticator ORDER BY id LIMIT 100"
        };
        let query = pager.query(sql).timeout(Duration::from_secs(10));
        let mut stream = if let Some(id) = after {
            query.param("$after", id).await?
        } else {
            query.await?
        };
        let mut last = None;
        while let Some(rows) = stream.next_result_set().await? {
            for mut row in rows {
                let id: i64 = row.remove_field_by_name("id")?.try_into()?;
                let user_id: i32 = row.remove_field_by_name("user_id")?.try_into()?;
                let kind: String = row.remove_field_by_name("type")?.try_into()?;
                let data: String = row.remove_field_by_name("data")?.try_into()?;
                report.record_mfa(&kind, &data);
                let seen = per_user.entry(user_id).or_default();
                let slot = match kind.as_str() {
                    "totp" => Some(&mut seen.0),
                    "recovery_codes" => Some(&mut seen.1),
                    _ => None,
                };
                if let Some(slot) = slot {
                    if *slot {
                        report.duplicate_totp_or_recovery += 1;
                    }
                    *slot = true;
                }
                last = Some(id);
            }
        }
        stream.close().await?;
        let Some(id) = last else { break };
        ensure!(
            after.is_none_or(|previous| id > previous),
            "MFA audit did not advance"
        );
        after = Some(id);
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_only_aggregates_and_gates_unsupported_formats() -> Result<()> {
        let mut report = LoginCredentialAudit::default();
        report.record_password("argon2$argon2id$v=19$private");
        report.record_password("pbkdf2_sha256$720000$private");
        report.record_password("!unusable");
        report.record_mfa("totp", r#"{"secret":"private"}"#);
        report.record_mfa("recovery_codes", r#"{"seed":"private","used_mask":0}"#);
        assert!(report.supported());
        let output = serde_json::to_string(&report)?;
        assert!(!output.contains("private"));
        report.record_password("unknown$private");
        assert!(!report.supported());
        Ok(())
    }
}
