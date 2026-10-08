//! Atomic creation of a new account and its immutable public identity.
//! Signup never issues a session: the new email must first be verified.

use crate::{
    email_verify,
    password_policy::{self, AccountWords},
    tx_retry::retry_known_abort,
};
use anyhow::{Result, ensure};
use chrono::{Datelike, NaiveDate, Utc};
use rand::random;
use std::time::{Duration, SystemTime};
use tokio::sync::Semaphore;
use uuid::Uuid;
use ydb::{Client, Transaction, TxMode, closure};

const VERIFY_TTL: Duration = Duration::from_secs(24 * 3600);

#[derive(Clone)]
pub struct SignupInput {
    pub username: String,
    pub email: String,
    pub password: String,
    pub language: String,
    pub timezone: String,
    pub consent_data_processing: bool,
    pub consent_marketing: bool,
    pub is_minor: bool,
    pub guardian_email: Option<String>,
    pub guardian_consent: bool,
    pub birth_date: Option<NaiveDate>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignupResult {
    Created,
    EmailExists,
    UsernameExists,
}

pub fn requires_guardian(explicit: bool, birth_date: Option<NaiveDate>) -> bool {
    if explicit {
        return true;
    }
    let Some(birth_date) = birth_date else {
        return false;
    };
    let today = Utc::now().date_naive();
    let age = today.year()
        - birth_date.year()
        - i32::from((today.month(), today.day()) < (birth_date.month(), birth_date.day()));
    age < 18
}

pub fn validate(input: &mut SignupInput) -> Result<()> {
    input.email = input.email.trim().to_lowercase();
    input.username = input.username.trim().to_owned();
    ensure!(
        input.consent_data_processing,
        "data processing consent required"
    );
    ensure!(
        input.email.len() <= 254 && crate::password_mail::valid_recipient(&input.email),
        "invalid email"
    );
    ensure!(
        !input.username.is_empty()
            && input.username.chars().count() <= 150
            && input
                .username
                .chars()
                .all(|ch| ch.is_alphanumeric() || "@.+-_".contains(ch)),
        "invalid username"
    );
    ensure!(
        input.password.len() <= 4096
            && password_policy::acceptable(
                &input.password,
                "",
                &AccountWords {
                    username: input.username.clone(),
                    email: input.email.clone(),
                    first_name: String::new(),
                    last_name: String::new(),
                }
            ),
        "weak password"
    );
    ensure!(
        matches!(input.language.as_str(), "ru" | "en"),
        "invalid language"
    );
    ensure!(
        input.timezone.len() <= 64
            && (input.timezone.is_empty() || input.timezone.parse::<chrono_tz::Tz>().is_ok()),
        "invalid timezone"
    );
    if let Some(birth_date) = input.birth_date {
        let today = Utc::now().date_naive();
        ensure!(birth_date <= today, "invalid birth date");
    }
    input.is_minor = requires_guardian(input.is_minor, input.birth_date);
    if input.is_minor {
        ensure!(input.guardian_consent, "parental consent required");
        let guardian_email = input
            .guardian_email
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_lowercase();
        ensure!(
            guardian_email.len() <= 254 && crate::password_mail::valid_recipient(&guardian_email),
            "guardian email required or invalid"
        );
        input.guardian_email = Some(guardian_email);
    } else {
        input.guardian_email = None;
        input.guardian_consent = false;
    }
    Ok(())
}

/// Hash outside the executor and cap concurrent Argon2 work.
pub async fn create(
    client: &Client,
    slots: &Semaphore,
    mut input: SignupInput,
    now: SystemTime,
) -> Result<SignupResult> {
    validate(&mut input)?;
    let permit = slots.acquire().await?;
    let password = std::mem::take(&mut input.password);
    let hash =
        tokio::task::spawn_blocking(move || id_compat::password::hash_new(&password)).await??;
    drop(permit);
    let expires = now
        .checked_add(VERIFY_TTL)
        .ok_or_else(|| anyhow::anyhow!("verification expiry overflow"))?;
    // Negative account IDs stay outside Django's positive AutoField sequence.
    // Every candidate is checked in the same transaction as its insertion.
    for _ in 0..8 {
        let user_id =
            -i32::try_from(u32::from_le_bytes(random::<[u8; 4]>()) % (i32::MAX as u32 - 1) + 1)?;
        let identity_id = Uuid::new_v4();
        let mail_id = Uuid::new_v4().to_string();
        let email_id = user_id;
        let prefs_id = i64::from(user_id);
        let consent_id = i64::from(user_id) * 4;
        let input = input.clone();
        let hash = hash.clone();
        let outcome = retry_known_abort(|| {
            let (input, hash, mail_id) = (input.clone(), hash.clone(), mail_id.clone());
            async move {
                client.query_client().retry_tx(closure!([input, hash, mail_id], async |tx: &mut Transaction| {
                    if tx.query_row("SELECT id FROM auth_user WHERE id = $id")
                        .param("$id", user_id).optional().await?.is_some() {
                        return Ok(None);
                    }
                    if tx.query_row("SELECT id FROM account_emailaddress WHERE id = $id")
                        .param("$id", email_id).optional().await?.is_some() {
                        return Ok(None);
                    }
                    if tx.query_row("SELECT user_id FROM accounts_accountemaillookup VIEW acct_email_key_idx WHERE email_key = $email LIMIT 1")
                        .param("$email", input.email.clone()).optional().await?.is_some() {
                        return Ok(Some(SignupResult::EmailExists));
                    }
                    if tx.query_row("SELECT user_id FROM usid_user VIEW usid_user_email_idx WHERE email = $email LIMIT 1")
                        .param("$email", input.email.clone()).optional().await?.is_some() {
                        return Ok(Some(SignupResult::EmailExists));
                    }
                    if tx.query_row("SELECT id FROM auth_user WHERE username = $username LIMIT 1")
                        .param("$username", input.username.clone()).optional().await?.is_some() {
                        return Ok(Some(SignupResult::UsernameExists));
                    }
                    tx.exec("INSERT INTO auth_user (id, password, username, first_name, last_name, email, is_superuser, is_staff, is_active, date_joined) VALUES ($id, $hash, $username, '', '', $email, false, false, true, CAST($now AS Datetime))")
                        .param("$id", user_id).param("$hash", hash.clone()).param("$username", input.username.clone())
                        .param("$email", input.email.clone()).param("$now", now).await?;
                    tx.exec("INSERT INTO accounts_accountemaillookup (user_id, email_key) VALUES ($id, $email)")
                        .param("$id", user_id).param("$email", input.email.clone()).await?;
                    tx.exec("INSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($id, $user_id, $email, false, true)")
                        .param("$id", email_id).param("$user_id", user_id).param("$email", input.email.clone()).await?;
                    tx.exec("INSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($identity, $username, $username, $email, false, 'active', false, CAST($now AS Datetime))")
                        .param("$identity", identity_id).param("$username", input.username.chars().take(64).collect::<String>())
                        .param("$email", input.email.clone()).param("$now", now).await?;
                    tx.exec("INSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($id, $identity, $subject, CAST($now AS Datetime))")
                        .param("$id", user_id).param("$identity", identity_id).param("$subject", identity_id.to_string())
                        .param("$now", now).await?;
                    tx.exec("INSERT INTO accounts_userpreferences (id, user_id, language, timezone, marketing_opt_in, privacy_scope_defaults, created_at, updated_at) VALUES ($id, $user_id, $language, $timezone, $marketing, '{}', CAST($now AS Datetime), CAST($now AS Datetime))")
                        .param("$id", prefs_id).param("$user_id", user_id).param("$language", input.language.clone())
                        .param("$timezone", input.timezone.clone()).param("$marketing", input.consent_marketing).param("$now", now).await?;
                    if input.consent_marketing {
                        tx.exec("UPDATE accounts_userpreferences SET marketing_opt_in_at = CAST($now AS Datetime) WHERE user_id = $user_id")
                            .param("$now", now).param("$user_id", user_id).await?;
                    }
                    tx.exec("INSERT INTO accounts_userconsent (id, user_id, kind, version, granted_at, source, meta) VALUES ($id, $user_id, 'data_processing', 'v1', CAST($now AS Datetime), 'signup', '{}')")
                        .param("$id", consent_id).param("$user_id", user_id).param("$now", now).await?;
                    if input.consent_marketing {
                        tx.exec("INSERT INTO accounts_userconsent (id, user_id, kind, version, granted_at, source, meta) VALUES ($id, $user_id, 'marketing', 'v1', CAST($now AS Datetime), 'signup', '{}')")
                            .param("$id", consent_id + 1).param("$user_id", user_id).param("$now", now).await?;
                    }
                    if let Some(birth_date) = input.birth_date {
                        tx.exec("INSERT INTO accounts_userprofile (user_id, avatar_source, gravatar_enabled, phone_number, phone_verified, birth_date, created_at, updated_at) VALUES ($user_id, 'none', true, '', false, CAST($birth AS Date), CAST($now AS Datetime), CAST($now AS Datetime))")
                            .param("$user_id", user_id).param("$birth", birth_date.to_string()).param("$now", now).await?;
                    }
                    if input.is_minor {
                        let guardian_meta = serde_json::json!({"guardian_email": input.guardian_email.as_deref()}).to_string();
                        tx.exec("INSERT INTO accounts_userconsent (id, user_id, kind, version, granted_at, source, meta) VALUES ($id, $user_id, 'parental', 'v1', CAST($now AS Datetime), 'signup', Unwrap(CAST($meta AS Json)))")
                            .param("$id", consent_id + 2).param("$user_id", user_id).param("$now", now).param("$meta", guardian_meta).await?;
                    }
                    tx.exec(format!("INSERT INTO `{}` (id, user_id, recipient, expires_at, status, attempts, next_attempt_at, claim_token, created_at) VALUES ($mail_id, $user_id, $email, CAST($expires AS Datetime), 'pending', 0, CAST($now AS Datetime), '', CAST($now AS Datetime))", email_verify::TABLE))
                        .param("$mail_id", mail_id.clone()).param("$user_id", user_id).param("$email", input.email.clone())
                        .param("$expires", expires).param("$now", now).await?;
                    Ok(Some(SignupResult::Created))
                })).with_mode(TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(20)).await
            }
        }).await?;
        if let Some(outcome) = outcome {
            return Ok(outcome);
        }
    }
    anyhow::bail!("could not allocate a unique account ID")
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn input() -> SignupInput {
        SignupInput {
            username: "minor-test".into(),
            email: "minor-test@example.invalid".into(),
            password: "A strong, unusual registration password 2026!".into(),
            language: "ru".into(),
            timezone: "Europe/Moscow".into(),
            consent_data_processing: true,
            consent_marketing: false,
            is_minor: false,
            guardian_email: None,
            guardian_consent: false,
            birth_date: None,
        }
    }

    #[test]
    fn birth_date_requires_guardian_and_normalizes_email() {
        let mut candidate = input();
        candidate.birth_date = Utc::now()
            .date_naive()
            .checked_sub_months(chrono::Months::new(17 * 12));
        assert!(validate(&mut candidate).is_err());
        candidate.guardian_consent = true;
        candidate.guardian_email = Some(" Guardian@Example.Invalid ".into());
        assert!(validate(&mut candidate).is_ok());
        assert!(candidate.is_minor);
        assert_eq!(
            candidate.guardian_email.as_deref(),
            Some("guardian@example.invalid")
        );
    }

    #[test]
    fn future_birth_date_is_rejected() {
        let mut candidate = input();
        candidate.birth_date = Utc::now().date_naive().succ_opt();
        candidate.guardian_consent = true;
        candidate.guardian_email = Some("guardian@example.invalid".into());
        assert!(validate(&mut candidate).is_err());
    }
}
