//! Read-only password/login policy preflight against the legacy YDB schema.
//! A future session-issuing transaction must recheck the hash and policy snapshot.

use crate::ids::{AccountId, IdentityId, PublicSubject};
use anyhow::{Context, Result, bail};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use uuid::Uuid;
use ydb::{Client, Transaction, TxMode, closure};

// Generated with Django's current Argon2PasswordHasher and a synthetic value.
// Unknown addresses still pay the same password-hash cost as a normal account.
const DUMMY_HASH: &str = "argon2$argon2id$v=19$m=102400,t=2,p=8$cnVzdC1sb2dpbi1kdW1teS1zYWx0$bQXwkwn8h2t5j9yPoSTPrfayyfBxHwRKnJgoqERyeUk";

pub struct LoginPreflight {
    client: Arc<Client>,
    hashing_slots: Arc<Semaphore>,
}

pub enum LoginDecision {
    InvalidCredentials,
    EmailVerificationRequired,
    MfaRequired(VerifiedAccount),
    Ready(VerifiedAccount),
}

/// Carries the password hash read during preflight only for a later comparison
/// inside session issuance. It must never be serialized or logged.
pub struct VerifiedAccount {
    pub account_id: AccountId,
    pub identity_id: IdentityId,
    pub public_subject: PublicSubject,
    password_hash: String,
    email_key: String,
    pub(crate) has_mfa: bool,
}

impl VerifiedAccount {
    pub fn password_hash(&self) -> &str {
        &self.password_hash
    }

    pub fn email_key(&self) -> &str {
        &self.email_key
    }
}

struct Candidate {
    account_id: i32,
    password_hash: String,
    is_active: bool,
    verified_email: bool,
    has_mfa: bool,
    identity_id: Option<Uuid>,
    public_subject: Option<String>,
    identity_active: bool,
    deleting: bool,
}

impl LoginPreflight {
    pub fn new(client: Arc<Client>, max_parallel_hashes: usize) -> Result<Self> {
        if !(1..=4).contains(&max_parallel_hashes) {
            bail!("password hashing parallelism must be between 1 and 4");
        }
        Ok(Self {
            client,
            hashing_slots: Arc::new(Semaphore::new(max_parallel_hashes)),
        })
    }

    /// No session or JWT is issued here. Password verification runs on a
    /// bounded blocking pool; YDB and ambiguous ownership failures are errors,
    /// never converted into invalid credentials or an MFA bypass.
    pub async fn verify(&self, email: &str, password: &str) -> Result<LoginDecision> {
        let started = Instant::now();
        let normalized = email.trim().to_lowercase();
        if normalized.is_empty() || normalized.len() > 320 {
            return Ok(LoginDecision::InvalidCredentials);
        }
        let candidate = read_candidate(&self.client, &normalized).await?;
        let read_ms = started.elapsed().as_millis();
        let hash = candidate
            .as_ref()
            .map_or(DUMMY_HASH, |row| row.password_hash.as_str())
            .to_owned();
        let password = password.to_owned();
        let permit = self
            .hashing_slots
            .clone()
            .try_acquire_owned()
            .context("password hashing pool saturated")?;
        let matched = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            id_compat::password::verify(&password, &hash)
        })
        .await
        .context("password verification task failed")??;
        let hash_ms = started.elapsed().as_millis() - read_ms;
        let Some(candidate) = candidate else {
            return Ok(LoginDecision::InvalidCredentials);
        };
        if !matched || !candidate.is_active || candidate.deleting {
            return Ok(LoginDecision::InvalidCredentials);
        }
        let (Some(identity_id), Some(public_subject)) =
            (candidate.identity_id, candidate.public_subject)
        else {
            bail!("login account lacks an immutable identity binding");
        };
        let Some(public_subject) = PublicSubject::parse(public_subject) else {
            bail!("login account has an invalid public subject");
        };
        if !candidate.identity_active {
            return Ok(LoginDecision::InvalidCredentials);
        }
        if !candidate.verified_email {
            return Ok(LoginDecision::EmailVerificationRequired);
        }
        tracing::info!(target: "id_runtime::login_timing", read_ms, hash_ms, "password preflight stage durations");
        let verified = VerifiedAccount {
            account_id: AccountId::new(i64::from(candidate.account_id)),
            identity_id: IdentityId::new(identity_id),
            public_subject,
            password_hash: candidate.password_hash,
            email_key: normalized,
            has_mfa: candidate.has_mfa,
        };
        if candidate.has_mfa {
            return Ok(LoginDecision::MfaRequired(verified));
        }
        Ok(LoginDecision::Ready(verified))
    }
}

async fn read_candidate(client: &Client, normalized_email: &str) -> Result<Option<Candidate>> {
    let normalized_email = normalized_email.to_owned();
    client
        .query_client()
        .retry_tx(closure!(
            [normalized_email],
            async |tx: &mut Transaction| { read_candidate_tx(tx, normalized_email.as_str()).await }
        ))
        .isolation(TxMode::SnapshotReadOnly)
        .timeout(Duration::from_secs(5))
        .await
        .context("read legacy account for password login")
}

/// Ownership must already be established by a verified external credential.
/// Resolve the same account policy as password login;
/// session issuance repeats every mutable check in its write transaction.
pub(crate) async fn verified_credential_owner(
    client: &Client,
    account_id: i32,
) -> Result<Option<VerifiedAccount>> {
    let Some(mut row) = client
        .query_client()
        .query_row("SELECT email FROM auth_user WHERE id = $id")
        .param("$id", account_id)
        .optional()
        .await?
    else {
        return Ok(None);
    };
    let email: String = row.remove_field_by_name("email")?.try_into()?;
    let normalized = email.trim().to_lowercase();
    if normalized.is_empty() || normalized.len() > 320 {
        return Ok(None);
    }
    let Some(candidate) = read_candidate(client, &normalized).await? else {
        return Ok(None);
    };
    if candidate.account_id != account_id
        || !candidate.is_active
        || candidate.deleting
        || !candidate.identity_active
        || !candidate.verified_email
    {
        return Ok(None);
    }
    let (Some(identity_id), Some(subject)) = (candidate.identity_id, candidate.public_subject)
    else {
        bail!("credential owner lacks immutable identity binding")
    };
    let subject = PublicSubject::parse(subject).context("invalid credential owner subject")?;
    Ok(Some(VerifiedAccount {
        account_id: AccountId::new(i64::from(account_id)),
        identity_id: IdentityId::new(identity_id),
        public_subject: subject,
        password_hash: candidate.password_hash,
        email_key: normalized,
        has_mfa: candidate.has_mfa,
    }))
}

async fn read_candidate_tx(
    tx: &mut Transaction,
    normalized_email: &str,
) -> ydb::YdbResultWithCustomerErr<Option<Candidate>> {
    let mut stream = tx
        .query("SELECT user_id FROM accounts_accountemaillookup VIEW acct_email_key_idx WHERE email_key = $email LIMIT 2")
        .param("$email", normalized_email.to_owned())
        .await?;
    let mut account_ids = Vec::with_capacity(2);
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            account_ids.push(row.remove_field_by_name("user_id")?.try_into()?);
        }
    }
    stream.close().await?;
    if account_ids.len() > 1 {
        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
            "ambiguous case-insensitive account email",
        )));
    }
    let Some(account_id): Option<i32> = account_ids.pop() else {
        return Ok(None);
    };
    let Some(mut row) = tx
        .query_row("SELECT email, password, is_active FROM auth_user WHERE id = $user_id")
        .param("$user_id", account_id)
        .optional()
        .await?
    else {
        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
            "email lookup points to a missing account",
        )));
    };
    let stored_email: String = row.remove_field_by_name("email")?.try_into()?;
    if stored_email.trim().to_lowercase() != normalized_email {
        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
            "email lookup disagrees with account",
        )));
    }
    let password_hash: String = row.remove_field_by_name("password")?.try_into()?;
    let is_active: bool = row.remove_field_by_name("is_active")?.try_into()?;

    let verified_email = tx
        .query_row("SELECT id FROM account_emailaddress VIEW account_emailaddress_user_id_2c513194 WHERE user_id = $user_id AND Unicode::ToLower(email) = $email AND verified = true LIMIT 1")
        .param("$user_id", account_id)
        .param("$email", normalized_email.to_owned())
        .optional()
        .await?
        .is_some();
    let has_mfa = tx
        .query_row("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $user_id LIMIT 1")
        .param("$user_id", account_id)
        .optional()
        .await?
        .is_some();
    let binding = tx
        .query_row("SELECT identity_id, public_subject FROM accounts_accountidentity WHERE user_id = $user_id")
        .param("$user_id", account_id)
        .optional()
        .await?;
    let (identity_id, public_subject) = if let Some(mut row) = binding {
        (
            row.remove_field_by_name("identity_id")?.try_into()?,
            Some(row.remove_field_by_name("public_subject")?.try_into()?),
        )
    } else {
        (None, None)
    };
    let identity_active = if let Some(identity_id) = identity_id {
        let row = tx
            .query_row("SELECT status FROM usid_user WHERE user_id = $identity_id")
            .param("$identity_id", identity_id)
            .optional()
            .await?;
        if let Some(mut row) = row {
            let status: String = row.remove_field_by_name("status")?.try_into()?;
            status == "active"
        } else {
            false
        }
    } else {
        false
    };
    let deleting = tx
        .query_row("SELECT id FROM accounts_accountdeletionrequest VIEW accounts_accountdeletionrequest_user_id_6a166c52 WHERE user_id = $user_id AND status != 'canceled' LIMIT 1")
        .param("$user_id", account_id)
        .optional()
        .await?
        .is_some();
    Ok(Some(Candidate {
        account_id,
        password_hash,
        is_active,
        verified_email,
        has_mfa,
        identity_id,
        public_subject,
        identity_active,
        deleting,
    }))
}
