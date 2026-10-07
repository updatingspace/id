//! Bounded, resumable delivery of account-security mail. Login and password
//! transactions insert their intents. SMTP acknowledgement is not atomic with
//! YDB; an ambiguous acknowledgement may produce a duplicate alert.

use crate::ymq::YmqPublisher;
use crate::{
    email_verify::{self, VerifyMailConfig},
    magic_link_request::{self, MailConfig as MagicMailConfig},
    password_mail,
    password_reset::{self, ResetMailConfig},
    security_mail,
    tx_retry::retry_known_abort,
};
use anyhow::{Context, Result, bail};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentTransferEncoding},
    transport::smtp::authentication::Credentials,
};
use std::{
    env,
    sync::Arc,
    time::{Duration, SystemTime},
};
use ydb::{Client, Transaction, TxMode, closure};

const LEASE: Duration = Duration::from_secs(120);
const SMTP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Default, PartialEq, Eq)]
pub struct DrainResult {
    pub claimed: usize,
    pub sent: usize,
    pub deferred: usize,
    pub cancelled: usize,
}

impl DrainResult {
    fn add(&mut self, other: Self) {
        self.claimed += other.claimed;
        self.sent += other.sent;
        self.deferred += other.deferred;
        self.cancelled += other.cancelled;
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MailJob {
    NewDevice(i64),
    PasswordChanged(String),
    Security(String),
    PasswordReset(String),
    EmailVerify(String),
    MagicLink(String),
}

pub struct MailWorker {
    client: Arc<Client>,
    export: Option<crate::data_export_s3::S3Export>,
    export_mail: Option<crate::data_export_mail::MailConfig>,
    escrow_cleanup_enabled: bool,
    #[cfg(feature = "passkeys")]
    media: Option<crate::media_delete::S3MediaDelete>,
    mailer: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    publisher: Option<Arc<YmqPublisher>>,
    reset: Option<ResetMailConfig>,
    verify: Option<VerifyMailConfig>,
}

impl MailWorker {
    pub fn exports_enabled(&self) -> bool {
        self.export.is_some()
    }

    pub async fn drain_due_exports(
        &self,
        limit: u64,
    ) -> Result<crate::data_export_job::ExportDrain> {
        match &self.export {
            Some(storage) => {
                crate::data_export_job::drain_due(self.client.clone(), storage, limit).await
            }
            None => Ok(crate::data_export_job::ExportDrain::default()),
        }
    }
    pub async fn drain_due_export_mails(&self, limit: u64) -> Result<DrainResult> {
        match &self.export_mail {
            Some(config) => {
                crate::data_export_mail::drain_due(
                    &self.client,
                    limit,
                    config,
                    &self.mailer,
                    &self.from,
                )
                .await
            }
            None => Ok(DrainResult::default()),
        }
    }
    pub async fn drain_expired_exports(
        &self,
        limit: u64,
    ) -> Result<crate::data_export_job::ExportDrain> {
        match &self.export {
            Some(storage) => {
                let mut result = crate::data_export_job::clean_expired(
                    &self.client,
                    storage,
                    limit,
                    SystemTime::now(),
                )
                .await?;
                if self.escrow_cleanup_enabled {
                    let escrow = crate::data_export_job::clean_expired_escrow(
                        &self.client,
                        storage,
                        limit,
                        SystemTime::now(),
                    )
                    .await?;
                    result.attempted += escrow.attempted;
                    result.completed += escrow.completed;
                    result.deferred += escrow.deferred;
                }
                Ok(result)
            }
            None => Ok(crate::data_export_job::ExportDrain::default()),
        }
    }
    #[cfg(feature = "passkeys")]
    pub async fn drain_pending_deletions(
        &self,
        limit: u64,
    ) -> Result<crate::account_deletion_cleanup::CredentialDrain> {
        crate::account_deletion_cleanup::drain_pending(&self.client, limit).await
    }
    #[cfg(feature = "passkeys")]
    pub async fn drain_pending_avatars(
        &self,
        limit: u64,
    ) -> Result<crate::account_deletion_cleanup::CredentialDrain> {
        crate::account_deletion_cleanup::drain_pending_avatars(
            &self.client,
            self.media.as_ref(),
            limit,
        )
        .await
    }
    #[cfg(feature = "passkeys")]
    pub async fn drain_pending_profiles(
        &self,
        limit: u64,
    ) -> Result<crate::account_deletion_cleanup::CredentialDrain> {
        crate::account_deletion_cleanup::drain_pending_profiles_with_exports(
            &self.client,
            self.export.as_ref(),
            limit,
        )
        .await
    }
    #[cfg(feature = "passkeys")]
    pub async fn drain_pending_globals(
        &self,
        limit: u64,
    ) -> Result<crate::account_deletion_cleanup::CredentialDrain> {
        crate::account_deletion_cleanup::drain_pending_globals(&self.client, limit).await
    }
    #[cfg(feature = "passkeys")]
    pub async fn drain_pending_finalizations(
        &self,
        limit: u64,
    ) -> Result<crate::account_deletion_cleanup::CredentialDrain> {
        crate::account_deletion_finalize::drain_pending(&self.client, limit).await
    }
    #[cfg(test)]
    pub(crate) fn for_test(
        client: Arc<Client>,
        mailer: AsyncSmtpTransport<Tokio1Executor>,
        from: Mailbox,
    ) -> Self {
        Self {
            client,
            export: None,
            export_mail: None,
            escrow_cleanup_enabled: false,
            #[cfg(feature = "passkeys")]
            media: None,
            mailer,
            from,
            publisher: None,
            reset: None,
            verify: None,
        }
    }

    pub fn from_env(client: Arc<Client>) -> Result<Self> {
        let (mailer, from) = smtp_from_env()?;
        let export = if crate::me_http::env_flag("ID_EXPORT_JOBS_ENABLED", false)? {
            Some(crate::data_export_s3::S3Export::from_env()?)
        } else {
            None
        };
        let escrow_cleanup_pilot =
            crate::me_http::env_flag("ID_EXPORT_ESCROW_JOBS_PILOT_ENABLED", false)?;
        let escrow_cleanup_rollout =
            crate::me_http::env_flag("ID_EXPORT_ESCROW_JOBS_ROLLOUT_ENABLED", false)?;
        let escrow_cleanup_enabled = escrow_cleanup_pilot || escrow_cleanup_rollout;
        if escrow_cleanup_enabled {
            let endpoint = url::Url::parse(&env::var("YDB_ENDPOINT")?)?;
            let local_ydb = crate::me_http::env_flag("DJANGO_DEBUG", false)?
                && matches!(
                    endpoint.host_str(),
                    Some("localhost" | "127.0.0.1" | "[::1]")
                )
                && env::var("YDB_DATABASE")? == "/local";
            if (escrow_cleanup_pilot && !local_ydb) || export.is_none() {
                bail!("export escrow jobs require storage; pilot also requires local debug YDB");
            }
        }
        let export_mail = crate::data_export_mail::MailConfig::from_env()?;
        if export_mail.is_some() && export.is_none() {
            bail!("export escrow mail requires export storage jobs");
        }
        Ok(Self {
            client,
            export,
            export_mail,
            escrow_cleanup_enabled,
            #[cfg(feature = "passkeys")]
            media: crate::media_delete::S3MediaDelete::from_env()?,
            mailer,
            from,
            publisher: YmqPublisher::from_env()?.map(Arc::new),
            reset: ResetMailConfig::from_env()?,
            verify: VerifyMailConfig::from_env()?,
        })
    }

    pub async fn publish_due(&self, limit: u64) -> Result<usize> {
        if limit == 0 || limit > 100 {
            bail!("mail publish batch size must be between 1 and 100");
        }
        let publisher = self
            .publisher
            .as_ref()
            .context("YMQ publisher is not configured")?;
        let magic = MagicMailConfig::from_env()?;
        let mut sent = 0;
        for job in due_jobs(
            &self.client,
            limit,
            self.reset.is_some(),
            self.verify.is_some(),
            magic.is_some(),
        )
        .await?
        {
            match job {
                MailJob::NewDevice(event_id) => publisher.send_new_device_mail(event_id).await?,
                MailJob::PasswordChanged(event_id) => {
                    publisher.send_password_changed_mail(&event_id).await?
                }
                MailJob::Security(event_id) => publisher.send_security_mail(&event_id).await?,
                MailJob::PasswordReset(event_id) => {
                    publisher.send_password_reset_mail(&event_id).await?
                }
                MailJob::EmailVerify(event_id) => {
                    publisher.send_email_verify_mail(&event_id).await?
                }
                MailJob::MagicLink(event_id) => publisher.send_magic_link_mail(&event_id).await?,
            }
            sent += 1;
        }
        Ok(sent)
    }

    pub async fn drain_due(&self, limit: u64) -> Result<DrainResult> {
        let magic = MagicMailConfig::from_env()?;
        if let Some(config) = &magic {
            magic_link_request::cleanup_expired(
                &self.client,
                config.secret(),
                SystemTime::now(),
                limit,
            )
            .await?;
        }
        if self.reset.is_some() {
            password_reset::cleanup_expired(&self.client, SystemTime::now(), limit).await?;
        }
        if self.verify.is_some() {
            crate::email_change::cleanup_expired(&self.client, SystemTime::now(), limit).await?;
            email_verify::cleanup_expired(&self.client, SystemTime::now(), limit).await?;
        }
        drain_with_transport(
            &self.client,
            limit,
            &self.mailer,
            &self.from,
            self.reset.as_ref(),
            self.verify.as_ref(),
            magic.as_ref(),
        )
        .await
    }

    /// Recover only email-verification intents. This deliberately does not
    /// inspect the new-device, password or recovery-mail outboxes.
    pub async fn drain_due_verifications(&self, limit: u64) -> Result<DrainResult> {
        let verify = self
            .verify
            .as_ref()
            .context("email verification mail is disabled")?;
        let now = SystemTime::now();
        crate::email_change::cleanup_expired(&self.client, now, limit).await?;
        email_verify::cleanup_expired(&self.client, now, limit).await?;
        let mut result = DrainResult::default();
        for id in email_verify::due_ids(&self.client, now, limit).await? {
            result.add(
                email_verify::process_one(&self.client, &id, verify, &self.mailer, &self.from)
                    .await?,
            );
        }
        Ok(result)
    }

    /// Recover only password-reset intents. Existing new-device and
    /// password-change notifications are never selected by this timer.
    pub async fn drain_due_password_resets(&self, limit: u64) -> Result<DrainResult> {
        let reset = self
            .reset
            .as_ref()
            .context("password reset mail is disabled")?;
        let now = SystemTime::now();
        password_reset::cleanup_expired(&self.client, now, limit).await?;
        let mut result = DrainResult::default();
        for id in password_reset::due_ids(&self.client, now, limit).await? {
            result.add(
                password_reset::process_one(&self.client, &id, reset, &self.mailer, &self.from)
                    .await?,
            );
        }
        Ok(result)
    }

    /// Recover only password-change notices; never select reset links or
    /// account-deletion work.
    pub async fn drain_due_password_changes(&self, limit: u64) -> Result<DrainResult> {
        password_mail::drain_due(&self.client, limit, &self.mailer, &self.from).await
    }

    /// Recover only passkey removal notices. No password or verification
    /// intents are selected by this timer.
    pub async fn drain_due_security(&self, limit: u64) -> Result<DrainResult> {
        let mut result = DrainResult::default();
        for id in security_mail::due_ids(&self.client, SystemTime::now(), limit).await? {
            result.add(
                security_mail::process_one(&self.client, &id, &self.mailer, &self.from).await?,
            );
        }
        Ok(result)
    }

    pub async fn ready(&self) -> bool {
        let magic_ready = match MagicMailConfig::from_env() {
            Ok(Some(_)) => magic_link_request::due_ids(&self.client, SystemTime::now(), 1)
                .await
                .is_ok(),
            Ok(None) => true,
            Err(_) => false,
        };
        crate::probe(&self.client).await.is_ok()
            && magic_ready
            && (self.export.is_none()
                || crate::data_export_operation::due_ids(&self.client, SystemTime::now(), 1)
                    .await
                    .is_ok())
            && (self.export.is_none()
                || crate::data_export_operation::expired(&self.client, SystemTime::now(), 1)
                    .await
                    .is_ok())
            && (self.export_mail.is_none()
                || crate::data_export_mail::due_ids(&self.client, SystemTime::now(), 1)
                    .await
                    .is_ok())
            && password_mail::due_ids(&self.client, SystemTime::now(), 1)
                .await
                .is_ok()
            && security_mail::due_ids(&self.client, SystemTime::now(), 1)
                .await
                .is_ok()
            && (self.reset.is_none()
                || password_reset::due_ids(&self.client, SystemTime::now(), 1)
                    .await
                    .is_ok())
            && (self.verify.is_none()
                || email_verify::due_ids(&self.client, SystemTime::now(), 1)
                    .await
                    .is_ok())
    }

    pub async fn drain_ids(&self, ids: &[i64]) -> Result<DrainResult> {
        if ids.is_empty() || ids.len() > 100 {
            bail!("mail batch must contain between 1 and 100 event IDs");
        }
        let mut result = DrainResult::default();
        for id in ids {
            result.add(process_one(&self.client, *id, &self.mailer, &self.from).await?);
        }
        Ok(result)
    }

    pub async fn drain_jobs(&self, jobs: &[MailJob]) -> Result<DrainResult> {
        if jobs.is_empty() || jobs.len() > 100 {
            bail!("mail batch must contain between 1 and 100 jobs");
        }
        let mut result = DrainResult::default();
        let magic = MagicMailConfig::from_env()?;
        for job in jobs {
            result.add(match job {
                MailJob::NewDevice(id) => {
                    process_one(&self.client, *id, &self.mailer, &self.from).await?
                }
                MailJob::PasswordChanged(id) => {
                    password_mail::process_one(&self.client, id, &self.mailer, &self.from).await?
                }
                MailJob::Security(id) => {
                    security_mail::process_one(&self.client, id, &self.mailer, &self.from).await?
                }
                MailJob::PasswordReset(id) => {
                    let reset = self
                        .reset
                        .as_ref()
                        .context("password reset mail is disabled")?;
                    password_reset::process_one(&self.client, id, reset, &self.mailer, &self.from)
                        .await?
                }
                MailJob::EmailVerify(id) => {
                    let verify = self
                        .verify
                        .as_ref()
                        .context("email verification mail is disabled")?;
                    email_verify::process_one(&self.client, id, verify, &self.mailer, &self.from)
                        .await?
                }
                MailJob::MagicLink(id) => {
                    magic_link_request::process_one(
                        &self.client,
                        id,
                        magic.as_ref().context("magic-link mail is disabled")?,
                        &self.mailer,
                        &self.from,
                    )
                    .await?
                }
            });
        }
        Ok(result)
    }
}

struct Alert {
    recipient: String,
    ip: Option<String>,
    user_agent: String,
}

fn smtp_from_env() -> Result<(AsyncSmtpTransport<Tokio1Executor>, Mailbox)> {
    let host = env::var("EMAIL_HOST").context("EMAIL_HOST is required")?;
    let port: u16 = env::var("EMAIL_PORT")
        .unwrap_or_else(|_| "587".into())
        .parse()?;
    let from: Mailbox = env::var("DEFAULT_FROM_EMAIL")
        .context("DEFAULT_FROM_EMAIL is required")?
        .parse()?;
    let tls = env::var("EMAIL_USE_TLS").map_or(true, |value| value == "true" || value == "1");
    let mut builder = if tls {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)?
    } else if matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1") {
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
    } else {
        bail!("plaintext SMTP is allowed only on loopback");
    };
    builder = builder.port(port).timeout(Some(SMTP_TIMEOUT));
    if let (Ok(user), Ok(password)) = (env::var("EMAIL_HOST_USER"), env::var("EMAIL_HOST_PASSWORD"))
        && !user.is_empty()
    {
        builder = builder.credentials(Credentials::new(user, password));
    }
    Ok((builder.build(), from))
}

fn render(alert: &Alert, from: &Mailbox) -> Result<Message> {
    let ip = alert
        .ip
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or("неизвестно");
    let ua = if alert.user_agent.is_empty() {
        "неизвестно"
    } else {
        &alert.user_agent
    };
    let body = format!(
        "Обнаружен вход в ваш аккаунт с нового устройства.\n\nIP: {ip}\nУстройство/браузер: {ua}\n\nЕсли это не вы, срочно смените пароль и завершите все сессии."
    );
    Ok(Message::builder()
        .from(from.clone())
        .to(alert.recipient.parse()?)
        .subject("Новый вход в аккаунт")
        .header(ContentTransferEncoding::QuotedPrintable)
        .body(body)?)
}

async fn due_ids(client: &Client, now: SystemTime, limit: u64) -> Result<Vec<i64>> {
    let mut query_client = client.query_client();
    let mut rows = query_client
        .query("SELECT event_id FROM accounts_newdevicemailoutbox VIEW acct_device_mail_due_idx WHERE status = 'pending' AND next_attempt_at <= CAST($now AS Datetime) AND (lease_until IS NULL OR lease_until <= CAST($now AS Datetime)) ORDER BY next_attempt_at LIMIT $limit")
        .param("$now", now).param("$limit", limit)
        .await?;
    let mut ids = Vec::new();
    while let Some(set) = rows.next_result_set().await? {
        for mut row in set {
            ids.push(row.remove_field_by_name("event_id")?.try_into()?);
        }
    }
    rows.close().await?;
    Ok(ids)
}

async fn due_jobs(
    client: &Client,
    limit: u64,
    include_reset: bool,
    include_verify: bool,
    include_magic: bool,
) -> Result<Vec<MailJob>> {
    if limit == 0 || limit > 100 {
        bail!("mail batch size must be 1..=100");
    }
    let now = SystemTime::now();
    let old = due_ids(client, now, limit).await?;
    let password = password_mail::due_ids(client, now, limit).await?;
    let security = security_mail::due_ids(client, now, limit).await?;
    let reset = if include_reset {
        password_reset::due_ids(client, now, limit).await?
    } else {
        Vec::new()
    };
    let verify = if include_verify {
        email_verify::due_ids(client, now, limit).await?
    } else {
        Vec::new()
    };
    let magic = if include_magic {
        magic_link_request::due_ids(client, now, limit).await?
    } else {
        Vec::new()
    };
    let mut old = old.into_iter();
    let mut password = password.into_iter();
    let mut security = security.into_iter();
    let mut reset = reset.into_iter();
    let mut verify = verify.into_iter();
    let mut magic = magic.into_iter();
    let mut jobs = Vec::new();
    while jobs.len() < limit as usize {
        let before = jobs.len();
        if let Some(id) = password.next() {
            jobs.push(MailJob::PasswordChanged(id));
        }
        if jobs.len() < limit as usize
            && let Some(id) = security.next()
        {
            jobs.push(MailJob::Security(id));
        }
        if jobs.len() < limit as usize
            && let Some(id) = reset.next()
        {
            jobs.push(MailJob::PasswordReset(id));
        }
        if jobs.len() < limit as usize
            && let Some(id) = verify.next()
        {
            jobs.push(MailJob::EmailVerify(id));
        }
        if jobs.len() < limit as usize
            && let Some(id) = magic.next()
        {
            jobs.push(MailJob::MagicLink(id));
        }
        if jobs.len() < limit as usize
            && let Some(id) = old.next()
        {
            jobs.push(MailJob::NewDevice(id));
        }
        if jobs.len() == before {
            break;
        }
    }
    Ok(jobs)
}

async fn claim(client: &Client, id: i64, now: SystemTime) -> Result<Option<String>> {
    let token = format!("{:032x}", rand::random::<u128>());
    let token_for_tx = token.clone();
    let lease_until = now.checked_add(LEASE).context("lease overflow")?;
    let claimed = retry_known_abort(|| {
        let token_for_tx = token_for_tx.clone();
        async move {
            client
                .query_client()
                .retry_tx(closure!([token_for_tx], async |tx: &mut Transaction| {
                    claim_tx(tx, id, now, lease_until, token_for_tx).await
                }))
                .with_mode(TxMode::SerializableReadWrite)
                .idempotent(false)
                .timeout(Duration::from_secs(10))
                .await
        }
    })
    .await?;
    Ok(claimed.then_some(token))
}

async fn claim_tx(
    tx: &mut Transaction,
    id: i64,
    now: SystemTime,
    lease_until: SystemTime,
    token: &str,
) -> ydb::YdbResultWithCustomerErr<bool> {
    let mut rows = tx
        .query("SELECT status, next_attempt_at, lease_until FROM accounts_newdevicemailoutbox WHERE event_id = $id")
        .param("$id", id)
        .await?;
    let mut available = false;
    while let Some(set) = rows.next_result_set().await? {
        for mut row in set {
            let status: String = row.remove_field_by_name("status")?.try_into()?;
            let next: SystemTime = row.remove_field_by_name("next_attempt_at")?.try_into()?;
            let lease: Option<SystemTime> = row.remove_field_by_name("lease_until")?.try_into()?;
            available =
                status == "pending" && next <= now && lease.is_none_or(|until| until <= now);
        }
    }
    rows.close().await?;
    if !available {
        return Ok(false);
    }
    tx.exec("UPDATE accounts_newdevicemailoutbox SET claim_token = $token, lease_until = CAST($lease AS Datetime), attempts = attempts + 1 WHERE event_id = $id")
        .param("$token", token.to_owned())
        .param("$lease", lease_until)
        .param("$id", id)
        .await?;
    Ok(true)
}

async fn alert(client: &Client, id: i64) -> Result<Option<Alert>> {
    let mut event = client
        .query_client()
        .query_row("SELECT user_id, ip_address, user_agent FROM accounts_loginevent WHERE id = $id")
        .param("$id", id)
        .await?;
    let user_id: i32 = event.remove_field_by_name("user_id")?.try_into()?;
    let ip: Option<String> = event.remove_field_by_name("ip_address")?.try_into()?;
    let user_agent: String = event.remove_field_by_name("user_agent")?.try_into()?;
    let mut account = client
        .query_client()
        .query_row("SELECT is_active, email FROM auth_user WHERE id = $id")
        .param("$id", user_id)
        .await?;
    let active: bool = account.remove_field_by_name("is_active")?.try_into()?;
    let fallback_email: String = account.remove_field_by_name("email")?.try_into()?;
    if !active {
        return Ok(None);
    }
    let mut deletion = client.query_client().query_row(
        "SELECT COUNT(*) AS count FROM accounts_accountdeletionrequest VIEW accounts_accountdeletionrequest_user_id_6a166c52 WHERE user_id = $id AND status != 'canceled'"
    ).param("$id", user_id).await?;
    let deletion_count: u64 = deletion.remove_field_by_name("count")?.try_into()?;
    if deletion_count > 0 {
        return Ok(None);
    }
    let mut query_client = client.query_client();
    let mut primary = query_client.query(
        "SELECT email FROM account_emailaddress VIEW account_emailaddress_user_id_2c513194 WHERE user_id = $id AND primary = true LIMIT 1"
    ).param("$id", user_id).await?;
    let mut recipient = None;
    while let Some(set) = primary.next_result_set().await? {
        for mut row in set {
            recipient = Some(row.remove_field_by_name("email")?.try_into()?);
        }
    }
    primary.close().await?;
    let recipient: String = recipient.unwrap_or(fallback_email);
    if recipient.is_empty() {
        return Ok(None);
    }
    Ok(Some(Alert {
        recipient,
        ip,
        user_agent,
    }))
}

async fn finish(
    client: &Client,
    id: i64,
    token: &str,
    now: SystemTime,
    state: &str,
) -> Result<bool> {
    let token = token.to_owned();
    let state = state.to_owned();
    let next = now
        .checked_add(Duration::from_secs(60))
        .context("retry overflow")?;
    retry_known_abort(|| {
        let token = token.clone();
        let state = state.clone();
        async move {
            client
                .query_client()
                .retry_tx(closure!([token, state], async |tx: &mut Transaction| {
                    finish_tx(tx, id, token, now, next, state).await
                }))
                .with_mode(TxMode::SerializableReadWrite)
                .idempotent(false)
                .timeout(Duration::from_secs(10))
                .await
        }
    })
    .await
    .context("finalize new-device mail claim")
}

async fn finish_tx(
    tx: &mut Transaction,
    id: i64,
    token: &str,
    now: SystemTime,
    next: SystemTime,
    state: &str,
) -> ydb::YdbResultWithCustomerErr<bool> {
    let mut row = tx
        .query_row("SELECT claim_token FROM accounts_newdevicemailoutbox WHERE event_id = $id")
        .param("$id", id)
        .await?;
    let current: String = row.remove_field_by_name("claim_token")?.try_into()?;
    if current != token {
        return Ok(false);
    }
    tx.exec("UPDATE accounts_newdevicemailoutbox SET status = $state, claim_token = '', lease_until = NULL, sent_at = CASE WHEN $state = 'sent' THEN CAST($now AS Datetime) ELSE NULL END, next_attempt_at = CAST($next AS Datetime) WHERE event_id = $id")
        .param("$state", state.to_owned())
        .param("$now", now)
        .param("$next", next)
        .param("$id", id)
        .await?;
    Ok(true)
}

/// Process at most `limit` due alerts. A separate scheduler may invoke this
/// one-shot worker; notification of fresh rows is not yet wired to YMQ.
pub async fn drain_once(client: &Client, limit: u64) -> Result<DrainResult> {
    if limit == 0 || limit > 100 {
        bail!("mail batch size must be between 1 and 100");
    }
    let (mailer, from) = smtp_from_env()?;
    let reset = ResetMailConfig::from_env()?;
    let verify = VerifyMailConfig::from_env()?;
    let magic = MagicMailConfig::from_env()?;
    if let Some(config) = &magic {
        magic_link_request::cleanup_expired(client, config.secret(), SystemTime::now(), limit)
            .await?;
    }
    if reset.is_some() {
        password_reset::cleanup_expired(client, SystemTime::now(), limit).await?;
    }
    if verify.is_some() {
        crate::email_change::cleanup_expired(client, SystemTime::now(), limit).await?;
        email_verify::cleanup_expired(client, SystemTime::now(), limit).await?;
    }
    drain_with_transport(
        client,
        limit,
        &mailer,
        &from,
        reset.as_ref(),
        verify.as_ref(),
        magic.as_ref(),
    )
    .await
}

async fn drain_with_transport(
    client: &Client,
    limit: u64,
    mailer: &AsyncSmtpTransport<Tokio1Executor>,
    from: &Mailbox,
    reset: Option<&ResetMailConfig>,
    verify: Option<&VerifyMailConfig>,
    magic: Option<&MagicMailConfig>,
) -> Result<DrainResult> {
    if limit == 0 || limit > 100 {
        bail!("mail batch size must be between 1 and 100");
    }
    let mut result = DrainResult::default();
    for job in due_jobs(
        client,
        limit,
        reset.is_some(),
        verify.is_some(),
        magic.is_some(),
    )
    .await?
    {
        result.add(match job {
            MailJob::NewDevice(id) => process_one(client, id, mailer, from).await?,
            MailJob::PasswordChanged(id) => {
                password_mail::process_one(client, &id, mailer, from).await?
            }
            MailJob::Security(id) => security_mail::process_one(client, &id, mailer, from).await?,
            MailJob::PasswordReset(id) => {
                password_reset::process_one(
                    client,
                    &id,
                    reset.context("password reset mail disabled")?,
                    mailer,
                    from,
                )
                .await?
            }
            MailJob::EmailVerify(id) => {
                email_verify::process_one(
                    client,
                    &id,
                    verify.context("email verification mail disabled")?,
                    mailer,
                    from,
                )
                .await?
            }
            MailJob::MagicLink(id) => {
                magic_link_request::process_one(
                    client,
                    &id,
                    magic.context("magic-link mail disabled")?,
                    mailer,
                    from,
                )
                .await?
            }
        });
    }
    Ok(result)
}

async fn process_one(
    client: &Client,
    id: i64,
    mailer: &AsyncSmtpTransport<Tokio1Executor>,
    from: &Mailbox,
) -> Result<DrainResult> {
    let mut result = DrainResult::default();
    let Some(token) = claim(client, id, SystemTime::now()).await? else {
        return Ok(result);
    };
    result.claimed = 1;
    match alert(client, id).await {
        Ok(Some(payload)) => {
            let delivered = match render(&payload, from) {
                Ok(message) => tokio::time::timeout(SMTP_TIMEOUT, mailer.send(message))
                    .await
                    .is_ok_and(|outcome| outcome.is_ok()),
                Err(_) => false,
            };
            if delivered {
                if finish(client, id, &token, SystemTime::now(), "sent").await? {
                    result.sent = 1;
                }
            } else if finish(client, id, &token, SystemTime::now(), "pending").await? {
                result.deferred = 1;
            }
        }
        Ok(None) => {
            if finish(client, id, &token, SystemTime::now(), "cancelled").await? {
                result.cancelled = 1;
            }
        }
        Err(_) => {
            if finish(client, id, &token, SystemTime::now(), "pending").await? {
                result.deferred = 1;
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
        routing::post,
    };
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tower::ServiceExt;

    #[test]
    fn render_matches_legacy_alert() -> Result<()> {
        let from: Mailbox = "no-reply@example.invalid".parse()?;
        let alert = Alert {
            recipient: "person@example.invalid".into(),
            ip: Some("192.0.2.5".into()),
            user_agent: "Browser/1".into(),
        };
        let message = render(&alert, &from)?;
        let raw = String::from_utf8(message.formatted())?;
        assert!(raw.contains("Новый вход в аккаунт") || raw.contains("=?utf-8?"));
        assert!(raw.contains("person@example.invalid"));
        assert!(raw.contains("192.0.2.5"));
        assert!(raw.contains("Browser/1"));
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires migrated local /local YDB; verifies that the dedicated timer leaves new-device alerts untouched"]
    async fn verification_recovery_isolated_from_security_alerts() -> Result<()> {
        anyhow::ensure!(
            matches!(
                env::var("YDB_ENDPOINT")?.as_str(),
                "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
            ) && env::var("YDB_DATABASE")? == "/local",
            "verification recovery test requires local YDB"
        );
        let client = Arc::new(crate::connect_ydb().await?);
        email_verify::ensure_schema(&client).await?;
        let id = uuid::Uuid::new_v4().to_string();
        let alert_id = (rand::random::<u64>() & ((1u64 << 62) - 1)) as i64;
        let now = SystemTime::now();
        // Sort this fixture before any other due verification in a shared CI YDB.
        let due = SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_000);
        let expires = now + Duration::from_secs(3600);
        client.query_client().exec("INSERT INTO id_email_verification (id, user_id, recipient, expires_at, status, attempts, next_attempt_at, claim_token, created_at) VALUES ($id, -1, 'missing@example.invalid', CAST($expires AS Datetime), 'pending', 0, CAST($due AS Datetime), '', CAST($now AS Datetime))")
            .param("$id", id.clone()).param("$expires", expires).param("$due", due).param("$now", now).await?;
        client.query_client().exec("INSERT INTO accounts_newdevicemailoutbox (event_id, status, attempts, next_attempt_at, claim_token, created_at) VALUES ($id, 'pending', 0, CAST($now AS Datetime), '', CAST($now AS Datetime))")
            .param("$id", alert_id).param("$now", now).await?;
        let result: Result<()> = async {
            let worker = MailWorker {
                client: client.clone(),
                export: None,
                export_mail: None,
                escrow_cleanup_enabled: false,
                #[cfg(feature = "passkeys")]
                media: None,
                mailer: AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("127.0.0.1")
                    .port(9).build(),
                from: "no-reply@example.invalid".parse()?,
                publisher: None,
                reset: None,
                verify: Some(VerifyMailConfig::new(
                    email_verify::VerifyKey::new([7; 32])?,
                    "http://localhost/verify-email",
                )?),
            };
            let drained = worker.drain_due_verifications(1).await?;
            anyhow::ensure!(drained.claimed == 1 && drained.cancelled == 1);
            let mut alert = client.query_client().query_row(
                "SELECT status, attempts, claim_token FROM accounts_newdevicemailoutbox WHERE event_id = $id"
            ).param("$id", alert_id).await?;
            let status: String = alert.remove_field_by_name("status")?.try_into()?;
            let attempts: i32 = alert.remove_field_by_name("attempts")?.try_into()?;
            let claim_token: String = alert.remove_field_by_name("claim_token")?.try_into()?;
            anyhow::ensure!(status == "pending" && attempts == 0 && claim_token.is_empty(),
                "verification timer touched a security alert");
            Ok(())
        }.await;
        client
            .query_client()
            .exec("DELETE FROM id_email_verification WHERE id = $id")
            .param("$id", id)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM accounts_newdevicemailoutbox WHERE event_id = $id")
            .param("$id", alert_id)
            .await?;
        result
    }

    #[tokio::test]
    #[ignore = "requires migrated local /local YDB; reset recovery must leave security alerts untouched"]
    async fn reset_recovery_isolated_from_security_alerts() -> Result<()> {
        anyhow::ensure!(
            matches!(
                env::var("YDB_ENDPOINT")?.as_str(),
                "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
            ) && env::var("YDB_DATABASE")? == "/local",
            "reset recovery test requires local YDB"
        );
        let client = Arc::new(crate::connect_ydb().await?);
        password_reset::ensure_schema(&client).await?;
        let id = uuid::Uuid::new_v4().to_string();
        let alert_id = (rand::random::<u64>() & ((1u64 << 62) - 1)) as i64;
        let now = SystemTime::now();
        let due = SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_000);
        let expires = now + Duration::from_secs(3600);
        client.query_client().exec("INSERT INTO id_password_reset (id, user_id, recipient, password_version, expires_at, status, attempts, next_attempt_at, claim_token, created_at) VALUES ($id, -1, 'missing@example.invalid', '', CAST($expires AS Datetime), 'pending', 0, CAST($due AS Datetime), '', CAST($now AS Datetime))")
            .param("$id", id.clone()).param("$expires", expires).param("$due", due).param("$now", now).await?;
        client.query_client().exec("INSERT INTO accounts_newdevicemailoutbox (event_id, status, attempts, next_attempt_at, claim_token, created_at) VALUES ($id, 'pending', 0, CAST($now AS Datetime), '', CAST($now AS Datetime))")
            .param("$id", alert_id).param("$now", now).await?;
        let result: Result<()> = async {
            let worker = MailWorker {
                client: client.clone(),
                export: None,
                export_mail: None,
                escrow_cleanup_enabled: false,
                #[cfg(feature = "passkeys")]
                media: None,
                mailer: AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("127.0.0.1")
                    .port(9).build(),
                from: "no-reply@example.invalid".parse()?,
                publisher: None,
                reset: Some(ResetMailConfig::new(
                    password_reset::ResetKey::new([9; 32])?,
                    "http://localhost/reset-password",
                )?),
                verify: None,
            };
            let drained = worker.drain_due_password_resets(1).await?;
            anyhow::ensure!(drained.claimed == 1 && drained.cancelled == 1);
            let mut alert = client.query_client().query_row(
                "SELECT status, attempts, claim_token FROM accounts_newdevicemailoutbox WHERE event_id = $id"
            ).param("$id", alert_id).await?;
            let status: String = alert.remove_field_by_name("status")?.try_into()?;
            let attempts: i32 = alert.remove_field_by_name("attempts")?.try_into()?;
            let claim_token: String = alert.remove_field_by_name("claim_token")?.try_into()?;
            anyhow::ensure!(status == "pending" && attempts == 0 && claim_token.is_empty(),
                "reset timer touched a security alert");
            Ok(())
        }.await;
        client
            .query_client()
            .exec("DELETE FROM id_password_reset WHERE id = $id")
            .param("$id", id)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM accounts_newdevicemailoutbox WHERE event_id = $id")
            .param("$id", alert_id)
            .await?;
        result
    }

    #[tokio::test]
    #[ignore = "requires migrated local /local YDB; password-change recovery must leave unrelated mail untouched"]
    async fn password_change_recovery_isolated_from_other_mail() -> Result<()> {
        anyhow::ensure!(
            matches!(
                env::var("YDB_ENDPOINT")?.as_str(),
                "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
            ) && env::var("YDB_DATABASE")? == "/local",
            "password-change recovery test requires local YDB"
        );
        let client = Arc::new(crate::connect_ydb().await?);
        password_mail::ensure_schema(&client).await?;
        let id = uuid::Uuid::new_v4().to_string();
        let other_id = (rand::random::<u64>() & ((1u64 << 62) - 1)) as i64;
        let now = SystemTime::now();
        let due = SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_000);
        client.query_client().exec("INSERT INTO id_password_mail (id, user_id, recipient, status, attempts, next_attempt_at, claim_token, created_at) VALUES ($id, -1, 'missing@example.invalid', 'pending', 0, CAST($due AS Datetime), '', CAST($now AS Datetime))")
            .param("$id", id.clone()).param("$due", due).param("$now", now).await?;
        client.query_client().exec("INSERT INTO accounts_newdevicemailoutbox (event_id, status, attempts, next_attempt_at, claim_token, created_at) VALUES ($id, 'pending', 0, CAST($now AS Datetime), '', CAST($now AS Datetime))")
            .param("$id", other_id).param("$now", now).await?;
        let result: Result<()> = async {
            let worker = MailWorker {
                client: client.clone(),
                export: None,
                export_mail: None,
                escrow_cleanup_enabled: false,
                #[cfg(feature = "passkeys")]
                media: None,
                mailer: AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("127.0.0.1")
                    .port(9).build(),
                from: "no-reply@example.invalid".parse()?,
                publisher: None,
                reset: None,
                verify: None,
            };
            let drained = worker.drain_due_password_changes(1).await?;
            anyhow::ensure!(drained.claimed == 1 && drained.cancelled == 1);
            let mut other = client.query_client().query_row(
                "SELECT status, attempts, claim_token FROM accounts_newdevicemailoutbox WHERE event_id = $id"
            ).param("$id", other_id).await?;
            let status: String = other.remove_field_by_name("status")?.try_into()?;
            let attempts: i32 = other.remove_field_by_name("attempts")?.try_into()?;
            let claim_token: String = other.remove_field_by_name("claim_token")?.try_into()?;
            anyhow::ensure!(status == "pending" && attempts == 0 && claim_token.is_empty(),
                "password-change timer touched unrelated mail");
            Ok(())
        }.await;
        client
            .query_client()
            .exec("DELETE FROM id_password_mail WHERE id = $id")
            .param("$id", id)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM accounts_newdevicemailoutbox WHERE event_id = $id")
            .param("$id", other_id)
            .await?;
        result
    }

    #[tokio::test]
    #[ignore = "requires migrated local /local YDB; creates and removes one synthetic outbox row"]
    async fn two_clients_claim_once_and_retry_after_failure() -> Result<()> {
        anyhow::ensure!(
            matches!(
                env::var("YDB_ENDPOINT")?.as_str(),
                "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
            ) && env::var("YDB_DATABASE")? == "/local",
            "mail claim test requires local YDB"
        );
        let first = Arc::new(crate::connect_ydb().await?);
        let second = Arc::new(crate::connect_ydb().await?);
        let id = (rand::random::<u64>() & ((1u64 << 62) - 1)) as i64;
        // Keep this claim fixture out of the concurrent timer scan test.
        let now = SystemTime::now()
            .checked_add(Duration::from_secs(3600))
            .context("clock overflow")?;
        first.query_client().exec("INSERT INTO accounts_newdevicemailoutbox (event_id, status, attempts, next_attempt_at, claim_token, created_at) VALUES ($id, 'pending', 0, CAST($now AS Datetime), '', CAST($now AS Datetime))")
            .param("$id", id).param("$now", now).await?;
        let result: Result<()> = async {
            anyhow::ensure!(due_ids(&first, now, 100).await?.contains(&id));
            let mut tasks = tokio::task::JoinSet::new();
            for index in 0..100 {
                let client = if index % 2 == 0 { first.clone() } else { second.clone() };
                tasks.spawn(async move { claim(&client, id, now).await });
            }
            let mut winners = Vec::new();
            while let Some(outcome) = tasks.join_next().await {
                if let Some(token) = outcome?? { winners.push(token); }
            }
            anyhow::ensure!(winners.len() == 1, "one mail intent had {} winners", winners.len());
            let token = &winners[0];
            anyhow::ensure!(!finish(&second, id, "stale-claim", now, "sent").await?);
            anyhow::ensure!(finish(&first, id, token, now, "pending").await?);
            anyhow::ensure!(!finish(&second, id, token, now, "sent").await?);
            let later = now.checked_add(Duration::from_secs(61)).context("clock overflow")?;
            let retry = claim(&second, id, later).await?.context("retry was not claimable")?;
            anyhow::ensure!(finish(&second, id, &retry, later, "sent").await?);
            anyhow::ensure!(claim(&first, id, later).await?.is_none());
            let mut row = first.query_client().query_row(
                "SELECT status, attempts, claim_token FROM accounts_newdevicemailoutbox WHERE event_id = $id"
            ).param("$id", id).await?;
            let status: String = row.remove_field_by_name("status")?.try_into()?;
            let attempts: i32 = row.remove_field_by_name("attempts")?.try_into()?;
            let claim_token: String = row.remove_field_by_name("claim_token")?.try_into()?;
            anyhow::ensure!(status == "sent" && attempts == 2 && claim_token.is_empty());
            Ok(())
        }.await;
        first
            .query_client()
            .exec("DELETE FROM accounts_newdevicemailoutbox WHERE event_id = $id")
            .param("$id", id)
            .await?;
        result
    }

    #[tokio::test]
    #[ignore = "requires migrated local /local YDB; sends one synthetic alert to a loopback SMTP fixture"]
    async fn drains_success_and_defers_smtp_rejection() -> Result<()> {
        anyhow::ensure!(
            matches!(
                env::var("YDB_ENDPOINT")?.as_str(),
                "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
            ) && env::var("YDB_DATABASE")? == "/local",
            "SMTP fixture test requires local YDB"
        );
        let client = Arc::new(crate::connect_ydb().await?);
        crate::password_mail::ensure_schema(&client).await?;
        crate::security_mail::ensure_schema(&client).await?;
        let stamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_micros();
        let account_id = -i32::try_from(stamp % 1_000_000_000 + 1)?;
        let event_id = (rand::random::<u64>() & ((1u64 << 62) - 1)) as i64;
        let now = SystemTime::now();
        let recipient = format!("mail-test-{stamp}@example.invalid");
        client.query_client().exec("INSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, '', true, $name, '', '', $email, false, false, CAST($now AS Datetime))")
            .param("$id", account_id).param("$name", format!("mail-test-{stamp}"))
            .param("$email", recipient.clone()).param("$now", now).await?;
        let result: Result<()> = async {
            client.query_client().exec("INSERT INTO accounts_loginevent (id, user_id, status, ip_address, ip_hash, user_agent, device_id, location, is_new_device, reason, meta, created_at) VALUES ($id, $user_id, 'success', '192.0.2.5', '', 'Browser/1', '', '', true, '', Unwrap(CAST('{}' AS Json)), CAST($now AS Datetime))")
                .param("$id", event_id).param("$user_id", account_id).param("$now", now).await?;
            client.query_client().exec("INSERT INTO accounts_newdevicemailoutbox (event_id, status, attempts, next_attempt_at, claim_token, created_at) VALUES ($id, 'pending', 0, CAST($now AS Datetime), '', CAST($now AS Datetime))")
                .param("$id", event_id).param("$now", now).await?;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let port = listener.local_addr()?.port();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await?;
                let mut io = BufReader::new(stream);
                io.get_mut().write_all(b"220 localhost ESMTP\r\n").await?;
                let mut body = String::new();
                loop {
                    let mut line = String::new();
                    if io.read_line(&mut line).await? == 0 { bail!("SMTP client disconnected"); }
                    if line.starts_with("DATA") {
                        io.get_mut().write_all(b"354 send data\r\n").await?;
                        loop {
                            line.clear();
                            if io.read_line(&mut line).await? == 0 { bail!("SMTP body truncated"); }
                            if line == ".\r\n" { break; }
                            body.push_str(&line);
                        }
                        io.get_mut().write_all(b"250 queued\r\n").await?;
                        return Ok::<String, anyhow::Error>(body);
                    }
                    io.get_mut().write_all(b"250 ok\r\n").await?;
                }
            });
            let from: Mailbox = "no-reply@example.invalid".parse()?;
            let mailer = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("127.0.0.1")
                .port(port).timeout(Some(Duration::from_secs(5))).build();
            let queue_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let queue_port = queue_listener.local_addr()?.port();
            let (queue_sender, mut queue_receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
            let queue_app = axum::Router::new().route("/", post(move |body: axum::body::Bytes| {
                let sender = queue_sender.clone();
                async move {
                    let _ = sender.send(body.to_vec()).await;
                    "<SendMessageResponse><SendMessageResult><MessageId>local-test</MessageId></SendMessageResult></SendMessageResponse>"
                }
            }));
            let queue_server = tokio::spawn(async move { axum::serve(queue_listener, queue_app).await });
            let endpoint = format!("http://127.0.0.1:{queue_port}/");
            let queue_url = format!("http://127.0.0.1:{queue_port}/mail-test");
            let publisher = Arc::new(YmqPublisher::new(&endpoint, &queue_url,
                "test-access".into(), "test-secret".into())?);
            let app = crate::jobs_http::router(Arc::new(MailWorker {
                client: client.clone(), export: None, export_mail: None, escrow_cleanup_enabled: false, #[cfg(feature = "passkeys")] media: None, mailer, from: from.clone(), publisher: Some(publisher), reset: None, verify: None,
            }));
            let ready = app.clone().oneshot(Request::builder().uri("/readyz").body(Body::empty())?).await?;
            anyhow::ensure!(ready.status() == StatusCode::OK, "job is not ready with local YDB");
            let timer_body = serde_json::json!({"messages":[{"event_metadata":{"event_type":"yandex.cloud.events.serverless.triggers.TimerMessage"},"details":{"payload":""}}]});
            let request = Request::builder().method("POST").uri("/internal/jobs/publish")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(timer_body.to_string()))?;
            let response = app.clone().oneshot(request).await?;
            anyhow::ensure!(response.status() == StatusCode::OK, "mail publish timer failed");
            let queue_body = tokio::time::timeout(Duration::from_secs(5), queue_receiver.recv()).await?
                .context("mail publish timer sent no queue message")?;
            let parameters: std::collections::HashMap<_, _> =
                url::form_urlencoded::parse(&queue_body).into_owned().collect();
            let intent: serde_json::Value = serde_json::from_str(parameters.get("MessageBody")
                .context("mail queue message has no body")?)?;
            anyhow::ensure!(intent["event_id"] == event_id && intent["kind"] == "new_device_mail");
            queue_server.abort();
            let request = Request::builder().method("POST").uri("/internal/jobs/recover")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(timer_body.to_string()))?;
            let response = app.oneshot(request).await?;
            anyhow::ensure!(response.status() == StatusCode::OK, "timer invocation failed");
            let body = tokio::time::timeout(Duration::from_secs(5), server).await???;
            anyhow::ensure!(body.contains("Browser/1") && body.contains("192.0.2.5"));
            let mut row = client.query_client().query_row("SELECT status, attempts, sent_at FROM accounts_newdevicemailoutbox WHERE event_id = $id")
                .param("$id", event_id).await?;
            let status: String = row.remove_field_by_name("status")?.try_into()?;
            let attempts: i32 = row.remove_field_by_name("attempts")?.try_into()?;
            let sent_at: Option<SystemTime> = row.remove_field_by_name("sent_at")?.try_into()?;
            anyhow::ensure!(status == "sent" && attempts == 1 && sent_at.is_some());

            let rejected_id = event_id + 1;
            client.query_client().exec("INSERT INTO accounts_loginevent (id, user_id, status, ip_address, ip_hash, user_agent, device_id, location, is_new_device, reason, meta, created_at) VALUES ($id, $user_id, 'success', '192.0.2.6', '', 'Browser/2', '', '', true, '', Unwrap(CAST('{}' AS Json)), CAST($now AS Datetime))")
                .param("$id", rejected_id).param("$user_id", account_id).param("$now", now).await?;
            client.query_client().exec("INSERT INTO accounts_newdevicemailoutbox (event_id, status, attempts, next_attempt_at, claim_token, created_at) VALUES ($id, 'pending', 0, CAST($now AS Datetime), '', CAST($now AS Datetime))")
                .param("$id", rejected_id).param("$now", now).await?;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let port = listener.local_addr()?.port();
            let rejection_server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await?;
                let mut io = BufReader::new(stream);
                io.get_mut().write_all(b"220 localhost ESMTP\r\n").await?;
                loop {
                    let mut line = String::new();
                    if io.read_line(&mut line).await? == 0 { bail!("SMTP client disconnected"); }
                    if line.starts_with("DATA") {
                        io.get_mut().write_all(b"450 retry later\r\n").await?;
                        return Ok::<(), anyhow::Error>(());
                    }
                    io.get_mut().write_all(b"250 ok\r\n").await?;
                }
            });
            let mailer = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("127.0.0.1")
                .port(port).timeout(Some(Duration::from_secs(5))).build();
            let app = crate::jobs_http::router(Arc::new(MailWorker {
                client: client.clone(), export: None, export_mail: None, escrow_cleanup_enabled: false, #[cfg(feature = "passkeys")] media: None, mailer, from: from.clone(), publisher: None, reset: None, verify: None,
            }));
            let queue_body = serde_json::json!({"messages":[{"event_metadata":{"event_type":"yandex.cloud.events.messagequeue.QueueMessage"},"details":{"message":{"body":serde_json::json!({"version":1,"kind":"new_device_mail","event_id":rejected_id}).to_string()}}}]});
            let request = Request::builder().method("POST").uri("/internal/jobs/mail")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(queue_body.to_string()))?;
            let response = app.oneshot(request).await?;
            anyhow::ensure!(response.status() == StatusCode::SERVICE_UNAVAILABLE,
                "SMTP rejection must ask YMQ to retry");
            tokio::time::timeout(Duration::from_secs(5), rejection_server).await???;
            let mut row = client.query_client().query_row("SELECT status, attempts, sent_at, next_attempt_at FROM accounts_newdevicemailoutbox WHERE event_id = $id")
                .param("$id", rejected_id).await?;
            let status: String = row.remove_field_by_name("status")?.try_into()?;
            let attempts: i32 = row.remove_field_by_name("attempts")?.try_into()?;
            let sent_at: Option<SystemTime> = row.remove_field_by_name("sent_at")?.try_into()?;
            let next: SystemTime = row.remove_field_by_name("next_attempt_at")?.try_into()?;
            anyhow::ensure!(status == "pending" && attempts == 1 && sent_at.is_none());
            anyhow::ensure!(next > SystemTime::now());
            Ok(())
        }.await;
        client
            .query_client()
            .exec("DELETE FROM accounts_newdevicemailoutbox WHERE event_id = $id")
            .param("$id", event_id + 1)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM accounts_loginevent WHERE id = $id")
            .param("$id", event_id + 1)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM accounts_newdevicemailoutbox WHERE event_id = $id")
            .param("$id", event_id)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM accounts_loginevent WHERE id = $id")
            .param("$id", event_id)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM auth_user WHERE id = $id")
            .param("$id", account_id)
            .await?;
        result
    }
}
