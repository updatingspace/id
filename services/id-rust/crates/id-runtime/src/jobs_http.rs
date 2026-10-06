//! Private Serverless Containers entrypoints for YMQ wakeups and timer recovery.
//! Invocation authorization belongs to the container IAM binding; these routes
//! must never be included in the public ID API Gateway.

use crate::{
    gravatar_job::GravatarJob,
    new_device_mail::{DrainResult, MailJob, MailWorker},
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

const TIMER_EVENT: &str = "yandex.cloud.events.serverless.triggers.TimerMessage";
const QUEUE_EVENT: &str = "yandex.cloud.events.messagequeue.QueueMessage";
// Ten serial SMTP attempts at 30s each stay below the 600s container timeout.
const MAX_MESSAGES: usize = 10;

#[derive(Deserialize)]
struct TriggerBatch {
    messages: Vec<TriggerMessage>,
}

#[derive(Deserialize)]
struct TriggerMessage {
    event_metadata: EventMetadata,
    details: Value,
}

#[derive(Deserialize)]
struct EventMetadata {
    event_type: String,
}

#[derive(Deserialize)]
struct MailIntent {
    version: u8,
    kind: String,
    event_id: Value,
}

fn checked_batch(body: &[u8], kind: &str) -> Result<TriggerBatch, &'static str> {
    let batch: TriggerBatch = serde_json::from_slice(body).map_err(|_| "invalid trigger JSON")?;
    if batch.messages.is_empty() || batch.messages.len() > MAX_MESSAGES {
        return Err("trigger batch must contain 1..10 messages");
    }
    if batch
        .messages
        .iter()
        .any(|message| message.event_metadata.event_type != kind)
    {
        return Err("unexpected trigger event type");
    }
    Ok(batch)
}

fn queue_jobs(body: &[u8]) -> Result<Vec<MailJob>, &'static str> {
    let batch = checked_batch(body, QUEUE_EVENT)?;
    batch
        .messages
        .into_iter()
        .map(|event| {
            let value = event
                .details
                .get("message")
                .and_then(|message| message.get("body"))
                .and_then(Value::as_str)
                .ok_or("missing queue body")?;
            let intent: MailIntent =
                serde_json::from_str(value).map_err(|_| "invalid queue intent")?;
            if intent.version != 1 {
                return Err("unsupported queue intent");
            }
            match intent.kind.as_str() {
                "new_device_mail" => intent
                    .event_id
                    .as_i64()
                    .filter(|id| *id > 0)
                    .map(MailJob::NewDevice)
                    .ok_or("invalid new-device event ID"),
                "password_changed_mail" => intent
                    .event_id
                    .as_str()
                    .filter(|id| uuid::Uuid::parse_str(id).is_ok())
                    .map(|id| MailJob::PasswordChanged(id.to_owned()))
                    .ok_or("invalid password-change event ID"),
                "security_mail" => intent
                    .event_id
                    .as_str()
                    .filter(|id| uuid::Uuid::parse_str(id).is_ok())
                    .map(|id| MailJob::Security(id.to_owned()))
                    .ok_or("invalid security mail event ID"),
                "password_reset_mail" => intent
                    .event_id
                    .as_str()
                    .filter(|id| uuid::Uuid::parse_str(id).is_ok())
                    .map(|id| MailJob::PasswordReset(id.to_owned()))
                    .ok_or("invalid password-reset event ID"),
                "email_verify_mail" => intent
                    .event_id
                    .as_str()
                    .filter(|id| uuid::Uuid::parse_str(id).is_ok())
                    .map(|id| MailJob::EmailVerify(id.to_owned()))
                    .ok_or("invalid email-verification event ID"),
                "magic_link_mail" => intent
                    .event_id
                    .as_str()
                    .filter(|id| uuid::Uuid::parse_str(id).is_ok())
                    .map(|id| MailJob::MagicLink(id.to_owned()))
                    .ok_or("invalid magic-link event ID"),
                _ => Err("unsupported queue intent"),
            }
        })
        .collect()
}

fn timer_batch(body: &[u8]) -> Result<(), &'static str> {
    checked_batch(body, TIMER_EVENT).map(|_| ())
}

fn response(status: StatusCode, body: Value) -> impl IntoResponse {
    (status, [(header::CACHE_CONTROL, "no-store")], Json(body))
}

fn outcome(result: anyhow::Result<DrainResult>) -> impl IntoResponse {
    match result {
        Ok(result) => {
            let status = if result.deferred > 0 {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::OK
            };
            response(
                status,
                json!({"claimed": result.claimed, "sent": result.sent,
                "deferred": result.deferred, "cancelled": result.cancelled}),
            )
        }
        Err(_) => {
            tracing::error!("private mail job failed");
            response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"JOB_UNAVAILABLE"}),
            )
        }
    }
}

async fn queue(
    State(worker): State<Arc<MailWorker>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    match queue_jobs(&body) {
        Ok(jobs) => outcome(worker.drain_jobs(&jobs).await).into_response(),
        Err(reason) => response(StatusCode::BAD_REQUEST, json!({"error":reason})).into_response(),
    }
}

async fn recover(
    State(worker): State<Arc<MailWorker>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    match timer_batch(&body) {
        Ok(()) => {
            #[cfg(feature = "passkeys")]
            {
                // These stages share YDB progress tables. Running their schema
                // checks concurrently can defer otherwise ready operations.
                let mail = worker.drain_due(10).await;
                let deletions = worker.drain_pending_deletions(10).await;
                let avatars = worker.drain_pending_avatars(10).await;
                let profiles = worker.drain_pending_profiles(10).await;
                let globals = worker.drain_pending_globals(10).await;
                let finalizations = worker.drain_pending_finalizations(10).await;
                let exports = worker.drain_due_exports(1).await;
                let export_mails = worker.drain_due_export_mails(10).await;
                let expired_exports = worker.drain_expired_exports(10).await;
                match (
                    mail,
                    deletions,
                    avatars,
                    profiles,
                    globals,
                    finalizations,
                    exports,
                    export_mails,
                    expired_exports,
                ) {
                    (
                        Ok(mail),
                        Ok(deletions),
                        Ok(avatars),
                        Ok(profiles),
                        Ok(globals),
                        Ok(finalizations),
                        Ok(exports),
                        Ok(export_mails),
                        Ok(expired_exports),
                    ) => {
                        let status = if mail.deferred > 0
                            || deletions.deferred > 0
                            || avatars.deferred > 0
                            || profiles.deferred > 0
                            || globals.deferred > 0
                            || finalizations.deferred > 0
                            || exports.deferred > 0
                            || export_mails.deferred > 0
                            || expired_exports.deferred > 0
                        {
                            StatusCode::SERVICE_UNAVAILABLE
                        } else {
                            StatusCode::OK
                        };
                        response(
                            status,
                            json!({"claimed": mail.claimed, "sent": mail.sent,
                            "deferred": mail.deferred, "cancelled": mail.cancelled,
                            "deletions_attempted": deletions.attempted,
                            "deletions_completed": deletions.completed,
                            "deletions_deferred": deletions.deferred,
                            "avatars_attempted": avatars.attempted,
                            "avatars_completed": avatars.completed,
                            "avatars_deferred": avatars.deferred,
                            "profiles_attempted": profiles.attempted,
                            "profiles_completed": profiles.completed,
                            "profiles_deferred": profiles.deferred,
                            "globals_attempted": globals.attempted,
                            "globals_completed": globals.completed,
                            "globals_deferred": globals.deferred,
                            "finalizations_attempted": finalizations.attempted,
                            "finalizations_completed": finalizations.completed,
                            "finalizations_deferred": finalizations.deferred,
                            "exports_attempted": exports.attempted,
                            "exports_completed": exports.completed,
                            "exports_deferred": exports.deferred,
                            "export_mail_claimed": export_mails.claimed,
                            "export_mail_sent": export_mails.sent,
                            "export_mail_deferred": export_mails.deferred,
                            "expired_exports_attempted": expired_exports.attempted,
                            "expired_exports_completed": expired_exports.completed,
                            "expired_exports_deferred": expired_exports.deferred}),
                        )
                        .into_response()
                    }
                    _ => {
                        tracing::error!("private jobs recovery failed");
                        response(
                            StatusCode::SERVICE_UNAVAILABLE,
                            json!({"error":"JOB_UNAVAILABLE"}),
                        )
                        .into_response()
                    }
                }
            }
            #[cfg(not(feature = "passkeys"))]
            outcome(worker.drain_due(10).await).into_response()
        }
        Err(reason) => response(StatusCode::BAD_REQUEST, json!({"error":reason})).into_response(),
    }
}

/// Recover security mail without starting account deletion or export work.
async fn recover_mail(
    State(worker): State<Arc<MailWorker>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    match timer_batch(&body) {
        Ok(()) => outcome(worker.drain_due(10).await).into_response(),
        Err(reason) => response(StatusCode::BAD_REQUEST, json!({"error":reason})).into_response(),
    }
}

/// Recover only private exports and their expiry, without touching mail or deletion.
async fn recover_export(
    State(worker): State<Arc<MailWorker>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    if let Err(reason) = timer_batch(&body) {
        return response(StatusCode::BAD_REQUEST, json!({"error":reason})).into_response();
    }
    if !worker.exports_enabled() {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"EXPORT_JOB_DISABLED"}),
        )
        .into_response();
    }
    let due = worker.drain_due_exports(1).await;
    let mail = worker.drain_due_export_mails(10).await;
    let expired = worker.drain_expired_exports(10).await;
    match (due, mail, expired) {
        (Ok(due), Ok(mail), Ok(expired)) => response(
            if due.deferred > 0 || mail.deferred > 0 || expired.deferred > 0 {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::OK
            },
            json!({
                "exports_attempted":due.attempted,
                "exports_completed":due.completed,
                "exports_deferred":due.deferred,
                "mail_claimed":mail.claimed,
                "mail_sent":mail.sent,
                "mail_deferred":mail.deferred,
                "expired_attempted":expired.attempted,
                "expired_completed":expired.completed,
                "expired_deferred":expired.deferred,
            }),
        )
        .into_response(),
        _ => {
            tracing::error!("private export recovery failed");
            response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"JOB_UNAVAILABLE"}),
            )
            .into_response()
        }
    }
}

/// Recover verification links without touching pre-existing security alerts.
async fn recover_verify_mail(
    State(worker): State<Arc<MailWorker>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    match timer_batch(&body) {
        Ok(()) => outcome(worker.drain_due_verifications(10).await).into_response(),
        Err(reason) => response(StatusCode::BAD_REQUEST, json!({"error":reason})).into_response(),
    }
}

/// Recover reset links without draining unrelated security notifications.
async fn recover_reset_mail(
    State(worker): State<Arc<MailWorker>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    match timer_batch(&body) {
        Ok(()) => outcome(worker.drain_due_password_resets(10).await).into_response(),
        Err(reason) => response(StatusCode::BAD_REQUEST, json!({"error":reason})).into_response(),
    }
}

/// Recover password-change notices without touching reset or security mail.
async fn recover_password_mail(
    State(worker): State<Arc<MailWorker>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    match timer_batch(&body) {
        Ok(()) => outcome(worker.drain_due_password_changes(10).await).into_response(),
        Err(reason) => response(StatusCode::BAD_REQUEST, json!({"error":reason})).into_response(),
    }
}

/// Recover passkey-removal notices without dispatching other mail intents.
async fn recover_security_mail(
    State(worker): State<Arc<MailWorker>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    match timer_batch(&body) {
        Ok(()) => outcome(worker.drain_due_security(10).await).into_response(),
        Err(reason) => response(StatusCode::BAD_REQUEST, json!({"error":reason})).into_response(),
    }
}

async fn publish(
    State(worker): State<Arc<MailWorker>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    match timer_batch(&body) {
        Ok(()) => match worker.publish_due(100).await {
            Ok(published) => {
                response(StatusCode::OK, json!({"published":published})).into_response()
            }
            Err(_) => {
                tracing::error!("private mail queue publish failed");
                response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    json!({"error":"JOB_UNAVAILABLE"}),
                )
                .into_response()
            }
        },
        Err(reason) => response(StatusCode::BAD_REQUEST, json!({"error":reason})).into_response(),
    }
}

pub fn router(worker: Arc<MailWorker>) -> Router {
    Router::new()
        .route(
            "/healthz",
            get(|| async { response(StatusCode::OK, json!({"status":"ok"})) }),
        )
        .route(
            "/readyz",
            get(|State(worker): State<Arc<MailWorker>>| async move {
                let ready = worker.ready().await;
                response(
                    if ready {
                        StatusCode::OK
                    } else {
                        StatusCode::SERVICE_UNAVAILABLE
                    },
                    json!({"ready": ready}),
                )
            }),
        )
        .route("/internal/jobs/mail", post(queue))
        .route("/internal/jobs/recover-mail", post(recover_mail))
        .route("/internal/jobs/recover-export", post(recover_export))
        .route(
            "/internal/jobs/recover-verify-mail",
            post(recover_verify_mail),
        )
        .route(
            "/internal/jobs/recover-reset-mail",
            post(recover_reset_mail),
        )
        .route(
            "/internal/jobs/recover-password-mail",
            post(recover_password_mail),
        )
        .route(
            "/internal/jobs/recover-security-mail",
            post(recover_security_mail),
        )
        .route("/internal/jobs/publish", post(publish))
        .route("/internal/jobs/recover", post(recover))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(worker)
}

/// Separate private timer route. It never starts mail or deletion recovery.
pub fn gravatar_router(job: Arc<GravatarJob>, limit: usize) -> Router {
    Router::new()
        .route(
            "/refresh-gravatars",
            post(move |State(job): State<Arc<GravatarJob>>| async move {
                match job.run(limit).await {
                    Ok(report) if report.failed == 0 => {
                        response(StatusCode::OK, json!(report)).into_response()
                    }
                    Ok(report) => {
                        response(StatusCode::SERVICE_UNAVAILABLE, json!(report)).into_response()
                    }
                    Err(_) => {
                        tracing::error!("private Gravatar job failed");
                        response(
                            StatusCode::SERVICE_UNAVAILABLE,
                            json!({"error":"JOB_UNAVAILABLE"}),
                        )
                        .into_response()
                    }
                }
            }),
        )
        .with_state(job)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_batch_requires_versioned_intents_and_known_event_type() {
        let valid = json!({"messages":[{"event_metadata":{"event_type":QUEUE_EVENT},
            "details":{"message":{"body":"{\"version\":1,\"kind\":\"new_device_mail\",\"event_id\":42}"}}}]});
        assert_eq!(
            queue_jobs(valid.to_string().as_bytes()),
            Ok(vec![MailJob::NewDevice(42)])
        );
        let mut invalid = valid;
        invalid["messages"][0]["details"]["message"]["body"] =
            json!("{\"version\":2,\"kind\":\"new_device_mail\",\"event_id\":42}");
        assert!(queue_jobs(invalid.to_string().as_bytes()).is_err());
        invalid["messages"][0]["event_metadata"]["event_type"] = json!(TIMER_EVENT);
        assert!(queue_jobs(invalid.to_string().as_bytes()).is_err());
        let password = json!({"messages":[{"event_metadata":{"event_type":QUEUE_EVENT},
            "details":{"message":{"body":json!({"version":1,"kind":"password_changed_mail",
                "event_id":"123e4567-e89b-42d3-a456-426614174000"}).to_string()}}}]});
        assert_eq!(
            queue_jobs(password.to_string().as_bytes()),
            Ok(vec![MailJob::PasswordChanged(
                "123e4567-e89b-42d3-a456-426614174000".into()
            )])
        );
        let reset = json!({"messages":[{"event_metadata":{"event_type":QUEUE_EVENT},
            "details":{"message":{"body":json!({"version":1,"kind":"password_reset_mail",
                "event_id":"123e4567-e89b-42d3-a456-426614174000"}).to_string()}}}]});
        assert_eq!(
            queue_jobs(reset.to_string().as_bytes()),
            Ok(vec![MailJob::PasswordReset(
                "123e4567-e89b-42d3-a456-426614174000".into()
            )])
        );
        let verify = json!({"messages":[{"event_metadata":{"event_type":QUEUE_EVENT},
            "details":{"message":{"body":json!({"version":1,"kind":"email_verify_mail",
                "event_id":"123e4567-e89b-42d3-a456-426614174000"}).to_string()}}}]});
        assert_eq!(
            queue_jobs(verify.to_string().as_bytes()),
            Ok(vec![MailJob::EmailVerify(
                "123e4567-e89b-42d3-a456-426614174000".into()
            )])
        );
        let magic = json!({"messages":[{"event_metadata":{"event_type":QUEUE_EVENT},
            "details":{"message":{"body":json!({"version":1,"kind":"magic_link_mail",
                "event_id":"123e4567-e89b-42d3-a456-426614174000"}).to_string()}}}]});
        assert_eq!(
            queue_jobs(magic.to_string().as_bytes()),
            Ok(vec![MailJob::MagicLink(
                "123e4567-e89b-42d3-a456-426614174000".into()
            )])
        );
        let security = json!({"messages":[{"event_metadata":{"event_type":QUEUE_EVENT},
            "details":{"message":{"body":json!({"version":1,"kind":"security_mail",
                "event_id":"123e4567-e89b-42d3-a456-426614174000"}).to_string()}}}]});
        assert_eq!(
            queue_jobs(security.to_string().as_bytes()),
            Ok(vec![MailJob::Security(
                "123e4567-e89b-42d3-a456-426614174000".into()
            )])
        );
    }

    #[test]
    fn timer_rejects_queue_and_empty_batches() {
        let timer = json!({"messages":[{"event_metadata":{"event_type":TIMER_EVENT},"details":{"payload":""}}]});
        assert_eq!(timer_batch(timer.to_string().as_bytes()), Ok(()));
        assert!(timer_batch(b"{\"messages\":[]}").is_err());
        let queue =
            json!({"messages":[{"event_metadata":{"event_type":QUEUE_EVENT},"details":{}}]});
        assert!(timer_batch(queue.to_string().as_bytes()).is_err());
    }
}
