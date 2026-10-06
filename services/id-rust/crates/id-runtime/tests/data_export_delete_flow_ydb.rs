//! Public export and deletion requests must preserve an accepted archive.

use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    routing::any,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use id_compat::session::SessionCodec;
use id_runtime::{
    account_deletion::AccountDeletion,
    account_deletion_cleanup, account_deletion_finalize,
    account_deletion_http::{AccountDeletionHttpConfig, router as deletion_router},
    cache_store::CacheStore,
    data_export_escrow::{self, ExportEscrowKey},
    data_export_http::{ExportHttpConfig, ExportHttpSettings, router as export_router},
    data_export_mail, data_export_operation,
    data_export_s3::S3Export,
};
use std::{
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tower::ServiceExt;
use uuid::Uuid;

struct JobsProcess(Child);

impl Drop for JobsProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
#[ignore = "requires sealed disposable local YDB on port 2137"]
async fn accepted_export_survives_http_deletion_and_redeems_after_cooldown() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2137" | "grpc://127.0.0.1:2137"
        ) && std::env::var("YDB_DATABASE")? == "/local"
            && std::env::var("ID_DISPOSABLE_YDB").as_deref() == Ok("true"),
        "test requires explicitly disposable local YDB on port 2137"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    ensure!(
        id_runtime::legacy_cutover_reset::is_sealed(&client).await?,
        "legacy cutover must be sealed before the export/deletion rehearsal"
    );
    client.query_client().exec("CREATE TABLE IF NOT EXISTS id_shared_cache (cache_key Utf8 NOT NULL, value String, expires_at Uint64, PRIMARY KEY (cache_key))").await?;
    data_export_operation::ensure_schema(&client).await?;
    data_export_escrow::ensure_schema(&client).await?;
    data_export_mail::ensure_schema(&client).await?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let owner = i32::try_from(stamp % 800_000_000 + 100_000_000)?;
    let identity = Uuid::new_v4();
    let password = "synthetic-export-delete-password";
    let hash = id_compat::password::hash_new(password)?;
    client.query_client().exec("INSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $hash, true, 'export-delete', '', '', 'export-delete@example.invalid', false, false, CurrentUtcDatetime())")
        .param("$id", owner).param("$hash", hash.clone()).await?;
    client.query_client().exec("INSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, 'export-delete', '', 'export-delete@example.invalid', true, 'active', false, CurrentUtcDatetime())")
        .param("$id", identity).await?;
    client.query_client().exec("INSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($owner, $identity, $subject, CurrentUtcDatetime())")
        .param("$owner", owner).param("$identity", identity)
        .param("$subject", format!("export-delete-{stamp}")).await?;
    client.query_client().exec("INSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($id, $owner, 'export-delete@example.invalid', true, true)")
        .param("$id", owner + 1).param("$owner", owner).await?;

    let codec = Arc::new(SessionCodec::new(
        b"synthetic-export-delete-session-secret",
        &[],
    )?);
    let now = SystemTime::now();
    let session = format!("{stamp:032x}");
    let payload = serde_json::json!({
        "_auth_user_id": owner.to_string(),
        "_auth_user_backend": "accounts.backends.EmailBackend",
        "_auth_user_hash": codec.auth_hash(&hash)?,
    });
    let encoded = codec.encode(
        payload.as_object().context("session payload")?,
        i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?,
        true,
    )?;
    client.query_client().exec("INSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, $data, CAST($expiry AS Datetime))")
        .param("$key", session.clone()).param("$data", encoded)
        .param("$expiry", now + Duration::from_secs(3600)).await?;
    client.query_client().exec("INSERT INTO core_usersessionmeta (id, user_id, session_key, user_agent, first_seen, revoked_reason) VALUES ($id, $owner, $key, 'export-delete-test', CurrentUtcDatetime(), '')")
        .param("$id", i64::from(owner)).param("$owner", owner).param("$key", session.clone()).await?;

    let (sender, mut receiver) = tokio::sync::mpsc::channel::<String>(2);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let s3 = Router::new().fallback(any(move |request: Request<Body>| {
        let sender = sender.clone();
        async move {
            match *request.method() {
                axum::http::Method::PUT => {
                    let Ok(body) = to_bytes(request.into_body(), 1024 * 1024).await else {
                        return (StatusCode::PAYLOAD_TOO_LARGE, String::new());
                    };
                    if sender.send(String::from_utf8_lossy(&body).to_string()).await.is_err() {
                        return (StatusCode::SERVICE_UNAVAILABLE, String::new());
                    }
                    (StatusCode::OK, String::new())
                }
                axum::http::Method::GET => {
                    (StatusCode::OK, format!("<ListBucketResult><Name>private-exports</Name><Prefix>exports/user_{owner}/</Prefix><IsTruncated>false</IsTruncated></ListBucketResult>"))
                }
                _ => (StatusCode::METHOD_NOT_ALLOWED, String::new()),
            }
        }
    }));
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, s3).await;
    });
    let real_s3 = std::env::var("ID_EXPORT_TEST_REAL_S3").as_deref() == Ok("true");
    let s3_endpoint = if real_s3 {
        let endpoint = std::env::var("S3_ENDPOINT_URL")?;
        ensure!(
            endpoint.trim_end_matches('/') == "https://storage.yandexcloud.net",
            "real S3 rehearsal requires Yandex Object Storage"
        );
        endpoint
    } else {
        format!("http://127.0.0.1:{port}/")
    };
    let s3_bucket = if real_s3 {
        std::env::var("ID_EXPORT_S3_BUCKET_NAME")?
    } else {
        "private-exports".into()
    };
    let s3_access_key = if real_s3 {
        std::env::var("S3_ACCESS_KEY_ID")?
    } else {
        "synthetic-key".into()
    };
    let s3_secret_key = if real_s3 {
        std::env::var("S3_SECRET_ACCESS_KEY")?
    } else {
        "synthetic-secret".into()
    };
    let storage = S3Export::new(
        &s3_endpoint,
        &s3_bucket,
        "ru-central1",
        s3_access_key.clone(),
        s3_secret_key.clone(),
    )?;
    let cache = CacheStore::new(client.clone(), "id_shared_cache", "", 1)?;
    let escrow_key = ExportEscrowKey::from_base64(&STANDARD.encode([0x61; 32]))?;
    let http_storage = S3Export::new(
        &s3_endpoint,
        &s3_bucket,
        "ru-central1",
        s3_access_key.clone(),
        s3_secret_key.clone(),
    )?;
    let export = export_router(Arc::new(ExportHttpConfig::new(
        client.clone(),
        codec.clone(),
        http_storage,
        ExportHttpSettings {
            operation_key: vec![0x62; 32],
            cache: cache.clone(),
            seal_key: None,
            escrow_key: Some(Arc::new(escrow_key.clone())),
            session_cookie_name: "sessionid".into(),
            csrf_cookie_name: "csrftoken".into(),
            trusted_origins: vec!["http://id.localhost".into()],
        },
    )?));
    let created = export
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/data/exports")
                .header("x-session-token", &session)
                .header("idempotency-key", format!("export-{stamp}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(r#"{{"password":"{password}"}}"#)))?,
        )
        .await?;
    ensure!(
        created.status() == StatusCode::ACCEPTED,
        "export request rejected: {}",
        created.status()
    );
    let receipt: serde_json::Value =
        serde_json::from_slice(&to_bytes(created.into_body(), 4096).await?)?;
    let id = receipt["id"]
        .as_str()
        .context("export operation ID")?
        .to_owned();
    ensure!(receipt["status"] == "pending_delayed" && receipt["release_at"].is_string());
    let release = data_export_escrow::release_at(&client, &id, owner)
        .await?
        .context("accepted export release time")?;
    ensure!(
        data_export_mail::due_ids(&client, SystemTime::now(), 10)
            .await?
            .contains(&format!("{id}:notice"))
    );

    // A second request exercises the public owner cancellation route without
    // changing the export that must survive the following account deletion.
    let cancellable = export
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/data/exports")
                .header("x-session-token", &session)
                .header("idempotency-key", format!("cancel-export-{stamp}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(r#"{{"password":"{password}"}}"#)))?,
        )
        .await?;
    ensure!(cancellable.status() == StatusCode::ACCEPTED);
    let cancellable_receipt: serde_json::Value =
        serde_json::from_slice(&to_bytes(cancellable.into_body(), 4096).await?)?;
    let cancelled_id = cancellable_receipt["id"]
        .as_str()
        .context("cancellable export ID")?
        .to_owned();
    let csrf_rejected = export
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/auth/data/exports/{cancelled_id}"))
                .header("cookie", format!("sessionid={session}"))
                .body(Body::empty())?,
        )
        .await?;
    ensure!(csrf_rejected.status() == StatusCode::FORBIDDEN);
    let cancelled = export
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/auth/data/exports/{cancelled_id}"))
                .header("x-session-token", &session)
                .body(Body::empty())?,
        )
        .await?;
    ensure!(cancelled.status() == StatusCode::ACCEPTED);
    let cancelled_body: serde_json::Value =
        serde_json::from_slice(&to_bytes(cancelled.into_body(), 4096).await?)?;
    ensure!(cancelled_body["status"] == "cancelled" && cancelled_body["cleanup_pending"] == false);
    ensure!(
        data_export_escrow::release_at(&client, &cancelled_id, owner)
            .await?
            .is_none()
    );
    ensure!(
        data_export_escrow::release_at(&client, &id, owner)
            .await?
            .is_some()
    );

    let deletion = AccountDeletion::new(
        client.clone(),
        codec.clone(),
        cache,
        None,
        b"synthetic-export-delete-operation-key-min-32",
        2,
    )?;
    let delete = deletion_router(Arc::new(AccountDeletionHttpConfig::new(
        deletion,
        "sessionid".into(),
        "csrftoken".into(),
        vec!["http://id.localhost".into()],
    )?));
    let deleted = delete
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/account/deletions")
                .header("x-session-token", &session)
                .header("idempotency-key", format!("delete-{stamp}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(r#"{{"password":"{password}"}}"#)))?,
        )
        .await?;
    ensure!(
        deleted.status() == StatusCode::ACCEPTED,
        "deletion request rejected: {}",
        deleted.status()
    );
    let deletion_receipt: serde_json::Value =
        serde_json::from_slice(&to_bytes(deleted.into_body(), 4096).await?)?;
    let deletion_id: i64 = deletion_receipt["id"]
        .as_str()
        .context("deletion operation ID")?
        .parse()?;
    let credential_stage = account_deletion_cleanup::erase_credentials(&client, deletion_id)
        .await?
        .context("deletion credential job lost request")?;
    ensure!(credential_stage.credential_stage_completed && !credential_stage.cleanup_completed);
    ensure!(
        account_deletion_cleanup::erase_avatar(&client, None, deletion_id)
            .await?
            .is_none(),
        "avatar stage passed an unsealed export"
    );
    ensure!(
        !id_runtime::data_export_job::clean_owner(&client, &storage, owner, 100).await?,
        "deletion passed an unsealed export"
    );
    let timer = std::net::TcpListener::bind("127.0.0.1:0")?;
    let jobs_port = timer.local_addr()?.port();
    drop(timer);
    let jobs = JobsProcess(
        Command::new(env!("CARGO_BIN_EXE_id-jobs"))
            .args(["--serve"])
            .env("PORT", jobs_port.to_string())
            .env("ID_JOBS_HTTP_ENABLED", "true")
            .env("ID_EXPORT_JOBS_ENABLED", "true")
            .env("ID_EXPORT_ESCROW_JOBS_PILOT_ENABLED", "false")
            .env("ID_EXPORT_ESCROW_JOBS_ROLLOUT_ENABLED", "false")
            .env("ID_EXPORT_ESCROW_MAIL_PILOT_ENABLED", "false")
            .env("ID_EXPORT_ESCROW_MAIL_ROLLOUT_ENABLED", "false")
            .env("MEDIA_STORAGE_DRIVER", "local")
            .env("S3_ENDPOINT_URL", &s3_endpoint)
            .env("S3_REGION", "ru-central1")
            .env("S3_ACCESS_KEY_ID", &s3_access_key)
            .env("S3_SECRET_ACCESS_KEY", &s3_secret_key)
            .env("ID_EXPORT_S3_BUCKET_NAME", &s3_bucket)
            .env("EMAIL_HOST", "127.0.0.1")
            .env("EMAIL_USE_TLS", "false")
            .env("DEFAULT_FROM_EMAIL", "no-reply@example.invalid")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let jobs_http = reqwest::Client::new();
    let jobs_origin = format!("http://127.0.0.1:{jobs_port}");
    let mut ready = false;
    for _ in 0..100 {
        if let Ok(response) = jobs_http.get(format!("{jobs_origin}/healthz")).send().await
            && response.status().is_success()
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    ensure!(ready, "private jobs HTTP process did not start");
    let timer_event = serde_json::json!({"messages":[{
        "event_metadata":{"event_type":"yandex.cloud.events.serverless.triggers.TimerMessage"},
        "details":{"payload":""}
    }]});
    let queue_event = serde_json::json!({"messages":[{
        "event_metadata":{"event_type":"yandex.cloud.events.messagequeue.QueueMessage"},
        "details":{}
    }]});
    let rejected = jobs_http
        .post(format!("{jobs_origin}/internal/jobs/recover-export"))
        .json(&queue_event)
        .send()
        .await?;
    ensure!(rejected.status().as_u16() == StatusCode::BAD_REQUEST.as_u16());
    let recovered = jobs_http
        .post(format!("{jobs_origin}/internal/jobs/recover-export"))
        .json(&timer_event)
        .send()
        .await?;
    ensure!(
        recovered.status().is_success(),
        "private export timer rejected snapshot: {}",
        recovered.status()
    );
    let report: serde_json::Value = recovered.json().await?;
    ensure!(
        report["exports_completed"] == 1 && report["exports_deferred"] == 0,
        "private timer did not seal deleted account's snapshot: {report}"
    );
    let replay: serde_json::Value = jobs_http
        .post(format!("{jobs_origin}/internal/jobs/recover-export"))
        .json(&timer_event)
        .send()
        .await?
        .json()
        .await?;
    ensure!(
        replay["exports_completed"] == 0 && replay["exports_deferred"] == 0,
        "replayed timer attempted a second snapshot: {replay}"
    );
    drop(jobs);
    if !real_s3 {
        let archive = receiver.recv().await.context("no archive uploaded")?;
        ensure!(archive.contains("export-delete-") && !archive.contains(&hash));
    }
    ensure!(
        account_deletion_cleanup::erase_avatar(&client, None, deletion_id)
            .await?
            .is_some_and(|result| result.avatar_removed),
        "avatar job did not resume after snapshot seal"
    );
    ensure!(
        id_runtime::data_export_job::clean_owner(&client, &storage, owner, 100).await?,
        "deletion could not detach sealed export"
    );
    ensure!(
        account_deletion_cleanup::erase_profile_history(&client, deletion_id)
            .await?
            .is_some_and(|result| result.profile_history_removed),
        "profile job did not resume after export detachment"
    );
    ensure!(
        client
            .query_client()
            .query_row("SELECT session_key FROM django_session WHERE session_key = $key")
            .param("$key", session.clone())
            .optional()
            .await?
            .is_none(),
        "profile job retained the revoked Django session"
    );
    ensure!(account_deletion_cleanup::complete_global_pass(&client, deletion_id).await?);
    let finalization = account_deletion_finalize::drain_pending(&client, 10).await?;
    ensure!(
        finalization.attempted == 1 && finalization.completed == 1 && finalization.deferred == 0,
        "finalization timer did not erase account: {finalization:?}"
    );
    let completed = id_runtime::account_deletion::read_status(&client, deletion_id)
        .await?
        .context("deletion receipt missing after finalization")?;
    ensure!(completed.status == "succeeded" && completed.cleanup_completed);
    ensure!(
        client
            .query_client()
            .query_row("SELECT id FROM auth_user WHERE id = $id")
            .param("$id", owner)
            .optional()
            .await?
            .is_none()
    );
    ensure!(
        client
            .query_client()
            .query_row("SELECT user_id FROM usid_user WHERE user_id = $id")
            .param("$id", identity)
            .optional()
            .await?
            .is_none(),
        "finalizer retained master identity"
    );
    let mut delivery = client
        .query_client()
        .query_row("SELECT state FROM id_data_export_mail WHERE id = $id")
        .param("$id", format!("{id}:delivery"))
        .await?;
    let delivery_state: String = delivery.remove_field_by_name("state")?.try_into()?;
    ensure!(
        delivery_state == "pending",
        "deletion discarded the timed delivery intent"
    );

    let capability = escrow_key.capability(&id)?;
    ensure!(
        data_export_escrow::downloadable_key(
            &client,
            &escrow_key,
            &id,
            &capability,
            release - Duration::from_secs(1)
        )
        .await?
        .is_none()
    );
    ensure!(
        data_export_escrow::downloadable_key(&client, &escrow_key, &id, &capability, release)
            .await?
            .is_some()
    );
    // Advance only this synthetic request's clock, then exercise the public
    // bearer endpoint after its owner session has been revoked.
    let due = SystemTime::now() - Duration::from_secs(1);
    client
        .query_client()
        .exec("UPDATE id_data_export_escrow SET release_at = CAST($due AS Datetime) WHERE id = $id")
        .param("$due", due)
        .param("$id", id.clone())
        .await?;
    client.query_client().exec("UPDATE id_data_export_mail SET next_attempt_at = CAST($due AS Datetime) WHERE id = $id")
        .param("$due", due).param("$id", format!("{id}:delivery")).await?;
    let smtp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let smtp_port = smtp_listener.local_addr()?.port();
    let smtp = tokio::spawn(accept_smtp_mail(smtp_listener, 2));
    let mail_timer = std::net::TcpListener::bind("127.0.0.1:0")?;
    let mail_jobs_port = mail_timer.local_addr()?.port();
    drop(mail_timer);
    let mail_jobs = JobsProcess(
        Command::new(env!("CARGO_BIN_EXE_id-jobs"))
            .args(["--serve"])
            .env("PORT", mail_jobs_port.to_string())
            .env("ID_JOBS_HTTP_ENABLED", "true")
            .env("ID_EXPORT_JOBS_ENABLED", "true")
            .env("ID_EXPORT_ESCROW_JOBS_PILOT_ENABLED", "false")
            .env("ID_EXPORT_ESCROW_JOBS_ROLLOUT_ENABLED", "false")
            .env("ID_EXPORT_ESCROW_MAIL_PILOT_ENABLED", "true")
            .env("ID_EXPORT_ESCROW_MAIL_ROLLOUT_ENABLED", "false")
            .env("ID_EXPORT_ESCROW_KEY", STANDARD.encode([0x61; 32]))
            .env("ID_EXPORT_PUBLIC_ORIGIN", "http://localhost:8080/")
            .env("DJANGO_DEBUG", "true")
            .env("MEDIA_STORAGE_DRIVER", "local")
            .env("S3_ENDPOINT_URL", &s3_endpoint)
            .env("S3_REGION", "ru-central1")
            .env("S3_ACCESS_KEY_ID", &s3_access_key)
            .env("S3_SECRET_ACCESS_KEY", &s3_secret_key)
            .env("ID_EXPORT_S3_BUCKET_NAME", &s3_bucket)
            .env("EMAIL_HOST", "127.0.0.1")
            .env("EMAIL_PORT", smtp_port.to_string())
            .env("EMAIL_USE_TLS", "false")
            .env("DEFAULT_FROM_EMAIL", "no-reply@example.invalid")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let mail_origin = format!("http://127.0.0.1:{mail_jobs_port}");
    let mut mail_ready = false;
    for _ in 0..100 {
        if let Ok(response) = jobs_http.get(format!("{mail_origin}/healthz")).send().await
            && response.status().is_success()
        {
            mail_ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    ensure!(mail_ready, "private mail jobs HTTP process did not start");
    let mailed = jobs_http
        .post(format!("{mail_origin}/internal/jobs/recover-export"))
        .json(&timer_event)
        .send()
        .await?;
    ensure!(
        mailed.status().is_success(),
        "private mail timer rejected delivery"
    );
    let mail_report: serde_json::Value = mailed.json().await?;
    ensure!(
        mail_report["mail_sent"] == 2 && mail_report["mail_deferred"] == 0,
        "private timer did not deliver both export mails: {mail_report}"
    );
    let mail_bodies = tokio::time::timeout(Duration::from_secs(5), smtp).await???;
    drop(mail_jobs);
    let delivery_body = mail_bodies
        .iter()
        .find(|body| body.contains("data/export") && body.contains(&id))
        .context("timed delivery mail missing")?;
    ensure!(
        delivery_body.contains("data/export") && delivery_body.contains(&id),
        "timed mail omitted the deleted account's archive link"
    );
    let mut sent = client
        .query_client()
        .query_row("SELECT state FROM id_data_export_mail WHERE id = $id")
        .param("$id", format!("{id}:delivery"))
        .await?;
    let sent_state: String = sent.remove_field_by_name("state")?.try_into()?;
    ensure!(sent_state == "sent", "delivery intent could be sent twice");
    let redeemed = export
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/auth/data/exports/{id}/redeem"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({"token": capability}).to_string(),
                ))?,
        )
        .await?;
    ensure!(
        redeemed.status() == StatusCode::OK,
        "bearer redemption failed after deletion"
    );
    let download: serde_json::Value =
        serde_json::from_slice(&to_bytes(redeemed.into_body(), 4096).await?)?;
    ensure!(
        download["download_url"]
            .as_str()
            .is_some_and(|url| url.contains("exports/escrow/") && !url.contains(&capability))
    );
    if real_s3 {
        let url = download["download_url"]
            .as_str()
            .context("signed real S3 download URL")?;
        let fetched = jobs_http.get(url).send().await?;
        ensure!(
            fetched.status().is_success(),
            "real S3 archive download failed"
        );
        let archive = fetched.text().await?;
        ensure!(archive.contains("export-delete-") && !archive.contains(&hash));
        let object_key = data_export_escrow::downloadable_key(
            &client,
            &escrow_key,
            &id,
            &capability,
            SystemTime::now(),
        )
        .await?
        .context("real S3 escrow object key")?;
        storage.delete_object(&object_key).await?;
        let deleted = jobs_http.get(url).send().await?;
        ensure!(
            deleted.status().as_u16() == 404,
            "deleted real S3 archive remained readable"
        );
    }

    server.abort();
    client
        .query_client()
        .exec("DELETE FROM id_data_export_operation WHERE id = $id")
        .param("$id", id.clone())
        .await?;
    client
        .query_client()
        .exec("DELETE FROM id_data_export_escrow WHERE id = $id")
        .param("$id", id.clone())
        .await?;
    for kind in ["notice", "delivery"] {
        client
            .query_client()
            .exec("DELETE FROM id_data_export_mail WHERE id = $id")
            .param("$id", format!("{id}:{kind}"))
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM accounts_accountdeletionrequest WHERE id = $id")
        .param("$id", deletion_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM id_data_export_escrow WHERE id = $id")
        .param("$id", cancelled_id.clone())
        .await?;
    client
        .query_client()
        .exec("DELETE FROM id_data_export_operation WHERE id = $id")
        .param("$id", cancelled_id.clone())
        .await?;
    for kind in ["notice", "delivery"] {
        client
            .query_client()
            .exec("DELETE FROM id_data_export_mail WHERE id = $id")
            .param("$id", format!("{cancelled_id}:{kind}"))
            .await?;
    }
    Ok(())
}

async fn accept_smtp_mail(listener: tokio::net::TcpListener, count: usize) -> Result<Vec<String>> {
    let mut messages = Vec::new();
    for _ in 0..count {
        let (stream, _) = listener.accept().await?;
        let mut io = BufReader::new(stream);
        io.get_mut().write_all(b"220 localhost ESMTP\r\n").await?;
        let mut body = String::new();
        loop {
            let mut line = String::new();
            if io.read_line(&mut line).await? == 0 {
                anyhow::bail!("SMTP client disconnected");
            }
            if line.starts_with("DATA") {
                io.get_mut().write_all(b"354 send data\r\n").await?;
                loop {
                    line.clear();
                    if io.read_line(&mut line).await? == 0 {
                        anyhow::bail!("SMTP body truncated");
                    }
                    if line == ".\r\n" {
                        break;
                    }
                    body.push_str(&line);
                }
                io.get_mut().write_all(b"250 queued\r\n").await?;
                messages.push(body);
                break;
            }
            io.get_mut().write_all(b"250 ok\r\n").await?;
        }
    }
    Ok(messages)
}
