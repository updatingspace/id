//! Durable export operation behavior on disposable local YDB.

use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    routing::any,
};
use id_compat::session::SessionCodec;
use id_runtime::data_export_operation::{
    claim, complete, due_ids, ensure_schema, read_owned, request,
};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires disposable local /local YDB with frozen legacy schema"]
async fn idempotent_owner_operation_and_two_client_fencing() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "test requires local YDB"
    );
    let first = Arc::new(id_runtime::connect_ydb().await?);
    let second = Arc::new(id_runtime::connect_ydb().await?);
    ensure_schema(&first).await?;
    ensure_schema(&second).await?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let account_id = i32::try_from(stamp % 800_000_000 + 100_000_000)?;
    let identity = Uuid::new_v4();
    let password_hash = id_compat::password::hash_new("export-test-password")?;
    first.query_client().exec("INSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $hash, true, 'export-operation', '', '', 'operation@example.invalid', false, false, CurrentUtcDatetime())")
        .param("$id", account_id).param("$hash", password_hash.clone()).await?;
    first.query_client().exec("INSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, 'export-operation', '', 'operation@example.invalid', true, 'active', false, CurrentUtcDatetime())")
        .param("$id", identity).await?;
    first.query_client().exec("INSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($user, $identity, 'export-operation-subject', CurrentUtcDatetime())")
        .param("$user", account_id).param("$identity", identity).await?;

    let key = format!("op{stamp}");
    let secret = [7u8; 32];
    let now = SystemTime::now();
    let operation = request(&first, account_id, &key, &secret, now).await?;
    ensure!(operation.status == "pending");
    ensure!(request(&second, account_id, &key, &secret, now).await?.id == operation.id);
    ensure!(
        read_owned(&first, account_id + 1, &operation.id)
            .await?
            .is_none()
    );
    ensure!(
        read_owned(&first, account_id, &operation.id)
            .await?
            .is_some()
    );
    ensure!(
        due_ids(&first, now + Duration::from_secs(2), 100)
            .await?
            .contains(&operation.id)
    );

    let mut tasks = Vec::new();
    for index in 0..100 {
        let client = if index % 2 == 0 {
            first.clone()
        } else {
            second.clone()
        };
        let id = operation.id.clone();
        tasks.push(tokio::spawn(async move {
            claim(&client, &id, now + Duration::from_secs(2)).await
        }));
    }
    let mut winners = Vec::new();
    for task in tasks {
        if let Some(winner) = task.await?? {
            winners.push(winner);
        }
    }
    ensure!(
        winners.len() == 1,
        "concurrent export claims had {} winners",
        winners.len()
    );
    let stale = winners.remove(0);
    ensure!(
        claim(&first, &operation.id, now + Duration::from_secs(3))
            .await?
            .is_none()
    );
    let reclaimed = claim(&second, &operation.id, now + Duration::from_secs(16 * 60))
        .await?
        .context("expired lease must be reclaimable")?;
    let manifest = serde_json::json!({"format":"updspace-id-ndjson-v1","categories":[]});
    let stale_key = id_runtime::data_export_s3::S3Export::object_key(&stale)?;
    let reclaimed_key = id_runtime::data_export_s3::S3Export::object_key(&reclaimed)?;
    ensure!(!complete(&first, &stale, &stale_key, &manifest, now).await?);
    ensure!(complete(&second, &reclaimed, &reclaimed_key, &manifest, now).await?);
    ensure!(!complete(&second, &reclaimed, &reclaimed_key, &manifest, now).await?);
    let finished = read_owned(&first, account_id, &operation.id)
        .await?
        .context("owner operation")?;
    ensure!(
        finished.status == "succeeded"
            && finished.manifest == Some(manifest)
            && finished.expires_at.is_some()
    );
    ensure!(
        request(&first, account_id, &key, &secret, now)
            .await?
            .status
            == "succeeded"
    );

    let codec = Arc::new(SessionCodec::new(b"synthetic-export-session-secret", &[])?);
    let session = format!("{stamp:032x}");
    let payload = serde_json::json!({
        "_auth_user_id": account_id.to_string(),
        "_auth_user_backend": "accounts.backends.EmailBackend",
        "_auth_user_hash": codec.auth_hash(&password_hash)?,
    });
    let encoded = codec.encode(
        payload.as_object().context("session payload object")?,
        i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?,
        true,
    )?;
    first.query_client().exec("INSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, $data, CAST($expiry AS Datetime))")
        .param("$key", session.clone()).param("$data", encoded)
        .param("$expiry", now + Duration::from_secs(3600)).await?;
    let storage = id_runtime::data_export_s3::S3Export::new(
        "http://127.0.0.1:12345/",
        "private-exports",
        "ru-central1",
        "synthetic-key".into(),
        "synthetic-secret".into(),
    )?;
    let config = id_runtime::data_export_http::ExportHttpConfig::new(
        first.clone(),
        codec.clone(),
        storage,
        id_runtime::data_export_http::ExportHttpSettings {
            operation_key: secret.to_vec(),
            cache: id_runtime::cache_store::CacheStore::new(
                first.clone(),
                "id_shared_cache",
                "",
                1,
            )?,
            seal_key: None,
            escrow_key: None,
            session_cookie_name: "sessionid".into(),
            csrf_cookie_name: "csrftoken".into(),
            trusted_origins: vec!["http://id.localhost".into()],
        },
    )?;
    let app = id_runtime::data_export_http::router(Arc::new(config));
    let created = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/data/exports")
                .header("x-session-token", &session)
                .header("idempotency-key", &key)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"password":"export-test-password"}"#))?,
        )
        .await?;
    ensure!(
        created.status() == StatusCode::ACCEPTED,
        "idempotent HTTP export request failed"
    );
    let created_body: serde_json::Value =
        serde_json::from_slice(&to_bytes(created.into_body(), 4096).await?)?;
    ensure!(created_body["id"] == operation.id && created_body["status"] == "succeeded");
    let reauth_key = format!("fresh{stamp}");
    let wrong_password = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/data/exports")
                .header("x-session-token", &session)
                .header("idempotency-key", &reauth_key)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"password":"wrong-password"}"#))?,
        )
        .await?;
    ensure!(wrong_password.status() == StatusCode::BAD_REQUEST);
    let fresh = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/data/exports")
                .header("x-session-token", &session)
                .header("idempotency-key", &reauth_key)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"password":"export-test-password"}"#))?,
        )
        .await?;
    ensure!(fresh.status() == StatusCode::ACCEPTED);
    let fresh_body: serde_json::Value =
        serde_json::from_slice(&to_bytes(fresh.into_body(), 4096).await?)?;
    ensure!(fresh_body["status"] == "pending");
    let fresh_id = fresh_body["id"]
        .as_str()
        .context("fresh export operation ID")?;
    ensure!(read_owned(&first, account_id, fresh_id).await?.is_some());
    let repeated = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/data/exports")
                .header("x-session-token", &session)
                .header("idempotency-key", &reauth_key)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"password":"export-test-password"}"#))?,
        )
        .await?;
    ensure!(repeated.status() == StatusCode::ACCEPTED);
    let repeated_body: serde_json::Value =
        serde_json::from_slice(&to_bytes(repeated.into_body(), 4096).await?)?;
    ensure!(repeated_body["id"] == fresh_body["id"]);
    let path = format!("/api/v1/auth/data/exports/{}", operation.id);
    let status = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&path)
                .header("x-session-token", &session)
                .body(Body::empty())?,
        )
        .await?;
    ensure!(status.status() == StatusCode::OK);
    let status_body: serde_json::Value =
        serde_json::from_slice(&to_bytes(status.into_body(), 4096).await?)?;
    ensure!(status_body["manifest"]["format"] == "updspace-id-ndjson-v1");
    let download = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("{path}/download"))
                .header("x-session-token", &session)
                .body(Body::empty())?,
        )
        .await?;
    ensure!(download.status() == StatusCode::SEE_OTHER);
    let location = download
        .headers()
        .get(header::LOCATION)
        .context("download location missing")?
        .to_str()?;
    ensure!(location.contains("X-Amz-Expires=60") && location.contains(&reclaimed_key));
    let invalid_header = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&path)
                .header("x-session-token", "invalid")
                .header(header::COOKIE, format!("sessionid={session}"))
                .body(Body::empty())?,
        )
        .await?;
    ensure!(
        invalid_header.status() == StatusCode::UNAUTHORIZED,
        "invalid header fell back to cookie"
    );
    let missing_csrf = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/data/exports")
                .header("idempotency-key", &key)
                .header(header::COOKIE, format!("sessionid={session}"))
                .body(Body::empty())?,
        )
        .await?;
    ensure!(
        missing_csrf.status() == StatusCode::FORBIDDEN,
        "cookie mutation skipped CSRF"
    );
    first.query_client().exec("UPSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $owner, 'recovery_codes', Unwrap(CAST($data AS Json)), CurrentUtcDatetime())")
        .param("$id", i64::from(account_id) * 2 + 1).param("$owner", account_id)
        .param("$data", serde_json::json!({"migrated_codes":["87654321"]}).to_string()).await?;
    let mfa_payload = serde_json::json!({
        "_auth_user_id": account_id.to_string(),
        "_auth_user_backend": "accounts.backends.EmailBackend",
        "_auth_user_hash": codec.auth_hash(&password_hash)?,
        "id_mfa_verified_user_id": account_id.to_string(),
    });
    let mfa_session = codec.encode(
        mfa_payload
            .as_object()
            .context("MFA session payload object")?,
        i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?,
        true,
    )?;
    first
        .query_client()
        .exec("UPDATE django_session SET session_data = $data WHERE session_key = $key")
        .param("$data", mfa_session)
        .param("$key", session.clone())
        .await?;
    let mfa_key = format!("mfa{stamp}");
    let no_mfa = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/data/exports")
                .header("x-session-token", &session)
                .header("idempotency-key", &mfa_key)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"password":"export-test-password"}"#))?,
        )
        .await?;
    ensure!(no_mfa.status() == StatusCode::BAD_REQUEST);
    let consumed = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/data/exports")
                .header("x-session-token", &session)
                .header("idempotency-key", &mfa_key)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"password":"export-test-password","recovery_code":"87654321"}"#,
                ))?,
        )
        .await?;
    ensure!(consumed.status() == StatusCode::ACCEPTED);
    let consumed_body: serde_json::Value =
        serde_json::from_slice(&to_bytes(consumed.into_body(), 4096).await?)?;
    let retry = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/data/exports")
                .header("x-session-token", &session)
                .header("idempotency-key", &mfa_key)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"password":"export-test-password","recovery_code":"87654321"}"#,
                ))?,
        )
        .await?;
    ensure!(retry.status() == StatusCode::ACCEPTED);
    let retry_body: serde_json::Value =
        serde_json::from_slice(&to_bytes(retry.into_body(), 4096).await?)?;
    ensure!(retry_body["id"] == consumed_body["id"]);
    let replay_key = format!("replay{stamp}");
    let replay = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/data/exports")
                .header("x-session-token", &session)
                .header("idempotency-key", &replay_key)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"password":"export-test-password","recovery_code":"87654321"}"#,
                ))?,
        )
        .await?;
    ensure!(replay.status() == StatusCode::BAD_REQUEST);
    for expected in [
        StatusCode::BAD_REQUEST,
        StatusCode::BAD_REQUEST,
        StatusCode::TOO_MANY_REQUESTS,
    ] {
        let attempt = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/data/exports")
                    .header("x-session-token", &session)
                    .header("idempotency-key", format!("budget{stamp}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"password":"wrong-password"}"#))?,
            )
            .await?;
        ensure!(attempt.status() == expected, "export rate budget mismatch");
    }
    let job_key = format!("job{stamp}");
    let job = request(&first, account_id, &job_key, &secret, SystemTime::now()).await?;
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<String>(1);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let s3 = Router::new().fallback(any(move |request: Request<Body>| {
        let sender = sender.clone();
        async move {
            let method = request.method().clone();
            let path = request.uri().path().to_owned();
            let Ok(body) = to_bytes(request.into_body(), 2 * 1024 * 1024).await else {
                return StatusCode::BAD_REQUEST;
            };
            let Ok(text) = String::from_utf8(body.to_vec()) else {
                return StatusCode::BAD_REQUEST;
            };
            let message = if method == "DELETE" {
                format!("DELETE {path}")
            } else {
                text
            };
            if sender.send(message).await.is_err() {
                return StatusCode::SERVICE_UNAVAILABLE;
            }
            if method == "DELETE" {
                StatusCode::NO_CONTENT
            } else {
                StatusCode::OK
            }
        }
    }));
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, s3).await;
    });
    let storage = id_runtime::data_export_s3::S3Export::new(
        &format!("http://127.0.0.1:{port}/"),
        "private-exports",
        "ru-central1",
        "synthetic-key".into(),
        "synthetic-secret".into(),
    )?;
    let drain = id_runtime::data_export_job::drain_one(first.clone(), &storage, &job.id).await?;
    ensure!(
        drain.attempted == 1 && drain.completed == 1 && drain.deferred == 0,
        "export job did not complete: {drain:?}"
    );
    let archive = receiver
        .recv()
        .await
        .context("S3 fixture received no archive")?;
    ensure!(
        archive.contains("\"category\":\"account\"")
            && archive.contains("\"category\":\"manifest\"")
            && !archive.contains("synthetic-secret")
            && !archive.contains("\"password\""),
        "export archive missing manifest or leaked credentials"
    );
    ensure!(
        read_owned(&first, account_id, &job.id)
            .await?
            .is_some_and(|op| op.status == "succeeded")
    );
    let past = SystemTime::now()
        .checked_sub(Duration::from_secs(1))
        .context("test time underflow")?;
    first.query_client().exec("UPDATE id_data_export_operation SET expires_at = CAST($past AS Datetime) WHERE id = $id")
        .param("$past", past).param("$id", job.id.clone()).await?;
    let expired =
        id_runtime::data_export_job::clean_expired(&first, &storage, 10, SystemTime::now()).await?;
    ensure!(
        expired.attempted == 1 && expired.completed == 1 && expired.deferred == 0,
        "expired archive cleanup failed: {expired:?}"
    );
    let deleted = receiver
        .recv()
        .await
        .context("S3 fixture received no archive DELETE")?;
    ensure!(deleted.starts_with("DELETE /private-exports/exports/user_"));
    ensure!(
        read_owned(&first, account_id, &job.id).await?.is_none(),
        "expired export retained its owner"
    );
    ensure!(
        id_runtime::data_export_operation::download_key(
            &first,
            account_id,
            &job.id,
            SystemTime::now()
        )
        .await?
        .is_none()
    );
    ensure!(
        request(&first, account_id, &job_key, &secret, SystemTime::now())
            .await?
            .status
            == "failed",
        "expired idempotency key created a second operation"
    );
    let late = request(
        &first,
        account_id,
        &format!("late{stamp}"),
        &secret,
        SystemTime::now(),
    )
    .await?;
    first
        .query_client()
        .exec("UPDATE auth_user SET is_active = false WHERE id = $id")
        .param("$id", account_id)
        .await?;
    ensure!(
        claim(
            &second,
            &late.id,
            SystemTime::now() + Duration::from_secs(2)
        )
        .await?
        .is_none(),
        "export worker claimed a disabled account"
    );
    ensure!(
        read_owned(&first, account_id, &late.id)
            .await?
            .is_some_and(|op| op.status == "failed"),
        "disabled account export remained in the due queue"
    );
    server.abort();
    Ok(())
}
