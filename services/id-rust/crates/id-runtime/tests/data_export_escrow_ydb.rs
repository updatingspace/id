//! Escrow storage contract on disposable local YDB.

use anyhow::{Result, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
    response::Response,
    routing::any,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use id_compat::session::SessionCodec;
use id_runtime::data_export_escrow::{
    COOLDOWN, DELIVERY_WINDOW, ExportEscrowKey, cancel_owned, ensure_schema, insert_request_tx,
    seal_snapshot_tx,
};
use id_runtime::data_export_mail;
use id_runtime::data_export_operation;
use id_runtime::{
    cache_store::CacheStore,
    data_export_http::{ExportHttpConfig, ExportHttpSettings},
};
use lettre::{AsyncSmtpTransport, Tokio1Executor, message::Mailbox};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tower::ServiceExt;
use uuid::Uuid;
use ydb::{Transaction, TxMode, closure};

#[tokio::test]
#[ignore = "requires disposable local /local YDB"]
async fn owner_cancellation_revokes_mail_and_capability_without_cross_account_access() -> Result<()>
{
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "test requires local YDB"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    data_export_operation::ensure_schema(&client).await?;
    ensure_schema(&client).await?;
    data_export_mail::ensure_schema(&client).await?;
    let id = Uuid::new_v4().simple().to_string();
    let owner = 42;
    let now = SystemTime::now();
    let key = ExportEscrowKey::from_base64(&STANDARD.encode([0x63; 32]))?;
    let recipient = key.seal_recipient(&id, "cancel-export@example.invalid")?;
    let tx_id = id.clone();
    client
        .query_client()
        .retry_tx(closure!(
            [tx_id, recipient],
            async |tx: &mut Transaction| {
                insert_request_tx(tx, tx_id, owner, recipient, now).await?;
                data_export_mail::insert_request_tx(tx, tx_id, now).await
            }
        ))
        .with_mode(TxMode::SerializableReadWrite)
        .idempotent(false)
        .await?;
    let object_key = format!("exports/escrow/{id}/attempt.ndjson");
    let tx_id = id.clone();
    let tx_key = object_key.clone();
    client
        .query_client()
        .retry_tx(closure!([tx_id, tx_key], async |tx: &mut Transaction| {
            seal_snapshot_tx(tx, tx_id, owner, tx_key, "{}", now).await
        }))
        .with_mode(TxMode::SerializableReadWrite)
        .idempotent(false)
        .await?;
    client.query_client().exec("INSERT INTO id_data_export_operation (id, user_id, status, attempts, next_attempt_at, claim_token, object_key, manifest, created_at) VALUES ($id, $owner, 'cooldown', 1, CAST($now AS Datetime), '', $key, '{}', CAST($now AS Datetime))")
        .param("$id", id.clone()).param("$owner", owner).param("$now", now)
        .param("$key", object_key.clone()).await?;
    ensure!(cancel_owned(&client, &id, owner + 1).await?.is_none());
    client
        .query_client()
        .exec("UPDATE id_data_export_operation SET user_id = $other WHERE id = $id")
        .param("$id", id.clone())
        .param("$other", owner + 1)
        .await?;
    ensure!(cancel_owned(&client, &id, owner).await?.is_none());
    client
        .query_client()
        .exec("UPDATE id_data_export_operation SET user_id = $owner WHERE id = $id")
        .param("$id", id.clone())
        .param("$owner", owner)
        .await?;
    ensure!(
        id_runtime::data_export_escrow::release_at(&client, &id, owner)
            .await?
            .is_some(),
        "another owner changed the request"
    );
    ensure!(cancel_owned(&client, &id, owner).await? == Some(object_key.clone()));
    ensure!(cancel_owned(&client, &id, owner).await?.is_none());
    let capability = key.capability(&id)?;
    ensure!(
        id_runtime::data_export_escrow::downloadable_key(
            &client,
            &key,
            &id,
            &capability,
            now + COOLDOWN,
        )
        .await?
        .is_none(),
        "cancelled capability still downloaded"
    );
    for kind in ["notice", "delivery"] {
        let mut row = client
            .query_client()
            .query_row("SELECT state FROM id_data_export_mail WHERE id = $id")
            .param("$id", format!("{id}:{kind}"))
            .await?;
        let state: String = row.remove_field_by_name("state")?.try_into()?;
        ensure!(state == "cancelled", "mail intent survived cancellation");
    }
    ensure!(id_runtime::data_export_escrow::forget_cancelled(&client, &id, &object_key).await?);
    client
        .query_client()
        .exec("DELETE FROM id_data_export_escrow WHERE id = $id")
        .param("$id", id.clone())
        .await?;
    client
        .query_client()
        .exec("DELETE FROM id_data_export_operation WHERE id = $id")
        .param("$id", id.clone())
        .await?;
    for kind in ["notice", "delivery"] {
        client
            .query_client()
            .exec("DELETE FROM id_data_export_mail WHERE id = $id")
            .param("$id", format!("{id}:{kind}"))
            .await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable local /local YDB"]
async fn encrypted_request_has_cooldown_and_repeatable_schema() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "test requires local YDB"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    ensure_schema(&client).await?;
    ensure_schema(&client).await?;
    data_export_mail::ensure_schema(&client).await?;
    data_export_mail::ensure_schema(&client).await?;
    let id = Uuid::new_v4().simple().to_string();
    let key = ExportEscrowKey::from_base64(&STANDARD.encode([0x51; 32]))?;
    let encrypted = key.seal_recipient(&id, "export@example.invalid")?;
    let now = SystemTime::now();
    let tx_id = id.clone();
    let tx_encrypted = encrypted.clone();
    client
        .query_client()
        .retry_tx(closure!(
            [tx_id, tx_encrypted],
            async |tx: &mut Transaction| {
                insert_request_tx(tx, tx_id, 42, tx_encrypted, now).await?;
                data_export_mail::insert_request_tx(tx, tx_id, now).await
            }
        ))
        .with_mode(TxMode::SerializableReadWrite)
        .idempotent(false)
        .await?;

    let mut row = client.query_client().query_row(
        "SELECT user_id, encrypted_email, state, release_at, expires_at FROM id_data_export_escrow WHERE id = $id",
    ).param("$id", id.clone()).await?;
    let owner: i32 = row.remove_field_by_name("user_id")?.try_into()?;
    let stored: String = row.remove_field_by_name("encrypted_email")?.try_into()?;
    let state: String = row.remove_field_by_name("state")?.try_into()?;
    let release: SystemTime = row.remove_field_by_name("release_at")?.try_into()?;
    let expiry: SystemTime = row.remove_field_by_name("expires_at")?.try_into()?;
    ensure!(owner == 42 && state == "accepted");
    ensure!(stored == encrypted && !stored.contains("export@example.invalid"));
    ensure!(key.unseal_recipient(&id, &stored)? == "export@example.invalid");
    ensure!(
        release.duration_since(now + COOLDOWN).unwrap_or_default() < Duration::from_secs(1)
            || (now + COOLDOWN).duration_since(release).unwrap_or_default()
                < Duration::from_secs(1)
    );
    ensure!(expiry.duration_since(release)? == DELIVERY_WINDOW);
    let due_mail = data_export_mail::due_ids(&client, now + Duration::from_secs(1), 10).await?;
    ensure!(due_mail.contains(&format!("{id}:notice")));
    ensure!(!due_mail.contains(&format!("{id}:delivery")));

    let object_key = format!("exports/escrow/{id}/attempt.ndjson");
    let tx_id = id.clone();
    let tx_key = object_key.clone();
    let sealed_expiry = client
        .query_client()
        .retry_tx(closure!([tx_id, tx_key], async |tx: &mut Transaction| {
            seal_snapshot_tx(tx, tx_id, 42, tx_key, "{}", now).await
        }))
        .with_mode(TxMode::SerializableReadWrite)
        .idempotent(false)
        .await?;
    ensure!(sealed_expiry == expiry);
    let mut sealed = client
        .query_client()
        .query_row("SELECT state, object_key, manifest FROM id_data_export_escrow WHERE id = $id")
        .param("$id", id.clone())
        .await?;
    let sealed_state: String = sealed.remove_field_by_name("state")?.try_into()?;
    let sealed_key: String = sealed.remove_field_by_name("object_key")?.try_into()?;
    let manifest: String = sealed.remove_field_by_name("manifest")?.try_into()?;
    ensure!(sealed_state == "sealed" && sealed_key == object_key && manifest == "{}");
    let mail_config = data_export_mail::MailConfig::new(key.clone(), "http://localhost:8080/")?;
    let notice = send_one_mail(&client, &format!("{id}:notice"), &mail_config).await?;
    ensure!(notice.contains("UpdSpace ID") && !notice.contains("data/export"));
    let repeated = send_one_mail(&client, &format!("{id}:notice"), &mail_config).await;
    ensure!(repeated.is_err(), "sent notice was delivered twice");

    let due_now = SystemTime::now() - Duration::from_secs(1);
    client
        .query_client()
        .exec("UPDATE id_data_export_escrow SET release_at = CAST($due AS Datetime) WHERE id = $id")
        .param("$id", id.clone())
        .param("$due", due_now)
        .await?;
    client.query_client().exec("UPDATE id_data_export_mail SET next_attempt_at = CAST($due AS Datetime) WHERE id = $id")
        .param("$id", format!("{id}:delivery")).param("$due", due_now).await?;
    let delivery = send_one_mail(&client, &format!("{id}:delivery"), &mail_config).await?;
    ensure!(delivery.contains("data/export") && delivery.contains(&id));
    client.query_client().exec("UPDATE id_data_export_escrow SET release_at = CAST($release AS Datetime) WHERE id = $id")
        .param("$id", id.clone()).param("$release", release).await?;
    let capability = key.capability(&id)?;
    ensure!(
        id_runtime::data_export_escrow::downloadable_key(&client, &key, &id, &capability, now)
            .await?
            .is_none()
    );
    ensure!(
        id_runtime::data_export_escrow::downloadable_key(&client, &key, &id, "wrong", release)
            .await?
            .is_none()
    );
    ensure!(
        id_runtime::data_export_escrow::downloadable_key(&client, &key, &id, &capability, release)
            .await?
            == Some(object_key.clone())
    );

    data_export_operation::ensure_schema(&client).await?;
    client.query_client().exec("INSERT INTO id_data_export_operation (id, user_id, status, attempts, next_attempt_at, claim_token, object_key, manifest, created_at) VALUES ($id, 42, 'pending_delayed', 1, CAST($now AS Datetime), '', $key, '{}', CAST($now AS Datetime))")
        .param("$id", id.clone()).param("$key", object_key.clone()).param("$now", now).await?;
    let (storage, s3_server) = empty_owner_s3().await?;
    ensure!(data_export_operation::has_unsealed_delayed(&client, 42).await?);
    ensure!(
        !id_runtime::data_export_job::clean_owner(&client, &storage, 42, 100).await?,
        "deletion must wait for a pending snapshot"
    );
    client
        .query_client()
        .exec("UPDATE id_data_export_operation SET status = 'cooldown' WHERE id = $id")
        .param("$id", id.clone())
        .await?;
    ensure!(!data_export_operation::has_unsealed_delayed(&client, 42).await?);
    ensure!(
        id_runtime::data_export_job::clean_owner(&client, &storage, 42, 100).await?,
        "deletion should detach a sealed snapshot"
    );
    s3_server.abort();
    let mut detached = client
        .query_client()
        .query_row(
            "SELECT user_id, object_key, manifest FROM id_data_export_operation WHERE id = $id",
        )
        .param("$id", id.clone())
        .await?;
    let detached_owner: i32 = detached.remove_field_by_name("user_id")?.try_into()?;
    let detached_key: String = detached.remove_field_by_name("object_key")?.try_into()?;
    let detached_manifest: String = detached.remove_field_by_name("manifest")?.try_into()?;
    ensure!(detached_owner == 0 && detached_key.is_empty() && detached_manifest.is_empty());
    let mut detached_escrow = client
        .query_client()
        .query_row("SELECT user_id, object_key FROM id_data_export_escrow WHERE id = $id")
        .param("$id", id.clone())
        .await?;
    let escrow_owner: i32 = detached_escrow
        .remove_field_by_name("user_id")?
        .try_into()?;
    let escrow_object: String = detached_escrow
        .remove_field_by_name("object_key")?
        .try_into()?;
    ensure!(escrow_owner == 0 && escrow_object == object_key);
    ensure!(
        id_runtime::data_export_escrow::downloadable_key(&client, &key, &id, &capability, release)
            .await?
            == Some(object_key.clone())
    );

    // A detached export is redeemable with no cookie or surviving account.
    let storage = id_runtime::data_export_s3::S3Export::new(
        "http://127.0.0.1:9000/",
        "private-exports",
        "ru-central1",
        "test-access".into(),
        "test-secret".into(),
    )?;
    let config = ExportHttpConfig::new(
        client.clone(),
        Arc::new(SessionCodec::new(b"synthetic-export-session-secret", &[])?),
        storage,
        ExportHttpSettings {
            operation_key: vec![0x32; 32],
            cache: CacheStore::new(client.clone(), "id_shared_cache", "", 1)?,
            seal_key: None,
            escrow_key: Some(Arc::new(key.clone())),
            session_cookie_name: "sessionid".into(),
            csrf_cookie_name: "csrftoken".into(),
            trusted_origins: vec!["http://localhost:8080".into()],
        },
    )?;
    // The database release time is temporarily advanced for a real HTTP test.
    client.query_client().exec("UPDATE id_data_export_escrow SET release_at = CAST($release AS Datetime) WHERE id = $id")
        .param("$id", id.clone()).param("$release", SystemTime::now() - Duration::from_secs(1)).await?;
    let response = id_runtime::data_export_http::router(Arc::new(config))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/auth/data/exports/{id}/redeem"))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({"token":capability}).to_string(),
                ))?,
        )
        .await?;
    ensure!(response.status() == StatusCode::OK);
    ensure!(
        response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok())
            == Some("no-store")
    );
    let payload: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
    let signed_url = payload["download_url"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("download URL missing"))?;
    ensure!(
        signed_url.contains("private-exports/exports/escrow/") && !signed_url.contains(&capability)
    );
    client.query_client().exec("UPDATE id_data_export_escrow SET release_at = CAST($release AS Datetime) WHERE id = $id")
        .param("$id", id.clone()).param("$release", release).await?;

    let expired_at = expiry + Duration::from_secs(1);
    let expired = id_runtime::data_export_escrow::expired(&client, expired_at, 100).await?;
    let expired = expired
        .into_iter()
        .find(|candidate| candidate.id == id)
        .ok_or_else(|| anyhow::anyhow!("sealed escrow not found by expiry index"))?;
    ensure!(expired.object_key == object_key);
    ensure!(id_runtime::data_export_escrow::forget_expired(&client, &expired, expired_at).await?);
    ensure!(!id_runtime::data_export_escrow::forget_expired(&client, &expired, expired_at).await?);
    let mut forgotten = client
        .query_client()
        .query_row(
            "SELECT state, encrypted_email, object_key FROM id_data_export_escrow WHERE id = $id",
        )
        .param("$id", id.clone())
        .await?;
    let forgotten_state: String = forgotten.remove_field_by_name("state")?.try_into()?;
    let forgotten_email: String = forgotten
        .remove_field_by_name("encrypted_email")?
        .try_into()?;
    let forgotten_key: String = forgotten.remove_field_by_name("object_key")?.try_into()?;
    ensure!(forgotten_state == "expired" && forgotten_email.is_empty() && forgotten_key.is_empty());
    ensure!(
        id_runtime::data_export_escrow::downloadable_key(
            &client,
            &key,
            &id,
            &capability,
            expired_at
        )
        .await?
        .is_none()
    );

    client
        .query_client()
        .exec("DELETE FROM id_data_export_escrow WHERE id = $id")
        .param("$id", id.clone())
        .await?;
    client
        .query_client()
        .exec("DELETE FROM id_data_export_operation WHERE id = $id")
        .param("$id", id.clone())
        .await?;
    for kind in ["notice", "delivery"] {
        client
            .query_client()
            .exec("DELETE FROM id_data_export_mail WHERE id = $id")
            .param("$id", format!("{id}:{kind}"))
            .await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable local /local YDB"]
async fn exhausted_snapshot_sends_failure_instead_of_download_link() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "test requires local YDB"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    data_export_operation::ensure_schema(&client).await?;
    ensure_schema(&client).await?;
    data_export_mail::ensure_schema(&client).await?;
    let id = Uuid::new_v4().simple().to_string();
    let owner = i32::try_from(
        SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_micros()
            % 900_000_000
            + 100_000_000,
    )?;
    let now = SystemTime::now();
    let key = ExportEscrowKey::from_base64(&STANDARD.encode([0x52; 32]))?;
    let recipient = key.seal_recipient(&id, "failed-export@example.invalid")?;
    client.query_client().exec("INSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, 'synthetic-hash', true, 'failed-export', '', '', 'failed-export@example.invalid', false, false, CurrentUtcDatetime())")
        .param("$id", owner).await?;
    let tx_id = id.clone();
    client.query_client().retry_tx(closure!([tx_id, recipient], async |tx: &mut Transaction| {
        tx.exec("INSERT INTO id_data_export_operation (id, user_id, status, attempts, next_attempt_at, claim_token, object_key, manifest, created_at) VALUES ($id, $owner, 'pending_delayed', 10, CAST($due AS Datetime), '', '', '', CAST($now AS Datetime))")
            .param("$id", tx_id.clone()).param("$owner", owner)
            .param("$due", now - Duration::from_secs(1)).param("$now", now).await?;
        insert_request_tx(tx, tx_id, owner, recipient, now).await?;
        data_export_mail::insert_request_tx(tx, tx_id, now).await
    })).with_mode(TxMode::SerializableReadWrite).idempotent(false).await?;

    ensure!(
        data_export_operation::claim(&client, &id, now)
            .await?
            .is_none()
    );
    let mut operation = client
        .query_client()
        .query_row("SELECT status, user_id FROM id_data_export_operation WHERE id = $id")
        .param("$id", id.clone())
        .await?;
    let operation_status: String = operation.remove_field_by_name("status")?.try_into()?;
    let operation_owner: i32 = operation.remove_field_by_name("user_id")?.try_into()?;
    let mut escrow = client
        .query_client()
        .query_row("SELECT state, user_id FROM id_data_export_escrow WHERE id = $id")
        .param("$id", id.clone())
        .await?;
    let escrow_state: String = escrow.remove_field_by_name("state")?.try_into()?;
    let escrow_owner: i32 = escrow.remove_field_by_name("user_id")?.try_into()?;
    ensure!(operation_status == "failed" && operation_owner == owner);
    ensure!(escrow_state == "failed" && escrow_owner == 0);
    ensure!(!data_export_operation::has_unsealed_delayed(&client, owner).await?);

    let due = SystemTime::now() - Duration::from_secs(1);
    client
        .query_client()
        .exec("UPDATE id_data_export_escrow SET release_at = CAST($due AS Datetime) WHERE id = $id")
        .param("$id", id.clone())
        .param("$due", due)
        .await?;
    client.query_client().exec("UPDATE id_data_export_mail SET next_attempt_at = CAST($due AS Datetime) WHERE id = $id")
        .param("$id", format!("{id}:delivery")).param("$due", due).await?;
    let mail = send_one_mail(
        &client,
        &format!("{id}:delivery"),
        &data_export_mail::MailConfig::new(key.clone(), "http://localhost:8080/")?,
    )
    .await?;
    ensure!(
        mail.contains("=D0=9D=D0=B5 =D1=83") && !mail.contains("/data/export"),
        "failure mail must report the error without a download link"
    );
    ensure!(
        id_runtime::data_export_escrow::downloadable_key(
            &client,
            &key,
            &id,
            &key.capability(&id)?,
            SystemTime::now()
        )
        .await?
        .is_none()
    );

    let expired_at = now + COOLDOWN + DELIVERY_WINDOW + Duration::from_secs(1);
    let expired = id_runtime::data_export_escrow::expired(&client, expired_at, 100)
        .await?
        .into_iter()
        .find(|row| row.id == id)
        .ok_or_else(|| anyhow::anyhow!("failed escrow not found for cleanup"))?;
    ensure!(expired.object_key.is_empty());
    ensure!(id_runtime::data_export_escrow::forget_expired(&client, &expired, expired_at).await?);
    let mut forgotten = client
        .query_client()
        .query_row("SELECT encrypted_email, state FROM id_data_export_escrow WHERE id = $id")
        .param("$id", id.clone())
        .await?;
    let email: String = forgotten
        .remove_field_by_name("encrypted_email")?
        .try_into()?;
    let state: String = forgotten.remove_field_by_name("state")?.try_into()?;
    ensure!(email.is_empty() && state == "expired");
    for kind in ["notice", "delivery"] {
        client
            .query_client()
            .exec("DELETE FROM id_data_export_mail WHERE id = $id")
            .param("$id", format!("{id}:{kind}"))
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM id_data_export_escrow WHERE id = $id")
        .param("$id", id.clone())
        .await?;
    client
        .query_client()
        .exec("DELETE FROM id_data_export_operation WHERE id = $id")
        .param("$id", id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM auth_user WHERE id = $id")
        .param("$id", owner)
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable local /local YDB"]
async fn operator_cancel_revokes_sealed_archive_and_mail() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "test requires local YDB"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    data_export_operation::ensure_schema(&client).await?;
    ensure_schema(&client).await?;
    data_export_mail::ensure_schema(&client).await?;
    let id = Uuid::new_v4().simple().to_string();
    let owner = i32::try_from(
        SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_micros()
            % 900_000_000
            + 100_000_000,
    )?;
    let now = SystemTime::now();
    let key = ExportEscrowKey::from_base64(&STANDARD.encode([0x53; 32]))?;
    let recipient = key.seal_recipient(&id, "cancel-export@example.invalid")?;
    let object_key = format!("exports/escrow/{id}/sealed.ndjson");
    let tx_id = id.clone();
    let tx_key = object_key.clone();
    client.query_client().retry_tx(closure!([tx_id, recipient, tx_key], async |tx: &mut Transaction| {
        tx.exec("INSERT INTO id_data_export_operation (id, user_id, status, attempts, next_attempt_at, claim_token, object_key, manifest, created_at) VALUES ($id, $owner, 'cooldown', 1, CAST($now AS Datetime), '', $key, '{}', CAST($now AS Datetime))")
            .param("$id", tx_id.clone()).param("$owner", owner).param("$key", tx_key.clone()).param("$now", now).await?;
        insert_request_tx(tx, tx_id, owner, recipient, now).await?;
        data_export_mail::insert_request_tx(tx, tx_id, now).await?;
        seal_snapshot_tx(tx, tx_id, owner, tx_key, "{}", now).await?;
        Ok(())
    })).with_mode(TxMode::SerializableReadWrite).idempotent(false).await?;
    let capability = key.capability(&id)?;
    ensure!(
        id_runtime::data_export_escrow::downloadable_key(
            &client,
            &key,
            &id,
            &capability,
            now + COOLDOWN
        )
        .await?
            == Some(object_key.clone())
    );
    ensure!(
        id_runtime::data_export_escrow::cancel(&client, &id).await? == Some(object_key.clone())
    );
    ensure!(
        id_runtime::data_export_escrow::cancel(&client, &id).await? == Some(object_key.clone())
    );
    ensure!(
        id_runtime::data_export_escrow::downloadable_key(
            &client,
            &key,
            &id,
            &capability,
            now + COOLDOWN
        )
        .await?
        .is_none()
    );
    let mut row = client
        .query_client()
        .query_row(
            "SELECT user_id, encrypted_email, state FROM id_data_export_escrow WHERE id = $id",
        )
        .param("$id", id.clone())
        .await?;
    let escrow_owner: i32 = row.remove_field_by_name("user_id")?.try_into()?;
    let email: String = row.remove_field_by_name("encrypted_email")?.try_into()?;
    let state: String = row.remove_field_by_name("state")?.try_into()?;
    ensure!(escrow_owner == 0 && email.is_empty() && state == "cancelled");
    ensure!(
        data_export_mail::due_ids(&client, now + COOLDOWN + Duration::from_secs(1), 10)
            .await?
            .iter()
            .all(|mail_id| !mail_id.starts_with(&id))
    );
    ensure!(id_runtime::data_export_escrow::forget_cancelled(&client, &id, &object_key).await?);
    ensure!(!id_runtime::data_export_escrow::forget_cancelled(&client, &id, &object_key).await?);
    for kind in ["notice", "delivery"] {
        client
            .query_client()
            .exec("DELETE FROM id_data_export_mail WHERE id = $id")
            .param("$id", format!("{id}:{kind}"))
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM id_data_export_escrow WHERE id = $id")
        .param("$id", id.clone())
        .await?;
    client
        .query_client()
        .exec("DELETE FROM id_data_export_operation WHERE id = $id")
        .param("$id", id)
        .await?;
    Ok(())
}

async fn send_one_mail(
    client: &ydb::Client,
    mail_id: &str,
    config: &data_export_mail::MailConfig,
) -> Result<String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let server = tokio::spawn(async move {
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
                return Ok::<String, anyhow::Error>(body);
            }
            io.get_mut().write_all(b"250 ok\r\n").await?;
        }
    });
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("127.0.0.1")
        .port(port)
        .timeout(Some(Duration::from_secs(5)))
        .build();
    let from: Mailbox = "no-reply@example.invalid".parse()?;
    let result = data_export_mail::process_one(client, mail_id, config, &mailer, &from).await?;
    if result.sent != 1 {
        server.abort();
        anyhow::bail!("mail was not sent: {result:?}");
    }
    tokio::time::timeout(Duration::from_secs(5), server).await??
}

async fn empty_owner_s3() -> Result<(
    id_runtime::data_export_s3::S3Export,
    tokio::task::JoinHandle<()>,
)> {
    async fn list(request: Request<Body>) -> Response<Body> {
        assert_eq!(request.method(), Method::GET);
        assert_eq!(request.uri().path(), "/private-exports");
        assert!(
            request
                .uri()
                .query()
                .unwrap_or("")
                .contains("prefix=exports%2Fuser_42%2F")
        );
        Response::new(Body::from(
            "<ListBucketResult><Name>private-exports</Name><Prefix>exports/user_42/</Prefix><IsTruncated>false</IsTruncated></ListBucketResult>",
        ))
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let app = Router::new().fallback(any(list));
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let storage = id_runtime::data_export_s3::S3Export::new(
        &format!("http://127.0.0.1:{port}/"),
        "private-exports",
        "ru-central1",
        "test-access".into(),
        "test-secret".into(),
    )?;
    Ok((storage, server))
}
