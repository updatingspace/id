//! Large owner-scoped export on disposable local YDB.

use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::Request,
    http::StatusCode,
    routing::any,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use id_runtime::{
    account_deletion_cleanup,
    data_export::{write_ndjson, write_ndjson_with_avatar},
    data_export_escrow::{self, ExportEscrowKey},
    data_export_operation,
    data_export_s3::S3Export,
    media_url::MediaUrl,
};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWrite},
    sync::oneshot,
};
use uuid::Uuid;
use ydb::{Transaction, TxMode, closure};

/// Stop before the first consent page finishes, so the next query cannot race
/// ahead of the second client's committed changes.
struct PausedExportWriter {
    bytes: Vec<u8>,
    consents: usize,
    paused: Option<oneshot::Sender<()>>,
    resume: Option<oneshot::Receiver<()>>,
}

impl AsyncWrite for PausedExportWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.consents == 128 {
            if let Some(paused) = self.paused.take() {
                let _ = paused.send(());
            }
            if let Some(resume) = self.resume.as_mut() {
                match Pin::new(resume).poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(_)) => {
                        return Poll::Ready(Err(io::Error::other("export mutation was cancelled")));
                    }
                    Poll::Ready(Ok(())) => self.resume = None,
                }
            }
        }
        if serde_json::from_slice::<serde_json::Value>(bytes)
            .is_ok_and(|line| line["category"] == "consents")
        {
            self.consents += 1;
        }
        self.bytes.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
#[ignore = "requires disposable local /local YDB with frozen legacy schema"]
async fn exports_all_owner_rows_without_credentials_or_other_account_data() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "export test requires local YDB on port 2136"
    );
    let client = id_runtime::connect_ydb().await?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let owner = i32::try_from(stamp % 900_000_000 + 100_000_000)?;
    let other = owner + 1;
    let identity = Uuid::from_u128((stamp << 32) | u128::from(std::process::id()));
    client.query_client().exec("INSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, 'password-hash-secret', true, 'export-owner', '', '', 'owner@example.invalid', false, false, CurrentUtcDatetime())")
        .param("$id", owner).await?;
    client.query_client().exec("INSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, 'export-owner', '', 'owner@example.invalid', true, 'active', false, CurrentUtcDatetime())")
        .param("$id", identity).await?;
    client.query_client().exec("INSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($owner, $identity, 'export-subject', CurrentUtcDatetime())")
        .param("$owner", owner).param("$identity", identity).await?;
    client.query_client().exec("INSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, 'other-hash', true, 'other', '', '', 'other@example.invalid', false, false, CurrentUtcDatetime())")
        .param("$id", other).await?;

    let base = i64::try_from(stamp % 1_000_000_000)? * 1_000;
    client.query_client().exec("INSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($id, $user, 'owner@example.invalid', true, true)")
        .param("$id", owner + 100).param("$user", owner).await?;
    client.query_client().exec("INSERT INTO accounts_userprofile (id, user_id, avatar_source, gravatar_enabled, phone_number, phone_verified, created_at, updated_at) VALUES ($id, $user, 'none', false, '+10000000000', false, CurrentUtcDatetime(), CurrentUtcDatetime())")
        .param("$id", base + 20_000).param("$user", owner).await?;
    client.query_client().exec("INSERT INTO accounts_userpreferences (id, user_id, language, timezone, marketing_opt_in, privacy_scope_defaults, created_at, updated_at) VALUES ($id, $user, 'ru', 'Europe/Moscow', false, Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime(), CurrentUtcDatetime())")
        .param("$id", base + 20_001).param("$user", owner).await?;
    client.query_client().exec("INSERT INTO accounts_accountevent (id, user_id, action, meta, created_at) VALUES ($id, $user, 'synthetic', Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime())")
        .param("$id", base + 20_002).param("$user", owner).await?;
    client.query_client().exec("INSERT INTO accounts_userdevice (id, user_id, device_id, user_agent, first_seen) VALUES ($id, $user, 'device-one', 'Synthetic Browser', CurrentUtcDatetime())")
        .param("$id", base + 20_003).param("$user", owner).await?;
    client.query_client().exec("INSERT INTO idp_oidcconsent (id, user_id, client_id, scopes, created_at, updated_at) VALUES ($id, $user, 99, Unwrap(CAST('[\"openid\"]' AS Json)), CurrentUtcDatetime(), CurrentUtcDatetime())")
        .param("$id", base + 20_004).param("$user", owner).await?;
    client.query_client().exec("INSERT INTO socialaccount_socialaccount (id, user_id, provider, uid, last_login, date_joined, extra_data) VALUES ($id, $user, 'github', 'synthetic-uid', CurrentUtcDatetime(), CurrentUtcDatetime(), Unwrap(CAST('{}' AS Json)))")
        .param("$id", owner + 101).param("$user", owner).await?;
    for start in (0..205).step_by(50) {
        let end = (start + 50).min(205);
        let values = (start..end).map(|i| format!(
            "({}, {}, 'terms', 'v1', CurrentUtcDatetime(), NULL, 'test', Unwrap(CAST('{{}}' AS Json)))",
            base + i64::from(i), owner)).collect::<Vec<_>>().join(",");
        client.query_client().exec(format!(
            "INSERT INTO accounts_userconsent (id, user_id, kind, version, granted_at, revoked_at, source, meta) VALUES {values}"
        )).await?;
    }
    for start in (0..105).step_by(35) {
        let end = (start + 35).min(105);
        let values = (start..end).map(|i| format!(
            "({}, {}, 'success', '192.0.2.1', '', 'Synthetic Browser', 'device', '', false, '', Unwrap(CAST('{{}}' AS Json)), CurrentUtcDatetime())",
            base + 10_000 + i64::from(i), owner)).collect::<Vec<_>>().join(",");
        client.query_client().exec(format!(
            "INSERT INTO accounts_loginevent (id, user_id, status, ip_address, ip_hash, user_agent, device_id, location, is_new_device, reason, meta, created_at) VALUES {values}"
        )).await?;
    }
    client.query_client().exec("INSERT INTO accounts_userconsent (id, user_id, kind, version, granted_at, source, meta) VALUES ($id, $user, 'other', 'v1', CurrentUtcDatetime(), 'test', Unwrap(CAST('{}' AS Json)))")
        .param("$id", base + 300_000).param("$user", other).await?;

    let (mut writer, mut reader) = tokio::io::duplex(2 * 1024 * 1024);
    let manifest = write_ndjson(&client, owner, &mut writer).await?;
    drop(writer);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).await?;
    let text = String::from_utf8(bytes)?;
    ensure!(
        !text.contains("password-hash-secret")
            && !text.contains("other@example.invalid")
            && !text.contains("\"kind\":\"other\""),
        "export leaked a credential or another account's data"
    );
    let lines = text
        .lines()
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let count = |category: &str| {
        lines
            .iter()
            .filter(|line| line["category"] == category)
            .count()
    };
    ensure!(
        count("account") == 1
            && count("email_addresses") == 1
            && count("profile") == 1
            && count("preferences") == 1
            && count("consents") == 205
            && count("login_events") == 105
            && count("account_events") == 1
            && count("devices") == 1
            && count("oidc_consents") == 1
            && count("linked_accounts") == 1
            && count("manifest") == 1,
        "export silently truncated a category"
    );
    let consents = manifest
        .categories
        .iter()
        .find(|row| row.category == "consents")
        .context("consents missing from manifest")?;
    let logins = manifest
        .categories
        .iter()
        .find(|row| row.category == "login_events")
        .context("login events missing from manifest")?;
    ensure!(
        consents.records == 205 && logins.records == 105,
        "manifest counts differ from exported rows"
    );
    ensure!(
        lines
            .last()
            .is_some_and(|line| line["record"]["consistency"] == "snapshot"
                && line["record"]["snapshot_scope"] == "worker-attempt"),
        "export did not append its manifest"
    );
    ensure!(
        chrono::DateTime::parse_from_rfc3339(&manifest.snapshot_started_at)?
            <= chrono::DateTime::parse_from_rfc3339(&manifest.snapshot_completed_at)?,
        "invalid worker snapshot time bounds"
    );
    let avatar_key = format!("avatars/user_{owner}/synthetic.jpg");
    client.query_client()
        .exec("UPDATE accounts_userprofile SET avatar = CAST($avatar AS String) WHERE user_id = $owner")
        .param("$avatar", avatar_key.clone())
        .param("$owner", owner)
        .await?;
    let (mut rejected_writer, mut rejected_reader) = tokio::io::duplex(2 * 1024 * 1024);
    ensure!(
        write_ndjson(&client, owner, &mut rejected_writer)
            .await
            .is_err(),
        "avatar bytes were silently excluded without media access"
    );
    drop(rejected_writer);
    let mut rejected_archive = String::new();
    rejected_reader
        .read_to_string(&mut rejected_archive)
        .await?;
    ensure!(
        !rejected_archive.contains("\"category\":\"manifest\""),
        "failed avatar export published a manifest"
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let expected_path = format!("/id-media/{avatar_key}");
    let replacement_key = format!("avatars/user_{owner}/replacement.jpg");
    let replacement_path = format!("/id-media/{replacement_key}");
    let avatar_server = Router::new().fallback(any(move |request: Request<Body>| {
        let expected_path = expected_path.clone();
        let replacement_path = replacement_path.clone();
        async move {
            if request.uri().path() == expected_path {
                (StatusCode::OK, b"synthetic-avatar".to_vec())
            } else if request.uri().path() == replacement_path {
                (StatusCode::OK, b"replacement-avatar".to_vec())
            } else {
                (StatusCode::NOT_FOUND, Vec::new())
            }
        }
    }));
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, avatar_server).await;
    });
    let source = MediaUrl::signed(
        &format!("http://127.0.0.1:{port}/id-media/"),
        "ru-central1",
        "test-key".into(),
        "test-secret".into(),
        60,
    )?;
    let (mut avatar_writer, mut avatar_reader) = tokio::io::duplex(2 * 1024 * 1024);
    let avatar_manifest =
        write_ndjson_with_avatar(&client, owner, &mut avatar_writer, Some(&source)).await?;
    drop(avatar_writer);
    let mut avatar_archive = Vec::new();
    avatar_reader.read_to_end(&mut avatar_archive).await?;
    let avatar_lines = String::from_utf8(avatar_archive)?;
    let avatar_rows = avatar_lines
        .lines()
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut restored = Vec::new();
    for row in avatar_rows
        .iter()
        .filter(|row| row["category"] == "avatar_bytes")
    {
        ensure!(row["record"]["key"] == avatar_key);
        restored.extend(
            base64::engine::general_purpose::STANDARD.decode(
                row["record"]["base64"]
                    .as_str()
                    .context("avatar chunk missing")?,
            )?,
        );
    }
    ensure!(restored == b"synthetic-avatar");
    ensure!(
        avatar_rows
            .iter()
            .any(|row| row["category"] == "avatar_digest" && row["record"]["bytes"] == 16)
    );
    ensure!(
        avatar_manifest
            .categories
            .iter()
            .any(|item| item.category == "avatar_bytes" && item.records > 0)
    );

    let mutator = id_runtime::connect_ydb().await?;
    let (paused, wait_for_page) = oneshot::channel();
    let (resume, wait_for_commit) = oneshot::channel();
    let mut concurrent_writer = PausedExportWriter {
        bytes: Vec::new(),
        consents: 0,
        paused: Some(paused),
        resume: Some(wait_for_commit),
    };
    let mutate = async {
        wait_for_page.await?;
        mutator.query_client().retry_tx(closure!([replacement_key], async |tx: &mut Transaction| {
            tx.exec("DELETE FROM accounts_userconsent WHERE id = $id")
                .param("$id", base + 180).await?;
            tx.exec("UPDATE accounts_userconsent SET version = 'v2' WHERE id = $id")
                .param("$id", base + 190).await?;
            tx.exec("INSERT INTO accounts_userconsent (id, user_id, kind, version, granted_at, source, meta) VALUES ($id, $owner, 'new-after-snapshot', 'v2', CurrentUtcDatetime(), 'test', Unwrap(CAST('{}' AS Json)))")
                .param("$id", base + 300).param("$owner", owner).await?;
            tx.exec("UPDATE accounts_userprofile SET avatar = CAST($key AS String) WHERE id = $id")
                .param("$key", replacement_key.clone()).param("$id", base + 20_000).await?;
            tx.exec("UPDATE idp_oidcconsent SET scopes = Unwrap(CAST('[\"openid\",\"email\"]' AS Json)) WHERE id = $id")
                .param("$id", base + 20_004).await?;
            Ok(())
        })).isolation(TxMode::SerializableReadWrite).idempotent(false).await?;
        resume
            .send(())
            .map_err(|_| anyhow::anyhow!("export stopped before mutation committed"))?;
        Ok::<_, anyhow::Error>(())
    };
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        tokio::try_join!(
            write_ndjson_with_avatar(&client, owner, &mut concurrent_writer, Some(&source)),
            mutate,
        )
    })
    .await??;
    let concurrent_rows = String::from_utf8(concurrent_writer.bytes)?
        .lines()
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let exported_consents = concurrent_rows
        .iter()
        .filter(|row| row["category"] == "consents")
        .map(|row| &row["record"])
        .collect::<Vec<_>>();
    ensure!(
        exported_consents.len() == 205
            && exported_consents.iter().enumerate().all(|(offset, row)| {
                row["id"] == base + offset as i64 && row["version"] == "v1"
            }),
        "export drifted across pages after concurrent delete, update and insert"
    );
    ensure!(
        concurrent_rows
            .iter()
            .any(|row| row["category"] == "oidc_consents"
                && row["record"]["scopes"] == serde_json::json!(["openid"])),
        "export drifted between categories"
    );
    ensure!(
        concurrent_rows
            .iter()
            .filter(|row| row["category"] == "avatar_bytes")
            .all(|row| row["record"]["key"] == avatar_key),
        "export avatar differs from the profile snapshot"
    );
    ensure!(
        concurrent_rows
            .iter()
            .any(|row| row["category"] == "avatar_digest"
                && row["record"]["sha256"] == {
                    use sha2::Digest;
                    hex::encode(sha2::Sha256::digest(b"synthetic-avatar"))
                }),
        "export did not preserve snapshot avatar bytes"
    );
    client.query_client()
        .exec("UPDATE accounts_userprofile SET avatar = CAST($avatar AS String) WHERE user_id = $owner")
        .param("$avatar", format!("avatars/user_{owner}/missing.jpg"))
        .param("$owner", owner).await?;
    let (mut missing_writer, mut missing_reader) = tokio::io::duplex(2 * 1024 * 1024);
    ensure!(
        write_ndjson_with_avatar(&client, owner, &mut missing_writer, Some(&source))
            .await
            .is_err(),
        "missing avatar was silently excluded from the snapshot"
    );
    drop(missing_writer);
    let mut missing_archive = String::new();
    missing_reader.read_to_string(&mut missing_archive).await?;
    ensure!(
        !missing_archive.contains("\"category\":\"manifest\""),
        "missing avatar export published a manifest"
    );
    server.abort();
    client
        .query_client()
        .exec("UPDATE auth_user SET is_active = false WHERE id = $id")
        .param("$id", owner)
        .await?;
    let (mut rejected_writer, mut rejected_reader) = tokio::io::duplex(1024);
    ensure!(
        write_ndjson(&client, owner, &mut rejected_writer)
            .await
            .is_err(),
        "inactive account was exported"
    );
    drop(rejected_writer);
    let mut rejected = Vec::new();
    rejected_reader.read_to_end(&mut rejected).await?;
    ensure!(rejected.is_empty(), "rejected export emitted account data");
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable local /local YDB with frozen legacy schema"]
async fn accepted_escrow_snapshots_after_account_access_is_revoked() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "export test requires local YDB"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let owner = i32::try_from(stamp % 900_000_000 + 100_000_000)?;
    let identity = Uuid::new_v4();
    let deletion_id = i64::try_from(stamp)?;
    client.query_client().exec("INSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, 'secret-hash', true, 'deleted-export-owner', '', '', 'deleted@example.invalid', false, false, CurrentUtcDatetime())")
        .param("$id", owner).await?;
    client.query_client().exec("INSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, 'deleted-export-owner', '', 'deleted@example.invalid', true, 'active', false, CurrentUtcDatetime())")
        .param("$id", identity).await?;
    client.query_client().exec("INSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($owner, $identity, 'deleted-export-subject', CurrentUtcDatetime())")
        .param("$owner", owner).param("$identity", identity).await?;
    data_export_operation::ensure_schema(&client).await?;
    data_export_escrow::ensure_schema(&client).await?;
    let export_id = Uuid::new_v4().simple().to_string();
    let escrow_key = ExportEscrowKey::from_base64(&STANDARD.encode([0x57; 32]))?;
    let recipient = escrow_key.seal_recipient(&export_id, "deleted@example.invalid")?;
    let now = SystemTime::now();
    let tx_id = export_id.clone();
    client.query_client().retry_tx(closure!([tx_id, recipient], async |tx: &mut Transaction| {
        tx.exec("INSERT INTO id_data_export_operation (id, user_id, status, attempts, next_attempt_at, claim_token, object_key, manifest, created_at) VALUES ($id, $owner, 'pending_delayed', 0, CAST($due AS Datetime), '', '', '', CAST($now AS Datetime))")
            .param("$id", tx_id.clone()).param("$owner", owner)
            .param("$due", now - std::time::Duration::from_secs(1)).param("$now", now).await?;
        data_export_escrow::insert_request_tx(tx, tx_id, owner, recipient, now).await
    })).with_mode(TxMode::SerializableReadWrite).idempotent(false).await?;
    client.query_client().exec("INSERT INTO accounts_accountdeletionrequest (id, user_id, status, requested_at, reason) VALUES ($id, $owner, 'running', CurrentUtcDatetime(), 'synthetic test')")
        .param("$id", deletion_id).param("$owner", owner).await?;
    client
        .query_client()
        .exec("UPDATE auth_user SET is_active = false WHERE id = $id")
        .param("$id", owner)
        .await?;
    client
        .query_client()
        .exec("UPDATE usid_user SET status = 'suspended' WHERE user_id = $id")
        .param("$id", identity)
        .await?;
    ensure!(
        account_deletion_cleanup::erase_avatar(&client, None, deletion_id)
            .await?
            .is_none(),
        "avatar cleanup must wait for the accepted snapshot"
    );

    let (mut rejected_writer, _) = tokio::io::duplex(1024);
    ensure!(
        write_ndjson(&client, owner, &mut rejected_writer)
            .await
            .is_err()
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let app = Router::new().fallback(any(move |request: Request<Body>| async move {
        match *request.method() {
            axum::http::Method::PUT => {
                assert!(request.uri().path().starts_with("/private-exports/exports/escrow/"));
                let Ok(body) = to_bytes(request.into_body(), 1024 * 1024).await else {
                    return (StatusCode::PAYLOAD_TOO_LARGE, String::new());
                };
                assert!(String::from_utf8_lossy(&body).contains("deleted-export-subject"));
                assert!(!String::from_utf8_lossy(&body).contains("secret-hash"));
                (StatusCode::OK, String::new())
            }
            axum::http::Method::GET => {
                assert_eq!(request.uri().path(), "/private-exports");
                assert!(request.uri().query().unwrap_or("").contains(&format!("prefix=exports%2Fuser_{owner}%2F")));
                (StatusCode::OK, format!("<ListBucketResult><Name>private-exports</Name><Prefix>exports/user_{owner}/</Prefix><IsTruncated>false</IsTruncated></ListBucketResult>"))
            }
            _ => panic!("unexpected export S3 method"),
        }
    }));
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let storage = S3Export::new(
        &format!("http://127.0.0.1:{port}/"),
        "private-exports",
        "ru-central1",
        "test-access".into(),
        "test-secret".into(),
    )?;
    let claim = data_export_operation::claim(&client, &export_id, SystemTime::now())
        .await?
        .context("accepted escrow claim missing")?;
    let (key, manifest) = storage.upload_export(client.clone(), &claim).await?;
    ensure!(key.starts_with("exports/escrow/") && manifest.categories[0].records == 1);
    ensure!(
        account_deletion_cleanup::erase_avatar(&client, None, deletion_id)
            .await?
            .is_none(),
        "avatar cleanup must wait for an in-flight snapshot"
    );
    ensure!(
        data_export_operation::complete(
            &client,
            &claim,
            &key,
            &serde_json::to_value(&manifest)?,
            SystemTime::now()
        )
        .await?
    );
    ensure!(
        account_deletion_cleanup::erase_avatar(&client, None, deletion_id)
            .await?
            .is_some_and(|result| result.avatar_removed),
        "avatar cleanup did not resume after seal"
    );
    ensure!(
        id_runtime::data_export_job::clean_owner(&client, &storage, owner, 100).await?,
        "profile cleanup did not detach sealed export"
    );
    ensure!(
        account_deletion_cleanup::erase_profile_history(&client, deletion_id)
            .await?
            .is_some_and(|result| result.profile_history_removed),
        "profile cleanup did not resume after export seal"
    );
    ensure!(
        data_export_escrow::downloadable_key(
            &client,
            &escrow_key,
            &export_id,
            &escrow_key.capability(&export_id)?,
            now + data_export_escrow::COOLDOWN
        )
        .await?
            == Some(key)
    );
    server.abort();
    client
        .query_client()
        .exec("DELETE FROM id_deletion_progress WHERE operation_id = $id")
        .param("$id", deletion_id)
        .await?;
    for table in [
        "id_deletion_profile_progress",
        "id_deletion_global_progress",
    ] {
        client
            .query_client()
            .exec(format!("DELETE FROM `{table}` WHERE operation_id = $id"))
            .param("$id", deletion_id)
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM id_data_export_escrow WHERE id = $id")
        .param("$id", export_id.clone())
        .await?;
    client
        .query_client()
        .exec("DELETE FROM id_data_export_operation WHERE id = $id")
        .param("$id", export_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountdeletionrequest WHERE id = $id")
        .param("$id", deletion_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountidentity WHERE user_id = $id")
        .param("$id", owner)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM usid_user WHERE user_id = $id")
        .param("$id", identity)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM auth_user WHERE id = $id")
        .param("$id", owner)
        .await?;
    Ok(())
}
