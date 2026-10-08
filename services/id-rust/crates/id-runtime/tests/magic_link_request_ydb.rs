#![recursion_limit = "256"]
//! A durable intent and the one-time token agree on real local YDB.

use anyhow::{Context, Result, ensure};
use axum::{
    body::Body,
    http::{Request as HttpRequest, StatusCode},
};
use hmac::{Hmac, KeyInit, Mac};
use id_runtime::{
    cache_store::CacheStore,
    magic_link_http::{self, MagicLinkHttpConfig},
    magic_link_request::{self, MailConfig},
};
use lettre::{AsyncSmtpTransport, Tokio1Executor, message::Mailbox};
use sha2::Sha256;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires migrated disposable local YDB; writes synthetic Portal rows"]
async fn issued_link_is_durable_and_consumable_once() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "local YDB required"
    );
    let client = std::sync::Arc::new(id_runtime::connect_ydb().await?);
    magic_link_request::ensure_schema(&client).await?;
    magic_link_request::ensure_schema(&client).await?;
    let user_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let member_id = -i64::from(u32::from_le_bytes(rand::random::<[u8; 4]>())) - 1;
    let slug = format!("magic-{}", tenant_id.simple());
    let email = format!("{user_id}@example.invalid");
    let secret = b"synthetic-magic-link-hash-key-32-bytes";
    client.query_client().exec("INSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, '', '', $email, true, 'active', false, CurrentUtcDatetime())")
        .param("$id", user_id).param("$email", email.clone()).await?;
    client.query_client().exec("INSERT INTO usid_tenant (id, slug, created_at) VALUES ($id, $slug, CurrentUtcDatetime())")
        .param("$id", tenant_id).param("$slug", slug.clone()).await?;
    client.query_client().exec("INSERT INTO usid_tenant_membership (id, user_id, tenant_id, status, base_role, source, created_at) VALUES ($id, $user, $tenant, 'active', 'member', 'native', CurrentUtcDatetime())")
        .param("$id", member_id).param("$user", user_id).param("$tenant", tenant_id).await?;

    let result = async {
        let app = id_runtime::magic_link_http::router(MagicLinkHttpConfig::new(
            client.clone(), CacheStore::new(client.clone(), "id_shared_cache", "", 1)?,
            secret.to_vec(), vec![Url::parse("https://portal.example.invalid/")?], true)?);
        let send = |address: &str| -> Result<HttpRequest<Body>> {
            Ok(HttpRequest::builder().method("POST").uri("/api/v1/auth/magic-link/request")
                .header("x-request-id", Uuid::new_v4().to_string())
                .header("x-tenant-id", tenant_id.to_string())
                .header("x-tenant-slug", &slug)
                .header("x-forwarded-for", "192.0.2.1")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({"email":address,"redirect_to":"https://portal.example.invalid/callback"}).to_string()))?)
        };
        ensure!(app.clone().oneshot(send("missing@example.invalid")?).await?.status() == StatusCode::OK);
        ensure!(
            magic_link_request::due_ids(&client, SystemTime::now(), 100)
                .await?
                .is_empty(),
            "unknown user queued mail"
        );
        ensure!(app.clone().oneshot(send(&email)?).await?.status() == StatusCode::OK);
        let ids = magic_link_request::due_ids(&client, SystemTime::now(), 100).await?;
        ensure!(ids.len() == 1, "expected one durable mail intent");
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
        let config = MailConfig::new(
            secret.to_vec(),
            "http://127.0.0.1/api/v1/auth/magic-link/consume",
        )?;
        let sent =
            magic_link_request::process_one(&client, &ids[0], &config, &mailer, &from).await?;
        ensure!(
            sent.sent == 1 && sent.claimed == 1,
            "magic-link mail was not sent"
        );
        let body = tokio::time::timeout(Duration::from_secs(5), server).await???;
        ensure!(
            body.contains("127.0.0.1") && body.contains("tenant_sig"),
            "SMTP message did not contain signed link"
        );
        ensure!(
            magic_link_request::due_ids(&client, SystemTime::now(), 100)
                .await?
                .is_empty(),
            "sent mail remains due"
        );
        let raw = magic_link_request::token_for_id(secret, Uuid::parse_str(&ids[0])?)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret)?;
        mac.update(raw.as_bytes());
        let hash = hex::encode(mac.finalize().into_bytes());
        let mut token = client
            .query_client()
            .query_row("SELECT user_id FROM usid_magic_link_token WHERE token = $hash")
            .param("$hash", hash.clone())
            .await?;
        let owner: Uuid = token.remove_field_by_name("user_id")?.try_into()?;
        ensure!(owner == user_id);
        let redirect = "https://portal.example.invalid/callback";
        let signature = magic_link_http::link_signature(secret, &raw, tenant_id, &slug, redirect)?;
        let mut link = Url::parse("https://id.example.invalid/api/v1/auth/magic-link/consume")?;
        link.query_pairs_mut().append_pair("token", &raw)
            .append_pair("redirect_to", redirect)
            .append_pair("tenant_id", &tenant_id.to_string())
            .append_pair("tenant_slug", &slug)
            .append_pair("tenant_sig", &signature);
        let path = format!("{}?{}", link.path(), link.query().context("missing link query")?);
        let click = || -> Result<HttpRequest<Body>> {
            Ok(HttpRequest::builder().method("GET").uri(&path).body(Body::empty())?)
        };
        let response = app.clone().oneshot(click()?).await?;
        ensure!(response.status() == StatusCode::SEE_OTHER, "browser link did not redirect");
        let location = response.headers().get("location").context("missing redirect location")?.to_str()?;
        let target = Url::parse(location)?;
        ensure!(target.origin() == Url::parse(redirect)?.origin());
        let code = target.query_pairs().find(|(key, _)| key == "code")
            .map(|(_, value)| value.into_owned()).context("missing exchange code")?;
        ensure!(app.oneshot(click()?).await?.status() == StatusCode::CONFLICT, "replayed link succeeded");
        let cache = CacheStore::new(client.clone(), "id_shared_cache", "", 1)?;
        ensure!(cache.take(&format!("usid:exchange:{code}"), SystemTime::now()).await?.is_some(), "exchange code missing");
        let mut session = client.query_client().query_row("SELECT token FROM usid_session WHERE user_id = $user LIMIT 1")
            .param("$user", user_id).await?;
        let session_token: String = session.remove_field_by_name("token")?.try_into()?;
        client
            .query_client()
            .exec("DELETE FROM usid_session WHERE token = $token")
            .param("$token", session_token)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM usid_magic_link_token WHERE token = $hash")
            .param("$hash", hash)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM id_magic_link_mail WHERE id = $id")
            .param("$id", ids[0].clone())
            .await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    let cleanup = async {
        client
            .query_client()
            .exec("DELETE FROM usid_outbox WHERE tenant_id = $id")
            .param("$id", tenant_id)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM usid_audit_log WHERE actor_user_id = $id")
            .param("$id", user_id)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM usid_tenant_membership WHERE id = $id")
            .param("$id", member_id)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM usid_tenant WHERE id = $id")
            .param("$id", tenant_id)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM usid_user WHERE user_id = $id")
            .param("$id", user_id)
            .await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    result.context("request/consume scenario")?;
    cleanup?;
    Ok(())
}
