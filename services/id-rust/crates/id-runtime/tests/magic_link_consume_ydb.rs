#![recursion_limit = "256"]
//! Synthetic Portal magic link, one-time consume, and BFF code on local YDB.

use anyhow::{Context, Result, ensure};
use hmac::{Hmac, KeyInit, Mac};
use id_runtime::{
    cache_store::CacheStore,
    magic_link_consume::{self, ConsumeFailure, ConsumeRequest},
};
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::task::JoinSet;
use uuid::Uuid;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires migrated disposable local YDB; writes synthetic Portal rows"]
async fn magic_link_consumes_once_with_session_exchange_and_audit() -> Result<()> {
    let endpoint = std::env::var("YDB_ENDPOINT")?;
    ensure!(
        matches!(
            endpoint.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "magic link test requires local YDB on port 2136"
    );
    let first = Arc::new(id_runtime::connect_ydb().await?);
    let second = Arc::new(id_runtime::connect_ydb().await?);
    let cache_a = CacheStore::new(first.clone(), "id_shared_cache", "", 1)?;
    let cache_b = CacheStore::new(second.clone(), "id_shared_cache", "", 1)?;
    let user_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let member_id = -i64::from(u32::from_le_bytes(rand::random::<[u8; 4]>())) - 1;
    let slug = format!("magic-{}", tenant_id.simple());
    let raw_token = format!("test-{}", Uuid::new_v4().simple());
    let secret = b"synthetic-magic-link-hash-key-32-bytes";
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)?;
    mac.update(raw_token.as_bytes());
    let token_hash = hex::encode(mac.finalize().into_bytes());
    let ip = "192.0.2.8";
    let agent = "rust-magic-link-ydb-test";
    let ip_hash = hex::encode(Sha256::digest(ip.as_bytes()));
    let ua_hash = hex::encode(Sha256::digest(agent.as_bytes()));
    let now = SystemTime::now();

    first.query_client().exec("INSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, '', '', $email, true, 'active', false, CurrentUtcDatetime())")
        .param("$id", user_id).param("$email", format!("{user_id}@example.invalid")).await?;
    first.query_client().exec("INSERT INTO usid_tenant (id, slug, created_at) VALUES ($id, $slug, CurrentUtcDatetime())")
        .param("$id", tenant_id).param("$slug", slug.clone()).await?;
    first.query_client().exec("INSERT INTO usid_tenant_membership (id, user_id, tenant_id, status, base_role, source, created_at) VALUES ($id, $user, $tenant, 'active', 'member', 'native', CurrentUtcDatetime())")
        .param("$id", member_id).param("$user", user_id).param("$tenant", tenant_id).await?;
    first.query_client().exec("INSERT INTO usid_magic_link_token (token, user_id, expires_at, ip_hash, ua_hash, skip_context_validation, created_at) VALUES ($token, $user, CAST($expires AS Datetime), $ip, $ua, false, CurrentUtcDatetime())")
        .param("$token", token_hash.clone()).param("$user", user_id)
        .param("$expires", now + Duration::from_secs(900)).param("$ip", ip_hash).param("$ua", ua_hash).await?;

    let result: Result<()> = async {
        let request = ConsumeRequest {
            token: raw_token,
            tenant_id,
            tenant_slug: slug,
            ip: ip.into(),
            user_agent: agent.into(),
            issue_exchange: true,
        };
        let mut wrong_context = request.clone();
        wrong_context.ip = "192.0.2.9".into();
        ensure!(
            magic_link_consume::consume(&first, &cache_a, secret, wrong_context, now).await?
                == Err(ConsumeFailure::ContextMismatch),
            "wrong IP did not fail closed"
        );
        let mut wrong_tenant = request.clone();
        wrong_tenant.tenant_id = Uuid::new_v4();
        ensure!(
            magic_link_consume::consume(&first, &cache_a, secret, wrong_tenant, now).await?
                == Err(ConsumeFailure::InvalidTenant),
            "wrong tenant did not fail closed"
        );
        let mut contenders = JoinSet::new();
        for index in 0..100 {
            let client = if index % 2 == 0 {
                first.clone()
            } else {
                second.clone()
            };
            let cache = if index % 2 == 0 {
                cache_a.clone()
            } else {
                cache_b.clone()
            };
            let request = request.clone();
            contenders.spawn(async move {
                magic_link_consume::consume(&client, &cache, secret, request, SystemTime::now())
                    .await
            });
        }
        let mut success = None;
        while let Some(done) = contenders.join_next().await {
            match done.context("consumer panicked")?? {
                Ok(consumed) => {
                    ensure!(success.replace(consumed).is_none(), "double consumption");
                }
                Err(ConsumeFailure::Used) => {}
                Err(other) => anyhow::bail!("unexpected consume result: {other:?}"),
            }
        }
        let success = success.context("no consumer succeeded")?;
        ensure!(success.user_id == user_id);
        let code = success.exchange_code.context("missing BFF exchange code")?;
        let key = format!("usid:exchange:{code}");
        let value = cache_a
            .take(&key, SystemTime::now())
            .await?
            .context("exchange code missing")?;
        let id_compat::cache::CacheValue::Map(fields) = value else {
            anyhow::bail!("exchange payload malformed")
        };
        ensure!(
            fields.get("user_id")
                == Some(&id_compat::cache::CacheValue::String(user_id.to_string()))
        );
        ensure!(
            cache_b.take(&key, SystemTime::now()).await?.is_none(),
            "exchange replay succeeded"
        );
        let mut session = first
            .query_client()
            .query_row("SELECT user_id FROM usid_session WHERE token = $token")
            .param("$token", success.session_token.clone())
            .await?;
        let session_owner: Uuid = session.remove_field_by_name("user_id")?.try_into()?;
        ensure!(session_owner == user_id);
        first
            .query_client()
            .exec("DELETE FROM usid_session WHERE token = $token")
            .param("$token", success.session_token)
            .await?;
        Ok(())
    }
    .await;

    let cleanup = async {
        first
            .query_client()
            .exec("DELETE FROM usid_outbox WHERE tenant_id = $id")
            .param("$id", tenant_id)
            .await?;
        first
            .query_client()
            .exec("DELETE FROM usid_audit_log WHERE actor_user_id = $id")
            .param("$id", user_id)
            .await?;
        first
            .query_client()
            .exec("DELETE FROM usid_magic_link_token WHERE token = $token")
            .param("$token", token_hash)
            .await?;
        first
            .query_client()
            .exec("DELETE FROM usid_tenant_membership WHERE id = $id")
            .param("$id", member_id)
            .await?;
        first
            .query_client()
            .exec("DELETE FROM usid_tenant WHERE id = $id")
            .param("$id", tenant_id)
            .await?;
        first
            .query_client()
            .exec("DELETE FROM usid_user WHERE user_id = $id")
            .param("$id", user_id)
            .await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    result?;
    cleanup?;
    Ok(())
}
