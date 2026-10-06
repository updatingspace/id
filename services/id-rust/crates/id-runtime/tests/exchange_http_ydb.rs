#![recursion_limit = "256"]
//! Signed BFF exchange against a disposable local YDB cache table.

use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use hmac::{Hmac, Mac};
use id_compat::cache::CacheValue;
use id_runtime::{
    cache_store::CacheStore,
    exchange_http::{self, ExchangeHttpConfig},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::task::JoinSet;
use tower::ServiceExt;

const SECRET: &[u8] = b"synthetic-exchange-secret-32-bytes-long";

async fn exchange(
    app: Router,
    code: &str,
    request_id: &str,
    valid_signature: bool,
) -> Result<(StatusCode, Value)> {
    let body = serde_json::to_vec(&json!({"code":code}))?;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let canonical = format!(
        "POST\n/api/v1/auth/exchange\n{}\n{}\n{}",
        hex::encode(Sha256::digest(&body)),
        request_id,
        timestamp
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET)?;
    mac.update(canonical.as_bytes());
    let signature = if valid_signature {
        hex::encode(mac.finalize().into_bytes())
    } else {
        "bad".into()
    };
    let request = Request::builder()
        .uri("/api/v1/auth/exchange")
        .method("POST")
        .header("content-type", "application/json")
        .header("x-request-id", request_id)
        .header("x-updspace-timestamp", timestamp.to_string())
        .header("x-updspace-signature", signature)
        .body(Body::from(body))?;
    let response = app.oneshot(request).await?;
    let status = response.status();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 8192).await?)?;
    Ok((status, body))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires disposable local YDB; creates and drops a scratch cache table"]
async fn signed_exchange_is_atomic_across_two_api_instances() -> Result<()> {
    let endpoint = std::env::var("YDB_ENDPOINT")?;
    ensure!(
        matches!(
            endpoint.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "exchange test requires local YDB on port 2136"
    );
    let first = Arc::new(id_runtime::connect_ydb().await?);
    let second = Arc::new(id_runtime::connect_ydb().await?);
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let table = format!("id_exchange_test_{}_{}", std::process::id(), stamp);
    first.query_client().exec(format!(
        "CREATE TABLE `{table}` (cache_key Utf8 NOT NULL, value String, expires_at Uint64, PRIMARY KEY(cache_key))"
    )).await?;
    let result: Result<()> = async {
        let cache_a = CacheStore::new(first.clone(), &table, "", 1)?;
        let cache_b = CacheStore::new(second.clone(), &table, "", 1)?;
        let app_a =
            exchange_http::router(ExchangeHttpConfig::new(cache_a.clone(), SECRET.to_vec())?);
        let app_b = exchange_http::router(ExchangeHttpConfig::new(cache_b, SECRET.to_vec())?);
        let code = format!("synthetic-{stamp}");
        let payload = CacheValue::Map(BTreeMap::from([
            (
                "user_id".into(),
                CacheValue::String("0d5e5f5a-7fd8-4a8f-a327-778b0e537fcb".into()),
            ),
            (
                "master_flags".into(),
                CacheValue::Map(BTreeMap::from([
                    ("email_verified".into(), CacheValue::Bool(true)),
                    ("system_admin".into(), CacheValue::Bool(false)),
                ])),
            ),
            ("ttl_seconds".into(), CacheValue::Int(120)),
        ]));
        let now = SystemTime::now();
        ensure!(
            cache_a
                .add(
                    &format!("usid:exchange:{code}"),
                    &payload,
                    Some(now + Duration::from_secs(60)),
                    now
                )
                .await?
        );
        let (status, body) = exchange(app_a.clone(), &code, "bad-signature", false).await?;
        ensure!(status == StatusCode::UNAUTHORIZED && body["code"] == "UNAUTHORIZED");
        let mut contenders = JoinSet::new();
        for index in 0..100 {
            let app = if index % 2 == 0 {
                app_a.clone()
            } else {
                app_b.clone()
            };
            let code = code.clone();
            contenders.spawn(async move {
                exchange(app, &code, &format!("request-{index}"), true).await
            });
        }
        let mut success = 0;
        while let Some(done) = contenders.join_next().await {
            let (status, body) = done.context("exchange contender panicked")??;
            match status {
                StatusCode::OK => {
                    success += 1;
                    ensure!(body["user_id"] == "0d5e5f5a-7fd8-4a8f-a327-778b0e537fcb");
                    ensure!(body["master_flags"]["email_verified"] == true);
                    ensure!(body["ttl_seconds"] == 120);
                }
                StatusCode::UNAUTHORIZED => ensure!(body["code"] == "UNAUTHORIZED"),
                other => anyhow::bail!("unexpected exchange response: {other}: {body}"),
            }
        }
        ensure!(
            success == 1,
            "exactly one code exchange must succeed, got {success}"
        );
        ensure!(
            cache_a
                .get(&format!("usid:exchange:{code}"), SystemTime::now())
                .await?
                .is_none()
        );
        Ok(())
    }
    .await;
    let cleanup = first
        .query_client()
        .exec(format!("DROP TABLE `{table}`"))
        .await;
    result?;
    cleanup?;
    Ok(())
}
