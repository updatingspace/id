#![recursion_limit = "256"]
//! Independent Rust clients spend one fixed-window login budget in local YDB.

use anyhow::{Context, Result, ensure};
use id_compat::cache::{self, CacheValue};
use id_runtime::{cache_store::CacheStore, login_rate_limit::login_attempt};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires local YDB; creates and drops synthetic rate-limit cache table"]
async fn rust_instances_share_login_budgets() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "login rate test requires local YDB on port 2136"
    );
    let first = Arc::new(id_runtime::connect_ydb().await?);
    let second = Arc::new(id_runtime::connect_ydb().await?);
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let table = format!("id_rate_pilot_{}_{}", std::process::id(), stamp);
    first.query_client().exec(format!(
        "CREATE TABLE `{table}` (cache_key Utf8 NOT NULL, value String, expires_at Uint64, PRIMARY KEY(cache_key))"
    )).await?;
    let result: Result<()> = async {
        let a = CacheStore::new(first.clone(), &table, "", 1)?;
        let b = CacheStore::new(second.clone(), &table, "", 1)?;
        let now = SystemTime::now();
        let email = format!("rate-{stamp}@example.invalid");
        for _ in 0..4 {
            ensure!(!login_attempt(&a, Some("192.0.2.5"), Some(&email), 50, now).await?.blocked);
        }
        ensure!(!login_attempt(&b, Some("192.0.2.5"), Some(&email), 50, now).await?.blocked);
        ensure!(login_attempt(&b, Some("192.0.2.5"), Some(&email), 50, now).await?.blocked,
            "Rust did not enforce the shared account limit");
        let other = format!("other-{stamp}@example.invalid");
        ensure!(!login_attempt(&b, Some("192.0.2.5"), Some(&other), 50, now).await?.blocked,
            "account limit was incorrectly applied to another account");

        // Seven attempts have spent the shared IP budget so far. Distinct
        // emails must still exhaust that budget across both instances.
        for index in 7..50 {
            let email = format!("ip-{stamp}-{index}@example.invalid");
            ensure!(!login_attempt(&a, Some("192.0.2.5"), Some(&email), 50, now).await?.blocked);
        }
        let new_email = format!("ip-block-{stamp}@example.invalid");
        ensure!(login_attempt(&b, Some("192.0.2.5"), Some(&new_email), 50, now).await?.blocked);

        let shared_key = format!("rl:login:email:race-{stamp}@example.invalid");
        let mut tasks = tokio::task::JoinSet::new();
        for index in 0..100 {
            let store = if index % 2 == 0 { a.clone() } else { b.clone() };
            let key = shared_key.clone();
            tasks.spawn(async move { store.advance_window(&key, 300, now).await });
        }
        let mut counts = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            counts.push(joined??.count);
        }
        counts.sort_unstable();
        ensure!(counts == (1..=100).collect::<Vec<_>>(),
            "concurrent rate-limit increments lost or duplicated counts");

        let bad_key = format!("rl:login:email:bad-{stamp}@example.invalid");
        let raw = cache::encode(&CacheValue::String("malformed".into()))?;
        first.query_client().exec(format!(
            "UPSERT INTO `{table}` (cache_key, value, expires_at) VALUES ($key, $value, $expiry)"
        )).param("$key", a.key(&bad_key)).param("$value", ydb::Bytes::from(raw))
            .param("$expiry", Some((now + Duration::from_secs(300)).duration_since(UNIX_EPOCH)?.as_secs())).await?;
        ensure!(a.advance_window(&bad_key, 300, now).await.is_err(),
            "malformed active budget was reset instead of failing closed");
        let last = a.get(&shared_key, now).await?.context("missing race counter")?;
        let CacheValue::Map(fields) = last else { anyhow::bail!("rate counter is not a map") };
        ensure!(fields.get("count") == Some(&CacheValue::Int(100)));
        ensure!(b.advance_window(&shared_key, 300, now + Duration::from_secs(301)).await?.count == 1,
            "expired fixed window did not reset");
        Ok(())
    }.await;
    first
        .query_client()
        .exec(format!("DROP TABLE `{table}`"))
        .await?;
    result
}
