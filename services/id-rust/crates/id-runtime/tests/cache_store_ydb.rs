#![recursion_limit = "256"]
//! Only a uniquely named scratch table in an explicitly local YDB is changed.
use anyhow::{Context, Result, ensure};
use id_compat::cache::{self, CacheValue};
use id_runtime::cache_store::CacheStore;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use ydb::Client;

async fn insert(
    client: &Client,
    table: &str,
    key: String,
    value: Vec<u8>,
    expires_at: u64,
) -> Result<()> {
    client
        .query_client()
        .exec(format!(
            "UPSERT INTO `{table}` (cache_key, value, expires_at) VALUES ($key, $value, $expiry)"
        ))
        .param("$key", key)
        .param("$value", ydb::Bytes::from(value))
        .param("$expiry", expires_at)
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires local YDB; creates and drops one synthetic cache table"]
async fn portable_cache_preserves_ttl_and_one_time_consumption() -> Result<()> {
    let endpoint = std::env::var("YDB_ENDPOINT")?;
    ensure!(
        matches!(
            endpoint.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "scratch test requires local YDB on port 2136"
    );
    let first = Arc::new(id_runtime::connect_ydb().await?);
    let second = Arc::new(id_runtime::connect_ydb().await?);
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let table = format!("id_cache_pilot_{}_{}", std::process::id(), stamp);
    first
        .query_client()
        .exec(format!(
            "CREATE TABLE `{table}` (cache_key Utf8 NOT NULL, value String, expires_at Uint64, PRIMARY KEY(cache_key))"
        ))
        .await?;
    let result: Result<()> = async {
        let store_a = CacheStore::new(first.clone(), &table, "pilot", 1)?;
        let store_b = CacheStore::new(second.clone(), &table, "pilot", 1)?;
        ensure!(
            store_a.key("formtoken:synthetic")
                == "8af4ee25e3292e8be46ac3c20848d5d284470d2854a639ee56be93c8ac057f42",
            "Django cache key mismatch"
        );
        let now = SystemTime::now();
        let expiry = now.duration_since(UNIX_EPOCH)?.as_secs() + 3600;
        let value = CacheValue::String("synthetic-one-time-value".into());
        insert(
            &first,
            &table,
            store_a.key("single"),
            cache::encode(&value)?,
            expiry,
        )
        .await?;
        ensure!(
            store_b.get("single", now).await? == Some(value.clone()),
            "portable read failed"
        );
        ensure!(
            store_a.take("single", now).await? == Some(value.clone()),
            "first consume failed"
        );
        ensure!(
            store_b.take("single", now).await?.is_none(),
            "replay succeeded"
        );

        insert(
            &first,
            &table,
            store_a.key("expired"),
            cache::encode(&value)?,
            expiry - 7200,
        )
        .await?;
        ensure!(
            store_b.get("expired", now).await?.is_none(),
            "expired read succeeded"
        );
        ensure!(
            store_b.take("expired", now).await?.is_none(),
            "expired consume succeeded"
        );

        insert(
            &first,
            &table,
            store_a.key("legacy"),
            b"\x80\x04N.".to_vec(),
            expiry,
        )
        .await?;
        ensure!(
            store_b.get("legacy", now).await.is_err(),
            "legacy pickle appeared portable"
        );
        ensure!(
            store_b.take("legacy", now).await.is_err(),
            "legacy pickle was consumed"
        );
        insert(
            &first,
            &table,
            store_a.key("malformed"),
            b"USID-CACHE\x01\nnot-json".to_vec(),
            expiry,
        )
        .await?;
        for index in 0..105 {
            insert(
                &first,
                &table,
                store_a.key(&format!("audit-page-{index}")),
                cache::encode(&value)?,
                expiry,
            )
            .await?;
        }
        let audit = store_a.audit(now).await?;
        ensure!(
            audit.scanned == 108
                && audit.expired == 1
                && audit.legacy == 1
                && audit.malformed == 1
                && audit.portable == 105,
            "cache audit classifications differed: {audit:?}"
        );
        ensure!(
            store_a.add("legacy", &value, Some(now), now).await.is_err(),
            "add replaced an unsupported legacy row"
        );
        ensure!(
            store_a.add("malformed", &value, None, now).await.is_err(),
            "add replaced a malformed row"
        );
        ensure!(
            !store_a.add("audit-page-1", &value, None, now).await?,
            "add replaced a live row"
        );
        ensure!(
            store_a.add("expired", &value, None, now).await?,
            "add did not replace an expired row"
        );
        ensure!(
            store_a
                .add(
                    "counter",
                    &CacheValue::Int(0),
                    Some(now + std::time::Duration::from_secs(3600)),
                    now
                )
                .await?,
            "counter initialization failed"
        );
        let mut increments = tokio::task::JoinSet::new();
        for index in 0..100 {
            let store = if index % 2 == 0 {
                store_a.clone()
            } else {
                store_b.clone()
            };
            increments.spawn(async move { store.incr("counter", 1, SystemTime::now()).await });
        }
        let mut values = Vec::new();
        while let Some(task) = increments.join_next().await {
            values.push(task.context("counter contender panicked")??);
        }
        values.sort_unstable();
        ensure!(
            values == (1..=100).collect::<Vec<_>>(),
            "counter lost updates"
        );
        ensure!(
            store_a.get("counter", now).await? == Some(CacheValue::Int(100)),
            "final counter differs"
        );
        ensure!(
            store_a
                .get("counter", now + std::time::Duration::from_secs(3601))
                .await?
                .is_none(),
            "increment extended the original TTL"
        );
        ensure!(
            store_a.incr("missing", 1, now).await.is_err(),
            "missing counter incremented"
        );
        let add_barrier = Arc::new(tokio::sync::Barrier::new(100));
        let mut adds = tokio::task::JoinSet::new();
        for index in 0..100 {
            let store = if index % 2 == 0 {
                store_a.clone()
            } else {
                store_b.clone()
            };
            let barrier = add_barrier.clone();
            let value = value.clone();
            adds.spawn(async move {
                barrier.wait().await;
                store.add("add-race", &value, None, SystemTime::now()).await
            });
        }
        let mut added = 0;
        while let Some(task) = adds.join_next().await {
            added += usize::from(task.context("add contender panicked")??);
        }
        ensure!(added == 1, "{added} concurrent add operations succeeded");

        let rounds: usize = std::env::var("ID_CACHE_RACE_ROUNDS")
            .unwrap_or_else(|_| "10".into())
            .parse()?;
        ensure!(rounds > 0 && rounds <= 100, "rounds must be 1..=100");
        for round in 0..rounds {
            let key = format!("race-{round}");
            insert(
                &first,
                &table,
                store_a.key(&key),
                cache::encode(&value)?,
                expiry,
            )
            .await?;
            let barrier = Arc::new(tokio::sync::Barrier::new(100));
            let mut tasks = tokio::task::JoinSet::new();
            for index in 0..100 {
                let store = if index % 2 == 0 {
                    store_a.clone()
                } else {
                    store_b.clone()
                };
                let (key, barrier) = (key.clone(), barrier.clone());
                tasks.spawn(async move {
                    barrier.wait().await;
                    store.take(&key, SystemTime::now()).await
                });
            }
            let mut winners = 0;
            while let Some(task) = tasks.join_next().await {
                winners += usize::from(task.context("cache contender panicked")??.is_some());
            }
            ensure!(winners == 1, "round {round}: {winners} winners");
        }
        println!(
            "Portable YDB cache: {rounds} x 100 contenders, two clients, one winner per round"
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
