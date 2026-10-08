#![recursion_limit = "256"]
//! Destructive only to a uniquely named scratch table in a loopback YDB.
//! This is SDK evidence, not acceptance of production credential consumption.
use anyhow::{Context, Result, ensure};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use ydb::{Client, Transaction, TxMode, closure};

async fn consume(client: &Client, table: &str, key: String) -> Result<bool> {
    let select = format!("SELECT consumed FROM {table} WHERE key = $key");
    let update = format!("UPDATE {table} SET consumed = true WHERE key = $key");
    Ok(client
        .query_client()
        .retry_tx(closure!(
            [key, select, update],
            async |tx: &mut Transaction| {
                let Some(mut row) = tx
                    .query_row(select.clone())
                    .param("$key", key.clone())
                    .optional()
                    .await?
                else {
                    return Ok(false);
                };
                let consumed: Option<bool> = row.remove_field_by_name("consumed")?.try_into()?;
                if consumed != Some(false) {
                    return Ok(false);
                }
                // SDK 0.18.2's implicit commit returns even definitive ABORTED
                // without retry. Commit on the final query retries confirmed
                // aborts; idempotent(false) still rejects ambiguous outcomes.
                tx.exec(update.clone())
                    .param("$key", key.clone())
                    .with_commit(true)
                    .await?;
                Ok(true)
            }
        ))
        .with_mode(TxMode::SerializableReadWrite)
        .idempotent(false)
        .timeout(Duration::from_secs(30))
        .await?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicitly configured local YDB; creates and drops its own scratch table"]
async fn nullable_values_timestamps_and_single_winner_across_two_clients() -> Result<()> {
    let endpoint = std::env::var("YDB_ENDPOINT")?;
    ensure!(
        matches!(
            endpoint.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ),
        "scratch test requires local YDB on port 2136"
    );
    ensure!(
        std::env::var("YDB_DATABASE")? == "/local",
        "scratch test requires /local"
    );
    let first = Arc::new(id_runtime::connect_ydb().await?);
    let second = Arc::new(id_runtime::connect_ydb().await?);
    for client in [&first, &second] {
        ensure!(
            client.session_pool_stats().sessions_created == 0,
            "connecting must not eagerly create YDB sessions"
        );
        id_runtime::probe(client).await?;
        ensure!(
            client.session_pool_stats().sessions_created > 0,
            "readiness must exercise lazy session creation"
        );
    }
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let table = format!("id_rust_pilot_{}_{}", std::process::id(), stamp);
    first.query_client().exec(format!("CREATE TABLE {table} (key Utf8, consumed Bool, payload Utf8, expires Timestamp, PRIMARY KEY(key))"))
        .timeout(Duration::from_secs(30)).await?;
    let result: Result<()> = async {
        let expires = UNIX_EPOCH + Duration::from_micros(1_770_000_000_123_456);
        first.query_client().exec(format!("UPSERT INTO {table} (key, expires) VALUES ($key, $expires)"))
            .param("$key", "nullable").param("$expires", expires).await?;
        let mut row = second.query_client().query_row(format!("SELECT consumed, payload, expires FROM {table} WHERE key = $key"))
            .param("$key", "nullable").await?;
        let consumed: Option<bool> = row.remove_field_by_name("consumed")?.try_into()?;
        let payload: Option<String> = row.remove_field_by_name("payload")?.try_into()?;
        let restored: Option<SystemTime> = row.remove_field_by_name("expires")?.try_into()?;
        ensure!(consumed.is_none() && payload.is_none() && restored == Some(expires), "nullable/timestamp mismatch");
        ensure!(!consume(&first, &table, "nullable".into()).await?, "null must fail closed");
        ensure!(!consume(&first, &table, "missing".into()).await?, "missing must fail closed");
        let rounds: usize = std::env::var("ID_YDB_RACE_ROUNDS").unwrap_or_else(|_| "100".into()).parse()?;
        ensure!(rounds > 0 && rounds <= 100, "round count must be 1..=100");
        for round in 0..rounds {
            let key = format!("race-{round}");
            first.query_client().exec(format!("UPSERT INTO {table} (key, consumed) VALUES ($key, false)"))
                .param("$key", key.clone()).await?;
            let barrier = Arc::new(tokio::sync::Barrier::new(100));
            let mut tasks = tokio::task::JoinSet::new();
            for i in 0..100 {
                let client = if i % 2 == 0 { first.clone() } else { second.clone() };
                let (table, key, barrier) = (table.clone(), key.clone(), barrier.clone());
                tasks.spawn(async move {
                    barrier.wait().await;
                    consume(&client, &table, key).await
                });
            }
            let mut winners = 0;
            while let Some(task) = tasks.join_next().await {
                winners += usize::from(task.context("race task crashed")??);
            }
            ensure!(winners == 1, "round {round}: expected one winner, got {winners}");
            ensure!(!consume(&second, &table, key).await?, "replay must lose");
        }
        println!("YDB pilot: {rounds} rounds x 100 concurrent attempts, two independent clients, one winner per round");
        Ok(())
    }.await;
    let cleanup = first
        .query_client()
        .exec(format!("DROP TABLE {table}"))
        .timeout(Duration::from_secs(30))
        .await;
    result?;
    cleanup?;
    Ok(())
}
