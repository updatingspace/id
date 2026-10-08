#![recursion_limit = "256"]
//! Private HTTP worker for mail outboxes and resumable account-deletion stages.
use anyhow::{Result, ensure};
use clap::Parser;
use id_runtime::{
    jobs_http,
    new_device_mail::{self, MailWorker},
};
use std::{net::SocketAddr, sync::Arc};

#[derive(Parser)]
struct Args {
    #[arg(long, default_value_t = 25)]
    limit: u64,
    #[arg(long)]
    serve: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().json().init();
    let args = Args::parse();
    let client = Arc::new(id_runtime::connect_ydb().await?);
    if args.serve {
        ensure!(
            std::env::var("ID_JOBS_HTTP_ENABLED").as_deref() == Ok("true"),
            "private jobs HTTP mode requires ID_JOBS_HTTP_ENABLED=true"
        );
        let gravatar = if std::env::var("ID_GRAVATAR_JOB_ENABLED").as_deref() == Ok("true") {
            let limit: usize = std::env::var("GRAVATAR_BATCH_LIMIT")
                .unwrap_or_else(|_| "25".into())
                .parse()?;
            ensure!((1..=100).contains(&limit), "invalid Gravatar batch limit");
            Some((
                Arc::new(id_runtime::gravatar_job::GravatarJob::from_env(
                    client.clone(),
                )?),
                limit,
            ))
        } else {
            None
        };
        let worker = Arc::new(MailWorker::from_env(client)?);
        let port: u16 = std::env::var("PORT")
            .unwrap_or_else(|_| "8080".into())
            .parse()?;
        let listener =
            tokio::net::TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port))).await?;
        tracing::info!(port, "private Rust jobs listening");
        let deletion_rollout = match std::env::var("ID_DELETION_JOBS_ROLLOUT_ENABLED").as_deref() {
            Ok("true") => true,
            Ok("false") | Err(std::env::VarError::NotPresent) => false,
            _ => anyhow::bail!("invalid deletion recovery rollout flag"),
        };
        if deletion_rollout {
            ensure!(
                cfg!(feature = "passkeys")
                    && std::env::var("ID_EXPORT_ESCROW_JOBS_ROLLOUT_ENABLED").as_deref()
                        == Ok("true")
                    && worker.exports_enabled(),
                "deletion recovery requires delayed export escrow and storage jobs"
            );
        }
        let mut app = jobs_http::router(worker.clone());
        #[cfg(feature = "passkeys")]
        if deletion_rollout {
            app = app.merge(jobs_http::deletion_router(worker));
        }
        if let Some((job, limit)) = gravatar {
            app = app.merge(jobs_http::gravatar_router(job, limit));
        }
        axum::serve(listener, app)
            .with_graceful_shutdown(id_runtime::shutdown_signal())
            .await?;
        return Ok(());
    }
    let result = new_device_mail::drain_once(&client, args.limit).await?;
    println!(
        "{}",
        serde_json::json!({"claimed": result.claimed, "sent": result.sent,
            "deferred": result.deferred, "cancelled": result.cancelled})
    );
    Ok(())
}
