//! Legacy token cleanup against a migrated disposable local YDB.

use anyhow::{Result, ensure};
use id_runtime::token_cleanup::cleanup;
use std::time::{Duration, SystemTime};
use uuid::Uuid;
use ydb::Client;

async fn insert(
    client: &Client,
    table: &str,
    key: &str,
    expires: SystemTime,
    used: Option<SystemTime>,
) -> Result<()> {
    let user_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let used_expr = if used.is_some() {
        "CAST($used AS Datetime)"
    } else {
        "CAST(NULL AS Datetime?)"
    };
    let sql = match table {
        "usid_activation_token" => format!(
            "UPSERT INTO usid_activation_token (token, user_id, tenant_id, expires_at, used_at, created_at) VALUES ($key, $user_id, $tenant_id, CAST($expires AS Datetime), {used_expr}, CurrentUtcDatetime())"
        ),
        "usid_magic_link_token" => format!(
            "UPSERT INTO usid_magic_link_token (token, user_id, expires_at, used_at, ip_hash, ua_hash, skip_context_validation, created_at) VALUES ($key, $user_id, CAST($expires AS Datetime), {used_expr}, '', '', false, CurrentUtcDatetime())"
        ),
        "usid_oauth_state" => format!(
            "UPSERT INTO usid_oauth_state (state, nonce, provider, purpose, user_id, tenant_id, redirect_uri, expires_at, used_at, created_at) VALUES ($key, 'synthetic', 'github', 'login', $user_id, $tenant_id, '', CAST($expires AS Datetime), {used_expr}, CurrentUtcDatetime())"
        ),
        _ => anyhow::bail!("unsupported fixture table"),
    };
    let mut pager = client.query_client();
    let query = pager
        .exec(sql)
        .param("$key", key.to_owned())
        .param("$user_id", user_id)
        .param("$tenant_id", tenant_id)
        .param("$expires", expires);
    if let Some(used) = used {
        query.param("$used", used).await?;
    } else {
        query.await?;
    }
    Ok(())
}

async fn exists(client: &Client, table: &str, key: &str) -> Result<bool> {
    let field = if table == "usid_oauth_state" {
        "state"
    } else {
        "token"
    };
    let sql = format!("SELECT `{field}` FROM `{table}` WHERE `{field}` = $key");
    Ok(client
        .query_client()
        .query_row(sql)
        .param("$key", key.to_owned())
        .optional()
        .await?
        .is_some())
}

#[tokio::test]
#[ignore = "requires a disposable migrated local YDB"]
async fn dry_run_then_delete_due_rows_only_and_repeat_safely() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "test must use local YDB"
    );
    let client = id_runtime::connect_ydb().await?;
    let now = SystemTime::now();
    let prefix = format!("rust-cleanup-{}", Uuid::new_v4());
    let tables = [
        "usid_activation_token",
        "usid_magic_link_token",
        "usid_oauth_state",
    ];
    for table in tables {
        insert(
            &client,
            table,
            &format!("{prefix}-{table}-expired"),
            now - Duration::from_secs(60),
            None,
        )
        .await?;
        insert(
            &client,
            table,
            &format!("{prefix}-{table}-old-used"),
            now + Duration::from_secs(3600),
            Some(now - Duration::from_secs(8 * 86_400)),
        )
        .await?;
        insert(
            &client,
            table,
            &format!("{prefix}-{table}-recent-used"),
            now + Duration::from_secs(3600),
            Some(now - Duration::from_secs(86_400)),
        )
        .await?;
        insert(
            &client,
            table,
            &format!("{prefix}-{table}-active"),
            now + Duration::from_secs(3600),
            None,
        )
        .await?;
    }
    let dry = cleanup(&client, now, 7, 2, false).await?;
    ensure!(dry.dry_run && dry.eligible >= 6 && dry.deleted == 0);
    for table in tables {
        ensure!(exists(&client, table, &format!("{prefix}-{table}-expired")).await?);
    }
    let result = cleanup(&client, now, 7, 2, true).await?;
    ensure!(result.deleted >= 6, "due rows were not deleted: {result:?}");
    for table in tables {
        for suffix in ["expired", "old-used"] {
            ensure!(
                !exists(&client, table, &format!("{prefix}-{table}-{suffix}")).await?,
                "due token survived"
            );
        }
        for suffix in ["recent-used", "active"] {
            ensure!(
                exists(&client, table, &format!("{prefix}-{table}-{suffix}")).await?,
                "live token was deleted"
            );
            let field = if table == "usid_oauth_state" {
                "state"
            } else {
                "token"
            };
            client
                .query_client()
                .exec(format!("DELETE FROM `{table}` WHERE `{field}` = $key"))
                .param("$key", format!("{prefix}-{table}-{suffix}"))
                .await?;
        }
    }
    let repeated = cleanup(&client, now, 7, 2, true).await?;
    ensure!(repeated.deleted == 0, "second cleanup changed rows");
    Ok(())
}
