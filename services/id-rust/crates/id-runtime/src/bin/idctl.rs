#![recursion_limit = "256"]
#[path = "idctl/smoke_auth.rs"]
mod smoke_auth;
#[path = "idctl/smoke_exchange.rs"]
mod smoke_exchange;
#[path = "idctl/tested_revision.rs"]
mod tested_revision;
use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use id_compat::session::SessionCodec;
use serde_json::{Value, json};
use std::{fs, path::PathBuf, sync::Arc, time::SystemTime};

#[derive(Parser)]
#[command(about = "UpdSpace ID migration diagnostics (not production-qualified)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Reject a deployment unless the exact SHA passed every required CI job.
    VerifyTestedRevision,
    /// Exercise public auth forms without creating accounts or sending mail.
    SmokeAuth {
        #[arg(long, env = "SMOKE_BASE_URL")]
        base_url: String,
        #[arg(long, env = "SMOKE_HOST_HEADER")]
        host_header: Option<String>,
    },
    /// Exercise signed BFF exchange through a public Gateway with disposable YDB state.
    SmokeExchange {
        #[arg(long, env = "SMOKE_BASE_URL")]
        base_url: String,
    },
    /// Read-only YDB connection and query probe. Credentials come from environment.
    YdbProbe,
    /// Add or verify the shared one-time-state table used by Rust auth.
    CacheSchema {
        #[arg(long, env = "YDB_CACHE_TABLE", default_value = "id_shared_cache")]
        table: String,
    },
    /// Count portable, legacy, expired and malformed shared-cache rows without values.
    CacheAudit {
        #[arg(long, env = "YDB_CACHE_TABLE", default_value = "id_shared_cache")]
        table: String,
        #[arg(long)]
        require_portable: bool,
    },
    /// Count live MFA sessions that cannot yet cross to the Rust /me route.
    MfaSessionAudit {
        #[arg(long)]
        require_proven_mfa: bool,
    },
    /// Count legacy email collisions and Rust/YDB normalization differences.
    LoginEmailAudit {
        #[arg(long)]
        require_unambiguous: bool,
    },
    /// Count password hash and MFA formats without exposing credentials or identities.
    LoginCredentialAudit {
        #[arg(long)]
        require_supported: bool,
    },
    /// Repair derived email keys and remove orphan rows after draining old writers.
    LoginEmailReconcile {
        #[arg(long, default_value_t = 100)]
        batch: u64,
        #[arg(long)]
        apply: bool,
    },
    /// Audit or create unambiguous missing account/master identity bindings.
    IdentityReconcile {
        #[arg(long, default_value_t = 100)]
        batch: u64,
        #[arg(long)]
        apply: bool,
    },
    /// Count legacy passkeys that Rust can verify, plus invalid/duplicate credentials.
    #[cfg(feature = "passkeys")]
    PasskeyAudit {
        #[arg(long)]
        require_convertible: bool,
    },
    /// Create, backfill and verify the global passkey credential-ID index.
    #[cfg(feature = "passkeys")]
    PasskeyIndex,
    /// Create and verify the password-change notification outbox.
    PasswordMailSchema,
    /// Create and verify the account-security notification outbox.
    SecurityMailSchema,
    /// Create and verify password-recovery intents and their notification outbox.
    PasswordResetSchema,
    /// Create and verify Rust email-verification intents and indexes.
    EmailVerifySchema,
    /// Create and verify durable magic-link mail intents.
    MagicLinkSchema,
    /// Create and verify one-use email-change intents and address claims.
    EmailChangeSchema,
    /// Create and verify durable private export operation storage.
    DataExportSchema,
    /// Create and verify delayed export delivery escrow storage.
    DataExportEscrowSchema,
    /// Create and verify delayed export mail outbox storage.
    DataExportMailSchema,
    /// Revoke an unexpected delayed export; --apply also deletes its private archive.
    DataExportCancel {
        id: String,
        #[arg(long)]
        apply: bool,
    },
    /// Write, list, read and delete synthetic objects in the private export bucket.
    DataExportStorageSmoke,
    /// Check the frozen legacy YDB schema, or add missing objects on local YDB.
    LegacySchema {
        #[arg(long)]
        apply: bool,
    },
    /// Verify or record the four legacy migration versions after data audits.
    LegacyLedger {
        #[arg(long)]
        apply: bool,
    },
    /// Audit or delete expired legacy activation, magic-link and OAuth-state tokens.
    CleanupTokens {
        #[arg(long, default_value_t = 7)]
        retention_days: u64,
        #[arg(long, default_value_t = 200)]
        batch: u64,
        /// Actually delete eligible rows. Without this flag, only report counts.
        #[arg(long)]
        execute: bool,
    },
    /// Reset legacy sessions, applications and audit/outbox in bounded batches.
    LegacyCutoverReset {
        #[arg(long, default_value_t = 100)]
        batch: u64,
        #[arg(long)]
        apply: bool,
    },
    /// Seal completed legacy reset before admitting new Rust traffic.
    LegacyCutoverSeal {
        #[arg(long)]
        apply: bool,
    },
    /// Read an account deletion operation without exposing its owner or reason.
    DeletionStatus { id: i64 },
    /// Count residual identity references without printing personal data.
    #[cfg(feature = "passkeys")]
    DeletionAudit { id: i64 },
    /// Erase exact UUID references from legacy global audit/outbox rows.
    #[cfg(feature = "passkeys")]
    DeletionEraseGlobal {
        id: i64,
        #[arg(long)]
        apply: bool,
    },
    /// Complete a deletion after sealed cutover and all cleanup checks.
    #[cfg(feature = "passkeys")]
    DeletionFinalize {
        id: i64,
        #[arg(long)]
        apply: bool,
    },
    /// Erase credentials for one accepted deletion; personal-data cleanup remains pending.
    #[cfg(feature = "passkeys")]
    DeletionEraseCredentials {
        id: i64,
        #[arg(long)]
        apply: bool,
    },
    /// Retry the media marker for one deletion and surface an exact YDB error.
    #[cfg(feature = "passkeys")]
    DeletionEraseAvatar {
        id: i64,
        #[arg(long)]
        apply: bool,
    },
    /// Erase profile and history for one deletion without scanning other owners.
    #[cfg(feature = "passkeys")]
    DeletionEraseProfile {
        id: i64,
        #[arg(long)]
        apply: bool,
    },
    /// Confirm a clean global-reference scan for one deletion operation.
    #[cfg(feature = "passkeys")]
    DeletionCompleteGlobal {
        id: i64,
        #[arg(long)]
        apply: bool,
    },
    /// Verify synthetic Python fixtures and emit Rust sessions for reverse checks.
    CompatFixtures { input: PathBuf, output: PathBuf },
    /// Print the registered operation count and collisions from a Python baseline.
    Inventory { input: PathBuf },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::VerifyTestedRevision => {
            tested_revision::run().await?;
        }
        Command::SmokeAuth {
            base_url,
            host_header,
        } => {
            smoke_auth::run(&base_url, host_header.as_deref()).await?;
        }
        Command::SmokeExchange { base_url } => {
            smoke_exchange::run(&base_url).await?;
        }
        Command::YdbProbe => {
            let client = id_runtime::connect_ydb().await?;
            id_runtime::probe(&client).await?;
            println!(
                "{}",
                json!({"ydb_query": "pass", "production_qualified": false})
            );
        }
        Command::CacheSchema { table } => {
            let client = id_runtime::connect_ydb().await?;
            id_runtime::cache_store::ensure_schema(&client, &table).await?;
            println!("{}", json!({"table": table, "ready": true}));
        }
        Command::CacheAudit {
            table,
            require_portable,
        } => {
            let client = Arc::new(id_runtime::connect_ydb().await?);
            let store = id_runtime::cache_store::CacheStore::new(client, &table, "", 1)?;
            let audit = store.audit(SystemTime::now()).await?;
            println!("{}", serde_json::to_string(&audit)?);
            ensure!(
                !require_portable || (audit.legacy == 0 && audit.malformed == 0),
                "unexpired legacy or malformed cache rows remain"
            );
        }
        Command::MfaSessionAudit { require_proven_mfa } => {
            let client = id_runtime::connect_ydb().await?;
            let codec = id_runtime::session_store::session_codec_from_env()?;
            let audit = id_runtime::session_audit::audit_mfa_sessions(
                &client,
                codec,
                id_runtime::session_store::LEGACY_BACKENDS,
                SystemTime::now(),
            )
            .await?;
            println!("{}", serde_json::to_string(&audit)?);
            ensure!(
                !require_proven_mfa || audit.eligible_mfa_unproven == 0,
                "eligible MFA sessions without bound proof remain"
            );
        }
        Command::LoginEmailAudit {
            require_unambiguous,
        } => {
            let client = id_runtime::connect_ydb().await?;
            let audit = id_runtime::login_email_audit::audit_auth_user(&client).await?;
            println!("{}", serde_json::to_string(&audit)?);
            ensure!(
                !require_unambiguous || audit.unambiguous(),
                "account email collisions, lookup drift, empty emails or normalization differences remain"
            );
        }
        Command::LoginCredentialAudit { require_supported } => {
            let client = id_runtime::connect_ydb().await?;
            let audit = id_runtime::login_credential_audit::audit(&client).await?;
            println!("{}", serde_json::to_string(&audit)?);
            ensure!(
                !require_supported || audit.supported(),
                "unsupported password hashes or malformed MFA records remain"
            );
        }
        Command::LoginEmailReconcile { batch, apply } => {
            let client = id_runtime::connect_ydb().await?;
            let report =
                id_runtime::email_lookup_reconcile::reconcile(&client, batch, apply).await?;
            println!("{}", serde_json::to_string(&report)?);
        }
        Command::IdentityReconcile { batch, apply } => {
            if apply {
                id_runtime::legacy_schema::require_local_ydb_for_pilot()?;
            }
            let client = id_runtime::connect_ydb().await?;
            let report = id_runtime::identity_reconcile::reconcile(&client, batch, apply).await?;
            println!("{}", serde_json::to_string(&report)?);
        }
        #[cfg(feature = "passkeys")]
        Command::PasskeyAudit {
            require_convertible,
        } => {
            let client = id_runtime::connect_ydb().await?;
            let audit = id_runtime::passkey_audit::audit_from_env(&client).await?;
            println!("{}", serde_json::to_string(&audit)?);
            ensure!(
                !require_convertible || audit.ready(),
                "legacy passkeys require migration review"
            );
        }
        #[cfg(feature = "passkeys")]
        Command::PasskeyIndex => {
            let client = id_runtime::connect_ydb().await?;
            let report = id_runtime::passkey_index::backfill(&client).await?;
            println!("{}", serde_json::to_string(&report)?);
        }
        Command::PasswordMailSchema => {
            let client = id_runtime::connect_ydb().await?;
            id_runtime::password_mail::ensure_schema(&client).await?;
            println!("{}", json!({"password_mail_schema":"ready"}));
        }
        Command::SecurityMailSchema => {
            let client = id_runtime::connect_ydb().await?;
            id_runtime::security_mail::ensure_schema(&client).await?;
            println!("{}", json!({"security_mail_schema":"ready"}));
        }
        Command::PasswordResetSchema => {
            let client = id_runtime::connect_ydb().await?;
            id_runtime::password_mail::ensure_schema(&client).await?;
            id_runtime::password_reset::ensure_schema(&client).await?;
            println!(
                "{}",
                json!({"password_reset_schema":"ready","password_mail_schema":"ready"})
            );
        }
        Command::EmailVerifySchema => {
            let client = id_runtime::connect_ydb().await?;
            id_runtime::email_verify::ensure_schema(&client).await?;
            println!("{}", json!({"email_verify_schema":"ready"}));
        }
        Command::MagicLinkSchema => {
            let client = id_runtime::connect_ydb().await?;
            id_runtime::magic_link_request::ensure_schema(&client).await?;
            println!("{}", json!({"magic_link_schema":"ready"}));
        }
        Command::EmailChangeSchema => {
            let client = id_runtime::connect_ydb().await?;
            id_runtime::email_change::ensure_schema(&client).await?;
            println!("{}", json!({"email_change_schema":"ready"}));
        }
        Command::DataExportSchema => {
            let client = id_runtime::connect_ydb().await?;
            id_runtime::data_export_operation::ensure_schema(&client).await?;
            println!("{}", json!({"data_export_schema":"ready"}));
        }
        Command::DataExportEscrowSchema => {
            let client = id_runtime::connect_ydb().await?;
            id_runtime::data_export_escrow::ensure_schema(&client).await?;
            println!("{}", json!({"data_export_escrow_schema":"ready"}));
        }
        Command::DataExportMailSchema => {
            let client = id_runtime::connect_ydb().await?;
            id_runtime::data_export_mail::ensure_schema(&client).await?;
            println!("{}", json!({"data_export_mail_schema":"ready"}));
        }
        Command::DataExportCancel { id, apply } => {
            ensure!(
                id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "invalid export ID"
            );
            let client = id_runtime::connect_ydb().await?;
            if !apply {
                let row = client
                    .query_client()
                    .query_row("SELECT state, object_key FROM id_data_export_escrow WHERE id = $id")
                    .param("$id", id.clone())
                    .optional()
                    .await?;
                let Some(mut row) = row else {
                    println!("{}", json!({"export":"not_found", "applied":false}));
                    return Ok(());
                };
                let state: String = row.remove_field_by_name("state")?.try_into()?;
                let object_key: String = row.remove_field_by_name("object_key")?.try_into()?;
                println!(
                    "{}",
                    json!({"state":state, "private_object_present":!object_key.is_empty(), "applied":false})
                );
            } else {
                let Some(key) = id_runtime::data_export_escrow::cancel(&client, &id).await? else {
                    println!(
                        "{}",
                        json!({"export":"not_found_or_expired", "applied":false})
                    );
                    return Ok(());
                };
                if !key.is_empty() {
                    id_runtime::data_export_s3::S3Export::from_env()?
                        .delete_object(&key)
                        .await
                        .context(
                            "export link revoked; private object deletion still needs retry",
                        )?;
                }
                ensure!(
                    id_runtime::data_export_escrow::forget_cancelled(&client, &id, &key).await?,
                    "export link revoked; private object cleanup state needs inspection"
                );
                println!("{}", json!({"state":"expired", "applied":true}));
            }
        }
        Command::DataExportStorageSmoke => {
            let storage = id_runtime::data_export_s3::S3Export::from_env()?;
            let smoke_id = uuid::Uuid::new_v4();
            let escrow_id = smoke_id.simple().to_string();
            let keys = [
                format!("exports/user_0/smoke/{smoke_id}.ndjson"),
                format!("exports/escrow/{escrow_id}/{}.ndjson", uuid::Uuid::new_v4()),
            ];
            let body = b"{\"category\":\"smoke\"}\n".to_vec();
            for (index, key) in keys.into_iter().enumerate() {
                if let Err(error) = storage
                    .upload_stream(&key, std::io::Cursor::new(body.clone()))
                    .await
                {
                    let _ = storage.delete_object(&key).await;
                    return Err(error);
                }
                let checked = async {
                    let url = storage.download_url(&key)?;
                    let response = reqwest::Client::new().get(url).send().await?;
                    ensure!(response.status().is_success(), "export smoke GET failed");
                    ensure!(
                        response.bytes().await?.as_ref() == body,
                        "export smoke body mismatch"
                    );
                    if index == 1 {
                        let listed = storage.list_escrow_objects(&escrow_id).await?;
                        ensure!(
                            listed.keys == [key.clone()] && !listed.truncated,
                            "export smoke escrow listing did not return exactly its synthetic object"
                        );
                    }
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                let deleted = storage.delete_object(&key).await;
                checked?;
                deleted?;
                let removed = reqwest::Client::new()
                    .get(storage.download_url(&key)?)
                    .send()
                    .await?;
                ensure!(
                    removed.status() == reqwest::StatusCode::NOT_FOUND,
                    "export smoke object remained readable after deletion"
                );
                if index == 1 {
                    let listed = storage.list_escrow_objects(&escrow_id).await?;
                    ensure!(
                        listed.keys.is_empty() && !listed.truncated,
                        "export smoke escrow prefix was not empty after deletion"
                    );
                }
            }
            println!(
                "{}",
                json!({"data_export_storage":"pass", "prefixes":2, "escrow_listing":"pass"})
            );
        }
        Command::LegacySchema { apply } => {
            if apply {
                id_runtime::legacy_schema::require_local_ydb_for_pilot()?;
            }
            let client = id_runtime::connect_ydb().await?;
            let report = id_runtime::legacy_schema::reconcile(&client, apply).await?;
            println!("{}", serde_json::to_string(&report)?);
        }
        Command::LegacyLedger { apply } => {
            if apply {
                id_runtime::legacy_schema::require_local_ydb_for_pilot()?;
            }
            let client = id_runtime::connect_ydb().await?;
            let report = id_runtime::migration_ledger::reconcile(&client, apply).await?;
            println!("{}", serde_json::to_string(&report)?);
        }
        Command::CleanupTokens {
            retention_days,
            batch,
            execute,
        } => {
            let client = id_runtime::connect_ydb().await?;
            let report = id_runtime::token_cleanup::cleanup(
                &client,
                SystemTime::now(),
                retention_days,
                batch,
                execute,
            )
            .await?;
            println!("{}", serde_json::to_string(&report)?);
        }
        Command::LegacyCutoverReset { batch, apply } => {
            let client = id_runtime::connect_ydb().await?;
            let report = id_runtime::legacy_cutover_reset::reset(&client, batch, apply).await?;
            println!("{}", serde_json::to_string(&report)?);
        }
        Command::LegacyCutoverSeal { apply } => {
            let client = id_runtime::connect_ydb().await?;
            if apply {
                let created = id_runtime::legacy_cutover_reset::seal(&client).await?;
                println!("{}", json!({"sealed":true,"created":created}));
            } else {
                let report = id_runtime::legacy_cutover_reset::reset(&client, 1, false).await?;
                println!(
                    "{}",
                    json!({"dry_run":true,"ready_to_seal":report.complete})
                );
            }
        }
        Command::DeletionStatus { id } => {
            let client = id_runtime::connect_ydb().await?;
            let status = id_runtime::account_deletion::read_status(&client, id).await?;
            println!("{}", serde_json::to_string(&status)?);
            ensure!(status.is_some(), "deletion operation not found");
        }
        #[cfg(feature = "passkeys")]
        Command::DeletionAudit { id } => {
            let client = id_runtime::connect_ydb().await?;
            let report = id_runtime::account_deletion_audit::audit(&client, id).await?;
            println!("{}", serde_json::to_string(&report)?);
            ensure!(report.is_some(), "deletion operation not found");
        }
        #[cfg(feature = "passkeys")]
        Command::DeletionEraseGlobal { id, apply } => {
            let client = id_runtime::connect_ydb().await?;
            if apply {
                let result =
                    id_runtime::account_deletion_audit::erase_global_uuid_references(&client, id)
                        .await?;
                println!("{}", serde_json::to_string(&result)?);
                ensure!(result.is_some(), "deletion operation not found");
            } else {
                let report = id_runtime::account_deletion_audit::audit(&client, id).await?;
                println!("{}", serde_json::json!({"dry_run":true,"operation":report}));
                ensure!(report.is_some(), "deletion operation not found");
            }
        }
        #[cfg(feature = "passkeys")]
        Command::DeletionFinalize { id, apply } => {
            let client = id_runtime::connect_ydb().await?;
            if apply {
                let result = id_runtime::account_deletion_finalize::finalize(&client, id).await?;
                println!("{}", serde_json::to_string(&result)?);
                ensure!(result.is_some(), "deletion operation not found");
            } else {
                let status = id_runtime::account_deletion::read_status(&client, id).await?;
                println!("{}", json!({"dry_run":true,"operation":status}));
                ensure!(status.is_some(), "deletion operation not found");
            }
        }
        #[cfg(feature = "passkeys")]
        Command::DeletionEraseCredentials { id, apply } => {
            let client = id_runtime::connect_ydb().await?;
            if apply {
                let result =
                    id_runtime::account_deletion_cleanup::erase_credentials(&client, id).await?;
                println!("{}", serde_json::to_string(&result)?);
                ensure!(result.is_some(), "deletion operation not found");
            } else {
                let status = id_runtime::account_deletion::read_status(&client, id).await?;
                println!("{}", serde_json::json!({"dry_run":true,"operation":status}));
                ensure!(status.is_some(), "deletion operation not found");
            }
        }
        #[cfg(feature = "passkeys")]
        Command::DeletionEraseAvatar { id, apply } => {
            let client = id_runtime::connect_ydb().await?;
            if apply {
                // Without media credentials, a still-present object key fails closed.
                let result =
                    id_runtime::account_deletion_cleanup::erase_avatar(&client, None, id).await?;
                println!("{}", serde_json::to_string(&result)?);
                ensure!(result.is_some(), "deletion operation not found");
            } else {
                let status = id_runtime::account_deletion::read_status(&client, id).await?;
                println!("{}", json!({"dry_run":true,"operation":status}));
                ensure!(status.is_some(), "deletion operation not found");
            }
        }
        #[cfg(feature = "passkeys")]
        Command::DeletionEraseProfile { id, apply } => {
            let client = id_runtime::connect_ydb().await?;
            if apply {
                let result =
                    id_runtime::account_deletion_cleanup::erase_profile_history(&client, id)
                        .await?;
                println!("{}", serde_json::to_string(&result)?);
                ensure!(result.is_some(), "deletion operation not found");
            } else {
                let status = id_runtime::account_deletion::read_status(&client, id).await?;
                println!("{}", json!({"dry_run":true,"operation":status}));
                ensure!(status.is_some(), "deletion operation not found");
            }
        }
        #[cfg(feature = "passkeys")]
        Command::DeletionCompleteGlobal { id, apply } => {
            let client = id_runtime::connect_ydb().await?;
            if apply {
                let completed =
                    id_runtime::account_deletion_cleanup::complete_global_pass(&client, id).await?;
                println!(
                    "{}",
                    json!({"id":id.to_string(),"global_pass_completed":completed})
                );
            } else {
                let report = id_runtime::account_deletion_audit::audit(&client, id).await?;
                println!("{}", json!({"dry_run":true,"operation":report}));
                ensure!(report.is_some(), "deletion operation not found");
            }
        }
        Command::Inventory { input } => {
            let data: Value = serde_json::from_slice(&fs::read(input)?)?;
            let operations = data["operations"]
                .as_array()
                .context("missing operations")?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "registered_operations": operations.len(), "collisions": data["collisions"],
                    "scope": data["scope"], "functional_parity_verified": false
                }))?
            );
        }
        Command::CompatFixtures { input, output } => {
            let data: Value = serde_json::from_slice(&fs::read(input)?)?;
            ensure!(
                data["synthetic"] == true && data["format_version"] == 1,
                "only version 1 synthetic fixtures accepted"
            );
            let text = |value: &Value| -> Result<String> {
                Ok(value.as_str().context("fixture string missing")?.into())
            };
            let secret = text(&data["secret"])?;
            let codec = SessionCodec::new(secret.as_bytes(), &[])?;
            let password = text(&data["password"])?;
            // This CLI is offline; HTTP password verification must use a bounded blocking pool.
            for hash in data["password_hashes"]
                .as_array()
                .context("missing password hashes")?
            {
                ensure!(
                    id_compat::password::verify(&password, &text(hash)?)?,
                    "password fixture mismatch"
                );
            }
            for vector in data["session"]["vectors"]
                .as_array()
                .context("missing session vectors")?
            {
                let decoded = codec.decode(&text(&vector["encoded"])?)?;
                ensure!(
                    Value::Object(decoded.data) == data["session"]["payload"],
                    "session fixture mismatch"
                );
            }
            let payload = data["session"]["payload"]
                .as_object()
                .context("missing payload")?;
            let stamp = data["session"]["issued_at"]
                .as_i64()
                .context("missing signed_at")?;
            let sessions = [false, true]
                .into_iter()
                .map(|compress| codec.encode(payload, stamp, compress))
                .collect::<id_compat::Result<Vec<_>>>()?;
            fs::write(
                output,
                serde_json::to_vec_pretty(&json!({"synthetic": true, "sessions": sessions}))?,
            )?;
            println!(
                "Synthetic password/session compatibility verified; reverse-check output written"
            );
        }
    }
    Ok(())
}
