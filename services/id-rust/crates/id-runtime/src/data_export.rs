//! Bounded, owner-scoped NDJSON export core. Public authorization and private
//! archive storage are separate stages.

use crate::{media_delete::validate_avatar_key, media_url::MediaUrl};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use ydb::{Client, RetrySettings, Row, Transaction, TxMode, closure};

const PAGE: usize = 128;

#[derive(Clone, Copy)]
enum Field {
    Text(&'static str),
    OptionalText(&'static str),
    Bool(&'static str),
    Integer(&'static str),
    Datetime(&'static str),
    OptionalDatetime(&'static str),
    Json(&'static str),
}
impl Field {
    fn name(self) -> &'static str {
        match self {
            Self::Text(name)
            | Self::OptionalText(name)
            | Self::Bool(name)
            | Self::Integer(name)
            | Self::Datetime(name)
            | Self::OptionalDatetime(name)
            | Self::Json(name) => name,
        }
    }
}

struct Category {
    name: &'static str,
    table: &'static str,
    index: &'static str,
    serial_id: bool,
    fields: &'static [Field],
}
const CATEGORIES: &[Category] = &[
    Category {
        name: "email_addresses",
        table: "account_emailaddress",
        index: "account_emailaddress_user_id_2c513194",
        serial_id: true,
        fields: &[
            Field::Text("email"),
            Field::Bool("verified"),
            Field::Bool("primary"),
        ],
    },
    Category {
        name: "profile",
        table: "accounts_userprofile",
        index: "acct_profile_user_idx",
        serial_id: false,
        fields: &[
            Field::Text("phone_number"),
            Field::Bool("phone_verified"),
            Field::OptionalText("birth_date"),
            Field::OptionalText("avatar_key"),
            Field::Text("avatar_source"),
            Field::Bool("gravatar_enabled"),
            Field::Datetime("created_at"),
            Field::Datetime("updated_at"),
        ],
    },
    Category {
        name: "preferences",
        table: "accounts_userpreferences",
        index: "acct_prefs_user_idx",
        serial_id: false,
        fields: &[
            Field::Text("language"),
            Field::Text("timezone"),
            Field::Bool("marketing_opt_in"),
            Field::OptionalDatetime("marketing_opt_in_at"),
            Field::OptionalDatetime("marketing_opt_out_at"),
            Field::Json("privacy_scope_defaults"),
            Field::Datetime("created_at"),
            Field::Datetime("updated_at"),
        ],
    },
    Category {
        name: "consents",
        table: "accounts_userconsent",
        index: "accounts_userconsent_user_id_6d8d998a",
        serial_id: false,
        fields: &[
            Field::Text("kind"),
            Field::Text("version"),
            Field::Datetime("granted_at"),
            Field::OptionalDatetime("revoked_at"),
            Field::Text("source"),
        ],
    },
    Category {
        name: "login_events",
        table: "accounts_loginevent",
        index: "accounts_loginevent_user_id_0b0fdf50",
        serial_id: false,
        fields: &[
            Field::Text("status"),
            Field::OptionalText("ip_address"),
            Field::Text("user_agent"),
            Field::Text("device_id"),
            Field::Text("location"),
            Field::Bool("is_new_device"),
            Field::Text("reason"),
            Field::Datetime("created_at"),
        ],
    },
    Category {
        name: "account_events",
        table: "accounts_accountevent",
        index: "accounts_accountevent_user_id_ec4a3aac",
        serial_id: false,
        fields: &[Field::Text("action"), Field::Datetime("created_at")],
    },
    Category {
        name: "devices",
        table: "accounts_userdevice",
        index: "accounts_userdevice_user_id_2e91dbfd",
        serial_id: false,
        fields: &[
            Field::Text("device_id"),
            Field::Text("user_agent"),
            Field::Datetime("first_seen"),
            Field::OptionalDatetime("last_seen"),
            Field::OptionalText("last_ip"),
        ],
    },
    Category {
        name: "oidc_consents",
        table: "idp_oidcconsent",
        index: "idp_oidcconsent_user_id_f6d0a0ba",
        serial_id: false,
        fields: &[
            Field::Integer("client_id"),
            Field::Json("scopes"),
            Field::Datetime("created_at"),
            Field::Datetime("updated_at"),
            Field::OptionalDatetime("last_used_at"),
        ],
    },
    Category {
        name: "linked_accounts",
        table: "socialaccount_socialaccount",
        index: "socialaccount_socialaccount_user_id_8146e70c",
        serial_id: true,
        fields: &[
            Field::Text("provider"),
            Field::Text("uid"),
            Field::Datetime("last_login"),
            Field::Datetime("date_joined"),
        ],
    },
];

#[derive(Debug, Serialize)]
pub struct CategoryCount {
    pub category: &'static str,
    pub records: u64,
}
#[derive(Debug, Serialize)]
pub struct ExportManifest {
    pub format: &'static str,
    pub account_id: i32,
    pub generated_at: String,
    /// Wall-clock bounds of this worker attempt, not a request-time cutoff.
    pub snapshot_started_at: String,
    pub snapshot_completed_at: String,
    pub snapshot_scope: &'static str,
    pub categories: Vec<CategoryCount>,
    pub excluded: &'static [&'static str],
    pub consistency: &'static str,
}

/// The writer applies backpressure; no full category is collected in memory.
pub async fn write_ndjson<W: AsyncWrite + Unpin + Send>(
    client: &Client,
    account_id: i32,
    writer: &mut W,
) -> Result<ExportManifest> {
    write_ndjson_with_avatar(client, account_id, writer, None).await
}

pub async fn write_ndjson_with_avatar<W: AsyncWrite + Unpin + Send>(
    client: &Client,
    account_id: i32,
    writer: &mut W,
    avatar_source: Option<&MediaUrl>,
) -> Result<ExportManifest> {
    write_ndjson_inner(client, account_id, writer, avatar_source, false).await
}

/// Only an export request accepted while the account was active may use this
/// path. The deletion transaction revokes login immediately, but its profile
/// stage waits until the already accepted snapshot has been sealed.
pub(crate) async fn write_ndjson_with_avatar_for_escrow<W: AsyncWrite + Unpin + Send>(
    client: &Client,
    account_id: i32,
    writer: &mut W,
    avatar_source: Option<&MediaUrl>,
) -> Result<ExportManifest> {
    write_ndjson_inner(client, account_id, writer, avatar_source, true).await
}

async fn write_ndjson_inner<W: AsyncWrite + Unpin + Send>(
    client: &Client,
    account_id: i32,
    writer: &mut W,
    avatar_source: Option<&MediaUrl>,
    accepted_escrow: bool,
) -> Result<ExportManifest> {
    ensure!(account_id > 0, "invalid account ID for export");
    let snapshot_started_at = timestamp(SystemTime::now());
    // Retrying even a known abort would append a second snapshot to this stream.
    // A failed attempt is discarded by the caller; only a new claim may retry it.
    let snapshot_client = client.clone_with_retry_settings(RetrySettings::dont_retry());
    let counts = snapshot_client
        .query_client()
        .retry_tx(closure!(
            [
                &mut output = &mut *writer,
                account_id,
                avatar_source,
                accepted_escrow
            ],
            async |tx: &mut Transaction| {
                write_snapshot(tx, *account_id, output, *avatar_source, *accepted_escrow)
                    .await
                    .map_err(|error| {
                        ydb::YdbOrCustomerError::from_err(std::io::Error::other(error))
                    })
            }
        ))
        .isolation(TxMode::SnapshotReadOnly)
        .timeout(Duration::from_secs(10 * 60))
        .await?;
    let snapshot_completed_at = timestamp(SystemTime::now());
    let manifest = ExportManifest {
        format: "updspace-id-ndjson-v1",
        account_id,
        generated_at: snapshot_completed_at.clone(),
        snapshot_started_at,
        snapshot_completed_at,
        snapshot_scope: "worker-attempt",
        categories: counts,
        excluded: &[
            "password hashes and salts",
            "MFA and recovery secrets",
            "passkey cryptographic material",
            "session and bearer credentials",
            "social provider tokens",
            "unclassified free-form metadata",
        ],
        consistency: "snapshot",
    };
    write_line(writer, "manifest", serde_json::to_value(&manifest)?).await?;
    writer.flush().await?;
    Ok(manifest)
}

async fn write_snapshot<W: AsyncWrite + Unpin>(
    tx: &mut Transaction,
    account_id: i32,
    writer: &mut W,
    avatar_source: Option<&MediaUrl>,
    accepted_escrow: bool,
) -> Result<Vec<CategoryCount>> {
    let account = read_account(tx, account_id, accepted_escrow).await?;
    write_line(writer, "account", account).await?;
    let mut counts = vec![CategoryCount {
        category: "account",
        records: 1,
    }];
    for category in CATEGORIES {
        counts.push(CategoryCount {
            category: category.name,
            records: write_category(tx, account_id, category, writer).await?,
        });
    }
    counts.push(CategoryCount {
        category: "avatar_bytes",
        records: write_avatar(tx, account_id, writer, avatar_source).await?,
    });
    Ok(counts)
}

async fn write_avatar<W: AsyncWrite + Unpin>(
    tx: &mut Transaction,
    account_id: i32,
    writer: &mut W,
    source: Option<&MediaUrl>,
) -> Result<u64> {
    let mut query = tx
        .query("SELECT CAST(avatar AS Utf8) AS avatar_key FROM accounts_userprofile VIEW acct_profile_user_idx WHERE user_id = $id LIMIT 2")
        .param("$id", account_id)
        .await?;
    let mut keys = Vec::new();
    while let Some(rows) = query.next_result_set().await? {
        for mut row in rows {
            keys.push(Option::<String>::try_from(
                row.remove_field_by_name("avatar_key")?,
            )?);
        }
    }
    query.close().await?;
    ensure!(keys.len() <= 1, "multiple export profiles");
    let Some(key) = keys
        .into_iter()
        .next()
        .flatten()
        .filter(|key| !key.is_empty())
    else {
        return Ok(0);
    };
    validate_avatar_key(account_id, &key)?;
    let source = source.context("export avatar source is not configured")?;
    let url = source.avatar_url(&key)?;
    let mut response = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .get(url)
        .send()
        .await?;
    ensure!(response.status().is_success(), "export avatar GET failed");
    let mut bytes = 0usize;
    let mut chunks = 0u64;
    let mut hash = Sha256::new();
    while let Some(chunk) = response.chunk().await? {
        bytes = bytes
            .checked_add(chunk.len())
            .context("avatar size overflow")?;
        ensure!(
            bytes <= 6 * 1024 * 1024,
            "export avatar exceeds upload size limit"
        );
        hash.update(&chunk);
        write_line(
            writer,
            "avatar_bytes",
            json!({
                "key": key, "index": chunks, "base64": BASE64.encode(&chunk),
            }),
        )
        .await?;
        chunks += 1;
    }
    write_line(
        writer,
        "avatar_digest",
        json!({
            "key": key, "bytes": bytes, "sha256": hex::encode(hash.finalize()), "chunks": chunks,
        }),
    )
    .await?;
    Ok(chunks)
}

async fn read_account(
    tx: &mut Transaction,
    account_id: i32,
    accepted_escrow: bool,
) -> Result<Value> {
    let Some(mut account) = tx
        .query_row("SELECT username, email, first_name, last_name, is_active, date_joined FROM auth_user WHERE id = $id")
        .param("$id", account_id).optional().await? else { bail!("export account missing"); };
    let active = bool::try_from(account.remove_field_by_name("is_active")?)?;
    let Some(mut binding) = tx
        .query_row(
            "SELECT identity_id, public_subject FROM accounts_accountidentity WHERE user_id = $id",
        )
        .param("$id", account_id)
        .optional()
        .await?
    else {
        bail!("export identity binding missing");
    };
    let identity_id: Option<uuid::Uuid> =
        binding.remove_field_by_name("identity_id")?.try_into()?;
    let identity_id = identity_id.context("export identity ID missing")?;
    let public_subject: String = binding.remove_field_by_name("public_subject")?.try_into()?;
    let Some(mut identity) = tx
        .query_row("SELECT username, display_name, email, email_verified, status, created_at FROM usid_user WHERE user_id = $id")
        .param("$id", identity_id).optional().await? else { bail!("export master identity missing"); };
    let identity_status: String = identity.remove_field_by_name("status")?.try_into()?;
    let mut pending = tx.query(
        "SELECT id FROM accounts_accountdeletionrequest VIEW accounts_accountdeletionrequest_user_id_6a166c52 WHERE user_id = $id AND status IN ('pending', 'running') LIMIT 1")
        .param("$id", account_id).await?;
    let mut deleting = false;
    while let Some(rows) = pending.next_result_set().await? {
        deleting |= rows.into_iter().next().is_some();
    }
    pending.close().await?;
    ensure!(
        (active && identity_status == "active" && !deleting)
            || (accepted_escrow && !active && identity_status == "suspended" && deleting),
        "inactive or deleting account cannot be exported without an accepted escrow request"
    );
    let joined: SystemTime = account.remove_field_by_name("date_joined")?.try_into()?;
    let created: SystemTime = identity.remove_field_by_name("created_at")?.try_into()?;
    Ok(json!({
        "id": account_id,
        "username": String::try_from(account.remove_field_by_name("username")?)?,
        "email": String::try_from(account.remove_field_by_name("email")?)?,
        "first_name": String::try_from(account.remove_field_by_name("first_name")?)?,
        "last_name": String::try_from(account.remove_field_by_name("last_name")?)?,
        "date_joined": timestamp(joined),
        "identity_id": identity_id.to_string(), "public_subject": public_subject,
        "master_identity": {
            "username": String::try_from(identity.remove_field_by_name("username")?)?,
            "display_name": String::try_from(identity.remove_field_by_name("display_name")?)?,
            "email": String::try_from(identity.remove_field_by_name("email")?)?,
            "email_verified": bool::try_from(identity.remove_field_by_name("email_verified")?)?,
            "created_at": timestamp(created),
        }
    }))
}

async fn write_category<W: AsyncWrite + Unpin>(
    tx: &mut Transaction,
    account_id: i32,
    category: &Category,
    writer: &mut W,
) -> Result<u64> {
    let fields = category
        .fields
        .iter()
        .map(|field| match field {
            Field::Json(name) => format!("CAST({name} AS Utf8) AS {name}"),
            Field::OptionalText("birth_date") => "CAST(birth_date AS Utf8) AS birth_date".into(),
            Field::OptionalText("avatar_key") => "CAST(avatar AS Utf8) AS avatar_key".into(),
            _ => field.name().into(),
        })
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT id, {fields} FROM `{}` VIEW `{}` WHERE user_id = $user_id AND id > $after ORDER BY id LIMIT {PAGE}",
        category.table, category.index
    );
    let mut after = -1_i64;
    let mut count = 0_u64;
    loop {
        let mut query = if category.serial_id {
            tx.query(sql.clone())
                .param("$user_id", account_id)
                .param("$after", i32::try_from(after)?)
                .timeout(Duration::from_secs(20))
                .await?
        } else {
            tx.query(sql.clone())
                .param("$user_id", account_id)
                .param("$after", after)
                .timeout(Duration::from_secs(20))
                .await?
        };
        let mut page = 0;
        while let Some(rows) = query.next_result_set().await? {
            for mut row in rows {
                let id = if category.serial_id {
                    i64::from(i32::try_from(row.remove_field_by_name("id")?)?)
                } else {
                    i64::try_from(row.remove_field_by_name("id")?)?
                };
                ensure!(id > after, "export pagination did not advance");
                after = id;
                write_line(writer, category.name, render_row(category, id, row)?).await?;
                page += 1;
                count += 1;
            }
        }
        query.close().await?;
        if page < PAGE {
            break;
        }
    }
    Ok(count)
}

fn render_row(category: &Category, id: i64, mut row: Row) -> Result<Value> {
    let mut result = Map::new();
    result.insert("id".into(), json!(id));
    for field in category.fields {
        let name = field.name();
        let raw = row.remove_field_by_name(name)?;
        let value = match field {
            Field::Text(_) => json!(String::try_from(raw)?),
            Field::OptionalText(_) => json!(Option::<String>::try_from(raw)?),
            Field::Bool(_) => json!(bool::try_from(raw)?),
            Field::Integer(_) => json!(i64::try_from(raw)?),
            Field::Datetime(_) => json!(timestamp(SystemTime::try_from(raw)?)),
            Field::OptionalDatetime(_) => {
                json!(Option::<SystemTime>::try_from(raw)?.map(timestamp))
            }
            Field::Json(_) => serde_json::from_str(&String::try_from(raw)?)
                .context("invalid stored JSON in export")?,
        };
        result.insert(name.into(), value);
    }
    Ok(Value::Object(result))
}

async fn write_line<W: AsyncWrite + Unpin>(
    writer: &mut W,
    category: &str,
    record: Value,
) -> Result<()> {
    let line = serde_json::to_vec(&json!({"category": category, "record": record}))?;
    writer.write_all(&line).await?;
    writer.write_all(b"\n").await?;
    Ok(())
}

fn timestamp(value: SystemTime) -> String {
    DateTime::<Utc>::from(value).to_rfc3339_opts(SecondsFormat::Millis, true)
}
