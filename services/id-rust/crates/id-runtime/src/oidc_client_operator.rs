//! Explicit, password-confirmed CLI lifecycle operations for OIDC clients.
//! Secrets are persisted before commit and never included in reports or errors.

use crate::{
    admin_oidc_client_edit::valid_redirects,
    admin_suspend::{self, Preflight},
    oidc_protocol::narrow_scopes,
    session_store::{LEGACY_BACKENDS, restore_django_session_tx},
    tx_retry::retry_known_abort,
};
use anyhow::{Result, anyhow, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use id_compat::session::SessionCodec;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;
use ydb::{Client, Transaction, TxMode, closure};

static HASH_SLOTS: Semaphore = Semaphore::const_new(2);

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSpec {
    pub client_id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub grant_types: Vec<String>,
    pub is_public: bool,
    #[serde(default)]
    pub is_first_party: bool,
}

impl ClientSpec {
    pub fn validate(&self) -> Result<()> {
        validate_id(&self.client_id)?;
        ensure!(
            !self.name.is_empty()
                && self.name.len() <= 200
                && self.name.trim() == self.name
                && !self.name.chars().any(char::is_control)
                && self.description.len() <= 4000
                && !self.description.chars().any(char::is_control),
            "invalid client display fields"
        );
        ensure!(
            valid_redirects(&self.redirect_uris),
            "invalid exact redirect allowlist"
        );
        ensure!(
            narrow_scopes(&self.allowed_scopes.join(" "), None)
                .ok()
                .as_ref()
                == Some(&self.allowed_scopes),
            "invalid supported scopes; openid is required"
        );
        let grants = self
            .grant_types
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        ensure!(
            grants.len() == self.grant_types.len()
                && grants.contains("authorization_code")
                && grants
                    .iter()
                    .all(|value| matches!(*value, "authorization_code" | "refresh_token")),
            "invalid supported grants"
        );
        ensure!(
            !self
                .allowed_scopes
                .iter()
                .any(|scope| scope == "offline_access")
                || grants.contains("refresh_token"),
            "offline_access requires refresh_token grant"
        );
        Ok(())
    }
}

fn validate_id(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 64
            && value.trim() == value
            && !value.chars().any(char::is_control),
        "invalid exact client_id"
    );
    Ok(())
}

#[derive(Serialize)]
pub struct Report {
    pub status: &'static str,
    pub client_id: String,
    pub revision: Option<String>,
    pub is_public: bool,
    pub secret_generated: bool,
    pub configuration: ClientSpec,
}

#[derive(Clone)]
struct Operator {
    token: String,
    account_id: i32,
    password_hash: String,
}

#[derive(Clone, Serialize)]
struct StoredClient {
    id: i64,
    client_id: String,
    name: String,
    description: String,
    logo_url: String,
    redirects: String,
    scopes: String,
    grants: String,
    responses: String,
    is_public: bool,
    is_first_party: bool,
    secret_hash: String,
    updated_at: SystemTime,
}

impl StoredClient {
    fn revision(&self) -> Result<String, serde_json::Error> {
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(self)?)))
    }

    fn spec(&self) -> Result<ClientSpec> {
        Ok(ClientSpec {
            client_id: self.client_id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
            redirect_uris: serde_json::from_str(&self.redirects)?,
            allowed_scopes: serde_json::from_str(&self.scopes)?,
            grant_types: serde_json::from_str(&self.grants)?,
            is_public: self.is_public,
            is_first_party: self.is_first_party,
        })
    }
}

async fn operator(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: String,
    password: String,
) -> Result<Operator> {
    ensure!(
        !token.is_empty() && token.len() <= 4096 && !password.is_empty() && password.len() <= 4096,
        "invalid operator credential file"
    );
    let Preflight::Ready {
        actor_id,
        password_hash,
    } = admin_suspend::preflight(client, codec, &token, SystemTime::now())
        .await
        .map_err(|_| anyhow!("operator verification unavailable"))?
    else {
        return Err(anyhow!(
            "active staff and superuser session with verified MFA required"
        ));
    };
    let permit = HASH_SLOTS.acquire().await?;
    let hash = password_hash.clone();
    let verified =
        tokio::task::spawn_blocking(move || id_compat::password::verify(&password, &hash))
            .await
            .map_err(|_| anyhow!("operator password verification unavailable"))?
            .map_err(|_| anyhow!("operator password verification unavailable"))?;
    drop(permit);
    ensure!(verified, "operator password rejected");
    Ok(Operator {
        token,
        account_id: actor_id,
        password_hash,
    })
}

async fn actor_tx(
    tx: &mut Transaction,
    codec: &SessionCodec,
    actor: &Operator,
) -> ydb::YdbResultWithCustomerErr<uuid::Uuid> {
    let backends = LEGACY_BACKENDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    let Some(session) =
        restore_django_session_tx(tx, codec, &actor.token, &backends, SystemTime::now()).await?
    else {
        return Err(rejected("operator session expired or revoked"));
    };
    if session.principal.account_id.get() != i64::from(actor.account_id) {
        return Err(rejected("operator changed"));
    }
    let Some(mut row) = tx
        .query_row("SELECT password, is_staff, is_superuser FROM auth_user WHERE id = $id")
        .param("$id", actor.account_id)
        .optional()
        .await?
    else {
        return Err(rejected("operator missing"));
    };
    let hash: String = row.remove_field_by_name("password")?.try_into()?;
    let staff: bool = row.remove_field_by_name("is_staff")?.try_into()?;
    let superuser: bool = row.remove_field_by_name("is_superuser")?.try_into()?;
    let mfa = tx.query_row("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $id LIMIT 1")
        .param("$id", actor.account_id).optional().await?.is_some();
    if !staff || !superuser || !mfa || !session.mfa_verified || hash != actor.password_hash {
        return Err(rejected("operator authority or password changed"));
    }
    Ok(session.principal.identity_id.get())
}

fn rejected(message: &'static str) -> ydb::YdbOrCustomerError {
    ydb::YdbOrCustomerError::from_err(std::io::Error::other(message))
}

async fn read_tx(
    tx: &mut Transaction,
    client_id: &str,
) -> ydb::YdbResultWithCustomerErr<Option<StoredClient>> {
    let mut stream = tx.query("SELECT id, client_id, client_secret_hash, name, description, logo_url, CAST(redirect_uris AS Utf8) AS redirects, CAST(allowed_scopes AS Utf8) AS scopes, CAST(grant_types AS Utf8) AS grants, CAST(response_types AS Utf8) AS responses, is_public, is_first_party, updated_at FROM idp_oidcclient VIEW oidc_client_id_idx WHERE client_id = $client_id LIMIT 2")
        .param("$client_id", client_id.to_owned()).await?;
    let mut found = Vec::with_capacity(2);
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            found.push(StoredClient {
                id: row.remove_field_by_name("id")?.try_into()?,
                client_id: row.remove_field_by_name("client_id")?.try_into()?,
                secret_hash: row.remove_field_by_name("client_secret_hash")?.try_into()?,
                name: row.remove_field_by_name("name")?.try_into()?,
                description: row.remove_field_by_name("description")?.try_into()?,
                logo_url: row.remove_field_by_name("logo_url")?.try_into()?,
                redirects: row.remove_field_by_name("redirects")?.try_into()?,
                scopes: row.remove_field_by_name("scopes")?.try_into()?,
                grants: row.remove_field_by_name("grants")?.try_into()?,
                responses: row.remove_field_by_name("responses")?.try_into()?,
                is_public: row.remove_field_by_name("is_public")?.try_into()?,
                is_first_party: row.remove_field_by_name("is_first_party")?.try_into()?,
                updated_at: row.remove_field_by_name("updated_at")?.try_into()?,
            });
        }
    }
    stream.close().await?;
    if found.len() > 1 || found.first().is_some_and(|row| row.client_id != client_id) {
        return Err(rejected("ambiguous client_id"));
    }
    Ok(found.pop())
}

async fn review(
    client: &Client,
    codec: Arc<SessionCodec>,
    actor: Operator,
    client_id: String,
) -> Result<Option<StoredClient>> {
    client
        .query_client()
        .retry_tx(closure!(
            [codec, actor, client_id],
            async |tx: &mut Transaction| {
                actor_tx(tx, codec.as_ref(), actor).await?;
                read_tx(tx, client_id).await
            }
        ))
        .isolation(TxMode::SnapshotReadOnly)
        .timeout(Duration::from_secs(10))
        .await
        .map_err(|_| anyhow!("client review unavailable or operator authorization rejected"))
}

async fn new_secret() -> Result<(String, String)> {
    let secret = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let for_hash = secret.clone();
    let permit = HASH_SLOTS.acquire().await?;
    let hash = tokio::task::spawn_blocking(move || id_compat::password::hash_new(&for_hash))
        .await
        .map_err(|_| anyhow!("secret hashing unavailable"))?
        .map_err(|_| anyhow!("secret hashing unavailable"))?;
    drop(permit);
    Ok((secret, hash))
}

fn now_seconds() -> Result<SystemTime> {
    Ok(UNIX_EPOCH + Duration::from_secs(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()))
}

/// Credential inputs must be regular, private files; neither contents nor paths
/// are interpolated into errors. Read a bounded file without trimming passwords.
pub fn read_private_input(path: &Path) -> Result<String> {
    let expected = fs::symlink_metadata(path)
        .map_err(|_| anyhow!("cannot inspect operator credential file"))?;
    ensure!(
        expected.is_file() && expected.permissions().mode() & 0o077 == 0 && expected.len() <= 4096,
        "operator credential file must be a private regular file of at most 4096 bytes"
    );
    let file = File::open(path).map_err(|_| anyhow!("cannot open operator credential file"))?;
    let actual = file.metadata()?;
    ensure!(
        actual.dev() == expected.dev() && actual.ino() == expected.ino(),
        "operator credential file changed"
    );
    let mut contents = String::new();
    file.take(4097)
        .read_to_string(&mut contents)
        .map_err(|_| anyhow!("invalid operator credential file"))?;
    ensure!(
        !contents.is_empty() && contents.len() <= 4096,
        "invalid operator credential file"
    );
    Ok(contents)
}

fn persist_secret(path: &Path, client_id: &str, secret: &str, revision: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| {
            anyhow!("secret output must be a new writable file; no database write attempted")
        })?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    serde_json::to_writer(
        &mut file,
        &serde_json::json!({"client_id":client_id,"client_secret":secret,"revision":revision}),
    )?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()?;
    Ok(())
}

/// Validate and review without any writes unless apply is true.
pub async fn create(
    client: &Client,
    codec: Arc<SessionCodec>,
    session: String,
    password: String,
    spec: ClientSpec,
    apply: bool,
    secret_output: Option<&Path>,
) -> Result<Report> {
    spec.validate()?;
    ensure!(
        !spec.is_public || secret_output.is_none(),
        "public clients must not have a secret output"
    );
    ensure!(
        !apply || spec.is_public || secret_output.is_some(),
        "confidential apply requires --secret-output"
    );
    let actor = operator(client, codec.clone(), session, password).await?;
    ensure!(
        review(client, codec.clone(), actor.clone(), spec.client_id.clone())
            .await?
            .is_none(),
        "client_id already exists"
    );
    let mut report = Report {
        status: "dry_run",
        client_id: spec.client_id.clone(),
        revision: None,
        is_public: spec.is_public,
        secret_generated: false,
        configuration: spec.clone(),
    };
    if !apply {
        return Ok(report);
    }
    let (secret, hash) = if spec.is_public {
        (String::new(), String::new())
    } else {
        new_secret().await?
    };
    let record = StoredClient {
        id: ((rand::random::<u64>() & ((1u64 << 62) - 1)) | (1u64 << 62)) as i64,
        client_id: spec.client_id.clone(),
        name: spec.name,
        description: spec.description,
        logo_url: String::new(),
        redirects: serde_json::to_string(&spec.redirect_uris)?,
        scopes: serde_json::to_string(&spec.allowed_scopes)?,
        grants: serde_json::to_string(&spec.grant_types)?,
        responses: "[\"code\"]".into(),
        is_public: spec.is_public,
        is_first_party: spec.is_first_party,
        secret_hash: hash,
        updated_at: now_seconds()?,
    };
    let revision = record.revision()?;
    if let Some(path) = secret_output {
        persist_secret(path, &record.client_id, &secret, &revision)?;
    }
    commit(client, codec, actor, record, None).await?;
    report.status = "created";
    report.revision = Some(revision);
    report.secret_generated = !report.is_public;
    Ok(report)
}

pub struct Rotation<'a> {
    pub client_id: String,
    pub expected_revision: Option<String>,
    pub apply: bool,
    pub secret_output: Option<&'a Path>,
}

pub async fn rotate_secret(
    client: &Client,
    codec: Arc<SessionCodec>,
    session: String,
    password: String,
    input: Rotation<'_>,
) -> Result<Report> {
    validate_id(&input.client_id)?;
    ensure!(
        !input.apply || input.secret_output.is_some(),
        "rotation apply requires --secret-output"
    );
    if let Some(revision) = input.expected_revision.as_deref() {
        ensure!(
            revision.len() == 64 && revision.bytes().all(|value| value.is_ascii_hexdigit()),
            "invalid reviewed revision"
        );
    }
    ensure!(
        !input.apply || input.expected_revision.is_some(),
        "rotation apply requires --expected-revision from dry-run"
    );
    let actor = operator(client, codec.clone(), session, password).await?;
    let mut record = review(client, codec.clone(), actor.clone(), input.client_id)
        .await?
        .ok_or_else(|| anyhow!("client_id not found"))?;
    ensure!(!record.is_public, "public clients cannot rotate a secret");
    let previous = record.revision()?;
    if let Some(expected) = input.expected_revision {
        ensure!(expected == previous, "reviewed client revision changed");
    }
    let mut report = Report {
        status: "dry_run",
        client_id: record.client_id.clone(),
        revision: Some(previous.clone()),
        is_public: false,
        secret_generated: false,
        configuration: record
            .spec()
            .map_err(|_| anyhow!("invalid stored client configuration"))?,
    };
    if !input.apply {
        return Ok(report);
    }
    let (secret, hash) = new_secret().await?;
    record.secret_hash = hash;
    record.updated_at = now_seconds()?;
    let revision = record.revision()?;
    persist_secret(
        input
            .secret_output
            .ok_or_else(|| anyhow!("secret output required"))?,
        &record.client_id,
        &secret,
        &revision,
    )?;
    commit(client, codec, actor, record, Some(previous)).await?;
    report.status = "rotated";
    report.revision = Some(revision);
    report.secret_generated = true;
    Ok(report)
}

async fn commit(
    client: &Client,
    codec: Arc<SessionCodec>,
    actor: Operator,
    record: StoredClient,
    previous: Option<String>,
) -> Result<()> {
    retry_known_abort(|| {
        let (codec, actor, record, previous) = (codec.clone(), actor.clone(), record.clone(), previous.clone());
        async {
            client.query_client().retry_tx(closure!([codec, actor, record, previous], async |tx: &mut Transaction| {
                let actor_identity = actor_tx(tx, codec.as_ref(), actor).await?;
                let current = read_tx(tx, &record.client_id).await?;
                if let Some(expected) = previous.as_ref() {
                    let Some(current) = current else { return Err(rejected("client disappeared")); };
                    if current.revision().map_err(ydb::YdbOrCustomerError::from_err)? != *expected {
                        return Err(rejected("reviewed client changed"));
                    }
                    tx.exec("UPDATE idp_oidcclient SET client_secret_hash = $hash, updated_at = CAST($now AS Datetime) WHERE id = $id")
                        .param("$hash", record.secret_hash.clone()).param("$now", record.updated_at).param("$id", record.id).await?;
                } else {
                    if current.is_some() { return Err(rejected("client_id already exists")); }
                    tx.exec("INSERT INTO idp_oidcclient (id, client_id, client_secret_hash, name, description, logo_url, redirect_uris, allowed_scopes, grant_types, response_types, is_public, is_first_party, created_at, updated_at) VALUES ($id, $client_id, $hash, $name, $description, '', Unwrap(CAST($redirects AS Json)), Unwrap(CAST($scopes AS Json)), Unwrap(CAST($grants AS Json)), Unwrap(CAST($responses AS Json)), $public, $first_party, CAST($now AS Datetime), CAST($now AS Datetime))")
                        .param("$id", record.id).param("$client_id", record.client_id.clone()).param("$hash", record.secret_hash.clone())
                        .param("$name", record.name.clone()).param("$description", record.description.clone())
                        .param("$redirects", record.redirects.clone()).param("$scopes", record.scopes.clone())
                        .param("$grants", record.grants.clone()).param("$responses", record.responses.clone())
                        .param("$public", record.is_public).param("$first_party", record.is_first_party).param("$now", record.updated_at).await?;
                }
                let action = if previous.is_some() { "oidc_client.secret_rotated" } else { "oidc_client.created" };
                let meta = serde_json::json!({"previous_revision":previous,"revision":record.revision().map_err(ydb::YdbOrCustomerError::from_err)?,"is_public":record.is_public}).to_string();
                tx.exec("INSERT INTO usid_audit_log (actor_user_id, action, target_type, target_id, tenant_id, meta_json, created_at) VALUES ($actor, $action, 'oidc_client', $target, NULL, Unwrap(CAST($meta AS Json)), CAST($now AS Datetime))")
                    .param("$actor", actor_identity).param("$action", action).param("$target", record.client_id.clone())
                    .param("$meta", meta).param("$now", record.updated_at).await?;
                Ok(())
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false).timeout(Duration::from_secs(30)).await
        }
    }).await.map_err(|_| anyhow!("client mutation rejected or commit result uncertain; for a confidential client, retain the secret file and run oidc-client-rotate-secret with the same --client-id and operator files, without --apply or --expected-revision, to compare revisions; for a public client, inspect its read-only configuration; do not repeat apply blindly"))
}

#[cfg(test)]
mod tests {
    use super::*;

    include!("oidc_client_operator_tests.rs");

    fn spec() -> ClientSpec {
        ClientSpec {
            client_id: "operator-test".into(),
            name: "Test client".into(),
            description: String::new(),
            redirect_uris: vec!["https://rp.example.invalid/callback".into()],
            allowed_scopes: vec!["openid".into(), "email".into()],
            grant_types: vec!["authorization_code".into()],
            is_public: true,
            is_first_party: false,
        }
    }

    #[test]
    fn configurations_do_not_expand_what_the_protocol_supports() -> Result<()> {
        spec().validate()?;
        for redirect in [
            "https://*.example.invalid/cb",
            "https://rp.example.invalid/cb#fragment",
        ] {
            let mut input = spec();
            input.redirect_uris = vec![redirect.into()];
            assert!(input.validate().is_err());
        }
        for scopes in [
            vec!["openid", "email phone"],
            vec!["openid", "openid"],
            vec!["openid", "unknown"],
            vec!["openid", "offline_access"],
        ] {
            let mut input = spec();
            input.allowed_scopes = scopes.into_iter().map(str::to_owned).collect();
            assert!(input.validate().is_err());
        }
        let mut input = spec();
        input.grant_types.push("client_credentials".into());
        assert!(input.validate().is_err());
        let mut json = serde_json::to_value(spec())?;
        json["client_secret"] = "not-accepted".into();
        assert!(serde_json::from_value::<ClientSpec>(json).is_err());
        Ok(())
    }

    #[test]
    fn secret_file_is_private_exclusive_and_not_in_reports() -> Result<()> {
        let directory =
            std::env::temp_dir().join(format!("id-operator-file-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory)?;
        let path = directory.join("credential.json");
        let result = (|| -> Result<()> {
            persist_secret(&path, "test", "never-print-this", "revision")?;
            assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
            assert!(persist_secret(&path, "test", "replacement", "revision").is_err());
            assert!(fs::read_to_string(&path)?.contains("never-print-this"));
            let report = Report {
                status: "created",
                client_id: "test".into(),
                revision: Some("revision".into()),
                is_public: false,
                secret_generated: true,
                configuration: spec(),
            };
            assert!(!serde_json::to_string(&report)?.contains("never-print-this"));
            let link = directory.join("symlink");
            std::os::unix::fs::symlink(&path, &link)?;
            assert!(read_private_input(&link).is_err());
            assert!(persist_secret(&link, "test", "replacement", "revision").is_err());
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
            assert!(read_private_input(&path).is_err());
            Ok(())
        })();
        fs::remove_dir_all(directory)?;
        result
    }
}
