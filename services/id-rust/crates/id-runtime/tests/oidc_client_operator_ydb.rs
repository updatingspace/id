#![cfg(unix)]
#![recursion_limit = "256"]
//! Real idctl processes against local YDB: operator proof, exact client IDs,
//! one-winner creation, revision-checked rotation and private secret delivery.

use anyhow::{Context, Result, ensure};
use id_compat::session::SessionCodec;
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{Arc, Barrier},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use ydb::Client;

const SESSION_SECRET: &str = "synthetic-operator-cli-session-secret-at-least-32-bytes";
const PASSWORD: &str = "synthetic-operator-cli-password";
const WRONG_PASSWORD: &str = "synthetic-wrong-operator-password";
const BACKEND: &str = "django.contrib.auth.backends.ModelBackend";

struct Fixture {
    dir: PathBuf,
    token: String,
    actor_id: i32,
    identity_id: Uuid,
    client_ids: Vec<String>,
}

impl Fixture {
    fn command(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_idctl"));
        command
            .args(arguments)
            .arg("--operator-session-file")
            .arg(self.dir.join("session"))
            .arg("--operator-password-file")
            .arg(self.dir.join("password"))
            .env("DJANGO_SECRET_KEY", SESSION_SECRET)
            .env_remove("DJANGO_SECRET_KEY_FALLBACKS")
            .env("YDB_CREDENTIALS_MODE", "anonymous");
        command
    }

    async fn run(&self, arguments: &[&str]) -> Result<Output> {
        let mut command = self.command(arguments);
        let output = tokio::task::spawn_blocking(move || command.output()).await??;
        self.no_leaks(&output, &[])?;
        Ok(output)
    }

    fn no_leaks(&self, output: &Output, additional: &[&str]) -> Result<()> {
        for value in [
            PASSWORD,
            WRONG_PASSWORD,
            SESSION_SECRET,
            self.token.as_str(),
        ]
        .into_iter()
        .chain(additional.iter().copied())
        {
            ensure!(
                !value.is_empty()
                    && !output
                        .stdout
                        .windows(value.len())
                        .any(|bytes| bytes == value.as_bytes())
                    && !output
                        .stderr
                        .windows(value.len())
                        .any(|bytes| bytes == value.as_bytes()),
                "idctl exposed a credential in its captured output"
            );
        }
        Ok(())
    }

    async fn cleanup(&self, client: &Client) -> Result<()> {
        for client_id in &self.client_ids {
            client
                .query_client()
                .exec("DELETE FROM idp_oidcclient WHERE client_id = $id")
                .param("$id", client_id.clone())
                .await?;
        }
        client
            .query_client()
            .exec("DELETE FROM usid_audit_log WHERE actor_user_id = $id")
            .param("$id", self.identity_id)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM mfa_authenticator WHERE user_id = $id")
            .param("$id", self.actor_id)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM core_usersessionmeta WHERE user_id = $id")
            .param("$id", self.actor_id)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM usersessions_usersession WHERE user_id = $id")
            .param("$id", self.actor_id)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM django_session WHERE session_key = $key")
            .param("$key", self.token.clone())
            .await?;
        client
            .query_client()
            .exec("DELETE FROM accounts_accountidentity WHERE user_id = $id")
            .param("$id", self.actor_id)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM usid_user WHERE user_id = $id")
            .param("$id", self.identity_id)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM auth_user WHERE id = $id")
            .param("$id", self.actor_id)
            .await?;
        Ok(())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .write_all(bytes)?;
    Ok(())
}

fn report(output: &Output, status: &str, client_id: &str, is_public: bool) -> Result<Value> {
    ensure!(
        output.status.success(),
        "idctl {status} failed with {:?}",
        output.status.code()
    );
    let body: Value = serde_json::from_slice(&output.stdout).context("idctl JSON report")?;
    ensure!(
        body["status"] == status
            && body["client_id"] == client_id
            && body["is_public"] == is_public,
        "idctl returned an unexpected report contract"
    );
    ensure!(
        body.get("client_secret").is_none() && body.get("client_secret_hash").is_none(),
        "report included a credential field"
    );
    Ok(body)
}

fn revision(body: &Value) -> Result<&str> {
    let value = body["revision"]
        .as_str()
        .context("missing client revision")?;
    ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "client revision must be opaque 64-digit hex"
    );
    Ok(value)
}

fn review_digest(body: &Value) -> Result<&str> {
    let value = body["review_digest"]
        .as_str()
        .context("missing config review digest")?;
    ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "config review digest must be 64-digit hex"
    );
    Ok(value)
}

fn read_secret(path: &Path, client_id: &str, expected_revision: &str) -> Result<String> {
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_file(),
        "secret artifact is not a regular file"
    );
    ensure!(
        fs::metadata(path)?.permissions().mode() & 0o777 == 0o600,
        "secret artifact must have mode 0600"
    );
    let body: Value = serde_json::from_slice(&fs::read(path)?)?;
    ensure!(
        body["client_id"] == client_id && body["revision"] == expected_revision,
        "secret artifact identifies the wrong client revision"
    );
    let secret = body["client_secret"]
        .as_str()
        .context("missing generated client secret")?;
    ensure!(
        secret.len() >= 32 && secret.len() <= 512,
        "generated client secret length is invalid"
    );
    Ok(secret.to_owned())
}

async fn stored_clients(client: &Client, client_id: &str) -> Result<Vec<(String, bool, Value)>> {
    let mut query_client = client.query_client();
    let mut stream = query_client.query("SELECT client_secret_hash, is_public, CAST(redirect_uris AS Utf8) AS redirects, CAST(allowed_scopes AS Utf8) AS scopes, CAST(grant_types AS Utf8) AS grants, CAST(response_types AS Utf8) AS responses FROM idp_oidcclient VIEW oidc_client_id_idx WHERE client_id = $id LIMIT 3")
        .param("$id", client_id.to_owned()).await?;
    let mut found = Vec::new();
    while let Some(rows) = stream.next_result_set().await? {
        for mut row in rows {
            let hash: String = row.remove_field_by_name("client_secret_hash")?.try_into()?;
            let public: bool = row.remove_field_by_name("is_public")?.try_into()?;
            let mut lists = serde_json::Map::new();
            for field in ["redirects", "scopes", "grants", "responses"] {
                let raw: String = row.remove_field_by_name(field)?.try_into()?;
                lists.insert(field.to_owned(), serde_json::from_str(&raw)?);
            }
            found.push((hash, public, Value::Object(lists)));
        }
    }
    stream.close().await?;
    Ok(found)
}

async fn audit_rows(client: &Client, actor: Uuid) -> Result<Vec<(String, String)>> {
    let mut query_client = client.query_client();
    let mut stream = query_client.query("SELECT target_id, CAST(meta_json AS Utf8) AS meta FROM usid_audit_log WHERE actor_user_id = $id")
        .param("$id", actor).await?;
    let mut rows = Vec::new();
    while let Some(set) = stream.next_result_set().await? {
        for mut row in set {
            rows.push((
                row.remove_field_by_name("target_id")?.try_into()?,
                row.remove_field_by_name("meta")?.try_into()?,
            ));
        }
    }
    stream.close().await?;
    Ok(rows)
}

async fn matches_secret(secret: &str, hash: &str) -> Result<bool> {
    let (secret, hash) = (secret.to_owned(), hash.to_owned());
    Ok(tokio::task::spawn_blocking(move || id_compat::password::verify(&secret, &hash)).await??)
}

fn config(client_id: &str, public: bool) -> Value {
    json!({
        "client_id": client_id, "name": "Synthetic CLI relying party",
        "redirect_uris": ["https://rp.example.invalid/callback?source=id"],
        "allowed_scopes": ["openid", "email", "offline_access"],
        "grant_types": ["authorization_code", "refresh_token"], "is_public": public,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires migrated local YDB on localhost:2136 and /local"]
async fn oidc_client_operator_creates_and_rotates_without_leaking_credentials() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "operator CLI regression refuses non-local YDB"
    );
    let client = id_runtime::connect_ydb().await?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let unique = format!("{}-{stamp}", std::process::id());
    let fixture = Fixture {
        dir: std::env::temp_dir().join(format!("id-oidc-operator-{unique}")),
        token: format!("operator-cli-{unique}"),
        actor_id: 1_100_000_000 + i32::try_from(stamp % 300_000_000)?,
        identity_id: Uuid::from_u128(stamp),
        client_ids: ["private", "public", "race", "invalid"]
            .iter()
            .map(|kind| format!("cli-{kind}-{unique}"))
            .collect(),
    };
    ensure!(
        client
            .query_client()
            .query_row("SELECT id FROM auth_user WHERE id = $id")
            .param("$id", fixture.actor_id)
            .optional()
            .await?
            .is_none(),
        "synthetic operator ID collision; rerun without modifying that account"
    );
    fs::create_dir(&fixture.dir)?;
    fs::set_permissions(&fixture.dir, fs::Permissions::from_mode(0o700))?;
    private_file(&fixture.dir.join("session"), fixture.token.as_bytes())?;
    private_file(&fixture.dir.join("password"), PASSWORD.as_bytes())?;
    let codec = SessionCodec::new(SESSION_SECRET.as_bytes(), &[])?;
    let password_hash =
        tokio::task::spawn_blocking(|| id_compat::password::hash_new(PASSWORD)).await??;
    let now = SystemTime::now();
    let payload = json!({
        "_auth_user_id": fixture.actor_id.to_string(), "_auth_user_backend": BACKEND,
        "_auth_user_hash": codec.auth_hash(&password_hash)?,
        "id_mfa_verified_user_id": fixture.actor_id.to_string(),
    });
    let encoded = codec.encode(
        payload.as_object().context("session payload")?,
        i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?,
        true,
    )?;
    let result: Result<()> = async {
        client.query_client().exec("INSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $password, true, $name, '', '', $email, true, true, CurrentUtcDatetime())")
            .param("$id", fixture.actor_id).param("$password", password_hash.clone())
            .param("$name", format!("cli-operator-{unique}"))
            .param("$email", format!("cli-operator-{unique}@example.invalid")).await?;
        client.query_client().exec("INSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($id, $name, $name, $email, true, 'active', false, CurrentUtcDatetime())")
            .param("$id", fixture.identity_id).param("$name", format!("cli-operator-{unique}"))
            .param("$email", format!("cli-operator-{unique}@example.invalid")).await?;
        client.query_client().exec("INSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($user, $identity, $subject, CurrentUtcDatetime())")
            .param("$user", fixture.actor_id).param("$identity", fixture.identity_id)
            .param("$subject", format!("cli-operator-subject-{unique}")).await?;
        client.query_client().exec("INSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, $data, CAST($expires AS Datetime))")
            .param("$key", fixture.token.clone()).param("$data", encoded.clone())
            .param("$expires", now + Duration::from_secs(3600)).await?;
        client.query_client().exec("INSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $user, 'totp', Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime())")
            .param("$id", i64::from(fixture.actor_id)).param("$user", fixture.actor_id).await?;

        let private_id = &fixture.client_ids[0];
        let public_id = &fixture.client_ids[1];
        let race_id = &fixture.client_ids[2];
        let invalid_id = &fixture.client_ids[3];
        let config_path = fixture.dir.join("private.json");
        let output_path = fixture.dir.join("created-secret.json");
        let rotate_path = fixture.dir.join("rotated-secret.json");
        let refused_path = fixture.dir.join("refused-secret.json");
        let config_arg = config_path.to_str().context("config path")?;
        let output_arg = output_path.to_str().context("secret path")?;
        let rotate_arg = rotate_path.to_str().context("rotation path")?;
        let refused_arg = refused_path.to_str().context("refused path")?;
        private_file(&config_path, &serde_json::to_vec(&config(private_id, false))?)?;
        let create = ["oidc-client-create", "--config", config_arg, "--secret-output", output_arg];
        let dry = fixture.run(&create).await?;
        let body = report(&dry, "dry_run", private_id, false)?;
        ensure!(body["revision"].is_null() && body["secret_generated"] == false);
        ensure!(!output_path.exists() && stored_clients(&client, private_id).await?.is_empty());
        ensure!(audit_rows(&client, fixture.identity_id).await?.is_empty(), "dry run wrote audit state");
        let private_digest = review_digest(&body)?.to_owned();

        let missing_digest = fixture.run(&["oidc-client-create", "--config", config_arg,
            "--secret-output", output_arg, "--apply"]).await?;
        ensure!(!missing_digest.status.success()
            && String::from_utf8_lossy(&missing_digest.stderr).contains("--expected-config-digest"),
            "create skipped configuration review digest");
        let mut changed = config(private_id, false);
        changed["redirect_uris"] = json!(["https://another-rp.example.invalid/callback"]);
        fs::write(&config_path, serde_json::to_vec(&changed)?)?;
        let stale_digest = fixture.run(&["oidc-client-create", "--config", config_arg,
            "--expected-config-digest", &private_digest, "--secret-output", output_arg, "--apply"]).await?;
        ensure!(!stale_digest.status.success()
            && String::from_utf8_lossy(&stale_digest.stderr).contains("configuration changed"),
            "create accepted configuration changed since review");
        ensure!(!output_path.exists() && stored_clients(&client, private_id).await?.is_empty()
            && audit_rows(&client, fixture.identity_id).await?.is_empty(),
            "missing/stale digest generated a secret or wrote database state");
        fs::write(&config_path, serde_json::to_vec_pretty(&config(private_id, false))?)?;

        let apply = ["oidc-client-create", "--config", config_arg,
            "--expected-config-digest", &private_digest, "--secret-output", output_arg, "--apply"];
        fs::write(fixture.dir.join("password"), WRONG_PASSWORD)?;
        ensure!(!fixture.run(&apply).await?.status.success(), "wrong operator password was accepted");
        fs::write(fixture.dir.join("password"), PASSWORD)?;
        client.query_client().exec("UPDATE auth_user SET is_staff = false WHERE id = $id")
            .param("$id", fixture.actor_id).await?;
        ensure!(!fixture.run(&apply).await?.status.success(), "non-staff operator was accepted");
        client.query_client().exec("UPDATE auth_user SET is_staff = true WHERE id = $id")
            .param("$id", fixture.actor_id).await?;
        client.query_client().exec("UPDATE auth_user SET is_superuser = false WHERE id = $id")
            .param("$id", fixture.actor_id).await?;
        ensure!(!fixture.run(&apply).await?.status.success(), "non-superuser operator was accepted");
        client.query_client().exec("UPDATE auth_user SET is_superuser = true WHERE id = $id")
            .param("$id", fixture.actor_id).await?;
        client.query_client().exec("DELETE FROM mfa_authenticator WHERE id = $id")
            .param("$id", i64::from(fixture.actor_id)).await?;
        ensure!(!fixture.run(&apply).await?.status.success(), "operator without an MFA authenticator was accepted");
        client.query_client().exec("INSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($id, $user, 'totp', Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime())")
            .param("$id", i64::from(fixture.actor_id)).param("$user", fixture.actor_id).await?;
        let mut unbound = payload.clone();
        unbound.as_object_mut().context("session object")?.remove("id_mfa_verified_user_id");
        let unbound = codec.encode(unbound.as_object().context("session object")?,
            i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?, true)?;
        client.query_client().exec("UPDATE django_session SET session_data = $data WHERE session_key = $key")
            .param("$data", unbound).param("$key", fixture.token.clone()).await?;
        ensure!(!fixture.run(&apply).await?.status.success(), "unbound MFA session was accepted");
        client.query_client().exec("UPDATE django_session SET session_data = $data WHERE session_key = $key")
            .param("$data", encoded.clone()).param("$key", fixture.token.clone()).await?;
        ensure!(!output_path.exists() && stored_clients(&client, private_id).await?.is_empty(),
            "denied operator created a client or secret artifact");

        let mut invalid = config(invalid_id, false);
        invalid["redirect_uris"] = json!(["https://*.example.invalid/callback"]);
        fs::write(&config_path, serde_json::to_vec(&invalid)?)?;
        ensure!(!fixture.run(&apply).await?.status.success(), "wildcard redirect was accepted");
        invalid = config(invalid_id, false);
        invalid["unexpected"] = json!(true);
        fs::write(&config_path, serde_json::to_vec(&invalid)?)?;
        ensure!(!fixture.run(&apply).await?.status.success(), "unknown config field was accepted");
        ensure!(!output_path.exists() && stored_clients(&client, invalid_id).await?.is_empty());
        fs::write(&config_path, serde_json::to_vec(&config(private_id, false))?)?;

        let created = fixture.run(&apply).await?;
        let body = report(&created, "created", private_id, false)?;
        ensure!(body["secret_generated"] == true);
        let original_revision = revision(&body)?.to_owned();
        let original_secret = read_secret(&output_path, private_id, &original_revision)?;
        fixture.no_leaks(&created, &[&original_secret, &password_hash])?;
        let stored = stored_clients(&client, private_id).await?;
        ensure!(stored.len() == 1 && !stored[0].1 && matches_secret(&original_secret, &stored[0].0).await?);
        ensure!(stored[0].2 == json!({
            "redirects": ["https://rp.example.invalid/callback?source=id"],
            "scopes": ["openid", "email", "offline_access"],
            "grants": ["authorization_code", "refresh_token"], "responses": ["code"],
        }), "created client configuration differs from reviewed input");
        let original_hash = stored[0].0.clone();
        let audit_before_show = audit_rows(&client, fixture.identity_id).await?;
        let shown = fixture.run(&["oidc-client-show", "--client-id", private_id]).await?;
        let shown_body = report(&shown, "found", private_id, false)?;
        fixture.no_leaks(&shown, &[&original_secret, &original_hash, &password_hash])?;
        ensure!(revision(&shown_body)? == original_revision
            && shown_body["configuration"]["redirect_uris"] == body["configuration"]["redirect_uris"]
            && shown_body["configuration"]["response_types"] == json!(["code"])
            && shown_body["configuration"]["logo_url"] == "",
            "show omitted or changed stored configuration/revision");
        ensure!(stored_clients(&client, private_id).await? == stored
            && audit_rows(&client, fixture.identity_id).await? == audit_before_show,
            "read-only confidential lookup changed client or audit state");
        let duplicate = fixture.run(&["oidc-client-create", "--config", config_arg,
            "--expected-config-digest", &private_digest, "--secret-output", refused_arg, "--apply"]).await?;
        ensure!(!duplicate.status.success() && !refused_path.exists(), "duplicate create succeeded");
        ensure!(stored_clients(&client, private_id).await?[0].0 == original_hash);

        fs::write(fixture.dir.join("password"), WRONG_PASSWORD)?;
        ensure!(!fixture.run(&["oidc-client-show", "--client-id", private_id]).await?.status.success(),
            "show accepted incorrect operator password");
        let denied_rotation = fixture.run(&["oidc-client-rotate-secret", "--client-id", private_id,
            "--expected-revision", &original_revision, "--secret-output", rotate_arg, "--apply"]).await?;
        fs::write(fixture.dir.join("password"), PASSWORD)?;
        ensure!(!denied_rotation.status.success() && !rotate_path.exists()
            && stored_clients(&client, private_id).await?[0].0 == original_hash,
            "denied operator changed the existing client or created a rotation artifact");

        let dry = fixture.run(&["oidc-client-rotate-secret", "--client-id", private_id,
            "--secret-output", rotate_arg]).await?;
        let body = report(&dry, "dry_run", private_id, false)?;
        ensure!(revision(&body)? == original_revision && body["secret_generated"] == false);
        ensure!(!rotate_path.exists() && stored_clients(&client, private_id).await?[0].0 == original_hash,
            "rotation dry run changed credentials or created an artifact");
        let missing_revision = fixture.run(&["oidc-client-rotate-secret", "--client-id", private_id,
            "--secret-output", rotate_arg, "--apply"]).await?;
        ensure!(!missing_revision.status.success() && !rotate_path.exists(), "rotation skipped review revision");
        let stale = "0".repeat(64);
        let stale_output = fixture.run(&["oidc-client-rotate-secret", "--client-id", private_id,
            "--expected-revision", &stale, "--secret-output", rotate_arg, "--apply"]).await?;
        ensure!(!stale_output.status.success() && !rotate_path.exists(), "stale revision rotated secret");
        let rotated = fixture.run(&["oidc-client-rotate-secret", "--client-id", private_id,
            "--expected-revision", &original_revision, "--secret-output", rotate_arg, "--apply"]).await?;
        let body = report(&rotated, "rotated", private_id, false)?;
        ensure!(body["secret_generated"] == true);
        let current_revision = revision(&body)?.to_owned();
        ensure!(current_revision != original_revision, "rotation did not change revision");
        let current_secret = read_secret(&rotate_path, private_id, &current_revision)?;
        ensure!(current_secret != original_secret, "rotation reused the old secret");
        fixture.no_leaks(&rotated, &[&original_secret, &current_secret, &password_hash])?;
        let stored = stored_clients(&client, private_id).await?;
        ensure!(stored.len() == 1 && matches_secret(&current_secret, &stored[0].0).await?
            && !matches_secret(&original_secret, &stored[0].0).await?, "rotation authentication contract failed");
        let rotated_hash = stored[0].0.clone();
        let stale_output = fixture.run(&["oidc-client-rotate-secret", "--client-id", private_id,
            "--expected-revision", &original_revision, "--secret-output", refused_arg, "--apply"]).await?;
        ensure!(!stale_output.status.success() && !refused_path.exists());
        let original_artifact = fs::read(&output_path)?;
        let overwrite = fixture.run(&["oidc-client-rotate-secret", "--client-id", private_id,
            "--expected-revision", &current_revision, "--secret-output", output_arg, "--apply"]).await?;
        ensure!(!overwrite.status.success() && fs::read(&output_path)? == original_artifact,
            "rotation overwrote an existing credential artifact");
        ensure!(stored_clients(&client, private_id).await?[0].0 == rotated_hash);

        fs::write(&config_path, serde_json::to_vec(&config(public_id, true))?)?;
        let public_dry = fixture.run(&["oidc-client-create", "--config", config_arg]).await?;
        let public_digest = review_digest(&report(&public_dry, "dry_run", public_id, true)?)?.to_owned();
        let public_secret = fixture.run(&["oidc-client-create", "--config", config_arg,
            "--expected-config-digest", &public_digest, "--secret-output", refused_arg, "--apply"]).await?;
        ensure!(!public_secret.status.success() && !refused_path.exists()
            && stored_clients(&client, public_id).await?.is_empty(), "public create accepted secret output");
        let public_output = fixture.run(&["oidc-client-create", "--config", config_arg,
            "--expected-config-digest", &public_digest, "--apply"]).await?;
        let public_report = report(&public_output, "created", public_id, true)?;
        ensure!(public_report["secret_generated"] == false);
        let stored = stored_clients(&client, public_id).await?;
        ensure!(stored.len() == 1 && stored[0].1 && stored[0].0.is_empty(), "public client has a secret");
        let audit_before_show = audit_rows(&client, fixture.identity_id).await?;
        let shown = fixture.run(&["oidc-client-show", "--client-id", public_id]).await?;
        let shown_body = report(&shown, "found", public_id, true)?;
        fixture.no_leaks(&shown, &[&original_secret, &current_secret, &original_hash, &rotated_hash, &password_hash])?;
        ensure!(revision(&shown_body)? == revision(&public_report)?
            && shown_body["configuration"]["is_public"] == true
            && shown_body["configuration"]["allowed_scopes"] == public_report["configuration"]["allowed_scopes"]);
        ensure!(stored_clients(&client, public_id).await? == stored
            && audit_rows(&client, fixture.identity_id).await? == audit_before_show
            && !refused_path.exists(), "read-only public lookup changed client/audit or wrote a secret file");
        let public_rotate = fixture.run(&["oidc-client-rotate-secret", "--client-id", public_id,
            "--expected-revision", revision(&public_report)?, "--secret-output", refused_arg, "--apply"]).await?;
        ensure!(!public_rotate.status.success() && !refused_path.exists(), "public client received a secret");

        fs::write(&config_path, serde_json::to_vec(&config(race_id, true))?)?;
        let race_dry = fixture.run(&["oidc-client-create", "--config", config_arg]).await?;
        let race_digest = review_digest(&report(&race_dry, "dry_run", race_id, true)?)?.to_owned();
        let barrier = Arc::new(Barrier::new(2));
        let mut contenders = Vec::new();
        for _ in 0..2 {
            let mut command = fixture.command(&["oidc-client-create", "--config", config_arg,
                "--expected-config-digest", &race_digest, "--apply"]);
            let barrier = barrier.clone();
            contenders.push(tokio::task::spawn_blocking(move || {
                barrier.wait();
                command.output()
            }));
        }
        let mut winners = 0;
        for contender in contenders {
            let output = contender.await??;
            fixture.no_leaks(&output, &[&original_secret, &current_secret])?;
            if output.status.success() {
                report(&output, "created", race_id, true)?;
                winners += 1;
            }
        }
        ensure!(winners == 1 && stored_clients(&client, race_id).await?.len() == 1,
            "concurrent creation did not produce exactly one winner");
        let audits = audit_rows(&client, fixture.identity_id).await?;
        for (id, expected) in [(private_id, 2), (public_id, 1), (race_id, 1)] {
            ensure!(audits.iter().filter(|(target, _)| target == id).count() == expected,
                "committed client mutation is missing its single atomic audit record");
        }
        for (_, meta) in &audits {
            for credential in [original_secret.as_str(), current_secret.as_str(), original_hash.as_str(),
                rotated_hash.as_str(), password_hash.as_str(), PASSWORD, fixture.token.as_str()] {
                ensure!(!meta.contains(credential), "audit contains credential material");
            }
        }
        Ok(())
    }.await;
    let cleanup = fixture.cleanup(&client).await;
    cleanup.context("remove exact synthetic operator/client rows")?;
    result
}
