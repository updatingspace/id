#![recursion_limit = "256"]
//! Uses only synthetic rows in an explicitly local YDB with Django tables.
use anyhow::{Context, Result, ensure};
use id_compat::session::SessionCodec;
use id_runtime::session_store::SessionCookieExpiry;
use serde_json::json;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const BACKEND: &str = "django.contrib.auth.backends.ModelBackend";

#[tokio::test]
#[ignore = "requires local YDB after migrate_ydb; writes only synthetic negative-ID rows"]
async fn restores_only_active_bound_principal() -> Result<()> {
    let endpoint = std::env::var("YDB_ENDPOINT")?;
    ensure!(
        matches!(
            endpoint.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "session test requires local YDB on port 2136"
    );
    let client = id_runtime::connect_ydb().await?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let id = -i32::try_from(stamp % 1_000_000_000 + 1)?;
    let metadata_id = i64::from(id);
    let identity_id = Uuid::from_u128((stamp << 32) | u128::from(std::process::id()));
    let token = format!("rustpilot{stamp:032x}");
    let codec = Arc::new(SessionCodec::new(b"synthetic-session-test-key", &[])?);
    let password = "pbkdf2_sha256$1000000$synthetic$synthetic";
    let now = SystemTime::now();
    let payload = json!({
        "_auth_user_id": id.to_string(),
        "_auth_user_backend": BACKEND,
        "_auth_user_hash": codec.auth_hash(password)?,
    });
    let encoded = codec.encode(
        payload
            .as_object()
            .context("synthetic payload must be an object")?,
        i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?,
        true,
    )?;

    client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $password, true, $name, '', '', '', false, false, CurrentUtcDatetime())")
        .param("$id", id)
        .param("$password", password)
        .param("$name", format!("rust-pilot-{stamp}"))
        .await?;
    let result: Result<()> = async {
        client.query_client().exec("UPSERT INTO django_session (session_key, session_data, expire_date) VALUES ($key, $data, CAST($expires AS Datetime))")
            .param("$key", token.clone())
            .param("$data", encoded.clone())
            .param("$expires", now + Duration::from_secs(3600))
            .await?;
        let lookup = || id_runtime::session_store::restore_django_principal(
            &client, codec.clone(), &token, &[BACKEND], SystemTime::now()
        );
        let profile_lookup = || id_runtime::me_store::restore_django_profile(
            &client, codec.clone(), &token, &[BACKEND], SystemTime::now()
        );
        ensure!(lookup().await?.is_none(), "unbound session must not gain a principal");
        ensure!(profile_lookup().await?.is_none(), "unbound session exposed profile data");
        client.query_client().exec("UPSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($identity_id, $name, $name, $email, true, 'active', false, CurrentUtcDatetime())")
            .param("$identity_id", identity_id)
            .param("$name", format!("rust-pilot-{stamp}"))
            .param("$email", format!("rust-pilot-{stamp}@example.invalid"))
            .await?;
        client.query_client().exec("UPSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($user_id, $identity_id, $subject, CurrentUtcDatetime())")
            .param("$user_id", id)
            .param("$identity_id", identity_id)
            .param("$subject", format!("stable-subject-{stamp}"))
            .await?;
        let principal = lookup().await?.context("active bound session must restore")?;
        ensure!(principal.account_id.get() == i64::from(id) && principal.identity_id.get() == identity_id && principal.public_subject.as_str() == format!("stable-subject-{stamp}"), "principal identifiers changed");
        let combined = profile_lookup().await?.context("bound session profile must restore")?;
        ensure!(combined.principal == principal, "profile read changed principal");
        ensure!(combined.cookie_expiry == SessionCookieExpiry::Default, "default cookie expiry changed");
        let account = combined.details.account.context("authorized account missing")?;
        ensure!(account.username == format!("rust-pilot-{stamp}"));
        ensure!(combined.details.profile.is_none() && combined.details.preferences.is_none());

        let mut expiring_payload = payload.clone();
        expiring_payload["_session_expiry"] = json!(900);
        let custom_expiry_data = codec.encode(
            expiring_payload.as_object().context("synthetic payload must be an object")?,
            i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?,
            true,
        )?;
        client.query_client().exec("UPDATE django_session SET session_data = $data WHERE session_key = $key")
            .param("$data", custom_expiry_data).param("$key", token.clone()).await?;
        ensure!(profile_lookup().await?.context("custom-expiry session disappeared")?.cookie_expiry == SessionCookieExpiry::Seconds(900), "custom cookie age changed");
        client.query_client().exec("UPDATE django_session SET session_data = $data WHERE session_key = $key")
            .param("$data", encoded).param("$key", token.clone()).await?;
        client.query_client().exec("UPDATE usid_user SET status = 'suspended' WHERE user_id = $identity_id")
            .param("$identity_id", identity_id).await?;
        ensure!(lookup().await?.is_none(), "suspended master identity was accepted");
        ensure!(profile_lookup().await?.is_none(), "suspended identity exposed profile data");
        client.query_client().exec("UPDATE usid_user SET status = 'active' WHERE user_id = $identity_id")
            .param("$identity_id", identity_id).await?;
        client.query_client().exec("UPSERT INTO accounts_accountdeletionrequest (id, user_id, status, requested_at, reason) VALUES ($deletion_id, $user_id, 'pending', CurrentUtcDatetime(), '')")
            .param("$deletion_id", metadata_id)
            .param("$user_id", id).await?;
        ensure!(lookup().await?.is_none(), "pending deletion was accepted");
        ensure!(profile_lookup().await?.is_none(), "pending deletion exposed profile data");
        client.query_client().exec("UPDATE accounts_accountdeletionrequest SET status = 'canceled' WHERE id = $deletion_id")
            .param("$deletion_id", metadata_id).await?;
        ensure!(lookup().await?.is_some(), "canceled deletion still blocked the account");
        client.query_client().exec("UPDATE auth_user SET is_active = false WHERE id = $id")
            .param("$id", id).await?;
        ensure!(lookup().await?.is_none(), "disabled account was accepted");
        ensure!(profile_lookup().await?.is_none(), "disabled account exposed profile data");
        client.query_client().exec("UPDATE auth_user SET is_active = true WHERE id = $id")
            .param("$id", id).await?;
        client.query_client().exec("UPDATE accounts_accountidentity SET identity_id = NULL WHERE user_id = $id")
            .param("$id", id).await?;
        ensure!(lookup().await?.is_none(), "unlinked identity was accepted");
        client.query_client().exec("UPDATE accounts_accountidentity SET identity_id = $identity_id WHERE user_id = $id")
            .param("$identity_id", identity_id).param("$id", id).await?;
        ensure!(id_runtime::session_store::restore_django_principal(
            &client, codec.clone(), &token, &[], SystemTime::now()
        ).await?.is_none(), "unknown backend must fail");
        ensure!(id_runtime::session_store::restore_django_principal(
            &client, codec.clone(), "missing-local-token", &[BACKEND], SystemTime::now()
        ).await?.is_none(), "missing session must fail");

        client.query_client().exec("UPSERT INTO core_usersessionmeta (id, user_id, session_key, user_agent, first_seen, revoked_reason) VALUES ($meta_id, $id, $key, '', CurrentUtcDatetime(), '')")
            .param("$meta_id", metadata_id)
            .param("$id", id)
            .param("$key", token.clone())
            .await?;
        ensure!(lookup().await?.is_some(), "live metadata must pass");
        client.query_client().exec("UPDATE core_usersessionmeta SET revoked_at = CurrentUtcDatetime() WHERE id = $meta_id")
            .param("$meta_id", metadata_id).await?;
        ensure!(lookup().await?.is_none(), "revoked metadata must fail");
        client.query_client().exec("DELETE FROM core_usersessionmeta WHERE id = $meta_id")
            .param("$meta_id", metadata_id).await?;
        client.query_client().exec("UPDATE auth_user SET password = 'changed-password-hash' WHERE id = $id")
            .param("$id", id).await?;
        ensure!(lookup().await?.is_none(), "stale password hash must fail");
        client.query_client().exec("UPDATE auth_user SET password = $password WHERE id = $id")
            .param("$id", id).param("$password", password).await?;
        client.query_client().exec("UPDATE django_session SET expire_date = CAST($expires AS Datetime) WHERE session_key = $key")
            .param("$expires", UNIX_EPOCH + Duration::from_secs(1_700_000_000))
            .param("$key", token.clone()).await?;
        ensure!(lookup().await?.is_none(), "expired session must fail");
        Ok(())
    }.await;

    let cleanup_meta = client
        .query_client()
        .exec("DELETE FROM core_usersessionmeta WHERE id = $id")
        .param("$id", metadata_id)
        .await;
    let cleanup_deletion = client
        .query_client()
        .exec("DELETE FROM accounts_accountdeletionrequest WHERE id = $id")
        .param("$id", metadata_id)
        .await;
    let cleanup_binding = client
        .query_client()
        .exec("DELETE FROM accounts_accountidentity WHERE user_id = $id")
        .param("$id", id)
        .await;
    let cleanup_identity = client
        .query_client()
        .exec("DELETE FROM usid_user WHERE user_id = $id")
        .param("$id", identity_id)
        .await;
    let cleanup_session = client
        .query_client()
        .exec("DELETE FROM django_session WHERE session_key = $key")
        .param("$key", token)
        .await;
    let cleanup_user = client
        .query_client()
        .exec("DELETE FROM auth_user WHERE id = $id")
        .param("$id", id)
        .await;
    result?;
    cleanup_meta?;
    cleanup_deletion?;
    cleanup_binding?;
    cleanup_identity?;
    cleanup_session?;
    cleanup_user?;
    Ok(())
}
