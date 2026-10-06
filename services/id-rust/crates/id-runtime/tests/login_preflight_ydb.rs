#![recursion_limit = "256"]
//! Synthetic account rows only, in an explicitly local YDB with Django schema.

use anyhow::{Result, bail, ensure};
use id_runtime::login_preflight::{LoginDecision, LoginPreflight};
use std::{
    process::Command,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const PASSWORD: &str = "Synthetic пароль 🔐 with unicode and more than 72 bytes Synthetic пароль 🔐 with unicode and more than 72 bytes ";
const PASSWORD_HASH: &str = "argon2$argon2id$v=19$m=102400,t=2,p=8$U3ludGhldGljR29sZGVuU2FsdDEyMw$Q/uhIlhHnraeVEMP4b/SvQx5Gjb04zC0bEmIq6OPnUo";

async fn check_concurrent_lookup(verifier: &LoginPreflight, email: &str) -> Result<()> {
    for _ in 0..50 {
        match verifier.verify(email, PASSWORD).await? {
            LoginDecision::Ready(_) | LoginDecision::InvalidCredentials => {}
            LoginDecision::EmailVerificationRequired | LoginDecision::MfaRequired(_) => {
                bail!("observed partially committed email change during login")
            }
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires local YDB after migrate_ydb; writes only synthetic negative-ID rows"]
async fn password_preflight_preserves_login_gates() -> Result<()> {
    ensure!(
        matches!(
            std::env::var("YDB_ENDPOINT")?.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "login preflight test requires local YDB on port 2136"
    );
    let client = Arc::new(id_runtime::connect_ydb().await?);
    let verifier = LoginPreflight::new(client.clone(), 1)?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let user_id = -i32::try_from(stamp % 1_000_000_000 + 2)?;
    let second_id = user_id - 1;
    let identity_id = Uuid::from_u128((stamp << 32) | u128::from(std::process::id()));
    let email = format!("Rust-Login-{stamp}@Example.invalid");
    let login_email = format!("RUST-LOGIN-{stamp}@example.INVALID");
    let other_email = format!("missing-{stamp}@example.invalid");
    client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $password, true, $username, '', '', $email, false, false, CurrentUtcDatetime())")
        .param("$id", user_id).param("$password", PASSWORD_HASH)
        .param("$username", format!("rust-login-{stamp}"))
        .param("$email", email.clone()).await?;
    client
        .query_client()
        .exec(
            "UPSERT INTO accounts_accountemaillookup (user_id, email_key) VALUES ($id, $email_key)",
        )
        .param("$id", user_id)
        .param("$email_key", email.to_lowercase())
        .await?;
    let result: Result<()> = async {
        ensure!(matches!(verifier.verify(&other_email, PASSWORD).await?, LoginDecision::InvalidCredentials), "unknown account was accepted");
        ensure!(matches!(verifier.verify(&login_email, "wrong-password").await?, LoginDecision::InvalidCredentials), "wrong password was accepted");

        client.query_client().exec("UPSERT INTO usid_user (user_id, username, display_name, email, email_verified, status, system_admin, created_at) VALUES ($identity_id, $name, $name, $email, true, 'active', false, CurrentUtcDatetime())")
            .param("$identity_id", identity_id)
            .param("$name", format!("rust-login-{stamp}"))
            .param("$email", email.to_lowercase()).await?;
        client.query_client().exec("UPSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($user_id, $identity_id, $subject, CurrentUtcDatetime())")
            .param("$user_id", user_id).param("$identity_id", identity_id)
            .param("$subject", format!("stable-login-subject-{stamp}"))
            .await?;
        ensure!(matches!(verifier.verify(&login_email, PASSWORD).await?, LoginDecision::EmailVerificationRequired), "unverified email was accepted");
        client.query_client().exec("UPSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($row_id, $user_id, $email, true, true)")
            .param("$row_id", user_id).param("$user_id", user_id)
            .param("$email", email.clone()).await?;
        let LoginDecision::Ready(ready) = verifier.verify(&login_email, PASSWORD).await? else {
            anyhow::bail!("verified password/account was not ready")
        };
        ensure!(ready.account_id.get() == i64::from(user_id)
            && ready.identity_id.get() == identity_id
            && ready.public_subject.as_str() == format!("stable-login-subject-{stamp}")
            && ready.password_hash() == PASSWORD_HASH, "preflight changed account identity or hash");

        // A separate Django process changes auth_user, the derived lookup and
        // verified email in one transaction while two Rust clients read.
        let alternate_email = format!("Rust-Login-Alternate-{stamp}@Example.invalid");
        let other_client = Arc::new(id_runtime::connect_ydb().await?);
        let other_verifier = LoginPreflight::new(other_client, 1)?;
        let python_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../id")
            .canonicalize()?;
        let writer_email = email.clone();
        let writer_alternate = alternate_email.clone();
        let writer = tokio::task::spawn_blocking(move || {
            Command::new(python_dir.join(".venv/bin/python"))
                .arg("scripts/check_email_lookup_race.py")
                .arg(user_id.to_string())
                .arg(writer_email)
                .arg(writer_alternate)
                .arg("--rounds")
                .arg("100")
                .current_dir(python_dir)
                .env("PYTHONPATH", "src")
                .env("DJANGO_SETTINGS_MODULE", "app.settings")
                .env("DJANGO_DEBUG", "true")
                .env("DJANGO_SECRET_KEY", "synthetic-local-secret-min-32-characters")
                .env("DB_DRIVER", "ydb")
                .env("YDB_NAME", "default")
                .env("YDB_CREDENTIALS_MODE", "token")
                .env("YDB_TOKEN", "local-ydb-token")
                .env("REDIS_URL", "")
                .output()
        });
        let (original_reads, alternate_reads) = tokio::join!(
            check_concurrent_lookup(&verifier, &email),
            check_concurrent_lookup(&other_verifier, &alternate_email)
        );
        let output = writer.await??;
        ensure!(
            output.status.success(),
            "transition Django email writer failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        original_reads?;
        alternate_reads?;
        ensure!(
            matches!(verifier.verify(&login_email, PASSWORD).await?, LoginDecision::Ready(_)),
            "original email stopped working after concurrent changes"
        );
        ensure!(
            matches!(verifier.verify(&alternate_email, PASSWORD).await?, LoginDecision::InvalidCredentials),
            "alternate email remained available after the writer restored the original"
        );

        client.query_client().exec("UPDATE auth_user SET email = 'moved@example.invalid' WHERE id = $id")
            .param("$id", user_id).await?;
        ensure!(verifier.verify(&login_email, PASSWORD).await.is_err(), "stale indexed email issued a login decision");
        client.query_client().exec("UPDATE auth_user SET email = $email WHERE id = $id")
            .param("$email", email.clone()).param("$id", user_id).await?;

        client.query_client().exec("UPSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($row_id, $user_id, 'totp', Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime())")
            .param("$row_id", i64::from(user_id)).param("$user_id", user_id).await?;
        ensure!(matches!(verifier.verify(&login_email, PASSWORD).await?, LoginDecision::MfaRequired(_)), "MFA was bypassed");
        client.query_client().exec("DELETE FROM mfa_authenticator WHERE id = $id")
            .param("$id", i64::from(user_id)).await?;

        client.query_client().exec("UPDATE usid_user SET status = 'suspended' WHERE user_id = $id")
            .param("$id", identity_id).await?;
        ensure!(matches!(verifier.verify(&login_email, PASSWORD).await?, LoginDecision::InvalidCredentials), "suspended identity was accepted");
        client.query_client().exec("UPDATE usid_user SET status = 'active' WHERE user_id = $id")
            .param("$id", identity_id).await?;
        client.query_client().exec("UPSERT INTO accounts_accountdeletionrequest (id, user_id, status, requested_at, reason) VALUES ($row_id, $user_id, 'pending', CurrentUtcDatetime(), '')")
            .param("$row_id", i64::from(user_id)).param("$user_id", user_id).await?;
        ensure!(matches!(verifier.verify(&login_email, PASSWORD).await?, LoginDecision::InvalidCredentials), "deleting account was accepted");
        client.query_client().exec("DELETE FROM accounts_accountdeletionrequest WHERE id = $id")
            .param("$id", i64::from(user_id)).await?;
        client.query_client().exec("UPDATE auth_user SET is_active = false WHERE id = $id")
            .param("$id", user_id).await?;
        ensure!(matches!(verifier.verify(&login_email, PASSWORD).await?, LoginDecision::InvalidCredentials), "disabled account was accepted");
        client.query_client().exec("UPDATE auth_user SET is_active = true WHERE id = $id")
            .param("$id", user_id).await?;

        client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, $password, true, $username, '', '', $email, false, false, CurrentUtcDatetime())")
            .param("$id", second_id).param("$password", PASSWORD_HASH)
            .param("$username", format!("rust-login-duplicate-{stamp}"))
            .param("$email", email.to_lowercase()).await?;
        client.query_client().exec("UPSERT INTO accounts_accountemaillookup (user_id, email_key) VALUES ($id, $email_key)")
            .param("$id", second_id).param("$email_key", email.to_lowercase()).await?;
        ensure!(verifier.verify(&login_email, PASSWORD).await.is_err(), "case-insensitive duplicate was accepted");
        Ok(())
    }.await;

    client
        .query_client()
        .exec("DELETE FROM accounts_accountdeletionrequest WHERE id = $id")
        .param("$id", i64::from(user_id))
        .await?;
    client
        .query_client()
        .exec("DELETE FROM mfa_authenticator WHERE id = $id")
        .param("$id", i64::from(user_id))
        .await?;
    client
        .query_client()
        .exec("DELETE FROM account_emailaddress WHERE id = $id")
        .param("$id", user_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountidentity WHERE user_id = $id")
        .param("$id", user_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM usid_user WHERE user_id = $id")
        .param("$id", identity_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountemaillookup WHERE user_id = $id")
        .param("$id", second_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM accounts_accountemaillookup WHERE user_id = $id")
        .param("$id", user_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM auth_user WHERE id = $id")
        .param("$id", second_id)
        .await?;
    client
        .query_client()
        .exec("DELETE FROM auth_user WHERE id = $id")
        .param("$id", user_id)
        .await?;
    result
}
