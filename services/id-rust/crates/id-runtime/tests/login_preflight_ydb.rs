#![recursion_limit = "256"]
//! Synthetic account rows only, in an explicitly local YDB with Rust schema.

use anyhow::{Context, Result, bail, ensure};
use id_runtime::login_preflight::{LoginDecision, LoginPreflight};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use ydb::{Client, Transaction, TxMode, closure};

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

async fn move_email(client: &Client, user_id: i32, email: &str) -> Result<()> {
    let email = email.to_owned();
    let key = email.to_lowercase();
    client.query_client().retry_tx(closure!([email, key], async |tx: &mut Transaction| {
        tx.exec("UPDATE auth_user SET email = $email WHERE id = $id")
            .param("$email", email.clone()).param("$id", user_id).await?;
        tx.exec("UPDATE account_emailaddress SET email = $email WHERE user_id = $id AND primary = true")
            .param("$email", email.clone()).param("$id", user_id).await?;
        tx.exec("UPDATE accounts_accountemaillookup SET email_key = $key WHERE user_id = $id")
            .param("$key", key.clone()).param("$id", user_id).await?;
        Ok(())
    })).with_mode(TxMode::SerializableReadWrite).idempotent(false).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires Rust-bootstrapped local YDB; writes only synthetic negative-ID rows"]
async fn password_preflight_preserves_login_gates() -> Result<()> {
    let endpoint = std::env::var("YDB_ENDPOINT")?;
    let fixed_local = matches!(
        endpoint.as_str(),
        "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
    );
    let disposable_local = std::env::var("ID_DISPOSABLE_YDB").as_deref() == Ok("true")
        && (endpoint.starts_with("grpc://localhost:") || endpoint.starts_with("grpc://127.0.0.1:"));
    ensure!(
        (fixed_local || disposable_local) && std::env::var("YDB_DATABASE")? == "/local",
        "login preflight test requires local YDB"
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

        // A lookup without an account produces five empty policy result sets.
        client.query_client().exec("INSERT INTO accounts_accountemaillookup (user_id, email_key) VALUES ($id, $email)")
            .param("$id", second_id).param("$email", other_email.clone()).await?;
        let error = verifier.verify(&other_email, PASSWORD).await.err()
            .context("orphan email lookup was accepted")?;
        ensure!(format!("{error:#}").contains("email lookup points to a missing account"), "empty account result lost its ownership failure: {error:#}");
        client.query_client().exec("DELETE FROM accounts_accountemaillookup WHERE user_id = $id")
            .param("$id", second_id).await?;

        // Account only: all four trailing sets are empty. A correct password
        // must still fail closed on the absent immutable binding.
        let error = verifier.verify(&login_email, PASSWORD).await.err()
            .context("missing identity binding was accepted")?;
        ensure!(error.to_string().contains("lacks an immutable identity binding"), "empty trailing results changed the binding failure: {error:#}");

        // A populated last set after three empty middle sets must remain the
        // deletion gate, even before this fixture receives an identity binding.
        client.query_client().exec("INSERT INTO accounts_accountdeletionrequest (id, user_id, status, requested_at, reason) VALUES ($id, $user_id, 'pending', CurrentUtcDatetime(), '')")
            .param("$id", i64::from(user_id)).param("$user_id", user_id).await?;
        ensure!(matches!(verifier.verify(&login_email, PASSWORD).await?, LoginDecision::InvalidCredentials), "empty middle results hid a pending deletion");
        client.query_client().exec("DELETE FROM accounts_accountdeletionrequest WHERE id = $id")
            .param("$id", i64::from(user_id)).await?;

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
            .param("$email", format!(" {email} ")).await?;
        ensure!(matches!(verifier.verify(&login_email, PASSWORD).await?, LoginDecision::EmailVerificationRequired), "verified email comparison unexpectedly trimmed whitespace");
        client.query_client().exec("UPDATE account_emailaddress SET email = $email WHERE id = $id")
            .param("$email", email.clone()).param("$id", user_id).await?;
        let LoginDecision::Ready(ready) = verifier.verify(&login_email, PASSWORD).await? else {
            anyhow::bail!("verified password/account was not ready")
        };
        ensure!(ready.account_id.get() == i64::from(user_id)
            && ready.identity_id.get() == identity_id
            && ready.public_subject.as_str() == format!("stable-login-subject-{stamp}")
            && ready.password_hash() == PASSWORD_HASH, "preflight changed account identity or hash");

        // A separate Rust client changes the account, derived lookup and
        // verified email in one transaction while two clients read.
        let alternate_email = format!("Rust-Login-Alternate-{stamp}@Example.invalid");
        let other_client = Arc::new(id_runtime::connect_ydb().await?);
        let other_verifier = LoginPreflight::new(other_client, 1)?;
        let writer_client = id_runtime::connect_ydb().await?;
        let writer_email = email.clone();
        let writer_alternate = alternate_email.clone();
        let writer = tokio::spawn(async move {
            for _ in 0..50 {
                move_email(&writer_client, user_id, &writer_alternate).await?;
                tokio::task::yield_now().await;
                move_email(&writer_client, user_id, &writer_email).await?;
            }
            Ok::<(), anyhow::Error>(())
        });
        let (original_reads, alternate_reads) = tokio::join!(
            check_concurrent_lookup(&verifier, &email),
            check_concurrent_lookup(&other_verifier, &alternate_email)
        );
        writer.await??;
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
        client.query_client().exec("UPDATE accounts_accountdeletionrequest SET status = 'canceled' WHERE id = $id")
            .param("$id", i64::from(user_id)).await?;
        ensure!(matches!(verifier.verify(&login_email, PASSWORD).await?, LoginDecision::Ready(_)), "canceled deletion blocked login");
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
