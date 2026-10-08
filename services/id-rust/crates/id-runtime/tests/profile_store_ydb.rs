#![recursion_limit = "256"]
//! Synthetic profile rows in a local YDB with the Django schema.

use anyhow::{Context, Result, ensure};
use id_runtime::{ids::AccountId, profile_store::read_profile_details};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires local YDB after migrate_ydb; writes only synthetic negative-ID rows"]
async fn reads_indexed_profile_and_rejects_ambiguous_one_to_one_rows() -> Result<()> {
    let endpoint = std::env::var("YDB_ENDPOINT")?;
    ensure!(
        matches!(
            endpoint.as_str(),
            "grpc://localhost:2136" | "grpc://127.0.0.1:2136"
        ) && std::env::var("YDB_DATABASE")? == "/local",
        "profile test requires local YDB on port 2136"
    );
    let client = id_runtime::connect_ydb().await?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let id = -i32::try_from(stamp % 1_000_000_000 + 1)?;
    let first_row = i64::from(id);
    let second_row = first_row - 1_000_000_000;
    let second_email = id - 1;
    let second_provider = id - 2;
    let other_account = id - 3;
    let identity_id = Uuid::new_v4();
    let other_identity_id = Uuid::new_v4();
    let foreign_external = second_row - 1;

    let result: Result<()> = async {
        let initial = read_profile_details(&client, AccountId::new(i64::from(id))).await?;
        ensure!(initial.account.is_none() && initial.profile.is_none() && initial.preferences.is_none());
        ensure!(!initial.has_mfa && !initial.email_verified && initial.oauth_providers.is_empty());

        client.query_client().exec("UPSERT INTO auth_user (id, password, is_active, username, first_name, last_name, email, is_staff, is_superuser, date_joined) VALUES ($id, 'synthetic-unusable', true, $username, 'Ada', 'Lovelace', $email, true, false, CurrentUtcDatetime())")
            .param("$id", id)
            .param("$username", format!("rust-profile-{stamp}"))
            .param("$email", format!("rust-profile-{stamp}@example.invalid"))
            .await?;

        let account_only = read_profile_details(&client, AccountId::new(i64::from(id))).await?;
        ensure!(account_only.account.is_some() && account_only.profile.is_none() && account_only.preferences.is_none());
        ensure!(!account_only.has_mfa && !account_only.email_verified && account_only.oauth_providers.is_empty());

        client.query_client().exec("UPSERT INTO accounts_userprofile (id, user_id, avatar, avatar_source, gravatar_enabled, phone_number, phone_verified, birth_date, created_at, updated_at) VALUES ($row_id, $user_id, CAST('avatars/saved.jpg' AS String), 'upload', false, '+123456789', true, CAST('2001-02-03' AS Date), CurrentUtcDatetime(), CurrentUtcDatetime())")
            .param("$row_id", first_row).param("$user_id", id).await?;
        client.query_client().exec("UPSERT INTO accounts_userpreferences (id, user_id, language, timezone, marketing_opt_in, privacy_scope_defaults, created_at, updated_at) VALUES ($row_id, $user_id, 'ru', 'Europe/Moscow', false, Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime(), CurrentUtcDatetime())")
            .param("$row_id", first_row).param("$user_id", id).await?;

        let details = read_profile_details(&client, AccountId::new(i64::from(id))).await?;
        let account = details.account.context("account row not found")?;
        ensure!(account.first_name == "Ada" && account.last_name == "Lovelace");
        ensure!(account.is_active && account.is_staff && !account.is_superuser);
        let profile = details.profile.context("profile row not found via index")?;
        ensure!(profile.phone_number == "+123456789");
        ensure!(profile.phone_verified && !profile.gravatar_enabled);
        ensure!(profile.birth_date.as_deref() == Some("2001-02-03"));
        ensure!(profile.avatar_key.as_deref() == Some("avatars/saved.jpg"));
        ensure!(profile.avatar_source == "upload");
        let preferences = details.preferences.context("preferences row not found via index")?;
        ensure!(preferences.language == "ru" && preferences.timezone == "Europe/Moscow");

        client.query_client().exec("UPSERT INTO mfa_authenticator (id, user_id, type, data, created_at) VALUES ($row_id, $user_id, 'totp', Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime())")
            .param("$row_id", first_row).param("$user_id", id).await?;
        client.query_client().exec("UPSERT INTO socialaccount_socialaccount (id, user_id, provider, uid, last_login, date_joined, extra_data) VALUES ($row_id, $user_id, 'github', 'synthetic-github', CurrentUtcDatetime(), CurrentUtcDatetime(), Unwrap(CAST('{}' AS Json)))")
            .param("$row_id", id).param("$user_id", id).await?;
        client.query_client().exec("UPSERT INTO socialaccount_socialaccount (id, user_id, provider, uid, last_login, date_joined, extra_data) VALUES ($row_id, $user_id, 'discord', 'synthetic-discord', CurrentUtcDatetime(), CurrentUtcDatetime(), Unwrap(CAST('{}' AS Json)))")
            .param("$row_id", second_provider).param("$user_id", id).await?;
        client.query_client().exec("UPSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($row_id, $user_id, $email, true, true)")
            .param("$row_id", id).param("$user_id", id)
            .param("$email", format!("rust-profile-{stamp}@example.invalid"))
            .await?;
        let enriched = read_profile_details(&client, AccountId::new(i64::from(id))).await?;
        ensure!(enriched.has_mfa && enriched.email_verified);
        ensure!(enriched.oauth_providers == ["discord", "github"]);

        client.query_client().exec("UPSERT INTO account_emailaddress (id, user_id, email, verified, primary) VALUES ($row_id, $user_id, $email, false, true)")
            .param("$row_id", second_email).param("$user_id", id)
            .param("$email", format!("rust-profile-secondary-{stamp}@example.invalid"))
            .await?;
        let error = read_profile_details(&client, AccountId::new(i64::from(id)))
            .await
            .err()
            .context("duplicate primary email ownership must be rejected")?;
        ensure!(error.to_string().contains("multiple primary email rows"));
        client.query_client().exec("DELETE FROM account_emailaddress WHERE id = $row_id")
            .param("$row_id", second_email).await?;

        client.query_client().exec("UPSERT INTO accounts_userprofile (id, user_id, avatar_source, gravatar_enabled, phone_number, phone_verified, created_at, updated_at) VALUES ($row_id, $user_id, 'none', true, '', false, CurrentUtcDatetime(), CurrentUtcDatetime())")
            .param("$row_id", second_row).param("$user_id", id).await?;
        let error = read_profile_details(&client, AccountId::new(i64::from(id)))
            .await
            .err()
            .context("duplicate profile ownership must be rejected")?;
        ensure!(error.to_string().contains("multiple profile rows"));
        client.query_client().exec("DELETE FROM accounts_userprofile WHERE id = $row_id")
            .param("$row_id", second_row).await?;

        client.query_client().exec("UPSERT INTO accounts_userpreferences (id, user_id, language, timezone, marketing_opt_in, privacy_scope_defaults, created_at, updated_at) VALUES ($row_id, $user_id, 'en', '', false, Unwrap(CAST('{}' AS Json)), CurrentUtcDatetime(), CurrentUtcDatetime())")
            .param("$row_id", second_row).param("$user_id", id).await?;
        let error = read_profile_details(&client, AccountId::new(i64::from(id)))
            .await
            .err()
            .context("duplicate preference ownership must be rejected")?;
        ensure!(error.to_string().contains("multiple preference rows"));

        // Empty middle result sets must not shift MFA, providers or email into
        // the profile/preferences slots of the combined query.
        client.query_client().exec("DELETE FROM accounts_userpreferences WHERE id = $row_id")
            .param("$row_id", second_row).await?;
        client.query_client().exec("DELETE FROM accounts_userprofile WHERE id = $row_id")
            .param("$row_id", first_row).await?;
        let without_profile = read_profile_details(&client, AccountId::new(i64::from(id))).await?;
        ensure!(without_profile.account.is_some() && without_profile.profile.is_none());
        ensure!(without_profile.preferences.context("empty profile hid preferences")?.language == "ru");
        ensure!(without_profile.has_mfa && without_profile.email_verified);
        ensure!(without_profile.oauth_providers == ["discord", "github"]);
        client.query_client().exec("DELETE FROM accounts_userpreferences WHERE id = $row_id")
            .param("$row_id", first_row).await?;
        let without_preferences = read_profile_details(&client, AccountId::new(i64::from(id))).await?;
        ensure!(without_preferences.profile.is_none() && without_preferences.preferences.is_none());
        ensure!(without_preferences.has_mfa && without_preferences.email_verified);
        ensure!(without_preferences.oauth_providers == ["discord", "github"]);

        // External links are scoped by the account's immutable UUID binding,
        // never by email or by the mere presence of external identity rows.
        for (row_id, owner, provider) in [
            (first_row, identity_id, "github"),
            (second_row, identity_id, "steam"),
            (foreign_external, other_identity_id, "foreign-only"),
        ] {
            client.query_client().exec("INSERT INTO usid_external_identity (id, user_id, provider, subject, created_at) VALUES ($id, $owner, $provider, $subject, CurrentUtcDatetime())")
                .param("$id", row_id).param("$owner", owner).param("$provider", provider)
                .param("$subject", format!("profile-{stamp}-{provider}")).await?;
        }
        client.query_client().exec("INSERT INTO socialaccount_socialaccount (id, user_id, provider, uid, last_login, date_joined, extra_data) VALUES ($id, $id, 'foreign-social', $subject, CurrentUtcDatetime(), CurrentUtcDatetime(), Unwrap(CAST('{}' AS Json)))")
            .param("$id", other_account).param("$subject", format!("foreign-profile-{stamp}")).await?;
        let missing_binding = read_profile_details(&client, AccountId::new(i64::from(id))).await?;
        ensure!(missing_binding.oauth_providers == ["discord", "github"], "missing binding exposed external or foreign links");

        client.query_client().exec("INSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($id, $identity, $subject, CurrentUtcDatetime())")
            .param("$id", id).param("$identity", identity_id)
            .param("$subject", format!("profile-subject-{stamp}")).await?;
        let combined = read_profile_details(&client, AccountId::new(i64::from(id))).await?;
        ensure!(combined.oauth_providers == ["discord", "github", "steam"], "both provider stores must be distinct, ordered and owner-scoped");
        ensure!(combined.has_mfa && combined.email_verified, "provider union shifted another result set");

        for row_id in [id, second_provider] {
            client.query_client().exec("DELETE FROM socialaccount_socialaccount WHERE id = $id")
                .param("$id", row_id).await?;
        }
        let external_only = read_profile_details(&client, AccountId::new(i64::from(id))).await?;
        ensure!(external_only.oauth_providers == ["github", "steam"], "external-only links were hidden");

        client.query_client().exec("UPDATE accounts_accountidentity SET identity_id = NULL WHERE user_id = $id")
            .param("$id", id).await?;
        let null_binding = read_profile_details(&client, AccountId::new(i64::from(id))).await?;
        ensure!(null_binding.oauth_providers.is_empty(), "null binding exposed external links");
        client.query_client().exec("UPDATE accounts_accountidentity SET identity_id = $identity WHERE user_id = $id")
            .param("$identity", identity_id).param("$id", id).await?;

        // Even an orphan reverse binding makes the UUID owner ambiguous. Do
        // not turn this into an empty list that would advertise a free link.
        client.query_client().exec("INSERT INTO accounts_accountidentity (user_id, identity_id, public_subject, created_at) VALUES ($id, $identity, $subject, CurrentUtcDatetime())")
            .param("$id", other_account).param("$identity", identity_id)
            .param("$subject", format!("ambiguous-profile-{stamp}")).await?;
        let error = read_profile_details(&client, AccountId::new(i64::from(id))).await.err()
            .context("ambiguous reverse identity ownership was accepted")?;
        ensure!(format!("{error:#}").contains("ambiguous account identity ownership in profile"), "unexpected ambiguity error: {error:#}");
        client.query_client().exec("DELETE FROM accounts_accountidentity WHERE user_id = $id")
            .param("$id", other_account).await?;
        let restored = read_profile_details(&client, AccountId::new(i64::from(id))).await?;
        ensure!(restored.oauth_providers == ["github", "steam"], "ambiguity check changed stored links");
        Ok(())
    }.await;

    for row_id in [first_row, second_row] {
        client
            .query_client()
            .exec("DELETE FROM accounts_userprofile WHERE id = $row_id")
            .param("$row_id", row_id)
            .await?;
        client
            .query_client()
            .exec("DELETE FROM accounts_userpreferences WHERE id = $row_id")
            .param("$row_id", row_id)
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM mfa_authenticator WHERE id = $row_id")
        .param("$row_id", first_row)
        .await?;
    for row_id in [id, second_provider, other_account] {
        client
            .query_client()
            .exec("DELETE FROM socialaccount_socialaccount WHERE id = $row_id")
            .param("$row_id", row_id)
            .await?;
    }
    for (row_id, owner) in [
        (first_row, identity_id),
        (second_row, identity_id),
        (foreign_external, other_identity_id),
    ] {
        client
            .query_client()
            .exec("DELETE FROM usid_external_identity WHERE id = $id AND user_id = $owner")
            .param("$id", row_id)
            .param("$owner", owner)
            .await?;
    }
    for (owner, subject) in [
        (id, format!("profile-subject-{stamp}")),
        (other_account, format!("ambiguous-profile-{stamp}")),
    ] {
        client
            .query_client()
            .exec("DELETE FROM accounts_accountidentity WHERE user_id = $id AND public_subject = $subject")
            .param("$id", owner)
            .param("$subject", subject)
            .await?;
    }
    for row_id in [id, second_email] {
        client
            .query_client()
            .exec("DELETE FROM account_emailaddress WHERE id = $row_id")
            .param("$row_id", row_id)
            .await?;
    }
    client
        .query_client()
        .exec("DELETE FROM auth_user WHERE id = $id")
        .param("$id", id)
        .await?;
    result
}
