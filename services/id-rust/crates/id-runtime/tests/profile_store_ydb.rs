#![recursion_limit = "256"]
//! Synthetic profile rows in a local YDB with the Django schema.

use anyhow::{Context, Result, ensure};
use id_runtime::{ids::AccountId, profile_store::read_profile_details};
use std::time::{SystemTime, UNIX_EPOCH};

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
    for row_id in [id, second_provider] {
        client
            .query_client()
            .exec("DELETE FROM socialaccount_socialaccount WHERE id = $row_id")
            .param("$row_id", row_id)
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
