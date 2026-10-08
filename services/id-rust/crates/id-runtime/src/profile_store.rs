//! Legacy account profile fields used to assemble the future `/me` response.
//! Authorization and avatar URL signing belong to the API boundary, not here.

use crate::ids::AccountId;
use anyhow::{Context, Result, bail};
use std::time::Duration;
use ydb::{Client, Transaction, TxMode, closure};

#[derive(Debug, PartialEq, Eq)]
pub struct AccountFields {
    pub username: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub is_staff: bool,
    pub is_superuser: bool,
    pub is_active: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ProfileFields {
    pub phone_number: String,
    pub phone_verified: bool,
    pub birth_date: Option<String>,
    pub avatar_key: Option<String>,
    pub avatar_source: String,
    pub gravatar_enabled: bool,
}

impl Default for ProfileFields {
    fn default() -> Self {
        Self {
            phone_number: String::new(),
            phone_verified: false,
            birth_date: None,
            avatar_key: None,
            avatar_source: "none".into(),
            gravatar_enabled: true,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct PreferenceFields {
    pub language: String,
    pub timezone: String,
}

impl Default for PreferenceFields {
    fn default() -> Self {
        Self {
            language: "en".into(),
            timezone: String::new(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ProfileDetails {
    pub account: Option<AccountFields>,
    pub profile: Option<ProfileFields>,
    pub preferences: Option<PreferenceFields>,
    pub has_mfa: bool,
    pub oauth_providers: Vec<String>,
    pub email_verified: bool,
}

/// Reads legacy account/profile state from one YDB snapshot. The caller must
/// already have authorized the account. Missing records remain explicit because
/// Django's current read path creates them, while this adapter is read-only.
pub async fn read_profile_details(
    client: &Client,
    account_id: AccountId,
) -> Result<ProfileDetails> {
    let user_id = i32::try_from(account_id.get()).context("account ID exceeds legacy YDB key")?;
    let rows = client
        .query_client()
        .retry_tx(closure!([user_id], async |tx: &mut Transaction| {
            read_profile_details_tx(tx, *user_id).await
        }))
        .isolation(TxMode::SnapshotReadOnly)
        .timeout(Duration::from_secs(5))
        .await
        .context("read legacy profile details")?;
    finish_profile_rows(rows)
}

pub(crate) type ProfileRows = (
    Option<AccountFields>,
    Vec<ProfileFields>,
    Vec<PreferenceFields>,
    bool,
    Vec<(i32, String)>,
    Vec<bool>,
);

pub(crate) async fn read_profile_details_tx(
    tx: &mut Transaction,
    user_id: i32,
) -> ydb::YdbResultWithCustomerErr<ProfileRows> {
    // QueryStream keeps SELECT result sets in order and assembles their chunks.
    // Keep the caller's transaction, using one ExecuteQuery RPC instead of six.
    let mut stream = tx
        .query(
            "SELECT username, email, first_name, last_name, is_staff, is_superuser, is_active FROM auth_user WHERE id = $user_id;
             SELECT phone_number, phone_verified, CAST(birth_date AS Utf8) AS birth_date, CAST(avatar AS Utf8) AS avatar_key, avatar_source, gravatar_enabled FROM accounts_userprofile VIEW acct_profile_user_idx WHERE user_id = $user_id LIMIT 2;
             SELECT language, timezone FROM accounts_userpreferences VIEW acct_prefs_user_idx WHERE user_id = $user_id LIMIT 2;
             SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $user_id LIMIT 1;
             SELECT id, provider FROM socialaccount_socialaccount VIEW socialaccount_socialaccount_user_id_8146e70c WHERE user_id = $user_id;
             SELECT verified FROM account_emailaddress VIEW account_emailaddress_user_id_2c513194 WHERE user_id = $user_id AND primary = true LIMIT 2;",
        )
        .param("$user_id", user_id)
        .await?;
    let mut sets = Vec::with_capacity(6);
    while let Some(rows) = stream.next_result_set().await? {
        sets.push(rows);
    }
    stream.close().await?;
    let [
        account_rows,
        profile_rows,
        preference_rows,
        mfa_rows,
        provider_rows,
        email_rows,
    ]: [ydb::ResultSet; 6] = sets
        .try_into()
        .map_err(|_| ydb::YdbError::Custom("expected six profile result sets".into()))?;
    let mut account_rows = account_rows.into_iter();
    let account = account_rows.next();
    if account_rows.next().is_some() {
        return Err(ydb::YdbError::Custom("expected at most one account row".into()).into());
    }
    let account = if let Some(mut row) = account {
        Some(AccountFields {
            username: row.remove_field_by_name("username")?.try_into()?,
            email: row.remove_field_by_name("email")?.try_into()?,
            first_name: row.remove_field_by_name("first_name")?.try_into()?,
            last_name: row.remove_field_by_name("last_name")?.try_into()?,
            is_staff: row.remove_field_by_name("is_staff")?.try_into()?,
            is_superuser: row.remove_field_by_name("is_superuser")?.try_into()?,
            is_active: row.remove_field_by_name("is_active")?.try_into()?,
        })
    } else {
        None
    };

    let mut profiles = Vec::with_capacity(2);
    for mut row in profile_rows {
        profiles.push(ProfileFields {
            phone_number: row.remove_field_by_name("phone_number")?.try_into()?,
            phone_verified: row.remove_field_by_name("phone_verified")?.try_into()?,
            birth_date: row.remove_field_by_name("birth_date")?.try_into()?,
            avatar_key: row.remove_field_by_name("avatar_key")?.try_into()?,
            avatar_source: row.remove_field_by_name("avatar_source")?.try_into()?,
            gravatar_enabled: row.remove_field_by_name("gravatar_enabled")?.try_into()?,
        });
    }
    let mut preferences = Vec::with_capacity(2);
    for mut row in preference_rows {
        preferences.push(PreferenceFields {
            language: row.remove_field_by_name("language")?.try_into()?,
            timezone: row.remove_field_by_name("timezone")?.try_into()?,
        });
    }

    let has_mfa = mfa_rows.into_iter().next().is_some();

    let mut providers = Vec::new();
    for mut row in provider_rows {
        let id: i32 = row.remove_field_by_name("id")?.try_into()?;
        let provider: String = row.remove_field_by_name("provider")?.try_into()?;
        providers.push((id, provider));
    }

    let mut primary_emails = Vec::with_capacity(2);
    for mut row in email_rows {
        primary_emails.push(row.remove_field_by_name("verified")?.try_into()?);
    }
    Ok((
        account,
        profiles,
        preferences,
        has_mfa,
        providers,
        primary_emails,
    ))
}

pub(crate) fn finish_profile_rows(rows: ProfileRows) -> Result<ProfileDetails> {
    let (account, mut profiles, mut preferences, has_mfa, mut providers, primary_emails) = rows;
    if profiles.len() > 1 {
        bail!("multiple profile rows for one account");
    }
    if preferences.len() > 1 {
        bail!("multiple preference rows for one account");
    }
    if primary_emails.len() > 1 {
        bail!("multiple primary email rows for one account");
    }
    providers.sort_by_key(|(id, _)| *id);
    Ok(ProfileDetails {
        account,
        profile: profiles.pop(),
        preferences: preferences.pop(),
        has_mfa,
        oauth_providers: providers
            .into_iter()
            .map(|(_, provider)| provider)
            .collect(),
        email_verified: primary_emails.first().copied().unwrap_or(false),
    })
}
