//! Exact JSON shape of Django's `CurrentUserOut` for the `/auth/me` boundary.

use crate::profile_store::ProfileDetails;
use anyhow::{Context, Result, ensure};
use serde::Serialize;

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct CurrentUserOut {
    pub user: Option<ProfileOut>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct ProfileOut {
    pub username: String,
    pub email: String,
    pub has_2fa: bool,
    pub oauth_providers: Vec<String>,
    pub is_staff: bool,
    pub is_superuser: bool,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone_number: Option<String>,
    pub phone_verified: Option<bool>,
    pub birth_date: Option<String>,
    pub language: Option<String>,
    pub timezone: Option<String>,
    pub avatar_url: Option<String>,
    pub avatar_source: Option<String>,
    pub avatar_gravatar_enabled: Option<bool>,
    pub email_verified: bool,
}

impl CurrentUserOut {
    pub fn guest() -> Self {
        Self { user: None }
    }

    /// Call only after a principal has been authenticated against session,
    /// identity and deletion state in the same YDB snapshot as `details`.
    /// The avatar URL must come from the configured storage adapter, which may
    /// need to sign an Object Storage URL.
    pub fn authenticated(details: ProfileDetails, avatar_url: Option<String>) -> Result<Self> {
        let account = details
            .account
            .context("authenticated account is missing")?;
        ensure!(account.is_active, "authenticated account became inactive");
        let profile = details.profile.unwrap_or_default();
        let preferences = details.preferences.unwrap_or_default();
        Ok(Self {
            user: Some(ProfileOut {
                username: account.username,
                email: account.email,
                has_2fa: details.has_mfa,
                oauth_providers: details.oauth_providers,
                is_staff: account.is_staff,
                is_superuser: account.is_superuser,
                first_name: nonempty(account.first_name),
                last_name: nonempty(account.last_name),
                phone_number: Some(profile.phone_number),
                phone_verified: Some(profile.phone_verified),
                birth_date: profile.birth_date,
                language: Some(preferences.language),
                timezone: Some(preferences.timezone),
                avatar_url: if profile.avatar_key.is_some() {
                    avatar_url
                } else {
                    None
                },
                avatar_source: Some(profile.avatar_source),
                avatar_gravatar_enabled: Some(profile.gravatar_enabled),
                email_verified: details.email_verified,
            }),
        })
    }
}

fn nonempty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile_store::{AccountFields, PreferenceFields, ProfileFields};
    use serde_json::json;

    fn account() -> AccountFields {
        AccountFields {
            username: "ada".into(),
            email: "ada@example.invalid".into(),
            first_name: String::new(),
            last_name: "Lovelace".into(),
            is_staff: false,
            is_superuser: false,
            is_active: true,
        }
    }

    #[test]
    fn guest_and_default_authenticated_json_match_django_contract() -> Result<()> {
        assert_eq!(
            serde_json::to_value(CurrentUserOut::guest())?,
            json!({"user": null})
        );
        let response = CurrentUserOut::authenticated(
            ProfileDetails {
                account: Some(account()),
                profile: None,
                preferences: None,
                has_mfa: false,
                oauth_providers: vec![],
                email_verified: false,
            },
            Some("https://ignored.example.invalid/avatar".into()),
        )?;
        assert_eq!(
            serde_json::to_value(response)?,
            json!({
                "user": {
                    "username": "ada", "email": "ada@example.invalid", "has_2fa": false,
                    "oauth_providers": [], "is_staff": false, "is_superuser": false,
                    "first_name": null, "last_name": "Lovelace", "phone_number": "",
                    "phone_verified": false, "birth_date": null, "language": "en", "timezone": "",
                    "avatar_url": null, "avatar_source": "none", "avatar_gravatar_enabled": true,
                    "email_verified": false
                }
            })
        );
        Ok(())
    }

    #[test]
    fn filled_profile_preserves_null_and_empty_distinctions() -> Result<()> {
        let response = CurrentUserOut::authenticated(
            ProfileDetails {
                account: Some(account()),
                profile: Some(ProfileFields {
                    phone_number: "+123".into(),
                    phone_verified: true,
                    birth_date: Some("2001-02-03".into()),
                    avatar_key: Some("avatars/saved.jpg".into()),
                    avatar_source: "upload".into(),
                    gravatar_enabled: false,
                }),
                preferences: Some(PreferenceFields {
                    language: "ru".into(),
                    timezone: "Europe/Moscow".into(),
                }),
                has_mfa: true,
                oauth_providers: vec!["github".into()],
                email_verified: true,
            },
            Some("https://media.example.invalid/avatars/saved.jpg".into()),
        )?;
        let user = serde_json::to_value(response)?["user"].clone();
        assert_eq!(user["phone_number"], "+123");
        assert_eq!(user["birth_date"], "2001-02-03");
        assert_eq!(
            user["avatar_url"],
            "https://media.example.invalid/avatars/saved.jpg"
        );
        assert_eq!(user["has_2fa"], true);
        assert_eq!(user["email_verified"], true);
        Ok(())
    }

    #[test]
    fn missing_or_inactive_account_is_never_rendered_as_authenticated() {
        let details = |account| ProfileDetails {
            account,
            profile: None,
            preferences: None,
            has_mfa: false,
            oauth_providers: vec![],
            email_verified: false,
        };
        assert!(CurrentUserOut::authenticated(details(None), None).is_err());
        let mut disabled = account();
        disabled.is_active = false;
        assert!(CurrentUserOut::authenticated(details(Some(disabled)), None).is_err());
    }
}
