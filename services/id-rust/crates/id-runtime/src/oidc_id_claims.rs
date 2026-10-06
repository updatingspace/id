//! Scope-limited ID token claims for authorization-code and refresh issuance.

use crate::media_url::MediaUrl;
use serde_json::{Value, json};
use ydb::{Transaction, YdbOrCustomerError};

pub async fn add_profile_claims(
    tx: &mut Transaction,
    id: &mut Value,
    user_id: i32,
    scopes: &[String],
    first_name: &str,
    last_name: &str,
    media: Option<&MediaUrl>,
) -> Result<(), YdbOrCustomerError> {
    let has = |wanted: &str| scopes.iter().any(|scope| scope == wanted);
    let wants_profile = has("profile") || has("profile_basic") || has("profile_extended");
    let wants_extended = has("profile_extended");
    let wants_phone = has("phone");
    if wants_profile || wants_phone {
        let mut rows = tx.query("SELECT CAST(avatar AS Utf8) AS avatar_key, phone_number, phone_verified, CAST(birth_date AS Utf8) AS birthdate FROM accounts_userprofile VIEW acct_profile_user_idx WHERE user_id = $id LIMIT 2")
            .param("$id", user_id).await?;
        let mut profiles = Vec::new();
        while let Some(set) = rows.next_result_set().await? {
            for mut row in set {
                let avatar: Option<String> = row.remove_field_by_name("avatar_key")?.try_into()?;
                let phone: String = row.remove_field_by_name("phone_number")?.try_into()?;
                let phone_verified: bool =
                    row.remove_field_by_name("phone_verified")?.try_into()?;
                let birthdate: Option<String> =
                    row.remove_field_by_name("birthdate")?.try_into()?;
                profiles.push((avatar, phone, phone_verified, birthdate));
            }
        }
        rows.close().await?;
        if profiles.len() > 1 {
            return Err(YdbOrCustomerError::from_err(std::io::Error::other(
                "ambiguous OIDC profile",
            )));
        }
        let profile = profiles.first();
        if wants_phone {
            id["phone_number"] = json!(profile.map(|row| row.1.as_str()).unwrap_or(""));
            id["phone_number_verified"] = json!(profile.is_some_and(|row| row.2));
        }
        if wants_profile {
            id["name"] = json!(format!("{first_name} {last_name}").trim());
            let picture = match profile
                .and_then(|row| row.0.as_deref())
                .filter(|key| !key.is_empty())
            {
                Some(key) => match media {
                    Some(media) => media.avatar_url(key).map_err(|_| {
                        YdbOrCustomerError::from_err(std::io::Error::other(
                            "invalid OIDC avatar path",
                        ))
                    })?,
                    None => String::new(),
                },
                None => String::new(),
            };
            id["picture"] = json!(picture);
        }
        if has("profile") || wants_extended {
            id["given_name"] = json!(first_name);
            id["family_name"] = json!(last_name);
            let mut rows = tx.query("SELECT language FROM accounts_userpreferences VIEW acct_prefs_user_idx WHERE user_id = $id LIMIT 2")
                .param("$id", user_id).await?;
            let mut languages = Vec::new();
            while let Some(set) = rows.next_result_set().await? {
                for mut row in set {
                    languages.push(row.remove_field_by_name("language")?.try_into()?);
                }
            }
            rows.close().await?;
            if languages.len() > 1 {
                return Err(YdbOrCustomerError::from_err(std::io::Error::other(
                    "ambiguous OIDC preferences",
                )));
            }
            id["locale"] = json!(
                languages
                    .first()
                    .filter(|value: &&String| !value.is_empty())
                    .map(String::as_str)
                    .unwrap_or("en")
            );
        }
        if wants_extended {
            id["birthdate"] = json!(profile.and_then(|row| row.3.as_deref()).unwrap_or(""));
        }
    }
    if has("address") {
        id["address"] = json!({});
    }
    Ok(())
}
