//! Signed access-token lookup with live revocation and immutable identity checks.

use crate::{
    media_url::MediaUrl, oidc_keys::OidcKeyRing, oidc_protocol::narrow_scopes,
    session_store::active_principal_tx,
};
use anyhow::Result;
use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use serde_json::{Map, Value, json};
use std::time::{SystemTime, UNIX_EPOCH};
use ydb::{Client, Transaction, TxMode, closure};

pub async fn userinfo(
    client: &Client,
    keys: &OidcKeyRing,
    issuer: &str,
    bearer: &str,
    media: Option<MediaUrl>,
    now: SystemTime,
) -> Result<Option<Value>> {
    if bearer.is_empty() || bearer.len() > 8192 {
        return Ok(None);
    }
    let Ok(header) = decode_header(bearer) else {
        return Ok(None);
    };
    if header.alg != Algorithm::RS256 {
        return Ok(None);
    }
    let kid = header.kid.as_deref().unwrap_or(keys.active_kid());
    let Some(key) = keys.verifier(kid) else {
        return Ok(None);
    };
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[issuer]);
    validation.validate_aud = false;
    validation.leeway = 0;
    let Ok(decoded) = decode::<Value>(bearer, key, &validation) else {
        return Ok(None);
    };
    let payload = decoded.claims;
    let Some(jti) = payload
        .get("jti")
        .and_then(Value::as_str)
        .filter(|jti| !jti.is_empty() && jti.len() <= 128)
    else {
        return Ok(None);
    };
    let Some(subject) = payload
        .get("sub")
        .and_then(Value::as_str)
        .filter(|subject| !subject.is_empty())
    else {
        return Ok(None);
    };
    let Some(audience) = payload
        .get("aud")
        .and_then(Value::as_str)
        .filter(|audience| !audience.is_empty())
    else {
        return Ok(None);
    };
    let Some(issued_at) = payload.get("iat").and_then(Value::as_i64) else {
        return Ok(None);
    };
    let now_seconds = i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?;
    if issued_at > now_seconds + 60 || payload.get("iss").and_then(Value::as_str) != Some(issuer) {
        return Ok(None);
    }
    let jti = jti.to_owned();
    let subject = subject.to_owned();
    let audience = audience.to_owned();
    let signed_scope = payload
        .get("scope")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let result = client.query_client().retry_tx(closure!([jti, subject, audience, signed_scope, media], async |tx: &mut Transaction| {
        let mut rows = tx.query("SELECT user_id, client_id, subject, scope, access_expires_at, revoked_at FROM idp_oidctoken VIEW oidc_token_access_idx WHERE access_jti = $jti LIMIT 2")
            .param("$jti", jti.clone()).await?;
        let mut tokens = Vec::new();
        while let Some(set) = rows.next_result_set().await? {
            for mut row in set {
                let user_id: i32 = row.remove_field_by_name("user_id")?.try_into()?;
                let client_id: i64 = row.remove_field_by_name("client_id")?.try_into()?;
                let stored_subject: Option<String> = row.remove_field_by_name("subject")?.try_into()?;
                let scope: String = row.remove_field_by_name("scope")?.try_into()?;
                let expires_at: SystemTime = row.remove_field_by_name("access_expires_at")?.try_into()?;
                let revoked_at: Option<SystemTime> = row.remove_field_by_name("revoked_at")?.try_into()?;
                tokens.push((user_id, client_id, stored_subject, scope, expires_at, revoked_at));
            }
        }
        rows.close().await?;
        let [(user_id, client_id, stored_subject, scope, expires_at, revoked_at)] = tokens.as_slice() else {
            return Ok(None);
        };
        if *expires_at <= now || revoked_at.is_some() || signed_scope.as_deref() != Some(scope.as_str())
            || stored_subject.as_deref().is_some_and(|stored| !stored.is_empty() && stored != subject) {
            return Ok(None);
        }
        let Some(mut client) = tx.query_row("SELECT client_id FROM idp_oidcclient WHERE id = $id")
            .param("$id", *client_id).optional().await? else { return Ok(None); };
        let client_name: String = client.remove_field_by_name("client_id")?.try_into()?;
        if client_name != audience.as_str() { return Ok(None); }
        let Some(principal) = active_principal_tx(tx, *user_id).await? else { return Ok(None); };
        if principal.public_subject.as_str() != subject { return Ok(None); }
        let Ok(scopes) = narrow_scopes(scope, None) else { return Ok(None); };
        let Some(mut account) = tx.query_row("SELECT first_name, last_name, email FROM auth_user WHERE id = $id")
            .param("$id", *user_id).optional().await? else { return Ok(None); };
        let first_name: String = account.remove_field_by_name("first_name")?.try_into()?;
        let last_name: String = account.remove_field_by_name("last_name")?.try_into()?;
        let email: String = account.remove_field_by_name("email")?.try_into()?;
        let Some(mut identity) = tx.query_row("SELECT system_admin, email_verified FROM usid_user WHERE user_id = $id")
            .param("$id", principal.identity_id.get()).optional().await? else { return Ok(None); };
        let system_admin: bool = identity.remove_field_by_name("system_admin")?.try_into()?;
        let master_email_verified: bool = identity.remove_field_by_name("email_verified")?.try_into()?;
        let mut claims = Map::new();
        claims.insert("sub".into(), json!(subject));
        claims.insert("user_id".into(), json!(principal.identity_id.get().to_string()));
        claims.insert("master_flags".into(), json!({"suspended":false,"banned":false,"system_admin":system_admin,"email_verified":master_email_verified,"status":"active"}));
        if scopes.iter().any(|scope| scope == "email") {
            let mut stream = tx.query("SELECT email, verified FROM account_emailaddress VIEW account_emailaddress_user_id_2c513194 WHERE user_id = $id AND primary = true LIMIT 2")
                .param("$id", *user_id).await?;
            let mut primary = Vec::new();
            while let Some(set) = stream.next_result_set().await? {
                for mut row in set {
                    let address: String = row.remove_field_by_name("email")?.try_into()?;
                    let verified: bool = row.remove_field_by_name("verified")?.try_into()?;
                    primary.push(address.eq_ignore_ascii_case(&email) && verified);
                }
            }
            stream.close().await?;
            if primary.len() > 1 { return Ok(None); }
            claims.insert("email".into(), json!(email));
            claims.insert("email_verified".into(), json!(primary.first().copied().unwrap_or(false)));
        }
        let wants_profile = scopes.iter().any(|scope| matches!(scope.as_str(), "profile" | "profile_basic" | "profile_extended"));
        let wants_extended = scopes.iter().any(|scope| scope == "profile_extended");
        let wants_phone = scopes.iter().any(|scope| scope == "phone");
        if wants_profile || wants_phone {
            let mut stream = tx.query("SELECT CAST(avatar AS Utf8) AS avatar_key, phone_number, phone_verified, CAST(birth_date AS Utf8) AS birthdate FROM accounts_userprofile VIEW acct_profile_user_idx WHERE user_id = $id LIMIT 2")
                .param("$id", *user_id).await?;
            let mut profiles = Vec::new();
            while let Some(set) = stream.next_result_set().await? {
                for mut row in set {
                    let avatar: Option<String> = row.remove_field_by_name("avatar_key")?.try_into()?;
                    let phone: String = row.remove_field_by_name("phone_number")?.try_into()?;
                    let phone_verified: bool = row.remove_field_by_name("phone_verified")?.try_into()?;
                    let birthdate: Option<String> = row.remove_field_by_name("birthdate")?.try_into()?;
                    profiles.push((avatar, phone, phone_verified, birthdate));
                }
            }
            stream.close().await?;
            if profiles.len() > 1 { return Ok(None); }
            let profile = profiles.first();
            if wants_phone {
                claims.insert("phone_number".into(), json!(profile.map(|row| row.1.as_str()).unwrap_or("")));
                claims.insert("phone_number_verified".into(), json!(profile.is_some_and(|row| row.2)));
            }
            if wants_profile {
                claims.insert("name".into(), json!(format!("{first_name} {last_name}").trim()));
                let picture = match profile.and_then(|row| row.0.as_deref()).filter(|key| !key.is_empty()) {
                    Some(key) => match media.as_ref() {
                        Some(media) => media.avatar_url(key).map_err(|_| ydb::YdbOrCustomerError::from_err(std::io::Error::other("invalid avatar path")))?,
                        None => return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("OIDC media base is not configured"))),
                    },
                    None => String::new(),
                };
                claims.insert("picture".into(), json!(picture));
            }
            if scopes.iter().any(|scope| scope == "profile") || wants_extended {
                claims.insert("given_name".into(), json!(first_name));
                claims.insert("family_name".into(), json!(last_name));
                let mut stream = tx.query("SELECT language FROM accounts_userpreferences VIEW acct_prefs_user_idx WHERE user_id = $id LIMIT 2")
                    .param("$id", *user_id).await?;
                let mut languages: Vec<String> = Vec::new();
                while let Some(set) = stream.next_result_set().await? {
                    for mut row in set { languages.push(row.remove_field_by_name("language")?.try_into()?); }
                }
                stream.close().await?;
                if languages.len() > 1 { return Ok(None); }
                let language = languages.first().filter(|value| !value.is_empty()).map(String::as_str).unwrap_or("en");
                claims.insert("locale".into(), json!(language));
            }
            if wants_extended {
                claims.insert("birthdate".into(), json!(profile.and_then(|row| row.3.as_deref()).unwrap_or("")));
            }
        }
        if scopes.iter().any(|scope| scope == "address") {
            claims.insert("address".into(), json!({}));
        }
        Ok(Some(Value::Object(claims)))
    })).isolation(TxMode::SerializableReadWrite).await?;
    Ok(result)
}
