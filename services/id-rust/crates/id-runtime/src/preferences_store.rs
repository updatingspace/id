//! Transactional adapter for legacy Django account preferences.

use crate::{
    consent_store::{new_consent_id, sync_marketing_consent_tx},
    preferences_domain::{clean_scope_policies, default_scope_policies, normalize_timezone},
    session_store::{LEGACY_BACKENDS, restore_django_session_tx},
    tx_retry::retry_known_abort,
};
use anyhow::Result;
use id_compat::session::SessionCodec;
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use ydb::{Client, Transaction, TxMode, closure};

const RUST_PREF_ID_PREFIX: i64 = 1 << 61;

#[derive(Clone, Default)]
pub struct PreferenceChanges {
    pub language: Option<String>,
    pub timezone: Option<String>,
    pub marketing_opt_in: Option<bool>,
    pub privacy_scope_defaults: Option<Map<String, Value>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PreferencesView {
    pub language: String,
    pub timezone: String,
    pub marketing_opt_in: bool,
    pub marketing_opt_in_at: Option<String>,
    pub marketing_opt_out_at: Option<String>,
    pub privacy_scope_defaults: Map<String, Value>,
}

struct PreferenceRow {
    id: i64,
    view: PreferencesView,
    empty_policies: bool,
}

pub async fn get_or_update_preferences(
    client: &Client,
    codec: Arc<SessionCodec>,
    token: &str,
    changes: Option<PreferenceChanges>,
    now: SystemTime,
) -> Result<Option<PreferencesView>> {
    let token = token.to_owned();
    let consent_id = new_consent_id();
    let marketing_version =
        std::env::var("MARKETING_CONSENT_VERSION").unwrap_or_else(|_| "v1".into());
    let backends: Vec<String> = LEGACY_BACKENDS
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    retry_known_abort(|| {
        let codec = codec.clone();
        let token = token.clone();
        let changes = changes.clone();
        let backends = backends.clone();
        let marketing_version = marketing_version.clone();
        async {
            client.query_client().retry_tx(closure!([codec, token, changes, backends, consent_id, marketing_version], async |tx: &mut Transaction| {
                let Some(session) = restore_django_session_tx(tx, codec.as_ref(), token, backends, now).await? else {
                    return Ok(None);
                };
                let user_id = i32::try_from(session.principal.account_id.get())
                    .map_err(ydb::YdbOrCustomerError::from_err)?;
                let has_mfa = tx.query_row("SELECT id FROM mfa_authenticator VIEW mfa_authenticator_user_id_0c3a50c0 WHERE user_id = $user_id LIMIT 1")
                    .param("$user_id", user_id).optional().await?.is_some();
                if has_mfa && !session.mfa_verified { return Ok(None); }

                let mut stream = tx.query("SELECT id, language, timezone, marketing_opt_in, CAST(marketing_opt_in_at AS Utf8) AS marketing_opt_in_at, CAST(marketing_opt_out_at AS Utf8) AS marketing_opt_out_at, CAST(privacy_scope_defaults AS Utf8) AS policies FROM accounts_userpreferences VIEW acct_prefs_user_idx WHERE user_id = $user_id LIMIT 2")
                    .param("$user_id", user_id).await?;
                let mut rows = Vec::with_capacity(2);
                while let Some(result_set) = stream.next_result_set().await? {
                    for mut row in result_set {
                        let policies_raw: Option<String> = row.remove_field_by_name("policies")?.try_into()?;
                        let policies: Map<String, Value> = policies_raw.as_deref()
                            .map(serde_json::from_str::<Value>)
                            .transpose().map_err(ydb::YdbOrCustomerError::from_err)?
                            .unwrap_or_else(|| json!({}))
                            .as_object().cloned().unwrap_or_default();
                        let empty_policies = policies.is_empty();
                        rows.push(PreferenceRow {
                            id: row.remove_field_by_name("id")?.try_into()?,
                            view: PreferencesView {
                                language: row.remove_field_by_name("language")?.try_into()?,
                                timezone: row.remove_field_by_name("timezone")?.try_into()?,
                                marketing_opt_in: row.remove_field_by_name("marketing_opt_in")?.try_into()?,
                                marketing_opt_in_at: row.remove_field_by_name("marketing_opt_in_at")?.try_into()?,
                                marketing_opt_out_at: row.remove_field_by_name("marketing_opt_out_at")?.try_into()?,
                                privacy_scope_defaults: policies,
                            },
                            empty_policies,
                        });
                    }
                }
                stream.close().await?;
                if rows.len() > 1 {
                    return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other("ambiguous preferences owner")));
                }
                let mut preference = if let Some(row) = rows.pop() {
                    row
                } else {
                    let id = RUST_PREF_ID_PREFIX + i64::from(user_id);
                    let defaults = serde_json::to_string(&default_scope_policies())
                        .map_err(ydb::YdbOrCustomerError::from_err)?;
                    tx.exec("INSERT INTO accounts_userpreferences (id, user_id, language, timezone, marketing_opt_in, privacy_scope_defaults, created_at, updated_at) VALUES ($id, $user_id, 'en', '', false, Unwrap(CAST($policies AS Json)), CAST($now AS Datetime), CAST($now AS Datetime))")
                        .param("$id", id).param("$user_id", user_id).param("$policies", defaults)
                        .param("$now", now).await?;
                    PreferenceRow {
                        id,
                        view: PreferencesView {
                            language: "en".into(), timezone: String::new(),
                            marketing_opt_in: false, marketing_opt_in_at: None, marketing_opt_out_at: None,
                            privacy_scope_defaults: serde_json::to_value(default_scope_policies())
                                .map_err(ydb::YdbOrCustomerError::from_err)?
                                .as_object().cloned().ok_or_else(|| ydb::YdbOrCustomerError::from_err(std::io::Error::other("invalid default policies")))?,
                        },
                        empty_policies: false,
                    }
                };
                if preference.empty_policies {
                    let defaults = serde_json::to_string(&default_scope_policies())
                        .map_err(ydb::YdbOrCustomerError::from_err)?;
                    tx.exec("UPDATE accounts_userpreferences SET privacy_scope_defaults = Unwrap(CAST($policies AS Json)), updated_at = CAST($now AS Datetime) WHERE id = $id")
                        .param("$policies", defaults).param("$now", now).param("$id", preference.id).await?;
                    preference.view.privacy_scope_defaults = serde_json::to_value(default_scope_policies())
                        .map_err(ydb::YdbOrCustomerError::from_err)?
                        .as_object().cloned().ok_or_else(|| ydb::YdbOrCustomerError::from_err(std::io::Error::other("invalid default policies")))?;
                }
                let mut updated_fields = Vec::new();
                if let Some(changes) = changes.as_ref() {
                    if let Some(language) = changes.language.as_ref() {
                        let language = language.trim();
                        if !language.is_empty() { preference.view.language = language.to_owned(); }
                        tx.exec("UPDATE accounts_userpreferences SET language = $language WHERE id = $id")
                            .param("$language", preference.view.language.clone()).param("$id", preference.id).await?;
                        updated_fields.push("language");
                    }
                    if let Some(timezone) = changes.timezone.as_ref() {
                        preference.view.timezone = normalize_timezone(timezone);
                        tx.exec("UPDATE accounts_userpreferences SET timezone = $timezone WHERE id = $id")
                            .param("$timezone", preference.view.timezone.clone()).param("$id", preference.id).await?;
                        updated_fields.push("timezone");
                    }
                    if let Some(marketing) = changes.marketing_opt_in {
                        if marketing && !preference.view.marketing_opt_in {
                            tx.exec("UPDATE accounts_userpreferences SET marketing_opt_in = true, marketing_opt_in_at = CAST($now AS Datetime), marketing_opt_out_at = NULL WHERE id = $id")
                                .param("$now", now).param("$id", preference.id).await?;
                            preference.view.marketing_opt_in = true;
                            preference.view.marketing_opt_in_at = Some(chrono::DateTime::<chrono::Utc>::from(now).format("%Y-%m-%dT%H:%M:%SZ").to_string());
                            preference.view.marketing_opt_out_at = None;
                            updated_fields.extend(["marketing_opt_in", "marketing_opt_in_at", "marketing_opt_out_at"]);
                        } else if !marketing && preference.view.marketing_opt_in {
                            tx.exec("UPDATE accounts_userpreferences SET marketing_opt_in = false, marketing_opt_out_at = CAST($now AS Datetime) WHERE id = $id")
                                .param("$now", now).param("$id", preference.id).await?;
                            preference.view.marketing_opt_in = false;
                            preference.view.marketing_opt_out_at = Some(chrono::DateTime::<chrono::Utc>::from(now).format("%Y-%m-%dT%H:%M:%SZ").to_string());
                            updated_fields.extend(["marketing_opt_in", "marketing_opt_out_at"]);
                        }
                        sync_marketing_consent_tx(tx, user_id, marketing, now, *consent_id, marketing_version).await?;
                    }
                    if let Some(scope_defaults) = changes.privacy_scope_defaults.as_ref() {
                        preference.view.privacy_scope_defaults = serde_json::to_value(clean_scope_policies(scope_defaults))
                            .map_err(ydb::YdbOrCustomerError::from_err)?
                            .as_object().cloned().ok_or_else(|| ydb::YdbOrCustomerError::from_err(std::io::Error::other("invalid policies")))?;
                        tx.exec("UPDATE accounts_userpreferences SET privacy_scope_defaults = Unwrap(CAST($policies AS Json)) WHERE id = $id")
                            .param("$policies", serde_json::to_string(&preference.view.privacy_scope_defaults).map_err(ydb::YdbOrCustomerError::from_err)?)
                            .param("$id", preference.id).await?;
                        updated_fields.push("privacy_scope_defaults");
                    }
                }
                if !updated_fields.is_empty() {
                    updated_fields.push("updated_at");
                    tx.exec("UPDATE accounts_userpreferences SET updated_at = CAST($now AS Datetime) WHERE id = $id")
                        .param("$now", now).param("$id", preference.id).await?;
                    let meta = json!({"fields": updated_fields, "source": "account"}).to_string();
                    tx.exec("INSERT INTO accounts_accountevent (user_id, action, meta, created_at) VALUES ($user_id, 'preferences_updated', Unwrap(CAST($meta AS Json)), CAST($now AS Datetime))")
                        .param("$user_id", user_id).param("$meta", meta).param("$now", now).await?;
                }
                Ok(Some(preference.view))
            })).with_mode(TxMode::SerializableReadWrite).idempotent(false)
                .timeout(Duration::from_secs(10)).await
        }
    }).await
}
