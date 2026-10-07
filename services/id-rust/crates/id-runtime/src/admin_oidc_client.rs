//! Read-only operator projection of an OIDC client. Never select its secret hash.

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{io, time::Duration};
use ydb::{Client, Transaction, TxMode, closure};

#[derive(Serialize)]
pub struct ClientSnapshot {
    pub client_id: String,
    pub name: String,
    pub description: String,
    pub redirect_uris: Vec<String>,
    pub redirect_revision: String,
    pub allowed_scopes: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub is_public: bool,
    pub is_first_party: bool,
}

pub enum LookupOutcome {
    Found(ClientSnapshot),
    NotFound,
    Ambiguous,
}

pub async fn by_client_id(client: &Client, client_id: String) -> Result<LookupOutcome> {
    client
        .query_client()
        .retry_tx(closure!([client_id], async |tx: &mut Transaction| {
            let mut stream = tx.query("SELECT client_id, name, description, CAST(redirect_uris AS Utf8) AS redirects, CAST(allowed_scopes AS Utf8) AS scopes, CAST(grant_types AS Utf8) AS grants, CAST(response_types AS Utf8) AS responses, is_public, is_first_party FROM idp_oidcclient VIEW oidc_client_id_idx WHERE client_id = $id LIMIT 2")
                .param("$id", client_id.clone()).await?;
            let mut found = Vec::with_capacity(2);
            while let Some(rows) = stream.next_result_set().await? {
                for mut row in rows {
                    let actual_id: String = row.remove_field_by_name("client_id")?.try_into()?;
                    if actual_id != *client_id {
                        return Err(ydb::YdbOrCustomerError::from_err(io::Error::other("OIDC client index disagrees with row")));
                    }
                    let redirects: String = row.remove_field_by_name("redirects")?.try_into()?;
                    let scopes: String = row.remove_field_by_name("scopes")?.try_into()?;
                    let grants: String = row.remove_field_by_name("grants")?.try_into()?;
                    let responses: String = row.remove_field_by_name("responses")?.try_into()?;
                    found.push(ClientSnapshot {
                        client_id: actual_id,
                        name: row.remove_field_by_name("name")?.try_into()?,
                        description: row.remove_field_by_name("description")?.try_into()?,
                        redirect_uris: parse_list(&redirects).map_err(ydb::YdbOrCustomerError::from_err)?,
                        redirect_revision: redirect_revision(&redirects),
                        allowed_scopes: parse_list(&scopes).map_err(ydb::YdbOrCustomerError::from_err)?,
                        grant_types: parse_list(&grants).map_err(ydb::YdbOrCustomerError::from_err)?,
                        response_types: parse_list(&responses).map_err(ydb::YdbOrCustomerError::from_err)?,
                        is_public: row.remove_field_by_name("is_public")?.try_into()?,
                        is_first_party: row.remove_field_by_name("is_first_party")?.try_into()?,
                    });
                }
            }
            stream.close().await?;
            Ok(match found.len() {
                0 => LookupOutcome::NotFound,
                1 => LookupOutcome::Found(found.remove(0)),
                _ => LookupOutcome::Ambiguous,
            })
        }))
        .isolation(TxMode::SnapshotReadOnly)
        .timeout(Duration::from_secs(5))
        .await
        .context("read operator OIDC client snapshot")
}

fn parse_list(raw: &str) -> Result<Vec<String>, io::Error> {
    let values: Vec<String> = serde_json::from_str(raw).map_err(io::Error::other)?;
    if values.len() > 100 || values.iter().any(|value| value.len() > 2048) {
        return Err(io::Error::other(
            "OIDC client field exceeds operator view limit",
        ));
    }
    Ok(values)
}

pub(crate) fn redirect_revision(raw: &str) -> String {
    hex::encode(Sha256::digest(raw.as_bytes()))
}
