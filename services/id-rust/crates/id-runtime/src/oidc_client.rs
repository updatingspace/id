//! OIDC client authentication shared by token and revocation operations.

use anyhow::Result;
use tokio::sync::Semaphore;
use ydb::{Client, Transaction};

static SECRET_HASH_SLOTS: Semaphore = Semaphore::const_new(4);

#[derive(Clone)]
pub(crate) struct ClientMeta {
    pub id: i64,
    pub client_id: String,
    pub secret_hash: String,
    pub is_public: bool,
    pub grant_types: Vec<String>,
}

impl ClientMeta {
    pub fn same_authentication(&self, other: &Self) -> bool {
        self.client_id == other.client_id
            && self.secret_hash == other.secret_hash
            && self.is_public == other.is_public
    }

    pub fn same_configuration(&self, other: &Self) -> bool {
        self.same_authentication(other) && self.grant_types == other.grant_types
    }
}

pub(crate) async fn authenticate(
    client: &Client,
    client_id: &str,
    client_secret: Option<&str>,
) -> Result<Option<ClientMeta>> {
    if client_id.is_empty()
        || client_id.len() > 64
        || client_secret.is_some_and(|value| value.len() > 512)
    {
        return Ok(None);
    }
    let Some(metadata) = read_client(client, client_id).await? else {
        return Ok(None);
    };
    if metadata.is_public {
        if client_secret.is_some_and(|secret| !secret.is_empty()) {
            return Ok(None);
        }
    } else {
        let Some(secret) = client_secret.filter(|secret| !secret.is_empty()) else {
            return Ok(None);
        };
        let permit = SECRET_HASH_SLOTS.acquire().await?;
        let hash = metadata.secret_hash.clone();
        let secret = secret.to_owned();
        let matched =
            tokio::task::spawn_blocking(move || id_compat::password::verify(&secret, &hash))
                .await??;
        drop(permit);
        if !matched {
            return Ok(None);
        }
    }
    Ok(Some(metadata))
}

async fn read_client(client: &Client, client_id: &str) -> Result<Option<ClientMeta>> {
    let mut query = client.query_client();
    let mut stream = query.query("SELECT id, client_id, client_secret_hash, is_public, CAST(grant_types AS Utf8) AS grants FROM idp_oidcclient VIEW oidc_client_id_idx WHERE client_id = $client_id LIMIT 2")
        .param("$client_id", client_id.to_owned()).await?;
    let mut rows = Vec::with_capacity(2);
    while let Some(set) = stream.next_result_set().await? {
        rows.extend(set);
    }
    stream.close().await?;
    if rows.len() != 1 {
        // An ambiguous client ID cannot safely authenticate either record.
        return Ok(None);
    }
    let mut row = rows.remove(0);
    let grants: String = row.remove_field_by_name("grants")?.try_into()?;
    Ok(Some(ClientMeta {
        id: row.remove_field_by_name("id")?.try_into()?,
        client_id: row.remove_field_by_name("client_id")?.try_into()?,
        secret_hash: row.remove_field_by_name("client_secret_hash")?.try_into()?,
        is_public: row.remove_field_by_name("is_public")?.try_into()?,
        grant_types: serde_json::from_str(&grants)?,
    }))
}

pub(crate) async fn read_client_tx(
    tx: &mut Transaction,
    client_id: i64,
) -> ydb::YdbResultWithCustomerErr<Option<ClientMeta>> {
    let Some(mut row) = tx.query_row("SELECT id, client_id, client_secret_hash, is_public, CAST(grant_types AS Utf8) AS grants FROM idp_oidcclient WHERE id = $id")
        .param("$id", client_id).optional().await? else { return Ok(None); };
    let grants: String = row.remove_field_by_name("grants")?.try_into()?;
    let metadata = ClientMeta {
        id: row.remove_field_by_name("id")?.try_into()?,
        client_id: row.remove_field_by_name("client_id")?.try_into()?,
        secret_hash: row.remove_field_by_name("client_secret_hash")?.try_into()?,
        is_public: row.remove_field_by_name("is_public")?.try_into()?,
        grant_types: serde_json::from_str(&grants).map_err(ydb::YdbOrCustomerError::from_err)?,
    };
    if !unique_client_pk_tx(tx, &metadata.client_id, metadata.id).await? {
        return Ok(None);
    }
    Ok(Some(metadata))
}

pub(crate) async fn unique_client_pk_tx(
    tx: &mut Transaction,
    client_id: &str,
    expected_pk: i64,
) -> ydb::YdbResultWithCustomerErr<bool> {
    let mut stream = tx
        .query("SELECT id FROM idp_oidcclient VIEW oidc_client_id_idx WHERE client_id = $client_id LIMIT 2")
        .param("$client_id", client_id.to_owned())
        .await?;
    let mut ids: Vec<i64> = Vec::with_capacity(2);
    while let Some(set) = stream.next_result_set().await? {
        for mut row in set {
            ids.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    stream.close().await?;
    Ok(ids.len() == 1 && ids[0] == expected_pk)
}
