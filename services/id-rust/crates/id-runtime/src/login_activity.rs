//! Django-compatible successful-login history and device tracking.
//! The caller runs this inside the session/JWT issuance transaction.

use crate::session_issuer::SessionClient;
use sha2::{Digest, Sha256};
use std::time::SystemTime;
use ydb::Transaction;

fn digest_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

pub(crate) fn device_fingerprint(account_id: i32, client: &SessionClient) -> String {
    let ip = client.ip.to_string();
    let ip_part = match client.ip {
        std::net::IpAddr::V4(_) => {
            let chunks: Vec<_> = ip.split('.').collect();
            format!("{}.{}.{}.0", chunks[0], chunks[1], chunks[2])
        }
        std::net::IpAddr::V6(_) => String::new(),
    };
    let ua: String = client.user_agent.chars().take(512).collect();
    digest_hex(&format!(
        "{account_id}:{ua}:{ip_part}:{}",
        client.device_fingerprint_salt
    ))
}

pub(crate) fn device_row_id(account_id: i32, device_id: &str) -> i64 {
    let digest = Sha256::digest(format!("device-row:{account_id}:{device_id}").as_bytes());
    let mut first = [0; 8];
    first.copy_from_slice(&digest[..8]);
    ((u64::from_be_bytes(first) & ((1u64 << 62) - 1)) | (1u64 << 62)) as i64
}

fn random_bigint_id() -> i64 {
    let value = (rand::random::<u64>() & ((1u64 << 62) - 1)) | (1u64 << 62);
    value as i64
}

pub(crate) async fn record_success_tx(
    tx: &mut Transaction,
    account_id: i32,
    client: &SessionClient,
    now: SystemTime,
    mfa_method: &str,
) -> ydb::YdbResultWithCustomerErr<Option<i64>> {
    let device_id = device_fingerprint(account_id, client);
    let ua: String = client.user_agent.chars().take(512).collect();
    let ip = client.ip.to_string();
    let mut rows = tx
        .query("SELECT id FROM accounts_userdevice VIEW acct_device_user_last_idx WHERE user_id = $user_id AND device_id = $device_id LIMIT 2")
        .param("$user_id", account_id)
        .param("$device_id", device_id.clone())
        .await?;
    let mut existing: Vec<i64> = Vec::with_capacity(2);
    while let Some(result_set) = rows.next_result_set().await? {
        for mut row in result_set {
            existing.push(row.remove_field_by_name("id")?.try_into()?);
        }
    }
    rows.close().await?;
    if existing.len() > 1 {
        return Err(ydb::YdbOrCustomerError::from_err(std::io::Error::other(
            "duplicate account device fingerprint",
        )));
    }
    let is_new = existing.is_empty();
    if let Some(id) = existing.pop() {
        if ua.is_empty() {
            tx.exec("UPDATE accounts_userdevice SET last_seen = CAST($now AS Datetime), last_ip = $ip WHERE id = $id")
                .param("$now", now).param("$ip", ip.clone()).param("$id", id).await?;
        } else {
            tx.exec("UPDATE accounts_userdevice SET user_agent = $ua, last_seen = CAST($now AS Datetime), last_ip = $ip WHERE id = $id")
                .param("$ua", ua.clone()).param("$now", now).param("$ip", ip.clone()).param("$id", id).await?;
        }
    } else {
        tx.exec("INSERT INTO accounts_userdevice (id, user_id, device_id, user_agent, first_seen, last_seen, last_ip) VALUES ($id, $user_id, $device_id, $ua, CAST($now AS Datetime), CAST($now AS Datetime), $ip)")
            .param("$id", device_row_id(account_id, &device_id))
            .param("$user_id", account_id)
            .param("$device_id", device_id.clone())
            .param("$ua", ua.clone())
            .param("$now", now)
            .param("$ip", ip.clone()).await?;
    }
    let meta = serde_json::json!({
        "mfa_enabled": !mfa_method.is_empty(),
        "mfa_method": mfa_method,
    });
    let event_id = random_bigint_id();
    tx.exec("INSERT INTO accounts_loginevent (id, user_id, status, ip_address, ip_hash, user_agent, device_id, location, is_new_device, reason, meta, created_at) VALUES ($id, $user_id, 'success', $ip, $ip_hash, $ua, $device_id, '', $is_new, '', Unwrap(CAST($meta AS Json)), CAST($now AS Datetime))")
        .param("$id", event_id)
        .param("$user_id", account_id)
        .param("$ip", ip.clone())
        .param("$ip_hash", digest_hex(&ip))
        .param("$ua", ua)
        .param("$device_id", device_id)
        .param("$is_new", is_new)
        .param("$meta", meta.to_string())
        .param("$now", now).await?;
    if is_new {
        tx.exec("INSERT INTO accounts_newdevicemailoutbox (event_id, status, attempts, next_attempt_at, claim_token, created_at) VALUES ($event_id, 'pending', 0, CAST($now AS Datetime), '', CAST($now AS Datetime))")
            .param("$event_id", event_id)
            .param("$now", now).await?;
    }
    Ok(is_new.then_some(event_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_and_row_id_match_python_activity() {
        let client = SessionClient {
            ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 5)),
            user_agent: "Browser/1".into(),
            device_fingerprint_salt: "device-salt".into(),
        };
        let device_id = device_fingerprint(41, &client);
        assert_eq!(
            device_id,
            "877952e5f0be43edfe8beb121500cab4d7a1253aab3a402305b195bc078b887a"
        );
        assert_eq!(device_row_id(41, &device_id), 4_808_357_026_138_604_847);
    }
}
