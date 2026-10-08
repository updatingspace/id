//! A disposable, positive production probe for the BFF exchange contract.

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use id_compat::cache::CacheValue;
use id_runtime::cache_store::CacheStore;
use rand::Rng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const PATH: &str = "/api/v1/auth/exchange";

pub async fn run(base_url: &str) -> Result<()> {
    let url = url::Url::parse(base_url)?.join(PATH)?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none(),
        "exchange smoke requires an HTTPS Gateway URL"
    );
    let secret = env::var("BFF_INTERNAL_HMAC_SECRET")
        .context("BFF_INTERNAL_HMAC_SECRET is required for exchange smoke")?;
    ensure!(secret.len() >= 32, "internal HMAC secret is too short");
    let table = env::var("YDB_CACHE_TABLE").unwrap_or_else(|_| "id_shared_cache".into());
    let cache = CacheStore::new(Arc::new(id_runtime::connect_ydb().await?), &table, "", 1)?;
    let mut random = [0u8; 32];
    rand::rng().fill_bytes(&mut random);
    let code = URL_SAFE_NO_PAD.encode(random);
    let identity = Uuid::new_v4();
    let key = format!("usid:exchange:{code}");
    let now = SystemTime::now();
    let value = CacheValue::Map(BTreeMap::from([
        ("user_id".into(), CacheValue::String(identity.to_string())),
        (
            "master_flags".into(),
            CacheValue::Map(BTreeMap::from([
                ("email_verified".into(), CacheValue::Bool(true)),
                ("system_admin".into(), CacheValue::Bool(false)),
            ])),
        ),
        ("ttl_seconds".into(), CacheValue::Int(120)),
    ]));
    ensure!(
        cache
            .add(&key, &value, Some(now + Duration::from_secs(60)), now)
            .await?,
        "synthetic exchange key collision"
    );
    let probe = probe(&url, secret.as_bytes(), &code, identity).await;
    let cleanup = cache.delete(&key).await;
    probe?;
    cleanup?;
    println!(
        "{}",
        json!({"exchange":"pass","replay":"rejected","synthetic_state":"removed"})
    );
    Ok(())
}

async fn probe(url: &url::Url, secret: &[u8], code: &str, identity: Uuid) -> Result<()> {
    let body = serde_json::to_vec(&json!({"code":code}))?;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let request_id = Uuid::new_v4().to_string();
    let canonical = format!(
        "POST\n{}\n{}\n{}\n{}",
        PATH,
        hex::encode(Sha256::digest(&body)),
        request_id,
        timestamp
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)?;
    mac.update(canonical.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let send = || {
        client
            .post(url.clone())
            .header("content-type", "application/json")
            .header("x-request-id", &request_id)
            .header("x-updspace-timestamp", timestamp.to_string())
            .header("x-updspace-signature", &signature)
            .body(body.clone())
    };
    let first = send().send().await?;
    let first_status = first.status();
    let first_body: Value = first.json().await?;
    if first_status != reqwest::StatusCode::OK {
        bail!(
            "first exchange returned {first_status}: {}",
            first_body["code"]
        );
    }
    ensure!(
        first_body["ok"] == true
            && first_body["user_id"] == identity.to_string()
            && first_body["master_flags"]["email_verified"] == true
            && first_body["ttl_seconds"] == 120,
        "first exchange response differed from BFF contract"
    );
    let second = send().send().await?;
    let second_status = second.status();
    let second_body: Value = second.json().await?;
    ensure!(
        second_status == reqwest::StatusCode::UNAUTHORIZED && second_body["code"] == "UNAUTHORIZED",
        "replayed exchange was not rejected"
    );
    Ok(())
}
