//! Existing Portal/BFF signature over raw request bytes. This preserves the
//! timestamp window; it does not add a replay cache or replace identity checks.

use crate::{Error, Result};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

pub struct SignedRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub body: &'a [u8],
    pub request_id: &'a str,
    pub timestamp: &'a str,
    pub signature: &'a str,
}

pub fn verify(secret: &[u8], request: &SignedRequest<'_>, now: i64) -> Result<bool> {
    let SignedRequest {
        method,
        path,
        body,
        request_id,
        timestamp,
        signature,
    } = *request;
    if secret.is_empty() || request_id.is_empty() {
        return Err(Error::Invalid);
    }
    let ts: i64 = timestamp.trim().parse().map_err(|_| Error::Invalid)?;
    if now.abs_diff(ts) > 300 {
        return Ok(false);
    }
    // Python compares against hexdigest(), so uppercase signatures are not accepted.
    if signature.len() != 64
        || !signature
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Invalid);
    }
    let canonical = format!(
        "{}\n{}\n{}\n{}\n{}",
        method.to_uppercase(),
        path,
        hex::encode(Sha256::digest(body)),
        request_id,
        ts
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| Error::Invalid)?;
    mac.update(canonical.as_bytes());
    Ok(mac
        .verify_slice(&hex::decode(signature).map_err(|_| Error::Invalid)?)
        .is_ok())
}
