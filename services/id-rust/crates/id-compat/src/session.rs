//! Django 5.2 JSON SessionStore codec, including compressed payloads and key rotation.
//! Signed time is preserved independently of authentication freshness and DB expiry.

use std::io::{Read, Write};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{Error, Result};

const SESSION_SALT: &[u8] = b"django.contrib.sessions.SessionStoresigner";
const AUTH_SALT: &[u8] = b"django.contrib.auth.models.AbstractBaseUser.get_session_auth_hash";
const B62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const MAX_JSON: usize = 1_048_576;
const MAX_ENCODED: usize = 1_500_000;

// Intentionally does not implement Debug: signing keys must never reach logs.
pub struct SessionCodec {
    keys: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq)]
pub struct DecodedSession {
    pub data: Map<String, Value>,
    pub signed_at: i64,
    pub needs_key_rotation: bool,
}

impl SessionCodec {
    /// The first key signs new data. Remaining keys only verify old data.
    pub fn new(primary: &[u8], fallbacks: &[&[u8]]) -> Result<Self> {
        if primary.is_empty() || fallbacks.iter().any(|key| key.is_empty()) {
            return Err(Error::Invalid);
        }
        Ok(Self {
            keys: std::iter::once(primary)
                .chain(fallbacks.iter().copied())
                .map(<[u8]>::to_vec)
                .collect(),
        })
    }

    pub fn decode(&self, encoded: &str) -> Result<DecodedSession> {
        if encoded.len() > MAX_ENCODED {
            return Err(Error::Limit);
        }
        let (signed, signature) = encoded.rsplit_once(':').ok_or(Error::Invalid)?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| Error::Invalid)?;
        let mut matched = None;
        for (index, key) in self.keys.iter().enumerate() {
            if bool::from(salted_hmac(SESSION_SALT, signed.as_bytes(), key)?.ct_eq(&signature))
                && matched.is_none()
            {
                matched = Some(index);
            }
        }
        let key_index = matched.ok_or(Error::Invalid)?;
        let (payload, stamp) = signed.rsplit_once(':').ok_or(Error::Invalid)?;
        let signed_at = decode_time(stamp)?;
        let compressed = payload.starts_with('.');
        let encoded_json = payload.strip_prefix('.').unwrap_or(payload);
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded_json)
            .map_err(|_| Error::Invalid)?;
        let bytes = if compressed {
            let mut output = Vec::new();
            ZlibDecoder::new(bytes.as_slice())
                .take((MAX_JSON + 1) as u64)
                .read_to_end(&mut output)
                .map_err(|_| Error::Invalid)?;
            output
        } else {
            bytes
        };
        if bytes.len() > MAX_JSON {
            return Err(Error::Limit);
        }
        // Django JSONSerializer decodes latin-1. Its own encoder emits ASCII escapes.
        let text: String = bytes.into_iter().map(char::from).collect();
        let data = serde_json::from_str(&text).map_err(|_| Error::Invalid)?;
        Ok(DecodedSession {
            data,
            signed_at,
            needs_key_rotation: key_index != 0,
        })
    }

    /// Produces data readable by Django, including non-ASCII JSON strings.
    pub fn encode(
        &self,
        data: &Map<String, Value>,
        signed_at: i64,
        compress: bool,
    ) -> Result<String> {
        let json = serde_json::to_string(data).map_err(|_| Error::Invalid)?;
        let mut ascii = String::new();
        for ch in json.chars() {
            if ch.is_ascii() {
                ascii.push(ch);
            } else {
                for unit in ch.encode_utf16(&mut [0; 2]) {
                    use std::fmt::Write as _;
                    write!(ascii, "\\u{unit:04x}").map_err(|_| Error::Invalid)?;
                }
            }
        }
        if ascii.len() > MAX_JSON {
            return Err(Error::Limit);
        }
        let payload = if compress {
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder
                .write_all(ascii.as_bytes())
                .map_err(|_| Error::Invalid)?;
            let compressed = encoder.finish().map_err(|_| Error::Invalid)?;
            if compressed.len() + 1 < ascii.len() {
                format!(".{}", URL_SAFE_NO_PAD.encode(compressed))
            } else {
                URL_SAFE_NO_PAD.encode(ascii)
            }
        } else {
            URL_SAFE_NO_PAD.encode(ascii)
        };
        let signed = format!("{payload}:{}", encode_time(signed_at));
        let signature = salted_hmac(SESSION_SALT, signed.as_bytes(), &self.keys[0])?;
        Ok(format!("{signed}:{}", URL_SAFE_NO_PAD.encode(signature)))
    }

    pub fn auth_hash(&self, encoded_password: &str) -> Result<String> {
        Ok(hex::encode(salted_hmac(
            AUTH_SALT,
            encoded_password.as_bytes(),
            &self.keys[0],
        )?))
    }

    /// A successful hash check alone is NOT authorization or session renewal.
    pub fn verify_auth_hash(&self, encoded_password: &str, stored_hash: &str) -> Result<bool> {
        let expected = hex::decode(stored_hash).map_err(|_| Error::Invalid)?;
        let mut valid = false;
        for key in &self.keys {
            valid |= bool::from(
                salted_hmac(AUTH_SALT, encoded_password.as_bytes(), key)?.ct_eq(&expected),
            );
        }
        Ok(valid)
    }
}

fn salted_hmac(salt: &[u8], value: &[u8], secret: &[u8]) -> Result<Vec<u8>> {
    let key = Sha256::new()
        .chain_update(salt)
        .chain_update(secret)
        .finalize();
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).map_err(|_| Error::Invalid)?;
    mac.update(value);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn encode_time(value: i64) -> String {
    let mut n = value.unsigned_abs();
    let mut out = Vec::new();
    loop {
        out.push(B62[(n % 62) as usize] as char);
        n /= 62;
        if n == 0 {
            break;
        }
    }
    if value < 0 {
        out.push('-');
    }
    out.into_iter().rev().collect()
}

fn decode_time(value: &str) -> Result<i64> {
    let (negative, value) = match value.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, value),
    };
    if value.is_empty() {
        return Err(Error::Invalid);
    }
    let mut out = 0_u64;
    for byte in value.bytes() {
        let digit = B62.iter().position(|b| *b == byte).ok_or(Error::Invalid)? as u64;
        out = out
            .checked_mul(62)
            .and_then(|n| n.checked_add(digit))
            .ok_or(Error::Invalid)?;
    }
    if negative && out == (1_u64 << 63) {
        return Ok(i64::MIN);
    }
    let out = i64::try_from(out).map_err(|_| Error::Invalid)?;
    Ok(if negative { -out } else { out })
}
