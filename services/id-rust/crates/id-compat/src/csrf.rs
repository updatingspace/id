//! Django masked/unmasked token comparison ONLY. Origin/referer, trusted hosts,
//! secure transport and safe-method rules still need the HTTP CSRF middleware.

use crate::{Error, Result};
use subtle::ConstantTimeEq;

const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

fn unmask(value: &str) -> Result<Vec<u8>> {
    if value.len() != 32 && value.len() != 64 {
        return Err(Error::Invalid);
    }
    let indices: Vec<usize> = value
        .bytes()
        .map(|b| CHARS.iter().position(|x| *x == b).ok_or(Error::Invalid))
        .collect::<Result<_>>()?;
    if value.len() == 32 {
        return Ok(value.as_bytes().to_vec());
    }
    Ok(indices[..32]
        .iter()
        .zip(&indices[32..])
        .map(|(mask, cipher)| CHARS[(cipher + 62 - mask) % 62])
        .collect())
}

/// Convert a current or pre-Django-4 masked cookie to its canonical 32-byte
/// secret before reissuing the readable CSRF cookie on a safe GET.
pub fn cookie_secret(value: &str) -> Result<String> {
    String::from_utf8(unmask(value)?).map_err(|_| Error::Invalid)
}

pub fn matches(cookie: &str, request_token: &str) -> Result<bool> {
    Ok(bool::from(unmask(cookie)?.ct_eq(&unmask(request_token)?)))
}
