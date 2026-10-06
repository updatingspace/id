//! Allauth's RFC 6238 TOTP calculation. This checks a code but never proves
//! that it was unused or authorizes issuance; the caller must claim the shared
//! replay key and recheck MFA policy in the session write transaction.

use crate::{Error, Result};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

fn decode_base32(secret: &str) -> Result<Vec<u8>> {
    if secret.is_empty() || secret.len() > 256 || !secret.len().is_multiple_of(8) {
        return Err(Error::Invalid);
    }
    let body = secret.trim_end_matches('=');
    let padding = secret.len() - body.len();
    if !matches!(padding, 0 | 1 | 3 | 4 | 6) {
        return Err(Error::Invalid);
    }
    let mut decoded = Vec::with_capacity(body.len() * 5 / 8);
    let mut value = 0u32;
    let mut bits = 0u8;
    for byte in body.bytes() {
        let digit = match byte.to_ascii_uppercase() {
            b'A'..=b'Z' => byte.to_ascii_uppercase() - b'A',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return Err(Error::Invalid),
        };
        value = (value << 5) | u32::from(digit);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            decoded.push((value >> bits) as u8);
            value &= (1 << bits) - 1;
        }
    }
    let expected_padding = match body.len() % 8 {
        0 => 0,
        2 => 6,
        4 => 4,
        5 => 3,
        7 => 1,
        _ => return Err(Error::Invalid),
    };
    if padding != expected_padding || value != 0 || decoded.is_empty() {
        return Err(Error::Invalid);
    }
    Ok(decoded)
}

/// Matches allauth's period/digits/tolerance settings. Insecure bypass codes
/// are deliberately unsupported. Unknown production settings must stop cutover.
pub fn validate(
    secret: &str,
    code: &str,
    unix_seconds: u64,
    period: u64,
    digits: u32,
    tolerance: u64,
) -> Result<bool> {
    if period == 0 || period > 300 || !(6..=8).contains(&digits) || tolerance > 2 {
        return Err(Error::Unsupported);
    }
    let secret = decode_base32(secret)?;
    if code.len() != digits as usize || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(false);
    }
    let current = unix_seconds / period;
    let mut matched = false;
    for delta in -(tolerance as i64)..=(tolerance as i64) {
        let Some(counter) = current.checked_add_signed(delta) else {
            continue;
        };
        let mut mac = Hmac::<Sha1>::new_from_slice(&secret).map_err(|_| Error::Invalid)?;
        mac.update(&counter.to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let offset = usize::from(digest[19] & 0x0f);
        let value = u32::from_be_bytes([
            digest[offset] & 0x7f,
            digest[offset + 1],
            digest[offset + 2],
            digest[offset + 3],
        ]) % 10u32.pow(digits);
        let expected = format!("{value:0width$}", width = digits as usize);
        matched |= bool::from(expected.as_bytes().ct_eq(code.as_bytes()));
    }
    Ok(matched)
}
