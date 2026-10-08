//! allauth 65.18 default recovery codes (10 codes, 8 decimal digits).
//! This module does not consume codes. Updating used_mask requires one YDB
//! transaction that also checks the user, revocation and current authenticator.

use crate::{Error, Result};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

pub fn codes(seed: &str) -> Result<Vec<String>> {
    if seed.len() != 80 || !seed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Invalid);
    }
    let mut mac = Hmac::<Sha1>::new_from_slice(seed.as_bytes()).map_err(|_| Error::Invalid)?;
    let mut result = Vec::new();
    for i in 0..10 {
        mac.update(format!("{i:3},").as_bytes());
        let digest = mac.clone().finalize().into_bytes();
        let value = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 100_000_000;
        result.push(format!("{value:08}"));
    }
    Ok(result)
}

/// Returns a candidate index; the caller must compare-and-set the saved mask.
pub fn unused_index(seed: &str, used_mask: u64, candidate: &str) -> Result<Option<usize>> {
    if used_mask >> 10 != 0 {
        return Err(Error::Invalid);
    }
    let mut matched = None;
    for (i, code) in codes(seed)?.iter().enumerate() {
        let equal = bool::from(code.as_bytes().ct_eq(candidate.as_bytes()));
        if equal && used_mask & (1 << i) == 0 && matched.is_none() {
            matched = Some(i);
        }
    }
    Ok(matched)
}

/// Older allauth accounts store the remaining migrated codes directly. Return
/// their index so the caller can remove exactly one in the same transaction as
/// session issuance. A duplicate entry is rejected rather than consumed twice.
pub fn migrated_index(codes: &[String], candidate: &str) -> Result<Option<usize>> {
    if codes.len() > 100 || codes.iter().any(|code| code.len() > 128) {
        return Err(Error::Invalid);
    }
    let mut matched = None;
    for (index, code) in codes.iter().enumerate() {
        if bool::from(code.as_bytes().ct_eq(candidate.as_bytes())) {
            if matched.is_some() {
                return Err(Error::Invalid);
            }
            matched = Some(index);
        }
    }
    Ok(matched)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn migrated_codes_match_once_and_reject_ambiguous_duplicates() {
        let codes = vec!["12345678".to_owned(), "87654321".to_owned()];
        assert_eq!(migrated_index(&codes, "87654321"), Ok(Some(1)));
        assert_eq!(migrated_index(&codes, "00000000"), Ok(None));
        assert_eq!(
            migrated_index(&["12345678".into(), "12345678".into()], "12345678"),
            Err(Error::Invalid)
        );
    }
}
