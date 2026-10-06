//! Strict public OAuth token input and authorization-code proof checks.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor},
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    fmt,
};
use subtle::ConstantTimeEq;

pub const MAX_REQUEST_BYTES: usize = 16_384;
pub const MAX_PARAMETERS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    InvalidRequest,
    UnsupportedContentType,
    InvalidPkce,
    InvalidScope,
}

struct UniqueParameters(BTreeMap<String, String>);

impl<'de> Deserialize<'de> for UniqueParameters {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueParameters;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an OAuth parameter object with unique string keys")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut result = BTreeMap::new();
                let mut seen = HashSet::new();
                let mut count = 0;
                while let Some((key, value)) = map.next_entry::<String, Option<String>>()? {
                    count += 1;
                    if count > MAX_PARAMETERS || !seen.insert(key.clone()) {
                        return Err(serde::de::Error::custom(
                            "duplicate or excessive OAuth parameter",
                        ));
                    }
                    if let Some(value) = value {
                        result.insert(key, value);
                    }
                }
                Ok(UniqueParameters(result))
            }
        }
        deserializer.deserialize_map(UniqueVisitor)
    }
}

pub fn parse_token_body(
    content_type: &str,
    bytes: &[u8],
) -> Result<BTreeMap<String, String>, ProtocolError> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(ProtocolError::InvalidRequest);
    }
    let mime = content_type.split(';').next().unwrap_or("").trim();
    if mime.eq_ignore_ascii_case("application/json") {
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let params = UniqueParameters::deserialize(&mut deserializer)
            .map_err(|_| ProtocolError::InvalidRequest)?;
        deserializer
            .end()
            .map_err(|_| ProtocolError::InvalidRequest)?;
        return Ok(params.0);
    }
    if !mime.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
        return Err(ProtocolError::UnsupportedContentType);
    }
    let mut result = BTreeMap::new();
    if bytes.is_empty() {
        return Ok(result);
    }
    let mut count = 0;
    for pair in bytes.split(|byte| *byte == b'&') {
        count += 1;
        if count > MAX_PARAMETERS {
            return Err(ProtocolError::InvalidRequest);
        }
        let (key, value) = if let Some(position) = pair.iter().position(|byte| *byte == b'=') {
            (&pair[..position], &pair[position + 1..])
        } else {
            (pair, &b""[..])
        };
        let key = decode_form_component(key)?;
        let value = decode_form_component(value)?;
        if result.insert(key, value).is_some() {
            return Err(ProtocolError::InvalidRequest);
        }
    }
    Ok(result)
}

pub(crate) fn decode_form_component(raw: &[u8]) -> Result<String, ProtocolError> {
    let mut decoded = Vec::with_capacity(raw.len());
    let mut cursor = 0;
    while cursor < raw.len() {
        match raw[cursor] {
            b'+' => decoded.push(b' '),
            b'%' => {
                if cursor + 2 >= raw.len() {
                    return Err(ProtocolError::InvalidRequest);
                }
                let high = hex_digit(raw[cursor + 1]).ok_or(ProtocolError::InvalidRequest)?;
                let low = hex_digit(raw[cursor + 2]).ok_or(ProtocolError::InvalidRequest)?;
                decoded.push(high * 16 + low);
                cursor += 2;
            }
            byte => decoded.push(byte),
        }
        cursor += 1;
    }
    String::from_utf8(decoded).map_err(|_| ProtocolError::InvalidRequest)
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

pub fn verify_pkce_s256(
    verifier: &str,
    challenge: &str,
    method: &str,
) -> Result<(), ProtocolError> {
    if method != "S256"
        || !(43..=128).contains(&verifier.len())
        || !verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte))
    {
        return Err(ProtocolError::InvalidPkce);
    }
    let digest = Sha256::digest(verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(digest);
    if computed.as_bytes().ct_eq(challenge.as_bytes()).unwrap_u8() != 1 {
        return Err(ProtocolError::InvalidPkce);
    }
    Ok(())
}

pub fn narrow_scopes(
    original: &str,
    requested: Option<&str>,
) -> Result<Vec<String>, ProtocolError> {
    let scope = requested.unwrap_or(original);
    let original: HashSet<&str> = original.split_whitespace().collect();
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for item in scope.split_whitespace() {
        if !original.contains(item) || !known_scope(item) {
            return Err(ProtocolError::InvalidScope);
        }
        if seen.insert(item) {
            result.push(item.to_owned());
        }
    }
    if !seen.contains("openid") {
        return Err(ProtocolError::InvalidScope);
    }
    Ok(result)
}

fn known_scope(value: &str) -> bool {
    matches!(
        value,
        "openid"
            | "profile"
            | "profile_basic"
            | "profile_extended"
            | "email"
            | "phone"
            | "address"
            | "offline_access"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_and_json_reject_duplicate_or_malformed_credentials() {
        assert_eq!(
            parse_token_body(
                "application/x-www-form-urlencoded",
                b"client_id=a&client_id=b"
            ),
            Err(ProtocolError::InvalidRequest)
        );
        assert_eq!(
            parse_token_body("application/json", br#"{"code":"a","code":"b"}"#),
            Err(ProtocolError::InvalidRequest)
        );
        assert_eq!(
            parse_token_body("application/json", br#"{"code":null,"code":"b"}"#),
            Err(ProtocolError::InvalidRequest)
        );
        assert_eq!(
            parse_token_body("application/x-www-form-urlencoded", b"code=%FF"),
            Err(ProtocolError::InvalidRequest)
        );
        assert_eq!(
            parse_token_body("application/x-www-form-urlencoded", b"code=%G1"),
            Err(ProtocolError::InvalidRequest)
        );
        assert_eq!(
            parse_token_body("text/plain", b"code=a"),
            Err(ProtocolError::UnsupportedContentType)
        );
        assert_eq!(
            parse_token_body("application/x-www-form-urlencoded", b"code=a%2Bb")
                .ok()
                .and_then(|map| map.get("code").cloned()),
            Some("a+b".into())
        );
    }

    #[test]
    fn pkce_and_scope_narrowing_are_strict() {
        let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        assert_eq!(verify_pkce_s256(verifier, &challenge, "S256"), Ok(()));
        assert_eq!(
            verify_pkce_s256(verifier, &challenge, "plain"),
            Err(ProtocolError::InvalidPkce)
        );
        assert_eq!(
            verify_pkce_s256("short", &challenge, "S256"),
            Err(ProtocolError::InvalidPkce)
        );
        assert_eq!(
            narrow_scopes("openid email offline_access", Some("openid email")),
            Ok(vec!["openid".into(), "email".into()])
        );
        assert_eq!(
            narrow_scopes("openid email", Some("openid phone")),
            Err(ProtocolError::InvalidScope)
        );
        assert_eq!(
            narrow_scopes("openid email", Some("email")),
            Err(ProtocolError::InvalidScope)
        );
    }
}
