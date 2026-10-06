//! The existing SimpleJWT account-token wire format (separate from OIDC).
//! Signing a token does not authorize its bearer: callers must enforce live
//! account/identity state and persist refresh revocation links before release.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;

use crate::{Error, Result};

const ACCESS_SECONDS: i64 = 15 * 60;
const REFRESH_SECONDS: i64 = 30 * 24 * 60 * 60;
const HEADER: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

// Deliberately no Debug implementation: this owns the Django signing key.
pub struct AccountJwtCodec {
    key: Vec<u8>,
}

pub struct AccountJwtPair {
    pub access: String,
    pub refresh: String,
    pub refresh_jti: String,
    pub refresh_expires_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRefresh {
    pub account_id: i32,
    pub session_key: String,
    pub jti: String,
    pub expires_at: i64,
}

impl AccountJwtCodec {
    pub fn new(django_secret_key: &[u8]) -> Result<Self> {
        if django_secret_key.is_empty() {
            return Err(Error::Invalid);
        }
        Ok(Self {
            key: django_secret_key.to_vec(),
        })
    }

    /// `jti` must be a newly generated random 128-bit lowercase hex value.
    /// SimpleJWT's access token intentionally lacks `session_key`: Python
    /// builds it before adding that claim to the refresh token.
    pub fn issue_pair(
        &self,
        account_id: i32,
        session_key: &str,
        issued_at: i64,
        refresh_jti: &str,
        access_jti: &str,
    ) -> Result<AccountJwtPair> {
        if account_id == 0
            || session_key.len() != 32
            || !session_key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            || !valid_jti(refresh_jti)
            || !valid_jti(access_jti)
            || refresh_jti == access_jti
        {
            return Err(Error::Invalid);
        }
        let access_exp = issued_at
            .checked_add(ACCESS_SECONDS)
            .ok_or(Error::Invalid)?;
        let refresh_exp = issued_at
            .checked_add(REFRESH_SECONDS)
            .ok_or(Error::Invalid)?;
        let access = self.sign(&json!({
            "token_type": "access", "exp": access_exp, "iat": issued_at,
            "jti": access_jti, "user_id": account_id.to_string(),
        }))?;
        let refresh = self.sign(&json!({
            "token_type": "refresh", "exp": refresh_exp, "iat": issued_at,
            "jti": refresh_jti, "user_id": account_id.to_string(),
            "session_key": session_key,
        }))?;
        Ok(AccountJwtPair {
            access,
            refresh,
            refresh_jti: refresh_jti.to_owned(),
            refresh_expires_at: refresh_exp,
        })
    }

    /// Accept only a signed, unexpired legacy account refresh. The database
    /// still decides whether the JTI is outstanding and unconsumed.
    pub fn verify_refresh(&self, token: &str, now: i64) -> Result<VerifiedRefresh> {
        if token.len() > 4096 {
            return Err(Error::Invalid);
        }
        let mut parts = token.split('.');
        let (Some(encoded_header), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(Error::Invalid);
        };
        let header: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(encoded_header)
                .map_err(|_| Error::Invalid)?,
        )
        .map_err(|_| Error::Invalid)?;
        if header.get("alg").and_then(Value::as_str) != Some("HS256")
            || header.get("typ").and_then(Value::as_str) != Some("JWT")
        {
            return Err(Error::Invalid);
        }
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| Error::Invalid)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).map_err(|_| Error::Invalid)?;
        mac.update(format!("{encoded_header}.{payload}").as_bytes());
        mac.verify_slice(&signature).map_err(|_| Error::Invalid)?;
        let claims: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(payload)
                .map_err(|_| Error::Invalid)?,
        )
        .map_err(|_| Error::Invalid)?;
        let expires_at = claims
            .get("exp")
            .and_then(Value::as_i64)
            .ok_or(Error::Invalid)?;
        let issued_at = claims
            .get("iat")
            .and_then(Value::as_i64)
            .ok_or(Error::Invalid)?;
        let account_id = claims
            .get("user_id")
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<i32>().ok())
            .filter(|value| *value != 0)
            .ok_or(Error::Invalid)?;
        let session_key = claims
            .get("session_key")
            .and_then(Value::as_str)
            .filter(|value| {
                value.len() == 32
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            })
            .ok_or(Error::Invalid)?;
        let jti = claims
            .get("jti")
            .and_then(Value::as_str)
            .filter(|value| valid_jti(value))
            .ok_or(Error::Invalid)?;
        if claims.get("token_type").and_then(Value::as_str) != Some("refresh")
            || issued_at < 0
            || issued_at > now.saturating_add(60)
            || expires_at <= now
            || expires_at <= issued_at
        {
            return Err(Error::Invalid);
        }
        Ok(VerifiedRefresh {
            account_id,
            session_key: session_key.to_owned(),
            jti: jti.to_owned(),
            expires_at,
        })
    }

    fn sign(&self, payload: &Value) -> Result<String> {
        let body = serde_json::to_vec(payload).map_err(|_| Error::Invalid)?;
        let input = format!("{HEADER}.{}", URL_SAFE_NO_PAD.encode(body));
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).map_err(|_| Error::Invalid)?;
        mac.update(input.as_bytes());
        Ok(format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        ))
    }
}

fn valid_jti(jti: &str) -> bool {
    jti.len() == 32
        && jti
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_claims_match_legacy_pair() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let codec = AccountJwtCodec::new(b"synthetic-secret")?;
        let pair = codec.issue_pair(
            17,
            "abcdefghijklmnopqrstuvwxyz012345",
            1_700_000_000,
            "0123456789abcdef0123456789abcdef",
            "fedcba9876543210fedcba9876543210",
        )?;
        for (jwt, kind, exp, session) in [
            (&pair.access, "access", 1_700_000_900, None),
            (
                &pair.refresh,
                "refresh",
                1_702_592_000,
                Some("abcdefghijklmnopqrstuvwxyz012345"),
            ),
        ] {
            let parts: Vec<_> = jwt.split('.').collect();
            assert_eq!(parts.len(), 3);
            let payload: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
            assert_eq!(payload["token_type"], kind);
            assert_eq!(payload["exp"], exp);
            assert_eq!(payload["iat"], 1_700_000_000);
            assert_eq!(payload["user_id"], "17");
            assert_eq!(payload.get("session_key").and_then(Value::as_str), session);
        }
        assert_eq!(pair.refresh_expires_at, 1_702_592_000);
        Ok(())
    }

    #[test]
    fn rejects_invalid_identifiers_and_overflow()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let codec = AccountJwtCodec::new(b"key")?;
        assert!(
            codec
                .issue_pair(
                    0,
                    "abcdefghijklmnopqrstuvwxyz012345",
                    0,
                    "0123456789abcdef0123456789abcdef",
                    "fedcba9876543210fedcba9876543210"
                )
                .is_err()
        );
        assert!(
            codec
                .issue_pair(
                    1,
                    "too-short",
                    0,
                    "0123456789abcdef0123456789abcdef",
                    "fedcba9876543210fedcba9876543210"
                )
                .is_err()
        );
        assert!(
            codec
                .issue_pair(
                    1,
                    "abcdefghijklmnopqrstuvwxyz012345",
                    i64::MAX,
                    "0123456789abcdef0123456789abcdef",
                    "fedcba9876543210fedcba9876543210"
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn refresh_verification_checks_signature_type_and_expiry()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let codec = AccountJwtCodec::new(b"synthetic-secret")?;
        let pair = codec.issue_pair(
            17,
            "abcdefghijklmnopqrstuvwxyz012345",
            1_700_000_000,
            "0123456789abcdef0123456789abcdef",
            "fedcba9876543210fedcba9876543210",
        )?;
        assert_eq!(
            codec.verify_refresh(&pair.refresh, 1_700_000_000)?,
            VerifiedRefresh {
                account_id: 17,
                session_key: "abcdefghijklmnopqrstuvwxyz012345".into(),
                jti: pair.refresh_jti.clone(),
                expires_at: pair.refresh_expires_at,
            }
        );
        assert!(codec.verify_refresh(&pair.access, 1_700_000_000).is_err());
        assert!(
            codec
                .verify_refresh(&pair.refresh, pair.refresh_expires_at)
                .is_err()
        );
        let other = AccountJwtCodec::new(b"other-secret")?;
        assert!(other.verify_refresh(&pair.refresh, 1_700_000_000).is_err());
        let mut tampered = pair.refresh.into_bytes();
        let first_payload_byte = tampered
            .iter()
            .position(|byte| *byte == b'.')
            .ok_or("no payload")?
            + 1;
        tampered[first_payload_byte] = if tampered[first_payload_byte] == b'A' {
            b'B'
        } else {
            b'A'
        };
        assert!(
            codec
                .verify_refresh(std::str::from_utf8(&tampered)?, 1_700_000_000)
                .is_err()
        );
        Ok(())
    }
}
