//! Dependency regressions for signed JWT claim validation and crypto providers.

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use id_compat::account_jwt::AccountJwtCodec;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    rsa::{Padding, Rsa},
    sign::{RsaPssSaltlen, Verifier},
};
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

const SECRET: &[u8] = b"synthetic-jwt-dependency-test-key-32-bytes";

#[test]
fn malformed_optional_time_claims_do_not_bypass_validation() -> Result<()> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims.clear();
    validation.validate_nbf = true;
    validation.leeway = 0;
    let signer = EncodingKey::from_secret(SECRET);
    let verifier = DecodingKey::from_secret(SECRET);
    let valid = json!({"sub":"synthetic-account", "exp":4_000_000_000_u64, "nbf":0});
    let verify = |claims: &Value| -> Result<bool> {
        let token = encode(&Header::new(Algorithm::HS256), claims, &signer)?;
        Ok(decode::<Value>(&token, &verifier, &validation).is_ok())
    };
    assert!(verify(&valid)?);
    assert!(verify(&json!({"sub":"synthetic-account"}))?);

    // GHSA-h395-gr6q-cpjc: an invalid type was treated as an absent optional
    // claim, even with its time validation enabled. Both tokens are signed.
    for claim in ["exp", "nbf"] {
        for malformed in [
            json!("4000000000"),
            json!([4_000_000_000_u64]),
            json!({"value":0}),
        ] {
            let mut claims = valid.clone();
            claims[claim] = malformed;
            assert!(!verify(&claims)?, "accepted malformed {claim}");
        }
    }
    assert!(!verify(&json!({"exp":1, "nbf":0}))?);
    assert!(!verify(
        &json!({"exp":4_000_000_000_u64, "nbf":4_000_000_000_u64})
    )?);
    Ok(())
}

#[test]
fn hs256_remains_compatible_with_account_refresh_codec() -> Result<()> {
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let codec = AccountJwtCodec::new(SECRET)?;
    let pair = codec.issue_pair(
        17,
        "abcdefghijklmnopqrstuvwxyz012345",
        now,
        "0123456789abcdef0123456789abcdef",
        "fedcba9876543210fedcba9876543210",
    )?;
    let validation = Validation::new(Algorithm::HS256);
    let claims = decode::<Value>(
        &pair.refresh,
        &DecodingKey::from_secret(SECRET),
        &validation,
    )?
    .claims;
    let reissued = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(SECRET),
    )?;
    assert_eq!(
        codec.verify_refresh(&reissued, now)?,
        codec.verify_refresh(&pair.refresh, now)?
    );
    assert!(
        decode::<Value>(
            &pair.refresh,
            &DecodingKey::from_secret(b"wrong-key"),
            &validation
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn oidc_rs256_and_ydb_iam_ps256_signatures_verify_with_openssl() -> Result<()> {
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let signer = EncodingKey::from_rsa_pem(&key.private_key_to_pem_pkcs8()?)?;
    let verifier = DecodingKey::from_rsa_pem(&key.public_key_to_pem()?)?;
    let claims = json!({"sub":"synthetic-account", "exp":4_000_000_000_u64});
    for algorithm in [Algorithm::RS256, Algorithm::PS256] {
        let token = encode(&Header::new(algorithm), &claims, &signer)?;
        assert_eq!(
            decode::<Value>(&token, &verifier, &Validation::new(algorithm))?.claims,
            claims
        );
        let (message, encoded_signature) =
            token.rsplit_once('.').context("missing JWT signature")?;
        let signature = URL_SAFE_NO_PAD.decode(encoded_signature)?;
        let mut independent_verifier = Verifier::new(MessageDigest::sha256(), &key)?;
        if algorithm == Algorithm::PS256 {
            independent_verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
            independent_verifier.set_rsa_mgf1_md(MessageDigest::sha256())?;
            independent_verifier.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
        }
        independent_verifier.update(message.as_bytes())?;
        ensure!(
            independent_verifier.verify(&signature)?,
            "JWT signature interoperability failed"
        );
    }
    Ok(())
}
