//! Verify Django hashes without changing their work factor.
//! Run behind a bounded blocking-work pool, never directly on the async executor.

use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::SaltString,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use rand::random;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{Error, Result};

/// Create a Django-readable Argon2id hash without reducing its configured work
/// factor. Call from a bounded blocking pool, just like `verify`.
pub fn hash_new(password: &str) -> Result<String> {
    if password.is_empty() || password.len() > 4096 {
        return Err(Error::Limit);
    }
    let salt = SaltString::encode_b64(&random::<[u8; 16]>()).map_err(|_| Error::Invalid)?;
    let params = Params::new(102_400, 2, 8, Some(32)).map_err(|_| Error::Invalid)?;
    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let phc = hasher
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| Error::Invalid)?;
    Ok(format!("argon2{phc}"))
}

pub fn verify(password: &str, encoded: &str) -> Result<bool> {
    if encoded.len() > 1024 || password.len() > 1_048_576 {
        return Err(Error::Limit);
    }
    if encoded.starts_with('!') {
        return Ok(false);
    }
    if let Some(phc) = encoded.strip_prefix("argon2") {
        let hash = PasswordHash::new(phc).map_err(|_| Error::Invalid)?;
        argon2::Algorithm::try_from(hash.algorithm).map_err(|_| Error::Invalid)?;
        if hash.salt.is_none() || hash.hash.is_none() {
            return Err(Error::Invalid);
        }
        let params = argon2::Params::try_from(&hash).map_err(|_| Error::Invalid)?;
        if params.m_cost() > 262_144 || params.t_cost() > 10 || params.p_cost() > 16 {
            return Err(Error::Limit);
        }
        return match Argon2::default().verify_password(password.as_bytes(), &hash) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(_) => Err(Error::Invalid),
        };
    }
    if let Some(hash) = encoded.strip_prefix("bcrypt_sha256$") {
        let cost: u32 = hash
            .split('$')
            .nth(2)
            .ok_or(Error::Invalid)?
            .parse()
            .map_err(|_| Error::Invalid)?;
        if cost > 16 {
            return Err(Error::Limit);
        }
        let prehash = hex::encode(Sha256::digest(password.as_bytes()));
        return bcrypt::verify(prehash, hash).map_err(|_| Error::Invalid);
    }
    if let Some(rest) = encoded.strip_prefix("pbkdf2_sha256$") {
        let mut fields = rest.split('$');
        let iterations: u32 = fields
            .next()
            .ok_or(Error::Invalid)?
            .parse()
            .map_err(|_| Error::Invalid)?;
        let salt = fields.next().ok_or(Error::Invalid)?;
        let digest = fields.next().ok_or(Error::Invalid)?;
        if fields.next().is_some() || salt.is_empty() || iterations == 0 {
            return Err(Error::Invalid);
        }
        if iterations > 10_000_000 {
            return Err(Error::Limit);
        }
        let expected = STANDARD.decode(digest).map_err(|_| Error::Invalid)?;
        if expected.len() != 32 {
            return Err(Error::Invalid);
        }
        let actual = pbkdf2::pbkdf2_hmac_array::<Sha256, 32>(
            password.as_bytes(),
            salt.as_bytes(),
            iterations,
        );
        return Ok(bool::from(actual.ct_eq(&expected)));
    }
    Err(Error::Unsupported)
}
