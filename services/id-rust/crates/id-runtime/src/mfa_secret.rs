//! MFA encryption key loading; Lockbox or an equivalent secret injector sets
//! `ID_MFA_SEAL_KEY_B64` before the Rust API starts.

use anyhow::{Context, Result};
use id_compat::mfa_seal::MfaSealKey;
use std::{env, sync::Arc};

pub fn key_from_env() -> Result<Option<Arc<MfaSealKey>>> {
    match env::var("ID_MFA_SEAL_KEY_B64") {
        Ok(encoded) => Ok(Some(Arc::new(
            MfaSealKey::from_base64(&encoded)
                .context("ID_MFA_SEAL_KEY_B64 must encode exactly 32 bytes")?,
        ))),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(error.into()),
    }
}
