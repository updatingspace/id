//! Versioned at-rest encryption for new MFA secrets. Old allauth plaintext
//! values remain readable until the credential migration is complete.

use crate::{Error, Result};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};

const PREFIX: &str = "id-mfa-v1:";
const NONCE_BYTES: usize = 12;

#[derive(Clone, Copy)]
pub enum SecretKind {
    Totp,
    RecoverySeed,
    PendingTotp,
}

impl SecretKind {
    fn label(self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::RecoverySeed => "recovery-seed",
            Self::PendingTotp => "pending-totp",
        }
    }
}

pub struct MfaSealKey([u8; 32]);

impl MfaSealKey {
    pub fn from_base64(encoded: &str) -> Result<Self> {
        let decoded = STANDARD.decode(encoded).map_err(|_| Error::Invalid)?;
        let key = <[u8; 32]>::try_from(decoded.as_slice()).map_err(|_| Error::Invalid)?;
        Ok(Self(key))
    }

    pub fn seal(&self, account_id: i64, kind: SecretKind, plaintext: &str) -> Result<String> {
        if account_id == 0 || plaintext.is_empty() || plaintext.len() > 512 || !plaintext.is_ascii()
        {
            return Err(Error::Invalid);
        }
        let nonce: [u8; NONCE_BYTES] = rand::random();
        let cipher = Aes256Gcm::new_from_slice(&self.0).map_err(|_| Error::Invalid)?;
        let ciphertext = cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: &associated_data(account_id, kind),
                },
            )
            .map_err(|_| Error::Invalid)?;
        let mut packed = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
        packed.extend_from_slice(&nonce);
        packed.extend_from_slice(&ciphertext);
        Ok(format!(
            "{PREFIX}{account_id}:{}:{}",
            kind.label(),
            URL_SAFE_NO_PAD.encode(packed)
        ))
    }

    pub fn unseal(&self, account_id: i64, kind: SecretKind, encoded: &str) -> Result<String> {
        if account_id == 0 {
            return Err(Error::Invalid);
        }
        let Some(envelope) = encoded.strip_prefix(PREFIX) else {
            return Err(Error::Unsupported);
        };
        let mut parts = envelope.splitn(3, ':');
        let stored_account = parts
            .next()
            .and_then(|value| value.parse::<i64>().ok())
            .ok_or(Error::Invalid)?;
        let stored_kind = parts.next().ok_or(Error::Invalid)?;
        let packed = parts.next().ok_or(Error::Invalid)?;
        if stored_account != account_id || stored_kind != kind.label() {
            return Err(Error::Invalid);
        }
        let packed = URL_SAFE_NO_PAD.decode(packed).map_err(|_| Error::Invalid)?;
        if packed.len() < NONCE_BYTES + 16 || packed.len() > 2048 {
            return Err(Error::Invalid);
        }
        let (nonce, ciphertext) = packed.split_at(NONCE_BYTES);
        let cipher = Aes256Gcm::new_from_slice(&self.0).map_err(|_| Error::Invalid)?;
        let plaintext = cipher
            .decrypt(
                &Nonce::try_from(nonce).map_err(|_| Error::Invalid)?,
                Payload {
                    msg: ciphertext,
                    aad: &associated_data(account_id, kind),
                },
            )
            .map_err(|_| Error::Invalid)?;
        let plaintext = String::from_utf8(plaintext).map_err(|_| Error::Invalid)?;
        if plaintext.is_empty() || plaintext.len() > 512 || !plaintext.is_ascii() {
            return Err(Error::Invalid);
        }
        Ok(plaintext)
    }
}

/// A missing key must never turn a new encrypted credential into plaintext.
pub fn read_existing(
    key: Option<&MfaSealKey>,
    account_id: i64,
    kind: SecretKind,
    value: &str,
) -> Result<String> {
    if value.starts_with(PREFIX) {
        return key
            .ok_or(Error::Unsupported)?
            .unseal(account_id, kind, value);
    }
    if value.is_empty() || value.len() > 512 || !value.is_ascii() {
        return Err(Error::Invalid);
    }
    Ok(value.to_owned())
}

fn associated_data(account_id: i64, kind: SecretKind) -> Vec<u8> {
    format!("updspace-id:mfa:{}:account:{account_id}", kind.label()).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_binds_ciphertext_to_account_and_purpose() -> Result<()> {
        let key = MfaSealKey::from_base64(&STANDARD.encode([0x42; 32]))?;
        let sealed = key.seal(42, SecretKind::Totp, "JBSWY3DPEHPK3PXP")?;
        assert!(sealed.starts_with(PREFIX));
        assert!(!sealed.contains("JBSWY3DPEHPK3PXP"));
        assert_eq!(
            key.unseal(42, SecretKind::Totp, &sealed)?,
            "JBSWY3DPEHPK3PXP"
        );
        assert_eq!(
            key.unseal(43, SecretKind::Totp, &sealed),
            Err(Error::Invalid)
        );
        assert_eq!(
            key.unseal(42, SecretKind::RecoverySeed, &sealed),
            Err(Error::Invalid)
        );
        assert_eq!(
            read_existing(None, 42, SecretKind::Totp, &sealed),
            Err(Error::Unsupported)
        );
        assert_eq!(
            read_existing(None, 42, SecretKind::Totp, "LEGACY")?,
            "LEGACY"
        );
        Ok(())
    }

    #[test]
    fn malformed_key_and_ciphertext_fail_closed() -> Result<()> {
        assert!(MfaSealKey::from_base64("short").is_err());
        let key = MfaSealKey::from_base64(&STANDARD.encode([0x11; 32]))?;
        let sealed = key.seal(1, SecretKind::PendingTotp, "PENDING")?;
        let mut packed = URL_SAFE_NO_PAD
            .decode(sealed.rsplit_once(':').ok_or(Error::Invalid)?.1)
            .map_err(|_| Error::Invalid)?;
        packed[NONCE_BYTES] ^= 1;
        let modified = format!("{PREFIX}1:pending-totp:{}", URL_SAFE_NO_PAD.encode(packed));
        assert_eq!(
            key.unseal(1, SecretKind::PendingTotp, &modified),
            Err(Error::Invalid)
        );
        Ok(())
    }

    #[test]
    fn python_aesgcm_fixture_decrypts_in_rust() -> Result<()> {
        let key = MfaSealKey::from_base64(&STANDARD.encode([0x42; 32]))?;
        let python_vector =
            "id-mfa-v1:42:totp:ERERERERERERERER-SV4RDT_xHd51Cj8UNCsxZgT5AAWb16wfCKf113ysp4";
        assert_eq!(
            key.unseal(42, SecretKind::Totp, python_vector)?,
            "JBSWY3DPEHPK3PXP"
        );
        Ok(())
    }
}
