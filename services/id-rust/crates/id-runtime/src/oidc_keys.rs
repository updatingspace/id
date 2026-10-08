//! Fail-closed OIDC RSA key loading; no runtime key generation.

use anyhow::{Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use simple_asn1::ASN1Block;
use std::{collections::HashMap, env};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyEntry {
    #[serde(default, alias = "private_key")]
    private_key_pem: Option<String>,
    #[serde(alias = "public_key")]
    public_key_pem: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default = "enabled", alias = "enabled")]
    active: bool,
}

fn enabled() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Entries {
    One(KeyEntry),
    Many(Vec<KeyEntry>),
}

pub struct OidcKeyRing {
    active_kid: String,
    active_signer: EncodingKey,
    verifiers: HashMap<String, DecodingKey>,
    public_pems: HashMap<String, String>,
    jwks: Vec<PublicJwk>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PublicJwk {
    kty: &'static str,
    #[serde(rename = "use")]
    key_use: &'static str,
    alg: &'static str,
    kid: String,
    n: String,
    e: String,
}

fn jwk_from_public_pem(public_pem: &str, kid: String) -> Result<PublicJwk> {
    let pem = pem::parse(public_pem)?;
    ensure!(
        pem.tag() == "PUBLIC KEY",
        "OIDC key must be a PEM public key"
    );
    let der = simple_asn1::from_der(pem.contents())?;
    let [ASN1Block::Sequence(_, fields)] = der.as_slice() else {
        bail!("invalid OIDC public key container");
    };
    let [
        ASN1Block::Sequence(_, algorithm),
        ASN1Block::BitString(_, bits, key_der),
    ] = fields.as_slice()
    else {
        bail!("invalid OIDC public key structure");
    };
    let [ASN1Block::ObjectIdentifier(_, oid), ASN1Block::Null(_)] = algorithm.as_slice() else {
        bail!("invalid OIDC public key algorithm");
    };
    ensure!(
        oid.as_vec::<u64>()? == [1, 2, 840, 113549, 1, 1, 1],
        "OIDC public key must be RSA"
    );
    ensure!(*bits == key_der.len() * 8, "invalid OIDC key bit string");
    let key = simple_asn1::from_der(key_der)?;
    let [ASN1Block::Sequence(_, numbers)] = key.as_slice() else {
        bail!("invalid OIDC RSA key");
    };
    let [
        ASN1Block::Integer(_, modulus),
        ASN1Block::Integer(_, exponent),
    ] = numbers.as_slice()
    else {
        bail!("invalid OIDC RSA components");
    };
    ensure!(
        modulus > &0.into() && exponent > &0.into(),
        "invalid OIDC RSA components"
    );
    let (_, n) = modulus.to_bytes_be();
    let (_, e) = exponent.to_bytes_be();
    ensure!(!n.is_empty() && !e.is_empty(), "empty OIDC RSA components");
    Ok(PublicJwk {
        kty: "RSA",
        key_use: "sig",
        alg: "RS256",
        kid,
        n: URL_SAFE_NO_PAD.encode(n),
        e: URL_SAFE_NO_PAD.encode(e),
    })
}

impl OidcKeyRing {
    pub fn from_env() -> Result<Self> {
        let pairs = env::var("OIDC_KEY_PAIRS").unwrap_or_default();
        let entries = if !pairs.trim().is_empty() {
            return Self::from_json(&pairs);
        } else {
            let private = env::var("OIDC_PRIVATE_KEY_PEM").unwrap_or_default();
            let public = env::var("OIDC_PUBLIC_KEY_PEM").unwrap_or_default();
            if private.is_empty() || public.is_empty() {
                bail!("OIDC signing keys are required");
            }
            vec![KeyEntry {
                private_key_pem: Some(private),
                public_key_pem: public,
                kid: env::var("OIDC_KEY_KID").ok(),
                active: true,
            }]
        };
        Self::from_entries(entries)
    }

    pub fn from_json(raw: &str) -> Result<Self> {
        let entries = match serde_json::from_str::<Entries>(raw)? {
            Entries::One(entry) => vec![entry],
            Entries::Many(entries) => entries,
        };
        Self::from_entries(entries)
    }

    fn from_entries(entries: Vec<KeyEntry>) -> Result<Self> {
        ensure!(!entries.is_empty(), "OIDC keyset is empty");
        let mut active = None;
        let mut verifiers = HashMap::new();
        let mut public_pems = HashMap::new();
        let mut jwks = Vec::new();
        for entry in entries {
            ensure!(!entry.public_key_pem.is_empty(), "OIDC public key is empty");
            let kid = entry.kid.unwrap_or_else(|| {
                hex::encode(Sha256::digest(entry.public_key_pem.as_bytes()))[..16].to_owned()
            });
            ensure!(
                !kid.is_empty() && kid.len() <= 128 && kid.is_ascii(),
                "invalid OIDC kid"
            );
            let verifier = DecodingKey::from_rsa_pem(entry.public_key_pem.as_bytes())
                .map_err(|_| anyhow::anyhow!("invalid OIDC public key"))?;
            if verifiers.insert(kid.clone(), verifier).is_some() {
                bail!("duplicate OIDC kid");
            }
            jwks.push(jwk_from_public_pem(&entry.public_key_pem, kid.clone())?);
            public_pems.insert(kid.clone(), entry.public_key_pem);
            if let Some(private) = entry
                .private_key_pem
                .as_deref()
                .filter(|value| !value.is_empty())
            {
                let signer = EncodingKey::from_rsa_pem(private.as_bytes())
                    .map_err(|_| anyhow::anyhow!("invalid OIDC private key"))?;
                let mut header = Header::new(Algorithm::RS256);
                header.kid = Some(kid.clone());
                let token = encode(&header, &serde_json::json!({"probe":true}), &signer)
                    .map_err(|_| anyhow::anyhow!("invalid OIDC RSA signing key"))?;
                let mut validation = Validation::new(Algorithm::RS256);
                validation.required_spec_claims.clear();
                validation.validate_exp = false;
                validation.validate_aud = false;
                decode::<serde_json::Value>(
                    &token,
                    verifiers
                        .get(&kid)
                        .ok_or_else(|| anyhow::anyhow!("missing OIDC verifier"))?,
                    &validation,
                )
                .map_err(|_| anyhow::anyhow!("OIDC public/private key mismatch"))?;
                if entry.active {
                    ensure!(active.is_none(), "multiple active OIDC signing keys");
                    active = Some((kid, signer));
                }
            } else if entry.active {
                bail!("active OIDC key has no private material");
            }
        }
        let (active_kid, active_signer) =
            active.ok_or_else(|| anyhow::anyhow!("no active OIDC signing key"))?;
        jwks.sort_by(|left, right| left.kid.cmp(&right.kid));
        Ok(Self {
            active_kid,
            active_signer,
            verifiers,
            public_pems,
            jwks,
        })
    }

    pub fn sign<T: Serialize>(&self, claims: &T) -> Result<String> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.active_kid.clone());
        encode(&header, claims, &self.active_signer)
            .map_err(|_| anyhow::anyhow!("OIDC signing failed"))
    }

    pub fn public_keys(&self) -> impl Iterator<Item = (&str, &str)> {
        self.public_pems
            .iter()
            .map(|(kid, pem)| (kid.as_str(), pem.as_str()))
    }

    pub fn jwks(&self) -> &[PublicJwk] {
        &self.jwks
    }

    pub fn verifier(&self, kid: &str) -> Option<&DecodingKey> {
        self.verifiers.get(kid)
    }

    pub fn active_kid(&self) -> &str {
        &self.active_kid
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::{
        io::Write,
        process::{Command, Stdio},
    };

    fn generated_pair() -> Result<(String, String)> {
        let private = Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
            ])
            .output()?;
        ensure!(private.status.success(), "ephemeral RSA generation failed");
        let mut child = Command::new("openssl")
            .args(["pkey", "-pubout"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("missing openssl stdin"))?
            .write_all(&private.stdout)?;
        let public = child.wait_with_output()?;
        ensure!(
            public.status.success(),
            "ephemeral RSA public export failed"
        );
        Ok((
            String::from_utf8(private.stdout)?,
            String::from_utf8(public.stdout)?,
        ))
    }

    #[test]
    fn rejects_empty_or_ambiguous_keyset_without_generating_keys() -> Result<()> {
        assert!(OidcKeyRing::from_entries(Vec::new()).is_err());
        let invalid = KeyEntry {
            private_key_pem: None,
            public_key_pem: "invalid".into(),
            kid: Some("a".into()),
            active: true,
        };
        assert!(OidcKeyRing::from_entries(vec![invalid]).is_err());
        assert!(
            serde_json::from_str::<Entries>(r#"[{"public_key_pem":"x","kid":"a","kid":"b"}]"#)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn signs_with_existing_key_and_rejects_mismatch() -> Result<()> {
        let (private, public) = generated_pair()?;
        let (_, unrelated_public) = generated_pair()?;
        let ring = OidcKeyRing::from_entries(vec![KeyEntry {
            private_key_pem: Some(private.clone()),
            public_key_pem: public.clone(),
            kid: Some("existing-kid".into()),
            active: true,
        }])?;
        let token =
            ring.sign(&serde_json::json!({"sub":"stable-subject","exp":4_000_000_000_u64}))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_aud = false;
        let decoded = decode::<serde_json::Value>(
            &token,
            ring.verifier("existing-kid")
                .ok_or_else(|| anyhow::anyhow!("missing verifier"))?,
            &validation,
        )?;
        assert_eq!(decoded.claims["sub"], "stable-subject");
        assert_eq!(ring.active_kid(), "existing-kid");
        let jwk = &ring.jwks()[0];
        assert_eq!(jwk.kid, "existing-kid");
        let jwk_verifier = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)?;
        assert_eq!(
            decode::<serde_json::Value>(&token, &jwk_verifier, &validation)?.claims["sub"],
            "stable-subject"
        );
        let rotated = OidcKeyRing::from_entries(vec![
            KeyEntry {
                private_key_pem: Some(private.clone()),
                public_key_pem: public,
                kid: Some("existing-kid".into()),
                active: true,
            },
            KeyEntry {
                private_key_pem: None,
                public_key_pem: unrelated_public.clone(),
                kid: Some("old-kid".into()),
                active: false,
            },
        ])?;
        assert_eq!(rotated.jwks().len(), 2);
        assert_eq!(rotated.jwks()[0].kid, "existing-kid");
        assert_eq!(rotated.jwks()[1].kid, "old-kid");
        assert!(
            OidcKeyRing::from_entries(vec![KeyEntry {
                private_key_pem: Some(private),
                public_key_pem: unrelated_public,
                kid: Some("wrong-kid".into()),
                active: true,
            }])
            .is_err()
        );
        Ok(())
    }
}
