//! Convert an already trusted allauth registration record to a Rust WebAuthn credential.
//!
//! Only use this for credentials read from the existing MFA table. The stored
//! registration response is historical evidence, not a new registration request.

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use webauthn_rs::prelude::{
    Passkey, PasskeyRegistration, RegisterPublicKeyCredential, Url, Uuid, WebauthnBuilder,
};

const MAX_LEGACY_RESPONSE: usize = 32 * 1024;

pub fn import_registration(registration: &Value, rp_id: &str, origin: &str) -> Result<Passkey> {
    ensure!(
        serde_json::to_vec(registration)?.len() <= MAX_LEGACY_RESPONSE,
        "oversized legacy WebAuthn registration"
    );
    let client_data = registration
        .pointer("/response/clientDataJSON")
        .and_then(Value::as_str)
        .context("missing clientDataJSON")?;
    let client_data = URL_SAFE_NO_PAD
        .decode(client_data)
        .context("invalid clientDataJSON encoding")?;
    ensure!(client_data.len() <= 4096, "oversized WebAuthn client data");
    let client_data: Value =
        serde_json::from_slice(&client_data).context("invalid WebAuthn client data")?;
    let challenge = client_data
        .get("challenge")
        .and_then(Value::as_str)
        .context("missing legacy challenge")?;
    ensure!(
        client_data.get("type").and_then(Value::as_str) == Some("webauthn.create"),
        "unexpected WebAuthn ceremony"
    );
    ensure!(
        client_data.get("origin").and_then(Value::as_str) == Some(origin),
        "legacy WebAuthn origin mismatch"
    );
    let credential: RegisterPublicKeyCredential = serde_json::from_value(registration.clone())
        .context("invalid legacy registration response")?;
    let rp_origin = Url::parse(origin).context("invalid WebAuthn origin")?;
    let webauthn = WebauthnBuilder::new(rp_id, &rp_origin)
        .context("invalid WebAuthn RP configuration")?
        .build()
        .context("cannot build WebAuthn RP")?;
    // The fresh state supplies current algorithm and UV policy. For this
    // historical record only, substitute the challenge stored in its original
    // signed clientDataJSON. This state never leaves the process or becomes an
    // active ceremony that a browser can complete.
    let (_, state) = webauthn
        .start_passkey_registration(Uuid::nil(), "legacy-import", "Legacy import", None)
        .context("cannot build legacy verification state")?;
    let mut state = serde_json::to_value(state)?;
    *state
        .pointer_mut("/rs/challenge")
        .context("missing library challenge")? = Value::String(challenge.to_owned());
    let state: PasskeyRegistration =
        serde_json::from_value(state).context("invalid legacy verification state")?;
    let passkey = webauthn
        .finish_passkey_registration(&credential, &state)
        .context("legacy WebAuthn registration fails verification")?;
    let raw_id = registration
        .get("rawId")
        .and_then(Value::as_str)
        .context("missing credential ID")?;
    let raw_id = URL_SAFE_NO_PAD
        .decode(raw_id)
        .context("invalid credential ID")?;
    ensure!(
        passkey.cred_id().as_ref() == raw_id.as_slice(),
        "legacy WebAuthn credential ID mismatch"
    );
    Ok(passkey)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> Value {
        serde_json::from_str(include_str!("../tests/fixtures/legacy_passkey.json"))
            .unwrap_or(Value::Null)
    }

    #[test]
    fn imports_existing_allauth_registration_without_changing_credential_id() -> Result<()> {
        let fixture = fixture();
        let credential = import_registration(
            &fixture["registration"],
            fixture["rp_id"].as_str().context("RP ID")?,
            fixture["origin"].as_str().context("origin")?,
        )?;
        assert_eq!(
            credential.cred_id().as_ref(),
            b"RUST-LEGACY-PASSKEY-TEST-000001"
        );
        let serialized = serde_json::to_value(&credential)?;
        let restored: Passkey = serde_json::from_value(serialized)?;
        assert_eq!(credential.cred_id(), restored.cred_id());
        Ok(())
    }

    #[test]
    fn rejects_wrong_origin_challenge_and_credential_id() -> Result<()> {
        let fixture = fixture();
        let rp_id = fixture["rp_id"].as_str().context("RP ID")?;
        let origin = fixture["origin"].as_str().context("origin")?;
        assert!(
            import_registration(
                &fixture["registration"],
                rp_id,
                "https://wrong.example.invalid"
            )
            .is_err()
        );
        let mut changed = fixture["registration"].clone();
        changed["rawId"] = json!("bm90LXRoZS1zYW1lLWlk");
        assert!(import_registration(&changed, rp_id, origin).is_err());
        let mut changed = fixture["registration"].clone();
        changed["response"]["clientDataJSON"] = json!("aW52YWxpZA");
        assert!(import_registration(&changed, rp_id, origin).is_err());
        Ok(())
    }
}
