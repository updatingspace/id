//! OIDC discovery metadata for capabilities already implemented by the Rust API.

use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::env;
use url::Url;

pub struct OidcDiscovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    revocation_endpoint: String,
}

impl OidcDiscovery {
    pub fn from_env(issuer: &str) -> Result<Self> {
        let public_base = env::var("OIDC_PUBLIC_BASE_URL").unwrap_or_else(|_| issuer.to_owned());
        let mut result = Self::new(issuer, &public_base)?;
        result.authorization_endpoint =
            env::var("OIDC_AUTHORIZATION_ENDPOINT").unwrap_or(result.authorization_endpoint);
        result.token_endpoint = env::var("OIDC_TOKEN_ENDPOINT").unwrap_or(result.token_endpoint);
        result.userinfo_endpoint =
            env::var("OIDC_USERINFO_ENDPOINT").unwrap_or(result.userinfo_endpoint);
        result.revocation_endpoint =
            env::var("OIDC_REVOCATION_ENDPOINT").unwrap_or(result.revocation_endpoint);
        result.jwks_uri = env::var("OIDC_JWKS_URI").unwrap_or(result.jwks_uri);
        result.validate()?;
        Ok(result)
    }

    pub fn new(issuer: &str, public_base: &str) -> Result<Self> {
        let issuer = issuer.trim_end_matches('/').to_owned();
        let public_base = public_base.trim_end_matches('/');
        let result = Self {
            authorization_endpoint: format!("{public_base}/oauth/authorize"),
            token_endpoint: format!("{public_base}/oauth/token"),
            userinfo_endpoint: format!("{public_base}/oauth/userinfo"),
            revocation_endpoint: format!("{public_base}/oauth/revoke"),
            jwks_uri: format!("{issuer}/.well-known/jwks.json"),
            issuer,
        };
        result.validate()?;
        Ok(result)
    }

    fn validate(&self) -> Result<()> {
        for value in [
            &self.issuer,
            &self.authorization_endpoint,
            &self.token_endpoint,
            &self.userinfo_endpoint,
            &self.jwks_uri,
            &self.revocation_endpoint,
        ] {
            let parsed = Url::parse(value)?;
            ensure!(
                parsed.scheme() == "https"
                    && parsed.host_str().is_some()
                    && parsed.username().is_empty()
                    && parsed.password().is_none()
                    && parsed.query().is_none()
                    && parsed.fragment().is_none(),
                "OIDC discovery URLs must be absolute HTTPS URLs without credentials or query"
            );
        }
        Ok(())
    }

    pub fn document(&self) -> Value {
        json!({
            "issuer": self.issuer,
            "authorization_endpoint": self.authorization_endpoint,
            "token_endpoint": self.token_endpoint,
            "userinfo_endpoint": self.userinfo_endpoint,
            "jwks_uri": self.jwks_uri,
            "revocation_endpoint": self.revocation_endpoint,
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "request_parameter_supported": false,
            "request_uri_parameter_supported": false,
            "claims_parameter_supported": false,
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "profile", "profile_basic", "profile_extended", "email", "phone", "address", "offline_access"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "claims_supported": ["address", "birthdate", "email", "email_verified", "family_name", "given_name", "locale", "name", "phone_number", "phone_number_verified", "picture", "sub"]
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn discovery_uses_existing_urls_and_advertises_existing_scopes() -> Result<()> {
        let discovery = OidcDiscovery::new(
            "https://id.example.invalid/",
            "https://api.example.invalid/",
        )?;
        let document = discovery.document();
        assert_eq!(document["issuer"], "https://id.example.invalid");
        assert_eq!(
            document["authorization_endpoint"],
            "https://api.example.invalid/oauth/authorize"
        );
        assert_eq!(
            document["jwks_uri"],
            "https://id.example.invalid/.well-known/jwks.json"
        );
        assert_eq!(
            document["grant_types_supported"],
            json!(["authorization_code", "refresh_token"])
        );
        assert!(
            document["scopes_supported"]
                .as_array()
                .is_some_and(|scopes| {
                    scopes.contains(&json!("offline_access"))
                        && scopes.contains(&json!("profile_extended"))
                        && scopes.contains(&json!("phone"))
                        && scopes.contains(&json!("address"))
                })
        );
        assert!(
            OidcDiscovery::new("http://id.example.invalid", "https://id.example.invalid").is_err()
        );
        assert!(
            OidcDiscovery::new(
                "https://id.example.invalid",
                "https://user:pass@id.example.invalid"
            )
            .is_err()
        );
        Ok(())
    }
}
