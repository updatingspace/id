#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]
//! Legacy wire/storage formats. These primitives do not authorize a request.
//! Callers must check live identity, MFA, expiry and revocation in the database.

pub mod account_jwt;
pub mod cache;
pub mod csrf;
pub mod headers;
pub mod internal_hmac;
pub mod mfa_seal;
pub mod password;
pub mod recovery;
pub mod session;
pub mod session_auth;
pub mod totp;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid legacy credential")]
    Invalid,
    #[error("legacy credential exceeds configured work or size limit")]
    Limit,
    #[error("unsupported legacy credential format")]
    Unsupported,
}

pub type Result<T> = std::result::Result<T, Error>;
