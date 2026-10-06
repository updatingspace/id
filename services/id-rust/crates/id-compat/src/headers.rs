//! Mirrors accounts.api.security.session_header. Invalid explicit authentication
//! never falls back to a cookie. Cookie parsing and CSRF policy belong to HTTP.

use http::HeaderMap;

use crate::{Error, Result};

pub fn session_token(headers: &HeaderMap) -> Result<Option<&str>> {
    // Reject ambiguous repeated credentials instead of trusting proxy join order.
    for name in ["authorization", "x-session-token"] {
        if headers.get_all(name).iter().count() > 1 {
            return Err(Error::Invalid);
        }
    }
    let header = |name| {
        headers
            .get(name)
            .map(|v| v.to_str().map_err(|_| Error::Invalid))
            .transpose()
    };
    let authorization = header("authorization")?;
    let session = header("x-session-token")?;
    if let Some(authorization) = authorization {
        let (scheme, token) = authorization.split_once(' ').ok_or(Error::Invalid)?;
        let token = token.trim();
        if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
            return Err(Error::Invalid);
        }
        if session.is_some_and(|other| other != token) {
            return Err(Error::Invalid);
        }
        return Ok(Some(token));
    }
    if session.is_some_and(|token| token.trim().is_empty()) {
        return Err(Error::Invalid);
    }
    Ok(session)
}
