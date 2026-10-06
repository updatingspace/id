//! Read-only Django session eligibility from one consistent database snapshot.
//! This does not check master-identity status, MFA policy, or account permissions.

use std::time::SystemTime;

use crate::session::SessionCodec;

#[derive(Clone, Copy)]
pub struct SessionMeta {
    pub user_id: i64,
    pub revoked: bool,
}

pub struct SessionSnapshot<'a> {
    pub encoded: &'a str,
    pub expires_at: SystemTime,
    pub user_id: i64,
    pub password_hash: &'a str,
    pub is_active: bool,
    pub metadata: &'a [SessionMeta],
}

/// Returns the Django account ID only when every known session check passes.
/// A caller must obtain the session, user and metadata in a consistent YDB read
/// and must not treat this alone as a complete identity authorization decision.
pub fn eligible_account_id(
    codec: &SessionCodec,
    snapshot: &SessionSnapshot<'_>,
    allowed_backends: &[&str],
    now: SystemTime,
) -> Option<i64> {
    if snapshot.expires_at <= now || !snapshot.is_active || snapshot.metadata.len() > 1 {
        return None;
    }
    if snapshot
        .metadata
        .iter()
        .any(|meta| meta.revoked || meta.user_id != snapshot.user_id)
    {
        return None;
    }

    let session = codec.decode(snapshot.encoded).ok()?;
    let account_id = session.data.get("_auth_user_id")?.as_str()?.parse().ok()?;
    if account_id != snapshot.user_id {
        return None;
    }
    let backend = session.data.get("_auth_user_backend")?.as_str()?;
    if !allowed_backends.contains(&backend) {
        return None;
    }
    let auth_hash = session.data.get("_auth_user_hash")?.as_str()?;
    if !codec
        .verify_auth_hash(snapshot.password_hash, auth_hash)
        .ok()?
    {
        return None;
    }
    Some(account_id)
}
