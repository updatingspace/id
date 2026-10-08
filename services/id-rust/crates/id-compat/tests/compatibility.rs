#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::{Engine, engine::general_purpose::STANDARD};
use http::{HeaderMap, HeaderValue};
use id_compat::{
    Error,
    cache::{self, CacheValue},
    csrf, headers, password, recovery,
    session::SessionCodec,
    session_auth::{SessionMeta, SessionSnapshot, eligible_account_id},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::time::{Duration, UNIX_EPOCH};

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/django.json")).unwrap()
}

#[test]
fn usable_passwords_share_supported_legacy_formats_and_reject_broken_backups() {
    let golden = fixture();
    for hash in golden["password_hashes"].as_array().unwrap() {
        assert!(password::is_usable(text(hash)));
    }
    for hash in [
        "",
        "!unusable",
        "pbkdf2_sha256$1000000$synthetic$synthetic",
        "pbkdf2_sha256$0$salt$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "pbkdf2_sha256$10000001$salt$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "bcrypt_sha256$$2b$04$broken",
        "argon2$argon2id$v=99$m=102400,t=2,p=8$c2FsdHNhbHQ$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "argon2$argon2id$v=19$m=102400,t=2,p=8$c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "argon2$argon2id$v=19$m=102400,t=2,p=8$...........$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "argon2$argon2id$v=19$m=102400,t=2,p=8$-----------$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "argon2$argon2id$v=19$m=262145,t=2,p=8$c2FsdHNhbHQ$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        assert!(!password::is_usable(hash), "unusable backup accepted");
        if !hash.starts_with('!') {
            assert!(
                password::verify("synthetic", hash).is_err(),
                "verifier disagrees with unusable format"
            );
        }
    }
    assert_eq!(
        password::verify(
            "synthetic",
            "argon2$argon2id$v=99$m=262145,t=2,p=8$...........$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ),
        Err(Error::Limit),
        "existing work-limit error must precede malformed salt/version"
    );
}
fn text(v: &Value) -> &str {
    v.as_str().unwrap()
}

fn map(entries: &[(&str, CacheValue)]) -> CacheValue {
    CacheValue::Map(
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone()))
            .collect::<BTreeMap<_, _>>(),
    )
}

#[test]
fn python_portable_cache_vectors_roundtrip_byte_for_byte() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/cache.json")).unwrap();
    let expected = [
        ("none", CacheValue::Null),
        ("bool", CacheValue::Bool(true)),
        ("int", CacheValue::Int(-(2_i64.pow(32)))),
        ("float", CacheValue::Float(1.25)),
        ("str", CacheValue::String("Пользователь 🔐".into())),
        (
            "bytes",
            CacheValue::Bytes(vec![0, 255, b't', b'e', b's', b't']),
        ),
        ("bytearray", CacheValue::ByteArray(b"\0test".to_vec())),
        (
            "list",
            CacheValue::List(vec![
                CacheValue::Float(1.25),
                CacheValue::Int(-7),
                CacheValue::String("token".into()),
            ]),
        ),
        (
            "tuple",
            CacheValue::Tuple(vec![
                CacheValue::String("cookie".into()),
                CacheValue::Bool(false),
            ]),
        ),
        (
            "form_token",
            map(&[
                ("purpose", CacheValue::String("login".into())),
                ("issued_at", CacheValue::Int(1_770_000_000)),
                ("expires_at", CacheValue::Int(1_770_000_900)),
                ("client_ip", CacheValue::Null),
                ("user_agent", CacheValue::String("Synthetic Browser".into())),
                ("used", CacheValue::Bool(false)),
            ]),
        ),
        (
            "rate_limit",
            map(&[
                ("count", CacheValue::Int(5)),
                ("reset_at", CacheValue::Int(1_770_000_060)),
            ]),
        ),
        (
            "exchange",
            map(&[
                (
                    "user_id",
                    CacheValue::String("00000000-0000-0000-0000-000000000042".into()),
                ),
                (
                    "master_flags",
                    map(&[
                        ("email_verified", CacheValue::Bool(true)),
                        ("system_admin", CacheValue::Bool(false)),
                    ]),
                ),
                ("ttl_seconds", CacheValue::Int(3600)),
                (
                    "issued_at",
                    CacheValue::String("2026-02-02T00:00:00+00:00".into()),
                ),
            ]),
        ),
    ];
    let vectors = fixture["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), expected.len());
    for (vector, (name, value)) in vectors.iter().zip(expected.iter()) {
        assert_eq!(text(&vector["name"]), *name);
        let bytes = STANDARD.decode(text(&vector["encoded_b64"])).unwrap();
        assert_eq!(cache::decode(&bytes), Ok(value.clone()), "{name}");
        assert_eq!(cache::encode(value), Ok(bytes), "{name}");
    }
    assert_eq!(cache::decode(b"\x80\x05N."), Err(Error::Unsupported));
}

#[test]
fn verifies_all_configured_django_hashers_and_unicode_long_password() {
    let f = fixture();
    for hash in f["password_hashes"].as_array().unwrap() {
        assert_eq!(password::verify(text(&f["password"]), text(hash)), Ok(true));
        assert_eq!(password::verify("wrong", text(hash)), Ok(false));
    }
    assert_eq!(password::verify("anything", "!unusable"), Ok(false));
    assert_eq!(
        password::verify("anything", "unknown$hash"),
        Err(Error::Unsupported)
    );
}

#[test]
fn newly_hashed_password_keeps_django_argon2_cost_and_random_salt() {
    let first = password::hash_new("long synthetic passphrase 🔐").unwrap();
    let second = password::hash_new("long synthetic passphrase 🔐").unwrap();
    assert!(first.starts_with("argon2$argon2id$v=19$m=102400,t=2,p=8$"));
    assert_ne!(first, second);
    assert_eq!(
        password::verify("long synthetic passphrase 🔐", &first),
        Ok(true)
    );
    assert_eq!(password::verify("wrong", &first), Ok(false));
    assert_eq!(password::hash_new(""), Err(Error::Limit));
}

#[test]
fn malformed_hashes_and_excessive_work_are_not_password_mismatches() {
    for hash in [
        "pbkdf2_sha256$0$salt$abc",
        "pbkdf2_sha256$1$salt$abc",
        "argon2$broken",
        "bcrypt_sha256$$2b$bad$hash",
        "pbkdf2_sha256$1$salt$abc$extra",
    ] {
        assert!(password::verify("password", hash).is_err(), "{hash}");
    }
    assert_eq!(
        password::verify("password", "pbkdf2_sha256$10000001$salt$hash"),
        Err(Error::Limit)
    );
    assert_eq!(
        password::verify("password", "bcrypt_sha256$$2b$31$abcdefghijklmnopqrstuu"),
        Err(Error::Limit)
    );
}

#[test]
fn python_sessions_decode_and_rust_roundtrip_without_freshness_change() {
    let f = fixture();
    let codec = SessionCodec::new(text(&f["secret"]).as_bytes(), &[]).unwrap();
    for vector in f["session"]["vectors"].as_array().unwrap() {
        let session = codec.decode(text(&vector["encoded"])).unwrap();
        assert_eq!(Value::Object(session.data.clone()), f["session"]["payload"]);
        assert_eq!(
            session.signed_at,
            f["session"]["issued_at"].as_i64().unwrap()
        );
        assert!(!session.needs_key_rotation);
        for compress in [false, true] {
            let encoded = codec
                .encode(&session.data, session.signed_at, compress)
                .unwrap();
            let decoded = codec.decode(&encoded).unwrap();
            assert!(decoded == session);
        }
    }
    let hash = text(&f["password_hashes"][2]);
    let expected = text(&f["session"]["payload"]["_auth_user_hash"]);
    assert_eq!(codec.auth_hash(hash).unwrap(), expected);
    assert_eq!(codec.verify_auth_hash(hash, expected), Ok(true));
    assert_eq!(
        codec.verify_auth_hash("changed-password-hash", expected),
        Ok(false)
    );
}

#[test]
fn session_eligibility_fails_closed_on_expiry_password_revocation_and_backend() {
    let f = fixture();
    let codec = SessionCodec::new(text(&f["secret"]).as_bytes(), &[]).unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(1_770_000_100);
    let encoded = text(&f["session"]["vectors"][0]["encoded"]);
    let password_hash = text(&f["password_hashes"][2]);
    let metadata = [SessionMeta {
        user_id: 42,
        revoked: false,
    }];
    let mut row = SessionSnapshot {
        encoded,
        expires_at: now + Duration::from_secs(60),
        user_id: 42,
        password_hash,
        is_active: true,
        metadata: &metadata,
    };
    let backends = ["django.contrib.auth.backends.ModelBackend"];
    assert_eq!(eligible_account_id(&codec, &row, &backends, now), Some(42));
    row.metadata = &[];
    assert_eq!(eligible_account_id(&codec, &row, &backends, now), Some(42));
    row.metadata = &metadata;

    row.expires_at = now;
    assert_eq!(eligible_account_id(&codec, &row, &backends, now), None);
    row.expires_at = now + Duration::from_secs(60);
    row.password_hash = "changed-password-hash";
    assert_eq!(eligible_account_id(&codec, &row, &backends, now), None);
    row.password_hash = password_hash;
    row.user_id = 43;
    assert_eq!(eligible_account_id(&codec, &row, &backends, now), None);
    row.user_id = 42;
    assert_eq!(eligible_account_id(&codec, &row, &[], now), None);
    row.is_active = false;
    assert_eq!(eligible_account_id(&codec, &row, &backends, now), None);
    row.is_active = true;

    let revoked = [SessionMeta {
        user_id: 42,
        revoked: true,
    }];
    row.metadata = &revoked;
    assert_eq!(eligible_account_id(&codec, &row, &backends, now), None);
    let wrong_owner = [SessionMeta {
        user_id: 43,
        revoked: false,
    }];
    row.metadata = &wrong_owner;
    assert_eq!(eligible_account_id(&codec, &row, &backends, now), None);
    let duplicates = [metadata[0], metadata[0]];
    row.metadata = &duplicates;
    assert_eq!(eligible_account_id(&codec, &row, &backends, now), None);
}

#[test]
fn rotated_keys_verify_old_sessions_and_password_hashes() {
    let f = fixture();
    let old_key = text(&f["secret"]).as_bytes();
    let rotated = SessionCodec::new(b"new synthetic secret", &[old_key]).unwrap();
    let session = rotated
        .decode(text(&f["session"]["vectors"][0]["encoded"]))
        .unwrap();
    assert!(session.needs_key_rotation);
    assert!(
        rotated
            .verify_auth_hash(
                text(&f["password_hashes"][2]),
                text(&f["session"]["payload"]["_auth_user_hash"])
            )
            .unwrap()
    );
    let new = rotated
        .encode(&session.data, session.signed_at, true)
        .unwrap();
    assert!(!rotated.decode(&new).unwrap().needs_key_rotation);
    assert!(
        SessionCodec::new(old_key, &[])
            .unwrap()
            .decode(&new)
            .is_err()
    );
    assert!(SessionCodec::new(b"", &[]).is_err());
}

#[test]
fn tampered_truncated_and_wrong_key_sessions_fail_closed() {
    let f = fixture();
    let encoded = text(&f["session"]["vectors"][0]["encoded"]);
    let codec = SessionCodec::new(text(&f["secret"]).as_bytes(), &[]).unwrap();
    for invalid in [
        "",
        "a:b:c",
        &encoded[..encoded.len() - 1],
        &format!("x{encoded}"),
    ] {
        assert!(codec.decode(invalid).is_err());
    }
    assert!(
        SessionCodec::new(b"wrong", &[])
            .unwrap()
            .decode(encoded)
            .is_err()
    );
    for timestamp in [0, -1, i64::MIN, i64::MAX] {
        let data = json!({"at": timestamp}).as_object().unwrap().clone();
        let encoded = codec.encode(&data, timestamp, false).unwrap();
        assert_eq!(codec.decode(&encoded).unwrap().signed_at, timestamp);
    }
}

#[test]
fn session_size_is_bounded() {
    let codec = SessionCodec::new(b"synthetic", &[]).unwrap();
    assert!(matches!(
        codec.decode(&"x".repeat(1_500_001)),
        Err(Error::Limit)
    ));
    let data = json!({"value": "a".repeat(1_048_576)})
        .as_object()
        .unwrap()
        .clone();
    assert!(matches!(codec.encode(&data, 0, true), Err(Error::Limit)));
}

#[test]
fn authentic_signatures_do_not_bypass_json_and_decompression_bounds() {
    let f = fixture();
    let codec = SessionCodec::new(text(&f["secret"]).as_bytes(), &[]).unwrap();
    for encoded in f["malformed_sessions"].as_array().unwrap() {
        assert!(matches!(codec.decode(text(encoded)), Err(Error::Invalid)));
    }
    assert!(matches!(
        codec.decode(text(&f["oversized_compressed_session"])),
        Err(Error::Limit)
    ));
}

#[test]
fn header_credentials_are_authoritative_and_conflicts_fail() {
    let mut h = HeaderMap::new();
    h.insert("cookie", HeaderValue::from_static("sessionid=valid-cookie"));
    assert_eq!(headers::session_token(&h), Ok(None));
    h.insert("authorization", HeaderValue::from_static("invalid"));
    assert_eq!(headers::session_token(&h), Err(Error::Invalid));
    h.insert("authorization", HeaderValue::from_static("bEaReR token "));
    assert_eq!(headers::session_token(&h), Ok(Some("token")));
    h.insert("x-session-token", HeaderValue::from_static("other"));
    assert_eq!(headers::session_token(&h), Err(Error::Invalid));
    h.insert("x-session-token", HeaderValue::from_static("token"));
    assert_eq!(headers::session_token(&h), Ok(Some("token")));
    h.append("authorization", HeaderValue::from_static("Bearer token"));
    assert_eq!(headers::session_token(&h), Err(Error::Invalid));
    h.remove("authorization");
    h.insert("x-session-token", HeaderValue::from_static(" token "));
    assert_eq!(headers::session_token(&h), Ok(Some(" token ")));
    h.insert("x-session-token", HeaderValue::from_static(" "));
    assert_eq!(headers::session_token(&h), Err(Error::Invalid));
}

#[test]
fn masked_and_plain_csrf_tokens_match_django() {
    let f = fixture();
    let secret = text(&f["csrf"]["secret"]);
    let masked = text(&f["csrf"]["masked"]);
    assert_eq!(csrf::matches(secret, masked), Ok(true));
    assert_eq!(csrf::matches(masked, secret), Ok(true));
    assert_eq!(csrf::cookie_secret(masked).as_deref(), Ok(secret));
    assert_eq!(csrf::cookie_secret(secret).as_deref(), Ok(secret));
    assert_eq!(csrf::matches(secret, secret), Ok(true));
    assert_eq!(csrf::matches(secret, &"x".repeat(32)), Ok(false));
    assert_eq!(csrf::matches(secret, "short"), Err(Error::Invalid));
    assert_eq!(csrf::matches(secret, &"!".repeat(64)), Err(Error::Invalid));
}

#[test]
fn recovery_codes_preserve_used_mask() {
    let f = fixture();
    let seed = text(&f["recovery"]["seed"]);
    let codes = recovery::codes(seed).unwrap();
    assert_eq!(json!(codes), f["recovery"]["codes"]);
    let mask = f["recovery"]["used_mask"].as_u64().unwrap();
    for (i, code) in codes.iter().enumerate() {
        let expected = if mask & (1 << i) != 0 { None } else { Some(i) };
        assert_eq!(recovery::unused_index(seed, mask, code), Ok(expected));
        assert_eq!(
            recovery::unused_index(seed, mask | (1 << i), code),
            Ok(None)
        );
    }
    assert_eq!(recovery::unused_index(seed, mask, "wrong"), Ok(None));
    assert_eq!(
        recovery::unused_index(seed, 1 << 63, "wrong"),
        Err(Error::Invalid)
    );
    assert_eq!(recovery::codes("invalid"), Err(Error::Invalid));
}

#[test]
fn internal_hmac_matches_python_and_binds_original_bytes() {
    use id_compat::internal_hmac::{SignedRequest, verify};
    let f = fixture();
    let h = &f["internal_hmac"];
    let now = h["timestamp"].as_i64().unwrap();
    let stamp = now.to_string();
    let mut request = SignedRequest {
        method: text(&h["method"]),
        path: text(&h["path"]),
        body: text(&h["body"]).as_bytes(),
        request_id: text(&h["request_id"]),
        timestamp: &stamp,
        signature: text(&h["signature"]),
    };
    let secret = text(&h["secret"]).as_bytes();
    for time in [now - 300, now, now + 300] {
        assert_eq!(verify(secret, &request, time), Ok(true));
    }
    for time in [now - 301, now + 301, i64::MIN, i64::MAX] {
        assert_eq!(verify(secret, &request, time), Ok(false));
    }
    assert_eq!(verify(b"wrong", &request, now), Ok(false));
    request.body = b"{}";
    assert_eq!(verify(secret, &request, now), Ok(false));
    request.signature = "not-a-signature";
    assert_eq!(verify(secret, &request, now), Err(Error::Invalid));
}
