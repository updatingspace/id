#![allow(clippy::unwrap_used)]

use id_compat::{Error, totp};
use serde_json::Value;

#[test]
fn allauth_totp_vectors_and_rejections() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/totp.json")).unwrap();
    assert_eq!(fixture["format_version"], 1);
    assert_eq!(fixture["synthetic"], true);
    let secret = fixture["secret"].as_str().unwrap();
    let period = fixture["period"].as_u64().unwrap();
    let digits = fixture["digits"].as_u64().unwrap() as u32;
    let tolerance = fixture["tolerance"].as_u64().unwrap();
    for vector in fixture["vectors"].as_array().unwrap() {
        let second = vector["unix_seconds"].as_u64().unwrap();
        let code = vector["code"].as_str().unwrap();
        assert_eq!(
            totp::validate(secret, code, second, period, digits, tolerance),
            Ok(true),
            "{second}"
        );
        assert_eq!(
            totp::validate(secret, "00000x", second, period, digits, tolerance),
            Ok(false)
        );
        let wrong = if code == "000000" { "999999" } else { "000000" };
        assert_eq!(
            totp::validate(secret, wrong, second, period, digits, tolerance),
            Ok(false)
        );
    }
    let first_code = fixture["vectors"][0]["code"].as_str().unwrap();
    assert_eq!(totp::validate(secret, first_code, 30, 30, 6, 0), Ok(false));
    assert_eq!(totp::validate(secret, first_code, 30, 30, 6, 1), Ok(true));
    assert_eq!(
        totp::validate(&secret.to_ascii_lowercase(), first_code, 0, 30, 6, 0),
        Ok(true)
    );
    assert_eq!(
        totp::validate("not-base32!", "123456", 59, 30, 6, 0),
        Err(Error::Invalid)
    );
    assert_eq!(
        totp::validate("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJ=", "123456", 59, 30, 6, 0),
        Err(Error::Invalid)
    );
    assert_eq!(
        totp::validate(secret, "123456", 59, 0, 6, 0),
        Err(Error::Unsupported)
    );
    assert_eq!(
        totp::validate(secret, "123456", 59, 30, 9, 0),
        Err(Error::Unsupported)
    );
    assert_eq!(
        totp::validate(secret, "123456", 59, 30, 6, 3),
        Err(Error::Unsupported)
    );
}
