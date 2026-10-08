//! Policy for newly chosen passwords. Existing hashes remain valid for login.

use flate2::read::GzDecoder;
use std::{
    collections::HashSet,
    io::{BufRead, BufReader},
    sync::OnceLock,
};

#[derive(Clone, Debug)]
pub struct AccountWords {
    pub username: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
}

static COMMON: OnceLock<std::io::Result<HashSet<String>>> = OnceLock::new();

fn common_passwords() -> Option<&'static HashSet<String>> {
    COMMON
        .get_or_init(|| {
            let compressed = include_bytes!("../data/common-passwords.txt.gz");
            BufReader::new(GzDecoder::new(compressed.as_slice()))
                .lines()
                .collect::<std::io::Result<HashSet<_>>>()
        })
        .as_ref()
        .ok()
}

pub fn acceptable(new: &str, current: &str, account: &AccountWords) -> bool {
    if new.chars().count() < 10
        || new.trim().is_empty()
        || new == current
        || new.chars().all(|ch| ch.is_numeric())
    {
        return false;
    }
    let lower = new.to_lowercase();
    let Some(common) = common_passwords() else {
        return false;
    };
    if common.contains(lower.trim()) {
        return false;
    }
    let email_name = account.email.split('@').next().unwrap_or_default();
    [
        account.username.as_str(),
        account.first_name.as_str(),
        account.last_name.as_str(),
        email_name,
    ]
    .iter()
    .flat_map(|value| value.split(|ch: char| !ch.is_alphanumeric()))
    .filter(|part| part.chars().count() >= 4)
    .all(|part| !lower.contains(&part.to_lowercase()))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{AccountWords, acceptable};

    fn account() -> AccountWords {
        AccountWords {
            username: "marina.sokolova".into(),
            email: "marina.sokolova@example.invalid".into(),
            first_name: "Marina".into(),
            last_name: "Sokolova".into(),
        }
    }

    #[test]
    fn rejects_common_numeric_and_personal_passwords() {
        let account = account();
        for password in [
            "password123",
            "PASSWORD123",
            "1234567890",
            "marina-safe-2026",
            "SOKOLOVA!2026",
            "correct horse battery staple",
        ] {
            let expected = password == "correct horse battery staple";
            assert_eq!(
                acceptable(password, "old strong password", &account),
                expected,
                "{password}"
            );
        }
        assert!(!acceptable(
            "old strong password",
            "old strong password",
            &account
        ));
        assert!(!acceptable("short", "old strong password", &account));
    }
}
