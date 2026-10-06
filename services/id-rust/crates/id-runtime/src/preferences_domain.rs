//! Django-compatible preference normalization and public timezone catalogue.

use chrono::{Offset, Utc};
use chrono_tz::Tz;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

pub const DEFAULT_SCOPE_POLICIES: [(&str, &str); 4] = [
    ("profile_basic", "allow"),
    ("email", "ask"),
    ("phone", "ask"),
    ("profile_extended", "ask"),
];

pub fn default_scope_policies() -> BTreeMap<String, String> {
    DEFAULT_SCOPE_POLICIES
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

pub fn clean_scope_policies(input: &serde_json::Map<String, Value>) -> BTreeMap<String, String> {
    let mut output = default_scope_policies();
    for (key, value) in input {
        let policy = match value.as_str() {
            Some("allow") => "allow",
            Some("deny") => "deny",
            _ => "ask",
        };
        output.insert(key.clone(), policy.to_owned());
    }
    output
}

// The source list is the transition Python pytz 2026.2 common_timezones set.
// Keep the whitelist stable for existing clients; chrono-tz supplies current
// IANA rules and requires no runtime filesystem or Python dependency.
const COMMON_TIMEZONES: &str = include_str!("../data/pytz-common-timezones.txt");

pub fn common_timezones() -> impl Iterator<Item = &'static str> {
    COMMON_TIMEZONES.lines()
}

pub fn normalize_timezone(value: &str) -> String {
    let value = value.trim();
    if common_timezones().any(|candidate| candidate == value) {
        value.to_owned()
    } else {
        String::new()
    }
}

#[derive(Debug, Serialize)]
pub struct TimezoneInfo {
    pub name: String,
    pub display_name: String,
    pub offset: String,
}

pub fn timezone_catalogue() -> Vec<TimezoneInfo> {
    let now = Utc::now();
    let mut rows = common_timezones()
        .filter_map(|name| {
            let tz: Tz = name.parse().ok()?;
            let seconds = now.with_timezone(&tz).offset().fix().local_minus_utc();
            let sign = if seconds < 0 { '-' } else { '+' };
            let absolute = seconds.unsigned_abs();
            let offset = format!("{sign}{:02}:{:02}", absolute / 3600, (absolute % 3600) / 60);
            Some((
                seconds,
                TimezoneInfo {
                    name: name.to_owned(),
                    display_name: format!("{name} (UTC{offset})"),
                    offset,
                },
            ))
        })
        .collect::<Vec<_>>();
    rows.sort_by(|(first_offset, first), (second_offset, second)| {
        first_offset
            .cmp(second_offset)
            .then_with(|| first.name.cmp(&second.name))
    });
    rows.into_iter().map(|(_, row)| row).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scope_and_timezone_normalization_matches_transition_rules() {
        let input =
            json!({"email":"deny", "phone":"unknown", "custom":"allow", "profile_basic":null});
        let cleaned = clean_scope_policies(input.as_object().unwrap_or_else(|| unreachable!()));
        assert_eq!(cleaned["email"], "deny");
        assert_eq!(cleaned["phone"], "ask");
        assert_eq!(cleaned["custom"], "allow");
        assert_eq!(cleaned["profile_basic"], "ask");
        assert_eq!(normalize_timezone(" Europe/Moscow "), "Europe/Moscow");
        assert_eq!(normalize_timezone("Not/AZone"), "");
        assert_eq!(common_timezones().count(), 433);
    }

    #[test]
    fn timezone_catalogue_is_complete_and_sorted() {
        let rows = timezone_catalogue();
        assert_eq!(rows.len(), 433);
        assert!(rows.iter().any(|row| row.name == "Europe/Moscow"));
    }
}
