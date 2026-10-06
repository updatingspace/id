//! Distinct identities that must never be substituted for one another.

use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AccountId(i64);

impl AccountId {
    pub fn new(value: i64) -> Self {
        Self(value)
    }

    pub fn get(self) -> i64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct IdentityId(Uuid);

impl IdentityId {
    pub fn new(value: Uuid) -> Self {
        Self(value)
    }

    pub fn get(self) -> Uuid {
        self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PublicSubject(String);

impl PublicSubject {
    pub fn parse(value: String) -> Option<Self> {
        if value.is_empty() || value.len() > 128 {
            None
        } else {
            Some(Self(value))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}
